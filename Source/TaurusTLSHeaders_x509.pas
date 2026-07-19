/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_x509.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_x509.h2pas
     and this file regenerated. TaurusTLSHeaders_x509.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_x509;

interface

// Headers for OpenSSL 1.1.1
// x509.h

{$IFDEF HAS_DIRECTIVE_HPPEMIT_NAMESPACE}
{$HPPEMIT OPENNAMESPACE}
{$ELSE}
(*$HPPEMIT 'namespace Taurustlsheaders_x509'*)
(*$HPPEMIT '{'*)
{$ENDIF}
(*$HPPEMIT '  struct X509_EXTENSION;'*)
(*$HPPEMIT '  typedef X509_EXTENSION* PX509_EXTENSION;'*)
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
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_stack,
  TaurusTLSHeaders_objects,
  TaurusTLSHeaders_types;

type
  {$EXTERNALSYM X509_ALGORS}
  X509_ALGORS = record end;

const
  (* Flags for X509_get_signature_info() *)
  (* Signature info is valid *)
  {$EXTERNALSYM X509_SIG_INFO_VALID}
  X509_SIG_INFO_VALID = $1;
  (* Signature is suitable for TLS use *)
  {$EXTERNALSYM X509_SIG_INFO_TLS}
  X509_SIG_INFO_TLS = $2;

  {$EXTERNALSYM X509_FILETYPE_PEM}
  X509_FILETYPE_PEM     = 1;
  {$EXTERNALSYM X509_FILETYPE_ASN1}
  X509_FILETYPE_ASN1    = 2;
  {$EXTERNALSYM X509_FILETYPE_DEFAULT}
  X509_FILETYPE_DEFAULT = 3;

  {$EXTERNALSYM X509v3_KU_DIGITAL_SIGNATURE}
  X509v3_KU_DIGITAL_SIGNATURE = $0080;
  {$EXTERNALSYM X509v3_KU_NON_REPUDIATION}
  X509v3_KU_NON_REPUDIATION   = $0040;
  {$EXTERNALSYM X509v3_KU_KEY_ENCIPHERMENT}
  X509v3_KU_KEY_ENCIPHERMENT  = $0020;
  {$EXTERNALSYM X509v3_KU_DATA_ENCIPHERMENT}
  X509v3_KU_DATA_ENCIPHERMENT = $0010;
  {$EXTERNALSYM X509v3_KU_KEY_AGREEMENT}
  X509v3_KU_KEY_AGREEMENT     = $0008;
  {$EXTERNALSYM X509v3_KU_KEY_CERT_SIGN}
  X509v3_KU_KEY_CERT_SIGN     = $0004;
  {$EXTERNALSYM X509v3_KU_CRL_SIGN}
  X509v3_KU_CRL_SIGN          = $0002;
  {$EXTERNALSYM X509v3_KU_ENCIPHER_ONLY}
  X509v3_KU_ENCIPHER_ONLY     = $0001;
  {$EXTERNALSYM X509v3_KU_DECIPHER_ONLY}
  X509v3_KU_DECIPHER_ONLY     = $8000;
  {$EXTERNALSYM X509v3_KU_UNDEF}
  X509v3_KU_UNDEF             = $ffff;

  {$EXTERNALSYM X509_EX_V_NETSCAPE_HACK}
  X509_EX_V_NETSCAPE_HACK = $8000;
  {$EXTERNALSYM X509_EX_V_INIT}
  X509_EX_V_INIT          = $0001;


  (* standard trust ids *)

  {$EXTERNALSYM X509_TRUST_DEFAULT}
  X509_TRUST_DEFAULT      = 0; (* Only valid in purpose settings *)

  {$EXTERNALSYM X509_TRUST_COMPAT}
  X509_TRUST_COMPAT       = 1;
  {$EXTERNALSYM X509_TRUST_SSL_CLIENT}
  X509_TRUST_SSL_CLIENT   = 2;
  {$EXTERNALSYM X509_TRUST_SSL_SERVER}
  X509_TRUST_SSL_SERVER   = 3;
  {$EXTERNALSYM X509_TRUST_EMAIL}
  X509_TRUST_EMAIL        = 4;
  {$EXTERNALSYM X509_TRUST_OBJECT_SIGN}
  X509_TRUST_OBJECT_SIGN  = 5;
  {$EXTERNALSYM X509_TRUST_OCSP_SIGN}
  X509_TRUST_OCSP_SIGN    = 6;
  {$EXTERNALSYM X509_TRUST_OCSP_REQUEST}
  X509_TRUST_OCSP_REQUEST = 7;
  {$EXTERNALSYM X509_TRUST_TSA}
  X509_TRUST_TSA          = 8;

  (* Keep these up to date! *)
  {$EXTERNALSYM X509_TRUST_MIN}
  X509_TRUST_MIN          = 1;
  {$EXTERNALSYM X509_TRUST_MAX}
  X509_TRUST_MAX          = 8;

  (* trust_flags values *)
  {$EXTERNALSYM X509_TRUST_DYNAMIC}
  X509_TRUST_DYNAMIC      = TIdC_UINT(1) shl 0;
  {$EXTERNALSYM X509_TRUST_DYNAMIC_NAME}
  X509_TRUST_DYNAMIC_NAME = TIdC_UINT(1) shl 1;
  (* No compat trust if self-signed, preempts "DO_SS" *)
  {$EXTERNALSYM X509_TRUST_NO_SS_COMPAT}
  X509_TRUST_NO_SS_COMPAT = TIdC_UINT(1) shl 2;
  (* Compat trust if no explicit accepted trust EKUs *)
  {$EXTERNALSYM X509_TRUST_DO_SS_COMPAT}
  X509_TRUST_DO_SS_COMPAT = TIdC_UINT(1) shl 3;
  (* Accept "anyEKU" as a wildcard trust OID *)
  {$EXTERNALSYM X509_TRUST_OK_ANY_EKU}
  X509_TRUST_OK_ANY_EKU   = TIdC_UINT(1) shl 4;

  (* check_trust return codes *)

  {$EXTERNALSYM X509_TRUST_TRUSTED}
  X509_TRUST_TRUSTED   = 1;
  {$EXTERNALSYM X509_TRUST_REJECTED}
  X509_TRUST_REJECTED  = 2;
  {$EXTERNALSYM X509_TRUST_UNTRUSTED}
  X509_TRUST_UNTRUSTED = 3;

  (* Flags for X509_print_ex() *)

  {$EXTERNALSYM X509_FLAG_COMPAT}
  X509_FLAG_COMPAT        = 0;
  {$EXTERNALSYM X509_FLAG_NO_HEADER}
  X509_FLAG_NO_HEADER     = TIdC_LONG(1);
  {$EXTERNALSYM X509_FLAG_NO_VERSION}
  X509_FLAG_NO_VERSION    = TIdC_LONG(1) shl 1;
  {$EXTERNALSYM X509_FLAG_NO_SERIAL}
  X509_FLAG_NO_SERIAL     = TIdC_LONG(1) shl 2;
  {$EXTERNALSYM X509_FLAG_NO_SIGNAME}
  X509_FLAG_NO_SIGNAME    = TIdC_LONG(1) shl 3;
  {$EXTERNALSYM X509_FLAG_NO_ISSUER}
  X509_FLAG_NO_ISSUER     = TIdC_LONG(1) shl 4;
  {$EXTERNALSYM X509_FLAG_NO_VALIDITY}
  X509_FLAG_NO_VALIDITY   = TIdC_LONG(1) shl 5;
  {$EXTERNALSYM X509_FLAG_NO_SUBJECT}
  X509_FLAG_NO_SUBJECT    = TIdC_LONG(1) shl 6;
  {$EXTERNALSYM X509_FLAG_NO_PUBKEY}
  X509_FLAG_NO_PUBKEY     = TIdC_LONG(1) shl 7;
  {$EXTERNALSYM X509_FLAG_NO_EXTENSIONS}
  X509_FLAG_NO_EXTENSIONS = TIdC_LONG(1) shl 8;
  {$EXTERNALSYM X509_FLAG_NO_SIGDUMP}
  X509_FLAG_NO_SIGDUMP    = TIdC_LONG(1) shl 9;
  {$EXTERNALSYM X509_FLAG_NO_AUX}
  X509_FLAG_NO_AUX        = TIdC_LONG(1) shl 10;
  {$EXTERNALSYM X509_FLAG_NO_ATTRIBUTES}
  X509_FLAG_NO_ATTRIBUTES = TIdC_LONG(1) shl 11;
  {$EXTERNALSYM X509_FLAG_NO_IDS}
  X509_FLAG_NO_IDS        = TIdC_LONG(1) shl 12;

  (* Flags specific to X509_NAME_print_ex() *)

  (* The field separator information *)

  {$EXTERNALSYM XN_FLAG_SEP_MASK}
  XN_FLAG_SEP_MASK       = $f shl 16;

  {$EXTERNALSYM XN_FLAG_COMPAT}
  XN_FLAG_COMPAT         = 0;(* Traditional; use old X509_NAME_print *)
  {$EXTERNALSYM XN_FLAG_SEP_COMMA_PLUS}
  XN_FLAG_SEP_COMMA_PLUS = 1 shl 16;(* RFC2253 ,+ *)
  {$EXTERNALSYM XN_FLAG_SEP_CPLUS_SPC}
  XN_FLAG_SEP_CPLUS_SPC  = 2 shl 16;(* ,+ spaced: more readable *)
  {$EXTERNALSYM XN_FLAG_SEP_SPLUS_SPC}
  XN_FLAG_SEP_SPLUS_SPC  = 3 shl 16;(* ;+ spaced *)
  {$EXTERNALSYM XN_FLAG_SEP_MULTILINE}
  XN_FLAG_SEP_MULTILINE  = 4 shl 16;(* One line per field *)

  {$EXTERNALSYM XN_FLAG_DN_REV}
  XN_FLAG_DN_REV         = 1 shl 20;(* Reverse DN order *)

  (* How the field name is shown *)

  {$EXTERNALSYM XN_FLAG_FN_MASK}
  XN_FLAG_FN_MASK        = $3 shl 21;

  {$EXTERNALSYM XN_FLAG_FN_SN}
  XN_FLAG_FN_SN          = 0;(* Object short name *)
  {$EXTERNALSYM XN_FLAG_FN_LN}
  XN_FLAG_FN_LN          = 1 shl 21;(* Object long name *)
  {$EXTERNALSYM XN_FLAG_FN_OID}
  XN_FLAG_FN_OID         = 2 shl 21;(* Always use OIDs *)
  {$EXTERNALSYM XN_FLAG_FN_NONE}
  XN_FLAG_FN_NONE        = 3 shl 21;(* No field names *)

  {$EXTERNALSYM XN_FLAG_SPC_EQ}
  XN_FLAG_SPC_EQ         = 1 shl 23;(* Put spaces round '=' *)

  {function codes}
  {$EXTERNALSYM X509_F_ADD_CERT_DIR}
  X509_F_ADD_CERT_DIR	= 100;
  {$EXTERNALSYM X509_F_BY_FILE_CTRL}
  X509_F_BY_FILE_CTRL	= 101;
  {$EXTERNALSYM X509_F_CHECK_NAME_CONSTRAINTS}
  X509_F_CHECK_NAME_CONSTRAINTS	= 106;
  {$EXTERNALSYM X509_F_CHECK_POLICY}
  X509_F_CHECK_POLICY	= 145;
  {$EXTERNALSYM X509_F_DIR_CTRL}
  X509_F_DIR_CTRL	= 102;
  {$EXTERNALSYM X509_F_GET_CERT_BY_SUBJECT}
  X509_F_GET_CERT_BY_SUBJECT	= 103;
  {$EXTERNALSYM X509_F_NETSCAPE_SPKI_B64_DECODE}
  X509_F_NETSCAPE_SPKI_B64_DECODE	= 129;
  {$EXTERNALSYM X509_F_NETSCAPE_SPKI_B64_ENCODE}
  X509_F_NETSCAPE_SPKI_B64_ENCODE	= 130;
  {$EXTERNALSYM X509_F_X509AT_ADD1_ATTR}
  X509_F_X509AT_ADD1_ATTR	= 135;
  {$EXTERNALSYM X509_F_X509V3_ADD_EXT}
  X509_F_X509V3_ADD_EXT	= 104;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_CREATE_BY_NID}
  X509_F_X509_ATTRIBUTE_CREATE_BY_NID	= 136;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ}
  X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ	= 137;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_CREATE_BY_TXT}
  X509_F_X509_ATTRIBUTE_CREATE_BY_TXT	= 140;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_GET0_DATA}
  X509_F_X509_ATTRIBUTE_GET0_DATA	= 139;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_SET1_DATA}
  X509_F_X509_ATTRIBUTE_SET1_DATA	= 138;
  {$EXTERNALSYM X509_F_X509_CHECK_PRIVATE_KEY}
  X509_F_X509_CHECK_PRIVATE_KEY	= 128;
  {$EXTERNALSYM X509_F_X509_CRL_DIFF}
  X509_F_X509_CRL_DIFF	= 105;
  {$EXTERNALSYM X509_F_X509_CRL_PRINT_FP}
  X509_F_X509_CRL_PRINT_FP	= 147;
  {$EXTERNALSYM X509_F_X509_EXTENSION_CREATE_BY_NID}
  X509_F_X509_EXTENSION_CREATE_BY_NID	= 108;
  {$EXTERNALSYM X509_F_X509_EXTENSION_CREATE_BY_OBJ}
  X509_F_X509_EXTENSION_CREATE_BY_OBJ	= 109;
  {$EXTERNALSYM X509_F_X509_GET_PUBKEY_PARAMETERS}
  X509_F_X509_GET_PUBKEY_PARAMETERS	= 110;
  {$EXTERNALSYM X509_F_X509_LOAD_CERT_CRL_FILE}
  X509_F_X509_LOAD_CERT_CRL_FILE	= 132;
  {$EXTERNALSYM X509_F_X509_LOAD_CERT_FILE}
  X509_F_X509_LOAD_CERT_FILE	= 111;
  {$EXTERNALSYM X509_F_X509_LOAD_CRL_FILE}
  X509_F_X509_LOAD_CRL_FILE	= 112;
  {$EXTERNALSYM X509_F_X509_NAME_ADD_ENTRY}
  X509_F_X509_NAME_ADD_ENTRY	= 113;
  {$EXTERNALSYM X509_F_X509_NAME_ENTRY_CREATE_BY_NID}
  X509_F_X509_NAME_ENTRY_CREATE_BY_NID	= 114;
  {$EXTERNALSYM X509_F_X509_NAME_ENTRY_CREATE_BY_TXT}
  X509_F_X509_NAME_ENTRY_CREATE_BY_TXT	= 131;
  {$EXTERNALSYM X509_F_X509_NAME_ENTRY_SET_OBJECT}
  X509_F_X509_NAME_ENTRY_SET_OBJECT	= 115;
  {$EXTERNALSYM X509_F_X509_NAME_ONELINE}
  X509_F_X509_NAME_ONELINE	= 116;
  {$EXTERNALSYM X509_F_X509_NAME_PRINT}
  X509_F_X509_NAME_PRINT	= 117;
  {$EXTERNALSYM X509_F_X509_PRINT_EX_FP}
  X509_F_X509_PRINT_EX_FP	= 118;
  {$EXTERNALSYM X509_F_X509_PUBKEY_GET}
  X509_F_X509_PUBKEY_GET	= 119;
  {$EXTERNALSYM X509_F_X509_PUBKEY_SET}
  X509_F_X509_PUBKEY_SET	= 120;
  {$EXTERNALSYM X509_F_X509_REQ_CHECK_PRIVATE_KEY}
  X509_F_X509_REQ_CHECK_PRIVATE_KEY	= 144;
  {$EXTERNALSYM X509_F_X509_REQ_PRINT_EX}
  X509_F_X509_REQ_PRINT_EX	= 121;
  {$EXTERNALSYM X509_F_X509_REQ_PRINT_FP}
  X509_F_X509_REQ_PRINT_FP	= 122;
  {$EXTERNALSYM X509_F_X509_REQ_TO_X509}
  X509_F_X509_REQ_TO_X509	= 123;
  {$EXTERNALSYM X509_F_X509_STORE_ADD_CERT}
  X509_F_X509_STORE_ADD_CERT	= 124;
  {$EXTERNALSYM X509_F_X509_STORE_ADD_CRL}
  X509_F_X509_STORE_ADD_CRL	= 125;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_GET1_ISSUER}
  X509_F_X509_STORE_CTX_GET1_ISSUER	= 146;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_INIT}
  X509_F_X509_STORE_CTX_INIT	= 143;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_NEW}
  X509_F_X509_STORE_CTX_NEW	= 142;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_PURPOSE_INHERIT}
  X509_F_X509_STORE_CTX_PURPOSE_INHERIT	= 134;
  {$EXTERNALSYM X509_F_X509_TO_X509_REQ}
  X509_F_X509_TO_X509_REQ	= 126;
  {$EXTERNALSYM X509_F_X509_TRUST_ADD}
  X509_F_X509_TRUST_ADD	= 133;
  {$EXTERNALSYM X509_F_X509_TRUST_SET}
  X509_F_X509_TRUST_SET	= 141;
  {$EXTERNALSYM X509_F_X509_VERIFY_CERT}
  X509_F_X509_VERIFY_CERT	= 127;

  {Reason Codes}
  {$EXTERNALSYM X509_R_AKID_MISMATCH}
  X509_R_AKID_MISMATCH 				= 110;
  {$EXTERNALSYM X509_R_BAD_X509_FILETYPE}
  X509_R_BAD_X509_FILETYPE 		        = 100;
  {$EXTERNALSYM X509_R_BASE64_DECODE_ERROR}
  X509_R_BASE64_DECODE_ERROR 		        = 118;
  {$EXTERNALSYM X509_R_CANT_CHECK_DH_KEY}
  X509_R_CANT_CHECK_DH_KEY 		        = 114;
  {$EXTERNALSYM X509_R_CERT_ALREADY_IN_HASH_TABLE}
  X509_R_CERT_ALREADY_IN_HASH_TABLE 		= 101;
  {$EXTERNALSYM X509_R_CRL_ALREADY_DELTA}
  X509_R_CRL_ALREADY_DELTA 		        = 127;
  {$EXTERNALSYM X509_R_CRL_VERIFY_FAILURE}
  X509_R_CRL_VERIFY_FAILURE 		        = 131;
  {$EXTERNALSYM X509_R_ERR_ASN1_LIB}
  X509_R_ERR_ASN1_LIB 		                = 102;
  {$EXTERNALSYM X509_R_IDP_MISMATCH}
  X509_R_IDP_MISMATCH 		                = 128;
  {$EXTERNALSYM X509_R_INVALID_DIRECTORY}
  X509_R_INVALID_DIRECTORY 		        = 113;
  {$EXTERNALSYM X509_R_INVALID_FIELD_NAME}
  X509_R_INVALID_FIELD_NAME 		        = 119;
  {$EXTERNALSYM X509_R_INVALID_TRUST}
  X509_R_INVALID_TRUST 		                = 123;
  {$EXTERNALSYM X509_R_ISSUER_MISMATCH}
  X509_R_ISSUER_MISMATCH 		        = 129;
  {$EXTERNALSYM X509_R_KEY_TYPE_MISMATCH}
  X509_R_KEY_TYPE_MISMATCH	= 115;
  {$EXTERNALSYM X509_R_KEY_VALUES_MISMATCH}
  X509_R_KEY_VALUES_MISMATCH	= 116;
  {$EXTERNALSYM X509_R_LOADING_CERT_DIR}
  X509_R_LOADING_CERT_DIR	= 103;
  {$EXTERNALSYM X509_R_LOADING_DEFAULTS}
  X509_R_LOADING_DEFAULTS	= 104;
  {$EXTERNALSYM X509_R_METHOD_NOT_SUPPORTED}
  X509_R_METHOD_NOT_SUPPORTED	= 124;
  {$EXTERNALSYM X509_R_NAME_TOO_LONG}
  X509_R_NAME_TOO_LONG	= 134;
  {$EXTERNALSYM X509_R_NEWER_CRL_NOT_NEWER}
  X509_R_NEWER_CRL_NOT_NEWER	= 132;
  {$EXTERNALSYM X509_R_NO_CERT_SET_FOR_US_TO_VERIFY}
  X509_R_NO_CERT_SET_FOR_US_TO_VERIFY	= 105;
  {$EXTERNALSYM X509_R_NO_CRL_NUMBER}
  X509_R_NO_CRL_NUMBER	= 130;
  {$EXTERNALSYM X509_R_PUBLIC_KEY_DECODE_ERROR}
  X509_R_PUBLIC_KEY_DECODE_ERROR	= 125;
  {$EXTERNALSYM X509_R_PUBLIC_KEY_ENCODE_ERROR}
  X509_R_PUBLIC_KEY_ENCODE_ERROR	= 126;
  {$EXTERNALSYM X509_R_SHOULD_RETRY}
  X509_R_SHOULD_RETRY	= 106;
  {$EXTERNALSYM X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN}
  X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN	= 107;
  {$EXTERNALSYM X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY}
  X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY	= 108;
  {$EXTERNALSYM X509_R_UNKNOWN_KEY_TYPE}
  X509_R_UNKNOWN_KEY_TYPE	= 117;
  {$EXTERNALSYM X509_R_UNKNOWN_NID}
  X509_R_UNKNOWN_NID	= 109;
  {$EXTERNALSYM X509_R_UNKNOWN_PURPOSE_ID}
  X509_R_UNKNOWN_PURPOSE_ID	= 121;
  {$EXTERNALSYM X509_R_UNKNOWN_TRUST_ID}
  X509_R_UNKNOWN_TRUST_ID	= 120;
  {$EXTERNALSYM X509_R_UNSUPPORTED_ALGORITHM}
  X509_R_UNSUPPORTED_ALGORITHM	= 111;
  {$EXTERNALSYM X509_R_WRONG_LOOKUP_TYPE}
  X509_R_WRONG_LOOKUP_TYPE	= 112;
  {$EXTERNALSYM X509_R_WRONG_TYPE}
  X509_R_WRONG_TYPE	= 122;

  (*
   * This determines if we dump fields we don't recognise: RFC2253 requires
   * this.
   *)

  {$EXTERNALSYM XN_FLAG_DUMP_UNKNOWN_FIELDS}
  XN_FLAG_DUMP_UNKNOWN_FIELDS = 1 shl 24;

  {$EXTERNALSYM XN_FLAG_FN_ALIGN}
  XN_FLAG_FN_ALIGN = 1 shl 25;(* Align field names to 20
                                             * characters *)

  (* Complete set of RFC2253 flags *)

  {$EXTERNALSYM XN_FLAG_RFC2253}
  XN_FLAG_RFC2253 = ASN1_STRFLGS_RFC2253 or XN_FLAG_SEP_COMMA_PLUS
    or XN_FLAG_DN_REV or XN_FLAG_FN_SN or XN_FLAG_DUMP_UNKNOWN_FIELDS;

  (* readable oneline form *)

  {$EXTERNALSYM XN_FLAG_ONELINE}
  XN_FLAG_ONELINE = ASN1_STRFLGS_RFC2253 or ASN1_STRFLGS_ESC_QUOTE
    or XN_FLAG_SEP_CPLUS_SPC or XN_FLAG_SPC_EQ or XN_FLAG_FN_SN;

  (* readable multiline form *)

  {$EXTERNALSYM XN_FLAG_MULTILINE}
  XN_FLAG_MULTILINE = ASN1_STRFLGS_ESC_CTRL or ASN1_STRFLGS_ESC_MSB
    or XN_FLAG_SEP_MULTILINE or XN_FLAG_SPC_EQ or XN_FLAG_FN_LN or XN_FLAG_FN_ALIGN;

  {$EXTERNALSYM X509_EXT_PACK_UNKNOWN}
  X509_EXT_PACK_UNKNOWN = 1;
  {$EXTERNALSYM X509_EXT_PACK_STRING}
  X509_EXT_PACK_STRING  = 2;

type

  {$EXTERNALSYM X509_val_st}
  X509_val_st = record
    notBefore: PASN1_TIME;
    notAfter: PASN1_TIME;
  end;
  {$EXTERNALSYM X509_VAL}
  X509_VAL = X509_val_st;
  {$EXTERNALSYM PX509_VAL}
  PX509_VAL = ^X509_VAL;
  {$EXTERNALSYM PPX509_VAL}
  PPX509_VAL = ^PX509_VAL;

  {$EXTERNALSYM X509_SIG}
  X509_SIG = record end; // X509_sig_st
  {$EXTERNALSYM PX509_SIG}
  PX509_SIG = ^X509_SIG;
  {$EXTERNALSYM PPX509_SIG}
  PPX509_SIG = ^PX509_SIG;

  {$EXTERNALSYM X509_NAME_ENTRY}
  X509_NAME_ENTRY = record end; // X509_name_entry_st
  {$EXTERNALSYM PX509_NAME_ENTRY}
  PX509_NAME_ENTRY = ^X509_NAME_ENTRY;
  {$EXTERNALSYM PPX509_NAME_ENTRY}
  PPX509_NAME_ENTRY = ^PX509_NAME_ENTRY;

  //DEFINE_STACK_OF(X509_NAME_ENTRY)
  {$EXTERNALSYM STACK_OF_X509_NAME_ENTRY}
  STACK_OF_X509_NAME_ENTRY = record end;
  {$EXTERNALSYM PSTACK_OF_X509_NAME_ENTRY}
  PSTACK_OF_X509_NAME_ENTRY = ^STACK_OF_X509_NAME_ENTRY;
  //
  //DEFINE_STACK_OF(X509_NAME)
  {$EXTERNALSYM STACK_OF_X509_NAME}
  STACK_OF_X509_NAME = record end;
  {$EXTERNALSYM PSTACK_OF_X509_NAME}
  PSTACK_OF_X509_NAME = ^STACK_OF_X509_NAME;

  {$EXTERNALSYM X509_EXTENSION}
  X509_EXTENSION = record end; // X509_extension_st
  {$EXTERNALSYM PX509_EXTENSION}
  PX509_EXTENSION = ^X509_EXTENSION;
  {$EXTERNALSYM PPX509_EXTENSION}
  PPX509_EXTENSION = ^PX509_EXTENSION;

  //typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;
  //
  {$EXTERNALSYM STACK_OF_X509_EXTENSION}
  STACK_OF_X509_EXTENSION = record end;
  {$EXTERNALSYM PSTACK_OF_X509_EXTENSION}
  PSTACK_OF_X509_EXTENSION = ^STACK_OF_X509_EXTENSION;
  {$EXTERNALSYM PX509_EXTENSIONS}
  PX509_EXTENSIONS = PSTACK_OF_X509_EXTENSION;
  {$EXTERNALSYM X509_ATTRIBUTE}
  X509_ATTRIBUTE = record end; // x509_attributes_st
  {$EXTERNALSYM PX509_ATTRIBUTE}
  PX509_ATTRIBUTE = ^X509_ATTRIBUTE;
  {$EXTERNALSYM PPX509_ATTRIBUTE}
  PPX509_ATTRIBUTE = ^PX509_ATTRIBUTE;

  {$EXTERNALSYM STACK_OF_X509_ATTRIBUTE}
  STACK_OF_X509_ATTRIBUTE = record end;
  {$EXTERNALSYM PSTACK_OF_X509_ATTRIBUTE}
  PSTACK_OF_X509_ATTRIBUTE = ^STACK_OF_X509_ATTRIBUTE;

  {$EXTERNALSYM X509_REQ_INFO}
  X509_REQ_INFO = record end; // X509_req_info_st
  {$EXTERNALSYM PX509_REQ_INFO}
  PX509_REQ_INFO = ^X509_REQ_INFO;
  {$EXTERNALSYM PPX509_REQ_INFO}
  PPX509_REQ_INFO = ^PX509_REQ_INFO;

  {$EXTERNALSYM X509_CERT_AUX}
  X509_CERT_AUX = record end; // x509_cert_aux_st

  {$EXTERNALSYM X509_CINF}
  X509_CINF = record end; // x509_cinf_st

  //DEFINE_STACK_OF(X509)

  (* This is used for a table of trust checking functions *)

  {$EXTERNALSYM Px509_trust_st}
  Px509_trust_st = ^x509_trust_st;
  {$EXTERNALSYM x509_trust_st}
  x509_trust_st = record
    trust: TIdC_INT;
    flags: TIdC_INT;
    check_trust: function(v1: Px509_trust_st; v2: PX509; v3: TIdC_INT): TIdC_INT; cdecl;
    name: PIdAnsiChar;
    arg1: TIdC_INT;
    arg2: Pointer;
  end;
  {$EXTERNALSYM X509_TRUST}
  X509_TRUST = x509_trust_st;
  {$EXTERNALSYM PX509_TRUST}
  PX509_TRUST = ^X509_TRUST;

  {$EXTERNALSYM STACK_OF_X509_TRUST}
  STACK_OF_X509_TRUST = record end;
  {$EXTERNALSYM PSTACK_OF_X509_TRUST}
  PSTACK_OF_X509_TRUST = ^STACK_OF_X509_TRUST;
  {$EXTERNALSYM STACK_OF_X509_REVOKED}
  STACK_OF_X509_REVOKED = record end;
  {$EXTERNALSYM PSTACK_OF_X509_REVOKED}
  PSTACK_OF_X509_REVOKED = ^STACK_OF_X509_REVOKED;
  {$EXTERNALSYM X509_CRL_INFO}
  X509_CRL_INFO = record end; // X509_crl_info_st
  {$EXTERNALSYM PX509_CRL_INFO}
  PX509_CRL_INFO = ^X509_CRL_INFO;
  {$EXTERNALSYM PPX509_CRL_INFO}
  PPX509_CRL_INFO = ^PX509_CRL_INFO;
  {$EXTERNALSYM STACK_OF_X509_CRL}
  STACK_OF_X509_CRL = record end;
  {$EXTERNALSYM PSTACK_OF_X509_CRL}
  PSTACK_OF_X509_CRL = ^STACK_OF_X509_CRL;

  {$EXTERNALSYM private_key_st}
  private_key_st = record
    version: TIdC_INT;
    (* The PKCS#8 data types *)
    enc_algor: PX509_ALGOR;
    enc_pkey: PASN1_OCTET_STRING; (* encrypted pub key *)
    (* When decrypted, the following will not be NULL *)
    dec_pkey: PEVP_PKEY;
    (* used to encrypt and decrypt *)
    key_length: TIdC_INT;
    key_data: PIdAnsiChar;
    key_free: TIdC_INT;               (* true if we should auto free key_data *)
    (* expanded version of 'enc_algor' *)
    cipher: EVP_CIPHER_INFO;
  end;
  {$EXTERNALSYM X509_PKEY}
  X509_PKEY = private_key_st;
  {$EXTERNALSYM PX509_PKEY}
  PX509_PKEY = ^X509_PKEY;

  {$EXTERNALSYM X509_info_st}
  X509_info_st = record
    x509: PX509;
    crl: PX509_CRL;
    x_pkey: PX509_PKEY;
    enc_cipher: EVP_CIPHER_INFO;
    enc_len: TIdC_INT;
    enc_data: PIdAnsiChar;
  end;
  {$EXTERNALSYM X509_INFO}
  X509_INFO = X509_info_st;
  {$EXTERNALSYM PX509_INFO}
  PX509_INFO = ^X509_INFO;

  (*
   * The next 2 structures and their 8 routines are used to manipulate Netscape's
   * spki structures - useful if you are writing a CA web page
   *)
  {$EXTERNALSYM Netscape_spkac_st}
  Netscape_spkac_st = record
    pubkey: PX509_PUBKEY;
    challenge: PASN1_IA5STRING;  (* challenge sent in atlas >= PR2 *)
  end;
  {$EXTERNALSYM NETSCAPE_SPKAC}
  NETSCAPE_SPKAC = Netscape_spkac_st;
  {$EXTERNALSYM PNETSCAPE_SPKAC}
  PNETSCAPE_SPKAC = ^NETSCAPE_SPKAC;

  {$EXTERNALSYM Netscape_spki_st}
  Netscape_spki_st = record
    spkac: PNETSCAPE_SPKAC;      (* signed public key and challenge *)
    sig_algor: X509_ALGOR;
    signature: PASN1_BIT_STRING;
  end;
  {$EXTERNALSYM NETSCAPE_SPKI}
  NETSCAPE_SPKI = Netscape_spki_st;
  {$EXTERNALSYM PNETSCAPE_SPKI}
  PNETSCAPE_SPKI = ^NETSCAPE_SPKI;

  (* Netscape certificate sequence structure *)
//  Netscape_certificate_sequence: record
//    type_: PASN1_OBJECT;
//    certs: P --> STACK_OF(X509) <--;
//  end;
//  NETSCAPE_CERT_SEQUENCE = Netscape_certificate_sequence;

  (*- Unused (and iv length is wrong)
  typedef struct CBCParameter_st
          {
          unsigned char iv[8];
          } CBC_PARAM;
  *)

  (* Password based encryption structure *)
  {$EXTERNALSYM PBEPARAM_st}
  PBEPARAM_st = record
    salt: PASN1_OCTET_STRING;
    iter: PASN1_INTEGER;
  end;
  {$EXTERNALSYM PBEPARAM}
  PBEPARAM = PBEPARAM_st;

  (* Password based encryption V2 structures *)
  {$EXTERNALSYM PBE2PARAM_st}
  PBE2PARAM_st = record
    keyfunc: PX509_ALGOR;
    encryption: X509_ALGOR;
  end;
  {$EXTERNALSYM PBE2PARAM}
  PBE2PARAM = PBE2PARAM_st;

  {$EXTERNALSYM PBKDF2PARAM_st}
  PBKDF2PARAM_st = record
  (* Usually OCTET STRING but could be anything *)
    salt: PASN1_TYPE;
    iter: PASN1_INTEGER;
    keylength: PASN1_INTEGER;
    prf: X509_ALGOR;
  end;
  {$EXTERNALSYM PBKDF2PARAM}
  PBKDF2PARAM = PBKDF2PARAM_st;

  {$EXTERNALSYM SCRYPT_PARAMS_st}
  SCRYPT_PARAMS_st = record
    salt: PASN1_OCTET_STRING;
    costParameter: PASN1_INTEGER;
    blockSize: PASN1_INTEGER;
    parallelizationParameter: PASN1_INTEGER;
    keyLength: ASN1_INTEGER;
  end;
  {$EXTERNALSYM SCRYPT_PARAMS}
  SCRYPT_PARAMS = SCRYPT_PARAMS_st;

  //# define         X509_extract_key(x)     X509_get_pubkey(x)(*****)
  //# define         X509_REQ_extract_key(a) X509_REQ_get_pubkey(a)
  //# define         X509_name_cmp(a,b)      X509_NAME_cmp((a),(b))
  //

{forward_compatibility}

const
  {$EXTERNALSYM ASIdentifierChoice_inherit}
  ASIdentifierChoice_inherit = 0;
  {$EXTERNALSYM ASIdentifierChoice_asIdsOrRanges}
  ASIdentifierChoice_asIdsOrRanges = 1;
  {$EXTERNALSYM SHA_DIGEST_LENGTH}
  SHA_DIGEST_LENGTH = 20;

type
  {$EXTERNALSYM PX509_CINF}
  PX509_CINF = ^_X509_CINF;
  {$EXTERNALSYM _X509_CINF}
  _X509_CINF = record
    version: PASN1_INTEGER;
    serialNumber: PASN1_INTEGER;
    signature: PX509_ALGOR;
    issuer: PX509_NAME;
    validity: PX509_VAL;
    subject: PX509_NAME;
    key: PX509_PUBKEY;
    issuerUID: PASN1_BIT_STRING; // [ 1 ] optional in v2
    subjectUID: PASN1_BIT_STRING; // [ 2 ] optional in v2
    extensions: PSTACK_OF_X509_EXTENSION;
    enc : ASN1_ENCODING;
  end;

  {$EXTERNALSYM PX509_ALGOR}
  PX509_ALGOR  = ^X509_ALGOR;
  {$EXTERNALSYM X509_ALGOR}
  X509_ALGOR = record
    algorithm : PASN1_OBJECT;
    parameter : PASN1_TYPE;
  end;

  {$EXTERNALSYM STACK_OF_ASIdOrRange}
  STACK_OF_ASIdOrRange = record end;
  {$EXTERNALSYM PSTACK_OF_ASIdOrRange}
  PSTACK_OF_ASIdOrRange = ^STACK_OF_ASIdOrRange;

  {$EXTERNALSYM STACK_OF_DIST_POINT}
  STACK_OF_DIST_POINT = record end;
  {$EXTERNALSYM PSTACK_OF_DIST_POINT}
  PSTACK_OF_DIST_POINT = ^STACK_OF_DIST_POINT;
  {$EXTERNALSYM STACK_OF_GENERAL_NAME}
  STACK_OF_GENERAL_NAME = record end;
  {$EXTERNALSYM PSTACK_OF_GENERAL_NAME}
  PSTACK_OF_GENERAL_NAME = ^STACK_OF_GENERAL_NAME;
  {$EXTERNALSYM STACK_OF_IPAddressFamily}
  STACK_OF_IPAddressFamily = record end;
  {$EXTERNALSYM PSTACK_OF_IPAddressFamily}
  PSTACK_OF_IPAddressFamily = ^STACK_OF_IPAddressFamily;
  {$EXTERNALSYM PASIdOrRanges}
  PASIdOrRanges = PSTACK_OF_ASIdOrRange;

  {$EXTERNALSYM ASIdentifierChoice_union}
  ASIdentifierChoice_union = record
  case byte of
   ASIdentifierChoice_inherit : (inherit : PASN1_NULL);
   ASIdentifierChoice_asIdsOrRanges : (asIdsOrRanges : PASIdOrRanges);
  end;

  {$EXTERNALSYM PASIdentifierChoice}
  PASIdentifierChoice = ^ASIdentifierChoice;
  {$EXTERNALSYM ASIdentifierChoice}
  ASIdentifierChoice = record
    _type : TIdC_INT;
    u : ASIdentifierChoice_union;
  end;

  {$EXTERNALSYM PASIdentifiers}
  PASIdentifiers = ^ASIdentifiers;
  {$EXTERNALSYM ASIdentifiers}
  ASIdentifiers = record
    asnum : PASIdentifierChoice;
    rdi : PASIdentifierChoice;
  end;

  {$EXTERNALSYM PX509_CERT_AUX}
  PX509_CERT_AUX = ^X509_CERT_AUX;


{X509 = record
    cert_info: PX509_CINF;
    sig_alg : PX509_ALGOR;
    signature : PASN1_BIT_STRING;
    valid : TIdC_INT;
    references : TIdC_INT;
    name : PIdAnsiChar;
    ex_data : CRYPTO_EX_DATA;
    // These contain copies of various extension values
    ex_pathlen : TIdC_LONG;
    ex_pcpathlen : TIdC_LONG;
    ex_flags : TIdC_ULONG;
    ex_kusage : TIdC_ULONG;
    ex_xkusage : TIdC_ULONG;
    ex_nscert : TIdC_ULONG;
    skid : PASN1_OCTET_STRING;
    akid : PAUTHORITY_KEYID;
    policy_cache : PX509_POLICY_CACHE;
    crldp : PSTACK_OF_DIST_POINT;
    altname : PSTACK_OF_GENERAL_NAME;
    nc : PNAME_CONSTRAINTS;
//    {$IFNDEF OPENSSL_NO_RFC3779}
{    rfc3779_addr : PSTACK_OF_IPAddressFamily;
    rfc3779_asid : PASIdentifiers;
//    {$ENDIF}
//    {$IFNDEF OPENSSL_NO_SHA}
//    sha1_hash : array [0..SHA_DIGEST_LENGTH-1] of TIdAnsiChar;
//    {$ENDIF}
//    aux : PX509_CERT_AUX;
//  end;       }

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
{helper_functions}
type
  {$EXTERNALSYM PSTACK_OF_X509_INFO}
  PSTACK_OF_X509_INFO = pointer;

 {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
type
  {$EXTERNALSYM Tsk_X509_new}
  Tsk_X509_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509 cdecl;
  {$EXTERNALSYM Tsk_X509_new_null}
  Tsk_X509_new_null = function : PSTACK_OF_X509 cdecl;
  {$EXTERNALSYM Tsk_X509_free}
  Tsk_X509_free = procedure(st : PSTACK_OF_X509) cdecl;
  {$EXTERNALSYM Tsk_X509_num}
  Tsk_X509_num = function (const sk : PSTACK_OF_X509) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_value}
  Tsk_X509_value = function (const sk : PSTACK_OF_X509; i : TIdC_INT) : PX509 cdecl;
  {$EXTERNALSYM Tsk_X509_push}
  Tsk_X509_push = function (sk : PSTACK_OF_X509; st : PX509 ) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_dup}
  Tsk_X509_dup = function (sk : PSTACK_OF_X509) : PSTACK_OF_X509 cdecl;
  {$EXTERNALSYM Tsk_X509_find}
  Tsk_X509_find = function (sk : PSTACK_OF_X509; _val : PX509 ) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_pop_free}
  Tsk_X509_pop_free = procedure (sk : PSTACK_OF_X509; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_new}
  Tsk_X509_NAME_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_NAME cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_new_null}
  Tsk_X509_NAME_new_null = function : PSTACK_OF_X509_NAME cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_free}
  Tsk_X509_NAME_free = procedure(st : PSTACK_OF_X509_NAME) cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_num}
  Tsk_X509_NAME_num = function (const sk : PSTACK_OF_X509_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_value}
  Tsk_X509_NAME_value = function (const sk : PSTACK_OF_X509_NAME; i : TIdC_INT) : PX509_NAME cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_push}
  Tsk_X509_NAME_push = function (sk : PSTACK_OF_X509_NAME; st : PX509_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_dup}
  Tsk_X509_NAME_dup = function (sk : PSTACK_OF_X509_NAME) : PSTACK_OF_X509_NAME cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_find}
  Tsk_X509_NAME_find = function (sk : PSTACK_OF_X509_NAME; _val : PX509_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_pop_free}
  Tsk_X509_NAME_pop_free = procedure (sk : PSTACK_OF_X509_NAME; func: TOPENSSL_sk_freefunc) cdecl;

  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_new}
  Tsk_X509_NAME_ENTRY_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_NAME_ENTRY cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_new_null}
  Tsk_X509_NAME_ENTRY_new_null = function : PSTACK_OF_X509_NAME_ENTRY cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_free}
  Tsk_X509_NAME_ENTRY_free = procedure(st : PSTACK_OF_X509_NAME_ENTRY) cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_num}
  Tsk_X509_NAME_ENTRY_num = function (const sk : PSTACK_OF_X509_NAME_ENTRY) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_value}
  Tsk_X509_NAME_ENTRY_value = function (const sk : PSTACK_OF_X509_NAME_ENTRY; i : TIdC_INT) : PX509_NAME cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_push}
  Tsk_X509_NAME_ENTRY_push = function (sk : PSTACK_OF_X509_NAME_ENTRY; st : PX509_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_dup}
  Tsk_X509_NAME_ENTRY_dup = function (sk : PSTACK_OF_X509_NAME_ENTRY) : PSTACK_OF_X509_NAME_ENTRY cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_find}
  Tsk_X509_NAME_ENTRY_find = function (sk : PSTACK_OF_X509_NAME_ENTRY; _val : PX509_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_NAME_ENTRY_pop_free}
  Tsk_X509_NAME_ENTRY_pop_free = procedure (sk : PSTACK_OF_X509_NAME_ENTRY; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_new}
  Tsk_X509_INFO_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_INFO cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_new_null}
  Tsk_X509_INFO_new_null = function : PSTACK_OF_X509_INFO cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_free}
  Tsk_X509_INFO_free = procedure(st : PSTACK_OF_X509_INFO) cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_num}
  Tsk_X509_INFO_num = function (const sk : PSTACK_OF_X509_INFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_value}
  Tsk_X509_INFO_value = function (const sk : PSTACK_OF_X509_INFO; i : TIdC_INT) : PX509_INFO cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_push}
  Tsk_X509_INFO_push = function (sk : PSTACK_OF_X509_INFO; st : PX509_INFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_dup}
  Tsk_X509_INFO_dup = function (sk : PSTACK_OF_X509_INFO) : PSTACK_OF_X509_INFO cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_find}
  Tsk_X509_INFO_find = function (sk : PSTACK_OF_X509_INFO; _val : PX509_INFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_INFO_pop_free}
  Tsk_X509_INFO_pop_free = procedure (sk : PSTACK_OF_X509_INFO; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_new}
  Tsk_X509_EXTENSION_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_EXTENSION cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_new_null}
  Tsk_X509_EXTENSION_new_null = function : PSTACK_OF_X509_EXTENSION cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_free}
  Tsk_X509_EXTENSION_free = procedure(st : PSTACK_OF_X509_EXTENSION) cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_num}
  Tsk_X509_EXTENSION_num = function (const sk : PSTACK_OF_X509_EXTENSION) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_value}
  Tsk_X509_EXTENSION_value = function (const sk : PSTACK_OF_X509_EXTENSION; i : TIdC_INT) : PX509_EXTENSION cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_push}
  Tsk_X509_EXTENSION_push = function (sk : PSTACK_OF_X509_EXTENSION; st : PX509_EXTENSION) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_dup}
  Tsk_X509_EXTENSION_dup = function (sk : PSTACK_OF_X509_EXTENSION) : PSTACK_OF_X509_EXTENSION cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_find}
  Tsk_X509_EXTENSION_find = function (sk : PSTACK_OF_X509_EXTENSION; _val : PX509_EXTENSION) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_EXTENSION_pop_free}
  Tsk_X509_EXTENSION_pop_free = procedure (sk : PSTACK_OF_X509_EXTENSION; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_new}
  Tsk_X509_TRUST_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_TRUST cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_new_null}
  Tsk_X509_TRUST_new_null = function : PSTACK_OF_X509_TRUST cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_free}
  Tsk_X509_TRUST_free = procedure(st : PSTACK_OF_X509_TRUST) cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_num}
  Tsk_X509_TRUST_num = function (const sk : PSTACK_OF_X509_TRUST) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_value}
  Tsk_X509_TRUST_value = function (const sk : PSTACK_OF_X509_TRUST; i : TIdC_INT) : PX509_NAME cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_push}
  Tsk_X509_TRUST_push = function (sk : PSTACK_OF_X509_TRUST; st : PX509_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_dup}
  Tsk_X509_TRUST_dup = function (sk : PSTACK_OF_X509_TRUST) : PSTACK_OF_X509_TRUST cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_find}
  Tsk_X509_TRUST_find = function (sk : PSTACK_OF_X509_TRUST; _val : PX509_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_TRUST_pop_free}
  Tsk_X509_TRUST_pop_free = procedure (sk : PSTACK_OF_X509_TRUST; func: TOPENSSL_sk_freefunc) cdecl;

  {$EXTERNALSYM Tsk_X509_REVOKED_new}
  Tsk_X509_REVOKED_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_REVOKED cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_new_null}
  Tsk_X509_REVOKED_new_null = function : PSTACK_OF_X509_REVOKED cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_free}
  Tsk_X509_REVOKED_free = procedure(st : PSTACK_OF_X509_REVOKED) cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_num}
  Tsk_X509_REVOKED_num = function (const sk : PSTACK_OF_X509_REVOKED) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_value}
  Tsk_X509_REVOKED_value = function (const sk : PSTACK_OF_X509_REVOKED; i : TIdC_INT) : PX509_REVOKED cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_push}
  Tsk_X509_REVOKED_push = function (sk : PSTACK_OF_X509_REVOKED; st : PX509_REVOKED) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_dup}
  Tsk_X509_REVOKED_dup = function (sk : PSTACK_OF_X509_REVOKED) : PSTACK_OF_X509_REVOKED cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_find}
  Tsk_X509_REVOKED_find = function (sk : PSTACK_OF_X509_REVOKED; _val : PX509_REVOKED) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_REVOKED_pop_free}
  Tsk_X509_REVOKED_pop_free = procedure (sk : PSTACK_OF_X509_REVOKED; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_new}
  Tsk_X509_CRL_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_CRL cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_new_null}
  Tsk_X509_CRL_new_null = function : PSTACK_OF_X509_CRL cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_free}
  Tsk_X509_CRL_free = procedure(st : PSTACK_OF_X509_CRL) cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_num}
  Tsk_X509_CRL_num = function (const sk : PSTACK_OF_X509_CRL) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_value}
  Tsk_X509_CRL_value = function (const sk : PSTACK_OF_X509_CRL; i : TIdC_INT) : PX509_CRL cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_push}
  Tsk_X509_CRL_push = function (sk : PSTACK_OF_X509_CRL; st : PX509_CRL) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_dup}
  Tsk_X509_CRL_dup = function (sk : PSTACK_OF_X509_CRL) : PSTACK_OF_X509_CRL cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_find}
  Tsk_X509_CRL_find = function (sk : PSTACK_OF_X509_CRL; _val : PX509_CRL) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_CRL_pop_free}
  Tsk_X509_CRL_pop_free = procedure (sk : PSTACK_OF_X509_CRL; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_new}
  Tsk_X509_ATTRIBUTE_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_ATTRIBUTE cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_new_null}
  Tsk_X509_ATTRIBUTE_new_null = function : PSTACK_OF_X509_ATTRIBUTE cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_free}
  Tsk_X509_ATTRIBUTE_free = procedure(st : PSTACK_OF_X509_ATTRIBUTE) cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_num}
  Tsk_X509_ATTRIBUTE_num = function (const sk : PSTACK_OF_X509_ATTRIBUTE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_value}
  Tsk_X509_ATTRIBUTE_value = function (const sk : PSTACK_OF_X509_ATTRIBUTE; i : TIdC_INT) : PX509_ATTRIBUTE cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_push}
  Tsk_X509_ATTRIBUTE_push = function (sk : PSTACK_OF_X509_ATTRIBUTE; st : PX509_ATTRIBUTE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_dup}
  Tsk_X509_ATTRIBUTE_dup = function (sk : PSTACK_OF_X509_ATTRIBUTE) : PSTACK_OF_X509_ATTRIBUTE cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_find}
  Tsk_X509_ATTRIBUTE_find = function (sk : PSTACK_OF_X509_ATTRIBUTE; _val : PX509_ATTRIBUTE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_ATTRIBUTE_pop_free}
  Tsk_X509_ATTRIBUTE_pop_free = procedure (sk : PSTACK_OF_X509_ATTRIBUTE; func: TOPENSSL_sk_freefunc) cdecl;

var

  {$EXTERNALSYM sk_X509_new}
  sk_X509_new: Tsk_X509_new = nil;
  {$EXTERNALSYM sk_X509_new_null}
  sk_X509_new_null : Tsk_X509_new_null = nil;
  {$EXTERNALSYM sk_X509_free}
  sk_X509_free : Tsk_X509_free = nil;
  {$EXTERNALSYM sk_X509_num}
  sk_X509_num : Tsk_X509_num = nil;
  {$EXTERNALSYM sk_X509_value}
  sk_X509_value : Tsk_X509_value = nil;
  {$EXTERNALSYM sk_X509_push}
  sk_X509_push : Tsk_X509_push = nil;
  {$EXTERNALSYM sk_X509_dup}
  sk_X509_dup : Tsk_X509_dup = nil;
  {$EXTERNALSYM sk_X509_find}
  sk_X509_find : Tsk_X509_find = nil;
  {$EXTERNALSYM sk_X509_pop_free}
  sk_X509_pop_free :  Tsk_X509_pop_free = nil;
  {$EXTERNALSYM sk_X509_NAME_new}
  sk_X509_NAME_new: Tsk_X509_NAME_new = nil;
  {$EXTERNALSYM sk_X509_NAME_new_null}
  sk_X509_NAME_new_null : Tsk_X509_NAME_new_null = nil;
  {$EXTERNALSYM sk_X509_NAME_free}
  sk_X509_NAME_free : Tsk_X509_NAME_free = nil;
  {$EXTERNALSYM sk_X509_NAME_num}
  sk_X509_NAME_num : Tsk_X509_NAME_num = nil;
  {$EXTERNALSYM sk_X509_NAME_value}
  sk_X509_NAME_value : Tsk_X509_NAME_value = nil;
  {$EXTERNALSYM sk_X509_NAME_push}
  sk_X509_NAME_push : Tsk_X509_NAME_push = nil;
  {$EXTERNALSYM sk_X509_NAME_dup}
  sk_X509_NAME_dup : Tsk_X509_NAME_dup = nil;
  {$EXTERNALSYM sk_X509_NAME_find}
  sk_X509_NAME_find : Tsk_X509_NAME_find = nil;
  {$EXTERNALSYM sk_X509_NAME_pop_free}
  sk_X509_NAME_pop_free :  Tsk_X509_NAME_pop_free = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_new}
  sk_X509_NAME_ENTRY_new: Tsk_X509_NAME_ENTRY_new = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_new_null}
  sk_X509_NAME_ENTRY_new_null : Tsk_X509_NAME_ENTRY_new_null = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_free}
  sk_X509_NAME_ENTRY_free : Tsk_X509_NAME_ENTRY_free = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_num}
  sk_X509_NAME_ENTRY_num : Tsk_X509_NAME_ENTRY_num = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_value}
  sk_X509_NAME_ENTRY_value : Tsk_X509_NAME_ENTRY_value = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_push}
  sk_X509_NAME_ENTRY_push : Tsk_X509_NAME_ENTRY_push = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_dup}
  sk_X509_NAME_ENTRY_dup : Tsk_X509_NAME_ENTRY_dup = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_find}
  sk_X509_NAME_ENTRY_find : Tsk_X509_NAME_ENTRY_find = nil;
  {$EXTERNALSYM sk_X509_NAME_ENTRY_pop_free}
  sk_X509_NAME_ENTRY_pop_free :  Tsk_X509_NAME_ENTRY_pop_free = nil;
  {$EXTERNALSYM sk_X509_INFO_new}
  sk_X509_INFO_new: Tsk_X509_INFO_new = nil;
  {$EXTERNALSYM sk_X509_INFO_new_null}
  sk_X509_INFO_new_null : Tsk_X509_INFO_new_null = nil;
  {$EXTERNALSYM sk_X509_INFO_free}
  sk_X509_INFO_free : Tsk_X509_INFO_free = nil;
  {$EXTERNALSYM sk_X509_INFO_num}
  sk_X509_INFO_num : Tsk_X509_INFO_num = nil;
  {$EXTERNALSYM sk_X509_INFO_value}
  sk_X509_INFO_value : Tsk_X509_INFO_value = nil;
  {$EXTERNALSYM sk_X509_INFO_push}
  sk_X509_INFO_push : Tsk_X509_INFO_push = nil;
  {$EXTERNALSYM sk_X509_INFO_dup}
  sk_X509_INFO_dup : Tsk_X509_INFO_dup = nil;
  {$EXTERNALSYM sk_X509_INFO_find}
  sk_X509_INFO_find : Tsk_X509_INFO_find = nil;
  {$EXTERNALSYM sk_X509_INFO_pop_free}
  sk_X509_INFO_pop_free : Tsk_X509_INFO_pop_free = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_new}
  sk_X509_EXTENSION_new: Tsk_X509_EXTENSION_new = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_new_null}
  sk_X509_EXTENSION_new_null : Tsk_X509_EXTENSION_new_null = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_free}
  sk_X509_EXTENSION_free : Tsk_X509_EXTENSION_free = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_num}
  sk_X509_EXTENSION_num : Tsk_X509_EXTENSION_num = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_value}
  sk_X509_EXTENSION_value : Tsk_X509_EXTENSION_value = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_push}
  sk_X509_EXTENSION_push : Tsk_X509_EXTENSION_push = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_dup}
  sk_X509_EXTENSION_dup : Tsk_X509_EXTENSION_dup = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_find}
  sk_X509_EXTENSION_find : Tsk_X509_EXTENSION_find = nil;
  {$EXTERNALSYM sk_X509_EXTENSION_pop_free}
  sk_X509_EXTENSION_pop_free : Tsk_X509_EXTENSION_pop_free = nil;
  {$EXTERNALSYM sk_X509_TRUST_new}
  sk_X509_TRUST_new: Tsk_X509_TRUST_new = nil;
  {$EXTERNALSYM sk_X509_TRUST_new_null}
  sk_X509_TRUST_new_null : Tsk_X509_TRUST_new_null = nil;
  {$EXTERNALSYM sk_X509_TRUST_free}
  sk_X509_TRUST_free : Tsk_X509_TRUST_free = nil;
  {$EXTERNALSYM sk_X509_TRUST_num}
  sk_X509_TRUST_num : Tsk_X509_TRUST_num = nil;
  {$EXTERNALSYM sk_X509_TRUST_value}
  sk_X509_TRUST_value : Tsk_X509_TRUST_value = nil;
  {$EXTERNALSYM sk_X509_TRUST_push}
  sk_X509_TRUST_push : Tsk_X509_TRUST_push = nil;
  {$EXTERNALSYM sk_X509_TRUST_dup}
  sk_X509_TRUST_dup : Tsk_X509_TRUST_dup = nil;
  {$EXTERNALSYM sk_X509_TRUST_find}
  sk_X509_TRUST_find : Tsk_X509_TRUST_find = nil;
  {$EXTERNALSYM sk_X509_TRUST_pop_free}
  sk_X509_TRUST_pop_free :  Tsk_X509_TRUST_pop_free = nil;
  {$EXTERNALSYM sk_X509_REVOKED_new}
  sk_X509_REVOKED_new: Tsk_X509_REVOKED_new = nil;
  {$EXTERNALSYM sk_X509_REVOKED_new_null}
  sk_X509_REVOKED_new_null : Tsk_X509_REVOKED_new_null = nil;
  {$EXTERNALSYM sk_X509_REVOKED_free}
  sk_X509_REVOKED_free : Tsk_X509_REVOKED_free = nil;
  {$EXTERNALSYM sk_X509_REVOKED_num}
  sk_X509_REVOKED_num : Tsk_X509_REVOKED_num = nil;
  {$EXTERNALSYM sk_X509_REVOKED_value}
  sk_X509_REVOKED_value : Tsk_X509_REVOKED_value = nil;
  {$EXTERNALSYM sk_X509_REVOKED_push}
  sk_X509_REVOKED_push : Tsk_X509_REVOKED_push = nil;
  {$EXTERNALSYM sk_X509_REVOKED_dup}
  sk_X509_REVOKED_dup : Tsk_X509_REVOKED_dup = nil;
  {$EXTERNALSYM sk_X509_REVOKED_find}
  sk_X509_REVOKED_find : Tsk_X509_REVOKED_find = nil;
  {$EXTERNALSYM sk_X509_REVOKED_pop_free}
  sk_X509_REVOKED_pop_free : Tsk_X509_REVOKED_pop_free = nil;
  {$EXTERNALSYM sk_X509_CRL_new}
  sk_X509_CRL_new: Tsk_X509_CRL_new = nil;
  {$EXTERNALSYM sk_X509_CRL_new_null}
  sk_X509_CRL_new_null : Tsk_X509_CRL_new_null = nil;
  {$EXTERNALSYM sk_X509_CRL_free}
  sk_X509_CRL_free : Tsk_X509_CRL_free = nil;
  {$EXTERNALSYM sk_X509_CRL_num}
  sk_X509_CRL_num : Tsk_X509_CRL_num = nil;
  {$EXTERNALSYM sk_X509_CRL_value}
  sk_X509_CRL_value : Tsk_X509_CRL_value = nil;
  {$EXTERNALSYM sk_X509_CRL_push}
  sk_X509_CRL_push : Tsk_X509_CRL_push = nil;
  {$EXTERNALSYM sk_X509_CRL_dup}
  sk_X509_CRL_dup : Tsk_X509_CRL_dup = nil;
  {$EXTERNALSYM sk_X509_CRL_find}
  sk_X509_CRL_find : Tsk_X509_CRL_find = nil;
  {$EXTERNALSYM sk_X509_CRL_pop_free}
  sk_X509_CRL_pop_free : Tsk_X509_CRL_pop_free = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_new}
  sk_X509_ATTRIBUTE_new: Tsk_X509_ATTRIBUTE_new = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_new_null}
  sk_X509_ATTRIBUTE_new_null : Tsk_X509_ATTRIBUTE_new_null = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_free}
  sk_X509_ATTRIBUTE_free : Tsk_X509_ATTRIBUTE_free = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_num}
  sk_X509_ATTRIBUTE_num : Tsk_X509_ATTRIBUTE_num = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_value}
  sk_X509_ATTRIBUTE_value : Tsk_X509_ATTRIBUTE_value = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_push}
  sk_X509_ATTRIBUTE_push : Tsk_X509_ATTRIBUTE_push = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_dup}
  sk_X509_ATTRIBUTE_dup : Tsk_X509_ATTRIBUTE_dup = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_find}
  sk_X509_ATTRIBUTE_find : Tsk_X509_ATTRIBUTE_find = nil;
  {$EXTERNALSYM sk_X509_ATTRIBUTE_pop_free}
  sk_X509_ATTRIBUTE_pop_free : Tsk_X509_ATTRIBUTE_pop_free = nil;
{$ELSE}
  {$EXTERNALSYM sk_X509_new}
  function sk_X509_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509 cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_new_null}
  function sk_X509_new_null : PSTACK_OF_X509 cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_free}
  procedure sk_X509_free(st : PSTACK_OF_X509) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_num}
  function sk_X509_num (const sk : PSTACK_OF_X509) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_value}
  function sk_X509_value (const sk : PSTACK_OF_X509; i : TIdC_INT): PX509  cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_push}
  function sk_X509_push (sk : PSTACK_OF_X509; st : PX509 ): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_dup}
  function sk_X509_dup (sk : PSTACK_OF_X509) : PSTACK_OF_X509 cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_find}
  function sk_X509_find (sk : PSTACK_OF_X509; _val : PX509 ) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_pop_free}
  procedure sk_X509_pop_free (sk : PSTACK_OF_X509; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_NAME_new}
  function sk_X509_NAME_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_NAME_new_null}
  function sk_X509_NAME_new_null : PSTACK_OF_X509_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_NAME_free}
  procedure sk_X509_NAME_free(st : PSTACK_OF_X509_NAME) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_NAME_num}
  function sk_X509_NAME_num (const sk : PSTACK_OF_X509_NAME) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_NAME_value}
  function sk_X509_NAME_value (const sk : PSTACK_OF_X509_NAME; i : TIdC_INT): PX509_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_NAME_push}
  function sk_X509_NAME_push (sk : PSTACK_OF_X509_NAME; st : PX509_NAME): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_NAME_dup}
  function sk_X509_NAME_dup (sk : PSTACK_OF_X509_NAME) : PSTACK_OF_X509_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_NAME_find}
  function sk_X509_NAME_find (sk : PSTACK_OF_X509_NAME; _val : PX509_NAME) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_NAME_pop_free}
  procedure sk_X509_NAME_pop_free (sk : PSTACK_OF_X509_NAME; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_TRUST_new}
  function sk_X509_TRUST_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_TRUST cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_TRUST_new_null}
  function sk_X509_TRUST_new_null : PSTACK_OF_X509_TRUST cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_TRUST_free}
  procedure sk_X509_TRUST_free(st : PSTACK_OF_X509_TRUST) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_TRUST_num}
  function sk_X509_TRUST_num (const sk : PSTACK_OF_X509_TRUST) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_TRUST_value}
  function sk_X509_TRUST_value (const sk : PSTACK_OF_X509_TRUST; i : TIdC_INT): PX509_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_TRUST_push}
  function sk_X509_TRUST_push (sk : PSTACK_OF_X509_TRUST; st : PX509_NAME): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_TRUST_dup}
  function sk_X509_TRUST_dup (sk : PSTACK_OF_X509_TRUST) : PSTACK_OF_X509_TRUST cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_TRUST_find}
  function sk_X509_TRUST_find (sk : PSTACK_OF_X509_TRUST; _val : PX509_NAME) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_TRUST_pop_free}
  procedure sk_X509_TRUST_pop_free (sk : PSTACK_OF_X509_TRUST; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_INFO_new}
  function sk_X509_INFO_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_INFO_new_null}
  function sk_X509_INFO_new_null : PSTACK_OF_X509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_INFO_free}
  procedure sk_X509_INFO_free(st : PSTACK_OF_X509_INFO) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_INFO_num}
  function sk_X509_INFO_num (const sk : PSTACK_OF_X509_INFO) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_INFO_value}
  function sk_X509_INFO_value (const sk : PSTACK_OF_X509_INFO; i : TIdC_INT) : PX509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_INFO_push}
  function sk_X509_INFO_push (sk : PSTACK_OF_X509_INFO; st : PX509_INFO) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_INFO_dup}
  function sk_X509_INFO_dup (sk : PSTACK_OF_X509_INFO) : PSTACK_OF_X509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_INFO_find}
  function sk_X509_INFO_find (sk : PSTACK_OF_X509_INFO; _val : PX509_INFO) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_INFO_pop_free}
  procedure sk_X509_INFO_pop_free (sk : PSTACK_OF_X509_INFO; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_EXTENSION_new}
  function sk_X509_EXTENSION_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_EXTENSION cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_EXTENSION_new_null}
  function sk_X509_EXTENSION_new_null : PSTACK_OF_X509_EXTENSION cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_EXTENSION_free}
  procedure sk_X509_EXTENSION_free(st : PSTACK_OF_X509_EXTENSION) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_EXTENSION_num}
  function sk_X509_EXTENSION_num (const sk : PSTACK_OF_X509_EXTENSION) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_EXTENSION_value}
  function sk_X509_EXTENSION_value (const sk : PSTACK_OF_X509_EXTENSION; i : TIdC_INT) : PX509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_EXTENSION_push}
  function sk_X509_EXTENSION_push (sk : PSTACK_OF_X509_EXTENSION; st : PX509_EXTENSION) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_EXTENSION_dup}
  function sk_X509_EXTENSION_dup (sk : PSTACK_OF_X509_EXTENSION) : PSTACK_OF_X509_EXTENSION cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_EXTENSION_find}
  function sk_X509_EXTENSION_find (sk : PSTACK_OF_X509_EXTENSION; _val : PX509_EXTENSION) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_EXTENSION_pop_free}
  procedure sk_X509_EXTENSION_pop_free (sk : PSTACK_OF_X509_EXTENSION; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_REVOKED_new}
  function sk_X509_REVOKED_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_REVOKED cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_REVOKED_new_null}
  function sk_X509_REVOKED_new_null : PSTACK_OF_X509_REVOKED cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_REVOKED_free}
  procedure sk_X509_REVOKED_free(st : PSTACK_OF_X509_REVOKED) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_REVOKED_num}
  function sk_X509_REVOKED_num (const sk : PSTACK_OF_X509_REVOKED) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_REVOKED_value}
  function sk_X509_REVOKED_value (const sk : PSTACK_OF_X509_REVOKED; i : TIdC_INT) : PX509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_REVOKED_push}
  function sk_X509_REVOKED_push (sk : PSTACK_OF_X509_REVOKED; st : PX509_REVOKED) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_REVOKED_dup}
  function sk_X509_REVOKED_dup (sk : PSTACK_OF_X509_REVOKED) : PSTACK_OF_X509_REVOKED cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_REVOKED_find}
  function sk_X509_REVOKED_find (sk : PSTACK_OF_X509_REVOKED; _val : PX509_REVOKED) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_REVOKED_pop_free}
  procedure sk_X509_REVOKED_pop_free (sk : PSTACK_OF_X509_REVOKED; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_CRL_new}
  function sk_X509_CRL_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_CRL cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_CRL_new_null}
  function sk_X509_CRL_new_null : PSTACK_OF_X509_CRL cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_CRL_free}
  procedure sk_X509_CRL_free(st : PSTACK_OF_X509_CRL) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_CRL_num}
  function sk_X509_CRL_num (const sk : PSTACK_OF_X509_CRL) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_CRL_value}
  function sk_X509_CRL_value (const sk : PSTACK_OF_X509_CRL; i : TIdC_INT) : PX509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_CRL_push}
  function sk_X509_CRL_push (sk : PSTACK_OF_X509_CRL; st : PX509_CRL) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_CRL_dup}
  function sk_X509_CRL_dup (sk : PSTACK_OF_X509_CRL) : PSTACK_OF_X509_CRL cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_CRL_find}
  function sk_X509_CRL_find (sk : PSTACK_OF_X509_CRL; _val : PX509_CRL) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_CRL_pop_free}
  procedure sk_X509_CRL_pop_free (sk : PSTACK_OF_X509_CRL; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_new}
  function sk_X509_ATTRIBUTE_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_ATTRIBUTE cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_new_null}
  function sk_X509_ATTRIBUTE_new_null : PSTACK_OF_X509_ATTRIBUTE cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_free}
  procedure sk_X509_ATTRIBUTE_free(st : PSTACK_OF_X509_ATTRIBUTE) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_num}
  function sk_X509_ATTRIBUTE_num (const sk : PSTACK_OF_X509_ATTRIBUTE) : TIdC_INT; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_value}
  function sk_X509_ATTRIBUTE_value (const sk : PSTACK_OF_X509_ATTRIBUTE; i : TIdC_INT) : PX509_INFO cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_push}
  function sk_X509_ATTRIBUTE_push (sk : PSTACK_OF_X509_ATTRIBUTE; st : PX509_ATTRIBUTE) : TIdC_INT cdecl; external CLibCrypto  name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_dup}
  function sk_X509_ATTRIBUTE_dup (sk : PSTACK_OF_X509_ATTRIBUTE) : PSTACK_OF_X509_ATTRIBUTE cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_find}
  function sk_X509_ATTRIBUTE_find (sk : PSTACK_OF_X509_ATTRIBUTE; _val : PX509_ATTRIBUTE) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_ATTRIBUTE_pop_free}
  procedure sk_X509_ATTRIBUTE_pop_free (sk : PSTACK_OF_X509_ATTRIBUTE; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
{$ENDIF}
{/helper_functions}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM X509_CRL_set_default_method}
  X509_CRL_set_default_method: procedure (const meth: PX509_CRL_METHOD); cdecl = nil;
//  function X509_CRL_METHOD_new(crl_init: function(crl: X509_CRL): TIdC_INT;
//    crl_free: function(crl: PX509_CRL): TIdC_INT;
//    crl_lookup: function(crl: PX509_CRL; ret: PPX509_REVOKED; ser: PASN1_INTEGER; issuer: PX509_NAME): TIdC_INT;
//    crl_verify: function(crl: PX509_CRL, pk: PEVP_PKEY): TIdC_INT): PX509_CRL_METHOD;
  {$EXTERNALSYM X509_CRL_METHOD_free}
  X509_CRL_METHOD_free: procedure (m: PX509_CRL_METHOD); cdecl = nil;

  {$EXTERNALSYM X509_CRL_set_meth_data}
  X509_CRL_set_meth_data: procedure (crl: PX509_CRL; dat: Pointer); cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_meth_data}
  X509_CRL_get_meth_data: function (crl: PX509_CRL): Pointer; cdecl = nil;

  {$EXTERNALSYM X509_verify_cert_error_string}
  X509_verify_cert_error_string: function (n: TIdC_LONG): PIdAnsiChar; cdecl = nil;

  {$EXTERNALSYM X509_verify}
  X509_verify: function (a: PX509; r: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_REQ_verify}
  X509_REQ_verify: function (a: PX509_REQ; r: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_verify}
  X509_CRL_verify: function (a: PX509_CRL; r: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_verify}
  NETSCAPE_SPKI_verify: function (a: PNETSCAPE_SPKI; r: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM NETSCAPE_SPKI_b64_decode}
  NETSCAPE_SPKI_b64_decode: function (const _str: PIdAnsiChar; len: TIdC_INT): PNETSCAPE_SPKI; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_b64_encode}
  NETSCAPE_SPKI_b64_encode: function (x: PNETSCAPE_SPKI): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_get_pubkey}
  NETSCAPE_SPKI_get_pubkey: function (x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_set_pubkey}
  NETSCAPE_SPKI_set_pubkey: function (x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM NETSCAPE_SPKI_print}
  NETSCAPE_SPKI_print: function (out_: PBIO; spki: PNETSCAPE_SPKI): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_signature_dump}
  X509_signature_dump: function (bp: PBIO; const sig: PASN1_STRING; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_signature_print}
  X509_signature_print: function (bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_sign}
  X509_sign: function (x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_sign_ctx}
  X509_sign_ctx: function (x: PX509; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_http_nbio}
  X509_http_nbio: function (rctx: POCSP_REQ_CTX; pcert: PPX509): TIdC_INT; cdecl = nil; {removed 3.0.0}

  {$EXTERNALSYM X509_REQ_sign}
  X509_REQ_sign: function (x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_sign_ctx}
  X509_REQ_sign_ctx: function (x: PX509_REQ; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_sign}
  X509_CRL_sign: function (x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_sign_ctx}
  X509_CRL_sign_ctx: function (x: PX509_CRL; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_CRL_http_nbio}
  X509_CRL_http_nbio: function (rctx: POCSP_REQ_CTX; pcrl: PPX509_CRL): TIdC_INT; cdecl = nil; {removed 3.0.0}

  {$EXTERNALSYM NETSCAPE_SPKI_sign}
  NETSCAPE_SPKI_sign: function (x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_pubkey_digest}
  X509_pubkey_digest: function (const data: PX509; const type_: PEVP_MD; md: PByte; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_digest}
  X509_digest: function (const data: PX509; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_digest}
  X509_CRL_digest: function (const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_digest}
  X509_REQ_digest: function (const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_digest}
  X509_NAME_digest: function (const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT; cdecl = nil;

  //# ifndef OPENSSL_NO_STDIO
  //X509 *d2i_X509_fp(FILE *fp, X509 **x509);
  //TIdC_INT i2d_X509_fp(FILE *fp, X509 *x509);
  //X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl);
  //TIdC_INT i2d_X509_CRL_fp(FILE *fp, X509_CRL *crl);
  //X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req);
  //TIdC_INT i2d_X509_REQ_fp(FILE *fp, X509_REQ *req);
  //#  ifndef OPENSSL_NO_RSA
  //RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa);
  //#  endif
  //#  ifndef OPENSSL_NO_DSA
  //DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
  //DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
  //#  endif
  //#  ifndef OPENSSL_NO_EC
  //EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
  //EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
  //#  endif
  //X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8);
  //TIdC_INT i2d_PKCS8_fp(FILE *fp, X509_SIG *p8);
  //PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
  //                                                PKCS8_PRIV_KEY_INFO **p8inf);
  //TIdC_INT i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf);
  //TIdC_INT i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
  //TIdC_INT i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
  //TIdC_INT i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
  //# endif

  {$EXTERNALSYM d2i_X509_bio}
  d2i_X509_bio: function (bp: PBIO; x509: PPX509): PX509; cdecl = nil;
  {$EXTERNALSYM i2d_X509_bio}
  i2d_X509_bio: function (bp: PBIO; x509: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_X509_CRL_bio}
  d2i_X509_CRL_bio: function (bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CRL_bio}
  i2d_X509_CRL_bio: function (bp: PBIO; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_X509_REQ_bio}
  d2i_X509_REQ_bio: function (bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REQ_bio}
  i2d_X509_REQ_bio: function (bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM d2i_RSAPrivateKey_bio}
  d2i_RSAPrivateKey_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil;
  {$EXTERNALSYM i2d_RSAPrivateKey_bio}
  i2d_RSAPrivateKey_bio: function (bp: PBIO; rsa: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_RSAPublicKey_bio}
  d2i_RSAPublicKey_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil;
  {$EXTERNALSYM i2d_RSAPublicKey_bio}
  i2d_RSAPublicKey_bio: function (bp: PBIO; rsa: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_RSA_PUBKEY_bio}
  d2i_RSA_PUBKEY_bio: function (bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil;
  {$EXTERNALSYM i2d_RSA_PUBKEY_bio}
  i2d_RSA_PUBKEY_bio: function (bp: PBIO; rsa: PRSA): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM d2i_DSA_PUBKEY_bio}
  d2i_DSA_PUBKEY_bio: function (bp: PBIO; dsa: PPDSA): PDSA; cdecl = nil;
  {$EXTERNALSYM i2d_DSA_PUBKEY_bio}
  i2d_DSA_PUBKEY_bio: function (bp: PBIO; dsa: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_DSAPrivateKey_bio}
  d2i_DSAPrivateKey_bio: function (bp: PBIO; dsa: PPDSA): PDSA; cdecl = nil;
  {$EXTERNALSYM i2d_DSAPrivateKey_bio}
  i2d_DSAPrivateKey_bio: function (bp: PBIO; dsa: PDSA): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM d2i_EC_PUBKEY_bio}
  d2i_EC_PUBKEY_bio: function (bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl = nil;
  {$EXTERNALSYM i2d_EC_PUBKEY_bio}
  i2d_EC_PUBKEY_bio: function (bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ECPrivateKey_bio}
  d2i_ECPrivateKey_bio: function (bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl = nil;
  {$EXTERNALSYM i2d_ECPrivateKey_bio}
  i2d_ECPrivateKey_bio: function (bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM d2i_PKCS8_bio}
  d2i_PKCS8_bio: function (bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8_bio}
  i2d_PKCS8_bio: function (bp: PBIO; p8: PX509_SIG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8_PRIV_KEY_INFO_bio}
  d2i_PKCS8_PRIV_KEY_INFO_bio: function (bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8_PRIV_KEY_INFO_bio}
  i2d_PKCS8_PRIV_KEY_INFO_bio: function (bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8PrivateKeyInfo_bio}
  i2d_PKCS8PrivateKeyInfo_bio: function (bp: PBIO; key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PrivateKey_bio}
  i2d_PrivateKey_bio: function (bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_PrivateKey_bio}
  d2i_PrivateKey_bio: function (bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PrivateKey_ex_bio}
  d2i_PrivateKey_ex_bio: function (bp : PBIO; a :PPEVP_PKEY;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM i2d_PUBKEY_bio}
  i2d_PUBKEY_bio: function (bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY_bio}
  d2i_PUBKEY_bio: function (bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;

  {$EXTERNALSYM X509_dup}
  X509_dup: function (x509: PX509): PX509; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_dup}
  X509_ATTRIBUTE_dup: function (xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_dup}
  X509_EXTENSION_dup: function (ex: PX509_EXTENSION): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_CRL_dup}
  X509_CRL_dup: function (crl: PX509_CRL): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_dup}
  X509_REVOKED_dup: function (rev: PX509_REVOKED): PX509_REVOKED; cdecl = nil;
  {$EXTERNALSYM X509_REQ_dup}
  X509_REQ_dup: function (req: PX509_REQ): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_dup}
  X509_ALGOR_dup: function (xn: PX509_ALGOR): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_set0}
  X509_ALGOR_set0: function (alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_get0}
  X509_ALGOR_get0: procedure (const paobj: PPASN1_OBJECT; pptype: PIdC_INT; const ppval: PPointer; const algor: PX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_set_md}
  X509_ALGOR_set_md: procedure (alg: PX509_ALGOR; const md: PEVP_MD); cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_cmp}
  X509_ALGOR_cmp: function (const a: PX509_ALGOR; const b: PX509_ALGOR): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_NAME_dup}
  X509_NAME_dup: function (xn: PX509_NAME): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_dup}
  X509_NAME_ENTRY_dup: function (ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl = nil;

  {$EXTERNALSYM X509_cmp_time}
  X509_cmp_time: function (const s: PASN1_TIME; t: PIdC_TIMET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_cmp_current_time}
  X509_cmp_current_time: function (const s: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_cmp_timeframe}
  X509_cmp_timeframe: function(const vpm : PX509_VERIFY_PARAM; start, _end : PASN1_TIME ) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_check_certificate_times}
  X509_check_certificate_times : function(const vpm : PX509_VERIFY_PARAM; X : PX509; _error : TIdC_INT) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_time_adj}
  X509_time_adj: function (s: PASN1_TIME; adj: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_time_adj_ex}
  X509_time_adj_ex: function (s: PASN1_TIME; offset_day: TIdC_INT; offset_sec: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_gmtime_adj}
  X509_gmtime_adj: function (s: PASN1_TIME; adj: TIdC_LONG): PASN1_TIME; cdecl = nil;

  {$EXTERNALSYM X509_get_default_cert_area}
  X509_get_default_cert_area: function : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_dir}
  X509_get_default_cert_dir: function : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_file}
  X509_get_default_cert_file: function : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_dir_env}
  X509_get_default_cert_dir_env: function : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_file_env}
  X509_get_default_cert_file_env: function : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_private_dir}
  X509_get_default_private_dir: function : PIdAnsiChar; cdecl = nil;

  {$EXTERNALSYM X509_to_X509_REQ}
  X509_to_X509_REQ: function (x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM X509_REQ_to_X509}
  X509_REQ_to_X509: function (r: PX509_REQ; days: TIdC_INT; pkey: PEVP_PKEY): PX509; cdecl = nil;

  {$EXTERNALSYM X509_ALGOR_new}
  X509_ALGOR_new: function : PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_free}
  X509_ALGOR_free: procedure (v1: PX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM d2i_X509_ALGOR}
  d2i_X509_ALGOR: function (a: PPX509_ALGOR; const in_: PPByte; len: TIdC_LONG): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ALGOR}
  i2d_X509_ALGOR: function (a: PX509_ALGOR; out_: PPByte): TIdC_INT; cdecl = nil;
  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_ALGORS, X509_ALGORS, X509_ALGORS)
  {$EXTERNALSYM X509_VAL_new}
  X509_VAL_new: function : PX509_VAL; cdecl = nil;
  {$EXTERNALSYM X509_VAL_free}
  X509_VAL_free: procedure (v1: PX509_VAL); cdecl = nil;
  {$EXTERNALSYM d2i_X509_VAL}
  d2i_X509_VAL: function (a: PPX509_VAL; const in_: PPByte; len: TIdC_LONG): PX509_VAL; cdecl = nil;
  {$EXTERNALSYM i2d_X509_VAL}
  i2d_X509_VAL: function (a: PX509_VAL; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_PUBKEY_new}
  X509_PUBKEY_new: function : PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_free}
  X509_PUBKEY_free: procedure (v1: PX509_PUBKEY); cdecl = nil;
  {$EXTERNALSYM d2i_X509_PUBKEY}
  d2i_X509_PUBKEY: function (a: PPX509_PUBKEY; const in_: PPByte; len: TIdC_LONG): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM i2d_X509_PUBKEY}
  i2d_X509_PUBKEY: function (a: PX509_PUBKEY; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_PUBKEY_set}
  X509_PUBKEY_set: function (x: PPX509_PUBKEY; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_get0}
  X509_PUBKEY_get0: function (key: PX509_PUBKEY): PEVP_PKEY; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_PUBKEY_get}
  X509_PUBKEY_get: function (key: PX509_PUBKEY): PEVP_PKEY; cdecl = nil;
//  function X509_get_pubkey_parameters(pkey: PEVP_PKEY; chain: P STACK_OF(X509)): TIdC_INT;
  {$EXTERNALSYM X509_get_pathlen}
  X509_get_pathlen: function (x: PX509): TIdC_LONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM i2d_PUBKEY}
  i2d_PUBKEY: function (a: PEVP_PKEY; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY}
  d2i_PUBKEY: function (a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY; cdecl = nil;

  {$EXTERNALSYM i2d_RSA_PUBKEY}
  i2d_RSA_PUBKEY: function (a: PRSA; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_RSA_PUBKEY}
  d2i_RSA_PUBKEY: function (a: PPRSA; const pp: PPByte; _length: TIdC_LONG): PRSA; cdecl = nil;

  {$EXTERNALSYM i2d_DSA_PUBKEY}
  i2d_DSA_PUBKEY: function (a: PDSA; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_DSA_PUBKEY}
  d2i_DSA_PUBKEY: function (a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA; cdecl = nil;

  {$EXTERNALSYM i2d_EC_PUBKEY}
  i2d_EC_PUBKEY: function (a: PEC_KEY; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_EC_PUBKEY}
  d2i_EC_PUBKEY: function (a: PPEC_KEY; const pp: PPByte; _length: TIdC_LONG): PEC_KEY; cdecl = nil;

  {$EXTERNALSYM X509_SIG_new}
  X509_SIG_new: function : PX509_SIG; cdecl = nil;
  {$EXTERNALSYM X509_SIG_free}
  X509_SIG_free: procedure (v1: PX509_SIG); cdecl = nil;
  {$EXTERNALSYM d2i_X509_SIG}
  d2i_X509_SIG: function (a: PPX509_SIG; const in_: PPByte; len: TIdC_LONG): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM i2d_X509_SIG}
  i2d_X509_SIG: function (a: PX509_SIG; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_SIG_get0}
  X509_SIG_get0: procedure (const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_SIG_getm}
  X509_SIG_getm: procedure (sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_REQ_INFO_new}
  X509_REQ_INFO_new: function : PX509_REQ_INFO; cdecl = nil;
  {$EXTERNALSYM X509_REQ_INFO_free}
  X509_REQ_INFO_free: procedure (v1: PX509_REQ_INFO); cdecl = nil;
  {$EXTERNALSYM d2i_X509_REQ_INFO}
  d2i_X509_REQ_INFO: function (a: PPX509_REQ_INFO; const in_: PPByte; len: TIdC_LONG): PX509_REQ_INFO; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REQ_INFO}
  i2d_X509_REQ_INFO: function (a: PX509_REQ_INFO; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_REQ_new}
  X509_REQ_new: function : PX509_REQ; cdecl = nil;
  {$EXTERNALSYM X509_REQ_free}
  X509_REQ_free: procedure (v1: PX509_REQ); cdecl = nil;
  {$EXTERNALSYM d2i_X509_REQ}
  d2i_X509_REQ: function (a: PPX509_REQ; const in_: PPByte; len: TIdC_LONG): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REQ}
  i2d_X509_REQ: function (a: PX509_REQ; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_ATTRIBUTE_new}
  X509_ATTRIBUTE_new: function : PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_free}
  X509_ATTRIBUTE_free: procedure (v1: PX509_ATTRIBUTE); cdecl = nil;
  {$EXTERNALSYM d2i_X509_ATTRIBUTE}
  d2i_X509_ATTRIBUTE: function (a: PPX509_ATTRIBUTE; const in_: PPByte; len: TIdC_LONG): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ATTRIBUTE}
  i2d_X509_ATTRIBUTE: function (a: PX509_ATTRIBUTE; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_create}
  X509_ATTRIBUTE_create: function (nid: TIdC_INT; trtype: TIdC_INT; value: Pointer): PX509_ATTRIBUTE; cdecl = nil;

  {$EXTERNALSYM X509_EXTENSION_new}
  X509_EXTENSION_new: function : PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_free}
  X509_EXTENSION_free: procedure (v1: PX509_EXTENSION); cdecl = nil;
  {$EXTERNALSYM d2i_X509_EXTENSION}
  d2i_X509_EXTENSION: function (a: PPX509_EXTENSION; const in_: PPByte; len: TIdC_LONG): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM i2d_X509_EXTENSION}
  i2d_X509_EXTENSION: function (a: PX509_EXTENSION; out_: PPByte): TIdC_INT; cdecl = nil;
  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)

  {$EXTERNALSYM X509_NAME_ENTRY_new}
  X509_NAME_ENTRY_new: function : PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_free}
  X509_NAME_ENTRY_free: procedure (v1: PX509_NAME_ENTRY); cdecl = nil;
  {$EXTERNALSYM d2i_X509_NAME_ENTRY}
  d2i_X509_NAME_ENTRY: function (a: PPX509_NAME_ENTRY; const in_: PPByte; len: TIdC_LONG): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM i2d_X509_NAME_ENTRY}
  i2d_X509_NAME_ENTRY: function (a: PX509_NAME_ENTRY; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_NAME_new}
  X509_NAME_new: function : PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_NAME_free}
  X509_NAME_free: procedure (v1: PX509_NAME); cdecl = nil;
  {$EXTERNALSYM d2i_X509_NAME}
  d2i_X509_NAME: function (a: PPX509_NAME; const in_: PPByte; len: TIdC_LONG): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM i2d_X509_NAME}
  i2d_X509_NAME: function (a: PX509_NAME; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_NAME_set}
  X509_NAME_set: function (xn: PPX509_NAME; name: PX509_NAME): TIdC_INT; cdecl = nil;

  //DECLARE_ASN1_FUNCTIONS(X509_CINF)

  {$EXTERNALSYM X509_new}
  X509_new: function : PX509; cdecl = nil;
  {$EXTERNALSYM X509_free}
  X509_free: procedure (v1: PX509); cdecl = nil;
  {$EXTERNALSYM d2i_X509}
  d2i_X509: function (a: PPX509; const in_: PPByte; len: TIdC_LONG): PX509; cdecl = nil;
  {$EXTERNALSYM i2d_X509}
  i2d_X509: function (a: PX509; out_: PPByte): TIdC_INT; cdecl = nil;

  //DECLARE_ASN1_FUNCTIONS(X509_CERT_AUX)
  //
  //#define X509_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef)
  {$EXTERNALSYM X509_set_ex_data}
  X509_set_ex_data: function (r: PX509; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ex_data}
  X509_get_ex_data: function (r: PX509; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM i2d_X509_AUX}
  i2d_X509_AUX: function (a: PX509; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_X509_AUX}
  d2i_X509_AUX: function (a: PPX509; const pp: PPByte; _length: TIdC_LONG): PX509; cdecl = nil;

  {$EXTERNALSYM i2d_re_X509_tbs}
  i2d_re_X509_tbs: function (x: PX509; pp: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_SIG_INFO_get}
  X509_SIG_INFO_get: function (const siginf: PX509_SIG_INFO; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_SIG_INFO_set}
  X509_SIG_INFO_set: procedure (siginf: PX509_SIG_INFO; mdnid: TIdC_INT; pknid: TIdC_INT; secbits: TIdC_INT; flags: TIdC_UINT32); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_get_signature_info}
  X509_get_signature_info: function (x: PX509; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_get0_signature}
  X509_get0_signature: procedure (var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_get_signature_nid}
  X509_get_signature_nid: function (const x: PX509): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_trusted}
  X509_trusted: function (const x: PX509): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_alias_set1}
  X509_alias_set1: function (x: PX509; const name: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_keyid_set1}
  X509_keyid_set1: function (x: PX509; const id: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_alias_get0}
  X509_alias_get0: function (x: PX509; len: PIdC_INT): PByte; cdecl = nil;
  {$EXTERNALSYM X509_keyid_get0}
  X509_keyid_get0: function (x: PX509; len: PIdC_INT): PByte; cdecl = nil;
//  TIdC_INT (*X509_TRUST_set_default(TIdC_INT (*trust) (TIdC_INT, X509 *, TIdC_INT))) (TIdC_INT, X509 *,
//                                                                  TIdC_INT);
  {$EXTERNALSYM X509_TRUST_set}
  X509_TRUST_set: function (t: PIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add1_trust_object}
  X509_add1_trust_object: function (x: PX509; const obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add1_reject_object}
  X509_add1_reject_object: function (x: PX509; const obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_trust_clear}
  X509_trust_clear: procedure (x: PX509); cdecl = nil;
  {$EXTERNALSYM X509_reject_clear}
  X509_reject_clear: procedure (x: PX509); cdecl = nil;

  //STACK_OF(ASN1_OBJECT) *X509_get0_trust_objects(X509 *x);
  //STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x);
  //
  {$EXTERNALSYM X509_REVOKED_new}
  X509_REVOKED_new: function : PX509_REVOKED; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_free}
  X509_REVOKED_free: procedure (v1: PX509_REVOKED); cdecl = nil;
  {$EXTERNALSYM d2i_X509_REVOKED}
  d2i_X509_REVOKED: function (a: PPX509_REVOKED; const in_: PPByte; len: TIdC_LONG): PX509_REVOKED; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REVOKED}
  i2d_X509_REVOKED: function (a: PX509_REVOKED; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_INFO_new}
  X509_CRL_INFO_new: function : PX509_CRL_INFO; cdecl = nil;
  {$EXTERNALSYM X509_CRL_INFO_free}
  X509_CRL_INFO_free: procedure (v1: PX509_CRL_INFO); cdecl = nil;
  {$EXTERNALSYM d2i_X509_CRL_INFO}
  d2i_X509_CRL_INFO: function (a: PPX509_CRL_INFO; const in_: PPByte; len: TIdC_LONG): PX509_CRL_INFO; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CRL_INFO}
  i2d_X509_CRL_INFO: function (a: PX509_CRL_INFO; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_new}
  X509_CRL_new: function : PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_CRL_free}
  X509_CRL_free: procedure (v1: PX509_CRL); cdecl = nil;
  {$EXTERNALSYM d2i_X509_CRL}
  d2i_X509_CRL: function (a: PPX509_CRL; const in_: PPByte; len: TIdC_LONG): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CRL}
  i2d_X509_CRL: function (a: PX509_CRL; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_CRL_add0_revoked}
  X509_CRL_add0_revoked: function (crl: PX509_CRL; rev: PX509_REVOKED): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_by_serial}
  X509_CRL_get0_by_serial: function (crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_by_cert}
  X509_CRL_get0_by_cert: function (crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_PKEY_new}
  X509_PKEY_new: function : PX509_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_PKEY_free}
  X509_PKEY_free: procedure (a: PX509_PKEY); cdecl = nil;

  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKI)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKAC)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)

  {$EXTERNALSYM X509_INFO_new}
  X509_INFO_new: function : PX509_INFO; cdecl = nil;
  {$EXTERNALSYM X509_INFO_free}
  X509_INFO_free: procedure (a: PX509_INFO); cdecl = nil;
  {$EXTERNALSYM X509_NAME_oneline}
  X509_NAME_oneline: function (const a: PX509_NAME; buf: PIdAnsiChar; size: TIdC_INT): PIdAnsiChar; cdecl = nil;

//  function ASN1_verify(i2d: Pi2d_of_void; algor1: PX509_ALGOR;
//    signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT;

//  TIdC_INT ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
//                  unsigned char *md, unsigned TIdC_INT *len);

//  TIdC_INT ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1,
//                X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
//                char *data, EVP_PKEY *pkey, const EVP_MD *type);

  {$EXTERNALSYM ASN1_item_digest}
  ASN1_item_digest: function (const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: PIdC_UINT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_item_verify}
  ASN1_item_verify: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ASN1_item_sign}
  ASN1_item_sign: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_sign_ctx}
  ASN1_item_sign_ctx: function (const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_get_version}
  X509_get_version: function (const x: PX509): TIdC_LONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_set_version}
  X509_set_version: function (x: PX509; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_serialNumber}
  X509_set_serialNumber: function (x: PX509; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_serialNumber}
  X509_get_serialNumber: function (x: PX509): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM X509_get0_serialNumber}
  X509_get0_serialNumber: function (const x: PX509): PASN1_INTEGER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_set_issuer_name}
  X509_set_issuer_name: function (x: PX509; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_issuer_name}
  X509_get_issuer_name: function (const a: PX509): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_set_subject_name}
  X509_set_subject_name: function (x: PX509; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_subject_name}
  X509_get_subject_name: function (const a: PX509): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_get0_notBefore}
  X509_get0_notBefore: function (const x: PX509): PASN1_TIME; cdecl = nil;  {introduced 1.1.0}
  {$EXTERNALSYM X509_getm_notBefore}
  X509_getm_notBefore: function (const x: PX509): PASN1_TIME; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_set1_notBefore}
  X509_set1_notBefore: function (x: PX509; const tm: PASN1_TIME): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_get0_notAfter}
  X509_get0_notAfter: function (const x: PX509): PASN1_TIME; cdecl = nil;  {introduced 1.1.0}
  {$EXTERNALSYM X509_getm_notAfter}
  X509_getm_notAfter: function (const x: PX509): PASN1_TIME; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_set1_notAfter}
  X509_set1_notAfter: function (x: PX509; const tm: PASN1_TIME): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_set_pubkey}
  X509_set_pubkey: function (x: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_up_ref}
  X509_up_ref: function (x: PX509): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_get_signature_type}
  X509_get_signature_type: function (const x: PX509): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  (*
   * This one is only used so that a binary form can output, as in
   * i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &buf)
   *)
  {$EXTERNALSYM X509_get_X509_PUBKEY}
  X509_get_X509_PUBKEY: function (const x: PX509): PX509_PUBKEY; cdecl = nil; {introduced 1.1.0}
//  const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x);
  {$EXTERNALSYM X509_get0_uids}
  X509_get0_uids: procedure (const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_get0_tbs_sigalg}
  X509_get0_tbs_sigalg: function (const x: PX509): PX509_ALGOR; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_get0_pubkey}
  X509_get0_pubkey: function (const x: PX509): PEVP_PKEY; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_get_pubkey}
  X509_get_pubkey: function (x: PX509): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_get0_pubkey_bitstr}
  X509_get0_pubkey_bitstr: function (const x: PX509): PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM X509_certificate_type}
  X509_certificate_type: function (const x: PX509; const pubkey: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_REQ_get_version}
  X509_REQ_get_version: function (const req: PX509_REQ): TIdC_LONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_set_version}
  X509_REQ_set_version: function (x: PX509_REQ; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_subject_name}
  X509_REQ_get_subject_name: function (const req: PX509_REQ): PX509_NAME; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_set_subject_name}
  X509_REQ_set_subject_name: function (req: PX509_REQ; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get0_signature}
  X509_REQ_get0_signature: procedure (const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl = nil; {introduced 1.1.0} 
  {$EXTERNALSYM X509_REQ_get_signature_nid}
  X509_REQ_get_signature_nid: function (const req: PX509_REQ): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM i2d_re_X509_REQ_tbs}
  i2d_re_X509_REQ_tbs: function (req: PX509_REQ; pp: PPByte): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_set_pubkey}
  X509_REQ_set_pubkey: function (x: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_pubkey}
  X509_REQ_get_pubkey: function (req: PX509_REQ): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get0_pubkey}
  X509_REQ_get0_pubkey: function (req: PX509_REQ): PEVP_PKEY; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_get_X509_PUBKEY}
  X509_REQ_get_X509_PUBKEY: function (req: PX509_REQ): PX509_PUBKEY; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_extension_nid}
  X509_REQ_extension_nid: function (nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_extension_nids}
  X509_REQ_get_extension_nids: function : PIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_set_extension_nids}
  X509_REQ_set_extension_nids: procedure (nids: PIdC_INT); cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_extensions}
  X509_REQ_get_extensions : function(req : PX509_REQ) : PSTACK_OF_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add_extensions_nid}
  X509_REQ_add_extensions_nid : function(req : PX509_REQ; exts : PSTACK_OF_X509_EXTENSION;
                                         nid : TIdC_INT) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add_extensions}
  X509_REQ_add_extensions : function(req : PX509_REQ; exts : PSTACK_OF_X509_EXTENSION) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr_count}
  X509_REQ_get_attr_count: function (const req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr_by_NID}
  X509_REQ_get_attr_by_NID: function (const req: PX509_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr_by_OBJ}
  X509_REQ_get_attr_by_OBJ: function (const req: PX509_REQ; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr}
  X509_REQ_get_attr: function (const req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_REQ_delete_attr}
  X509_REQ_delete_attr: function (req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr}
  X509_REQ_add1_attr: function (req: PX509_REQ; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr_by_OBJ}
  X509_REQ_add1_attr_by_OBJ: function (req: PX509_REQ; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr_by_NID}
  X509_REQ_add1_attr_by_NID: function (req: PX509_REQ; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr_by_txt}
  X509_REQ_add1_attr_by_txt: function (req: PX509_REQ; const attrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_CRL_set_version}
  X509_CRL_set_version: function (x: PX509_CRL; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_set_issuer_name}
  X509_CRL_set_issuer_name: function (x: PX509_CRL; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_set1_lastUpdate}
  X509_CRL_set1_lastUpdate: function (x: PX509_CRL; const tm: PASN1_TIME): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_set1_nextUpdate}
  X509_CRL_set1_nextUpdate: function (x: PX509_CRL; const tm: PASN1_TIME): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_sort}
  X509_CRL_sort: function (crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_up_ref}
  X509_CRL_up_ref: function (crl: PX509_CRL): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_CRL_get_version}
  X509_CRL_get_version: function (const crl: PX509_CRL): TIdC_LONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get0_lastUpdate}
  X509_CRL_get0_lastUpdate: function (const crl: PX509_CRL): PASN1_TIME; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get0_nextUpdate}
  X509_CRL_get0_nextUpdate: function (const crl: PX509_CRL): PASN1_TIME; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get_issuer}
  X509_CRL_get_issuer: function (const crl: PX509_CRL): PX509_NAME; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get0_extensions}
  X509_CRL_get0_extensions : function(const crl : PX509_CRL) : PSTACK_OF_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_REVOKED}
  X509_CRL_get_REVOKED : function(crl : PX509_CRL) : PSTACK_OF_X509_REVOKED; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_signature}
  X509_CRL_get0_signature: procedure (const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get_signature_nid}
  X509_CRL_get_signature_nid: function (const crl: PX509_CRL): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM i2d_re_X509_CRL_tbs}
  i2d_re_X509_CRL_tbs: function (req: PX509_CRL; pp: PPByte): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_REVOKED_get0_serialNumber}
  X509_REVOKED_get0_serialNumber: function (const x: PX509_REVOKED): PASN1_INTEGER; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_REVOKED_set_serialNumber}
  X509_REVOKED_set_serialNumber: function (x: PX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get0_revocationDate}
  X509_REVOKED_get0_revocationDate: function (const x: PX509_REVOKED): PASN1_TIME; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_REVOKED_set_revocationDate}
  X509_REVOKED_set_revocationDate: function (r: PX509_REVOKED; tm: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get0_extensions}
  X509_REVOKED_get0_extensions: function(const r : PX509_REVOKED) : PSTACK_OF_X509_EXTENSION; cdecl = nil;

  {$EXTERNALSYM X509_CRL_diff}
  X509_CRL_diff: function (base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_UINT): PX509_CRL; cdecl = nil;

  {$EXTERNALSYM X509_REQ_check_private_key}
  X509_REQ_check_private_key: function (x509: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_check_private_key}
  X509_check_private_key: function (const x509: PX509; const pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  //TIdC_INT X509_chain_check_suiteb(TIdC_INT *perror_depth,
  //                            X509 *x, STACK_OF(X509) *chain,
  //                            unsigned TIdC_LONG flags);
  {$EXTERNALSYM X509_CRL_check_suiteb}
  X509_CRL_check_suiteb: function (crl: PX509_CRL; pk: PEVP_PKEY; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  //STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *chain);

  {$EXTERNALSYM X509_issuer_and_serial_cmp}
  X509_issuer_and_serial_cmp: function (const a: PX509; const b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_issuer_and_serial_hash}
  X509_issuer_and_serial_hash: function (a: PX509): TIdC_ULONG; cdecl = nil;

  {$EXTERNALSYM X509_issuer_name_cmp}
  X509_issuer_name_cmp: function (const a: PX509; const b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_issuer_name_hash}
  X509_issuer_name_hash: function (a: PX509): TIdC_uLONG; cdecl = nil;

  {$EXTERNALSYM X509_subject_name_cmp}
  X509_subject_name_cmp: function (const a: PX509; const b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_subject_name_hash}
  X509_subject_name_hash: function (x: PX509): TIdC_ULONG; cdecl = nil;

  {$EXTERNALSYM X509_cmp}
  X509_cmp: function (const a: PX509; const b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_cmp}
  X509_NAME_cmp: function (const a: PX509_NAME; const b: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_hash}
  X509_NAME_hash: function (x: PX509_NAME): TIdC_ULONG; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM X509_NAME_hash_old}
  X509_NAME_hash_old: function (x: PX509_NAME): TIdC_ULONG; cdecl = nil;

  {$EXTERNALSYM X509_CRL_cmp}
  X509_CRL_cmp: function (const a: PX509_CRL; const b: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_match}
  X509_CRL_match: function (const a: PX509_CRL; const b: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_aux_print}
  X509_aux_print: function (out_: PBIO; x: PX509; indent: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  //# ifndef OPENSSL_NO_STDIO
  //TIdC_INT X509_print_ex_fp(FILE *bp, X509 *x, unsigned TIdC_LONG nmflag,
  //                     unsigned TIdC_LONG cflag);
  //TIdC_INT X509_print_fp(FILE *bp, X509 *x);
  //TIdC_INT X509_CRL_print_fp(FILE *bp, X509_CRL *x);
  //TIdC_INT X509_REQ_print_fp(FILE *bp, X509_REQ *req);
  //TIdC_INT X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, TIdC_INT indent,
  //                          unsigned TIdC_LONG flags);
  //# endif

  {$EXTERNALSYM X509_NAME_print}
  X509_NAME_print: function (bp: PBIO; const name: PX509_NAME; obase: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_print_ex}
  X509_NAME_print_ex: function (out_: PBIO; const nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_print_ex}
  X509_print_ex: function (bp: PBIO; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_print}
  X509_print: function (bp: PBIO; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ocspid_print}
  X509_ocspid_print: function (bp: PBIO; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_print_ex}
  X509_CRL_print_ex: function (out_: PBIO; x: PX509_CRL; nmflag: TIdC_ULONG): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_print}
  X509_CRL_print: function (bp: PBIO; x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_print_ex}
  X509_REQ_print_ex: function (bp: PBIO; x: PX509_REQ; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_print}
  X509_REQ_print: function (bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_NAME_entry_count}
  X509_NAME_entry_count: function (const name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_text_by_NID}
  X509_NAME_get_text_by_NID: function (name: PX509_NAME; nid: TIdC_INT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_text_by_OBJ}
  X509_NAME_get_text_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;

  (*
   * NOTE: you should be passing -1, not 0 as lastpos. The functions that use
   * lastpos, search after that position on.
   *)
  {$EXTERNALSYM X509_NAME_get_index_by_NID}
  X509_NAME_get_index_by_NID: function (name: PX509_NAME; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_index_by_OBJ}
  X509_NAME_get_index_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_entry}
  X509_NAME_get_entry: function (const name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_delete_entry}
  X509_NAME_delete_entry: function (name: PX509_NAME; loc: TIdC_INT): pX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry}
  X509_NAME_add_entry: function (name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry_by_OBJ}
  X509_NAME_add_entry_by_OBJ: function (name: PX509_NAME; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry_by_NID}
  X509_NAME_add_entry_by_NID: function (name: PX509_NAME; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_txt}
  X509_NAME_ENTRY_create_by_txt: function (ne: PPX509_NAME_ENTRY; const field: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_NID}
  X509_NAME_ENTRY_create_by_NID: function (ne: PPX509_NAME_ENTRY; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry_by_txt}
  X509_NAME_add_entry_by_txt: function (name: PX509_NAME; const field: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_OBJ}
  X509_NAME_ENTRY_create_by_OBJ: function (ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_set_object}
  X509_NAME_ENTRY_set_object: function (ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_set_data}
  X509_NAME_ENTRY_set_data: function (ne: PX509_NAME_ENTRY; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_get_object}
  X509_NAME_ENTRY_get_object: function (const ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_get_data}
  X509_NAME_ENTRY_get_data: function (const ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_set}
  X509_NAME_ENTRY_set: function (const ne: PX509_NAME_ENTRY): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_NAME_get0_der}
  X509_NAME_get0_der: function (nm: PX509_NAME; const pder: PPByte; pderlen: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  //TIdC_INT X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x);
  //TIdC_INT X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x,
  //                          TIdC_INT nid, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *x,
  //                          const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *x,
  //                               TIdC_INT crit, TIdC_INT lastpos);
  //X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x,
  //                                         X509_EXTENSION *ex, TIdC_INT loc);

  {$EXTERNALSYM X509_get_ext_count}
  X509_get_ext_count: function (const x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_by_NID}
  X509_get_ext_by_NID: function (const x: PX509; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_by_OBJ}
  X509_get_ext_by_OBJ: function (const x: PX509; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_by_critical}
  X509_get_ext_by_critical: function (const x: PX509; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext}
  X509_get_ext: function (const x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_delete_ext}
  X509_delete_ext: function (x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_add_ext}
  X509_add_ext: function (x: PX509; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_d2i}
  X509_get_ext_d2i: function (const x: PX509; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_add1_ext_i2d}
  X509_add1_ext_i2d: function (x: PX509; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_CRL_get_ext_count}
  X509_CRL_get_ext_count: function (const x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_by_NID}
  X509_CRL_get_ext_by_NID: function (const x: PX509_CRL; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_by_OBJ}
  X509_CRL_get_ext_by_OBJ: function (const x: PX509_CRL; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_by_critical}
  X509_CRL_get_ext_by_critical: function (const x: PX509_CRL; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext}
  X509_CRL_get_ext: function (const x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_CRL_delete_ext}
  X509_CRL_delete_ext: function (x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_CRL_add_ext}
  X509_CRL_add_ext: function (x: PX509_CRL; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_d2i}
  X509_CRL_get_ext_d2i: function (const x: PX509_CRL; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_CRL_add1_ext_i2d}
  X509_CRL_add1_ext_i2d: function (x: PX509_CRL; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_REVOKED_get_ext_count}
  X509_REVOKED_get_ext_count: function (const x: PX509_REVOKED): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_NID}
  X509_REVOKED_get_ext_by_NID: function (const x: PX509_REVOKED; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_OBJ}
  X509_REVOKED_get_ext_by_OBJ: function (const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_critical}
  X509_REVOKED_get_ext_by_critical: function (const x: PX509_REVOKED; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext}
  X509_REVOKED_get_ext: function (const x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_delete_ext}
  X509_REVOKED_delete_ext: function (x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_add_ext}
  X509_REVOKED_add_ext: function (x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_d2i}
  X509_REVOKED_get_ext_d2i: function (const x: PX509_REVOKED; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_add1_ext_i2d}
  X509_REVOKED_add1_ext_i2d: function (x: PX509_REVOKED; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_EXTENSION_create_by_NID}
  X509_EXTENSION_create_by_NID: function (ex: PPX509_EXTENSION; nid: TIdC_INT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_create_by_OBJ}
  X509_EXTENSION_create_by_OBJ: function (ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_set_object}
  X509_EXTENSION_set_object: function (ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_set_critical}
  X509_EXTENSION_set_critical: function (ex: PX509_EXTENSION; crit: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_set_data}
  X509_EXTENSION_set_data: function (ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_get_object}
  X509_EXTENSION_get_object: function (ex: PX509_EXTENSION): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_get_data}
  X509_EXTENSION_get_data: function (ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_get_critical}
  X509_EXTENSION_get_critical: function (const ex: PX509_EXTENSION): TIdC_INT; cdecl = nil;

  //TIdC_INT X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
  //TIdC_INT X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT nid,
  //                           TIdC_INT lastpos);
  //TIdC_INT X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk,
  //                           const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //X509_ATTRIBUTE *X509at_get_attr(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
  //                                           X509_ATTRIBUTE *attr);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const ASN1_OBJECT *obj,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, TIdC_INT nid, TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const PIdAnsiChar *attrname,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //void *X509at_get0_data_by_OBJ(STACK_OF(X509_ATTRIBUTE) *x,
  //                              const ASN1_OBJECT *obj, TIdC_INT lastpos, TIdC_INT type);
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_NID}
  X509_ATTRIBUTE_create_by_NID: function (attr: PPX509_ATTRIBUTE; nid: TIdC_INT; atrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_OBJ}
  X509_ATTRIBUTE_create_by_OBJ: function (attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_txt}
  X509_ATTRIBUTE_create_by_txt: function (attr: PPX509_ATTRIBUTE; const atrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_set1_object}
  X509_ATTRIBUTE_set1_object: function (attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_set1_data}
  X509_ATTRIBUTE_set1_data: function (attr: PX509_ATTRIBUTE; attrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_data}
  X509_ATTRIBUTE_get0_data: function (attr: PX509_ATTRIBUTE; idx: TIdC_INT; atrtype: TIdC_INT; data: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_count}
  X509_ATTRIBUTE_count: function (const attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_object}
  X509_ATTRIBUTE_get0_object: function (attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_type}
  X509_ATTRIBUTE_get0_type: function (attr: PX509_ATTRIBUTE; idx: TIdC_INT): PASN1_TYPE; cdecl = nil;

  {$EXTERNALSYM EVP_PKEY_get_attr_count}
  EVP_PKEY_get_attr_count: function (const key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get_attr_by_NID}
  EVP_PKEY_get_attr_by_NID: function (const key: PEVP_PKEY; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get_attr_by_OBJ}
  EVP_PKEY_get_attr_by_OBJ: function (const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get_attr}
  EVP_PKEY_get_attr: function (const key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_delete_attr}
  EVP_PKEY_delete_attr: function (key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr}
  EVP_PKEY_add1_attr: function (key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_OBJ}
  EVP_PKEY_add1_attr_by_OBJ: function (key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_NID}
  EVP_PKEY_add1_attr_by_NID: function (key: PEVP_PKEY; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_txt}
  EVP_PKEY_add1_attr_by_txt: function (key: PEVP_PKEY; const attrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_verify_cert}
  X509_verify_cert: function (ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;

  (* lookup a cert from a X509 STACK *)
//  function X509_find_by_issuer_and_serial(sk: P STACK_OF(X509); name: PX509_NAME; serial: PASN1_INTEGER): PX509;
//  X509 *X509_find_by_subject(STACK_OF(X509) *sk, X509_NAME *name);

  //DECLARE_ASN1_FUNCTIONS(PBEPARAM)
  //DECLARE_ASN1_FUNCTIONS(PBE2PARAM)
  //DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)
  //#ifndef OPENSSL_NO_SCRYPT
  //DECLARE_ASN1_FUNCTIONS(SCRYPT_PARAMS)
  //#endif

  {$EXTERNALSYM PKCS5_pbe_set0_algor}
  PKCS5_pbe_set0_algor: function (algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; const salt: PByte; saltlen: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM PKCS5_pbe_set}
  PKCS5_pbe_set: function (alg: TIdC_INT; iter: TIdC_INT; const salt: PByte; saltlen: TIdC_INT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe2_set}
  PKCS5_pbe2_set: function (const cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe2_set_iv}
  PKCS5_pbe2_set_iv: function (const cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; aiv: PByte; prf_nid: TIdC_INT): PX509_ALGOR; cdecl = nil;

  {$EXTERNALSYM PKCS5_pbe2_set_scrypt}
  PKCS5_pbe2_set_scrypt: function (const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TIdC_INT; aiv: PByte; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64): PX509_ALGOR; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS5_pbkdf2_set}
  PKCS5_pbkdf2_set: function (iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT): PX509_ALGOR; cdecl = nil;

  (* PKCS#8 utilities *)

  //DECLARE_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)

  {$EXTERNALSYM EVP_PKCS82PKEY}
  EVP_PKCS82PKEY: function (const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY2PKCS8}
  EVP_PKEY2PKCS8: function (pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO; cdecl = nil;

  {$EXTERNALSYM PKCS8_pkey_set0}
  PKCS8_pkey_set0: function (priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TIdC_INT; ptype: TIdC_INT; pval: Pointer; penc: PByte; penclen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_pkey_get0}
  PKCS8_pkey_get0: function (const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: PIdC_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;

  //const STACK_OF(X509_ATTRIBUTE) *
  //PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8);
  {$EXTERNALSYM PKCS8_pkey_add1_attr_by_NID}
  PKCS8_pkey_add1_attr_by_NID: function (p8: PPKCS8_PRIV_KEY_INFO; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM X509_PUBKEY_set0_param}
  X509_PUBKEY_set0_param: function (pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer; penc: PByte; penclen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_get0_param}
  X509_PUBKEY_get0_param: function (ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: PIdC_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_check_trust}
  X509_check_trust: function (x: PX509; id: TIdC_INT; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_count}
  X509_TRUST_get_count: function : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get0}
  X509_TRUST_get0: function (idx: TIdC_INT): PX509_TRUST; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_by_id}
  X509_TRUST_get_by_id: function (id: TIdC_INT): TIdC_INT; cdecl = nil;
//  TIdC_INT X509_TRUST_add(TIdC_INT id, TIdC_INT flags, TIdC_INT (*ck) (X509_TRUST *, X509 *, TIdC_INT),
//                     const PIdAnsiChar *name, TIdC_INT arg1, void *arg2);
  {$EXTERNALSYM X509_TRUST_cleanup}
  X509_TRUST_cleanup: procedure ; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_flags}
  X509_TRUST_get_flags: function (const xp: PX509_TRUST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get0_name}
  X509_TRUST_get0_name: function (const xp: PX509_TRUST): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_trust}
  X509_TRUST_get_trust: function (const xp: PX509_TRUST): TIdC_INT; cdecl = nil;

//  unsigned long X509_NAME_hash_ex(const X509_NAME *x, OSSL_LIB_CTX *libctx,
//                                const char *propq, int *ok);
  {$EXTERNALSYM X509_NAME_hash_ex}
  X509_NAME_hash_ex: function (const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PIdAnsiChar; ok: PIdC_INT): TIdC_ULONG; cdecl = nil; {introduced 3.0.0}


{$ELSE}
  {$EXTERNALSYM X509_CRL_set_default_method}
  procedure X509_CRL_set_default_method(const meth: PX509_CRL_METHOD) cdecl; external CLibCrypto;
//  function X509_CRL_METHOD_new(crl_init: function(crl: X509_CRL): TIdC_INT;
//    crl_free: function(crl: PX509_CRL): TIdC_INT;
//    crl_lookup: function(crl: PX509_CRL; ret: PPX509_REVOKED; ser: PASN1_INTEGER; issuer: PX509_NAME): TIdC_INT;
//    crl_verify: function(crl: PX509_CRL, pk: PEVP_PKEY): TIdC_INT): PX509_CRL_METHOD;
  {$EXTERNALSYM X509_CRL_METHOD_free}
  procedure X509_CRL_METHOD_free(m: PX509_CRL_METHOD) cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_CRL_set_meth_data}
  procedure X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get_meth_data}
  function X509_CRL_get_meth_data(crl: PX509_CRL): Pointer cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_verify_cert_error_string}
  function X509_verify_cert_error_string(n: TIdC_LONG): PIdAnsiChar cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_verify}
  function X509_verify(a: PX509; r: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_REQ_verify}
  function X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_verify}
  function X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM NETSCAPE_SPKI_verify}
  function NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM NETSCAPE_SPKI_b64_decode}
  function NETSCAPE_SPKI_b64_decode(const _str: PIdAnsiChar; len: TIdC_INT): PNETSCAPE_SPKI cdecl; external CLibCrypto;
  {$EXTERNALSYM NETSCAPE_SPKI_b64_encode}
  function NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM NETSCAPE_SPKI_get_pubkey}
  function NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM NETSCAPE_SPKI_set_pubkey}
  function NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM NETSCAPE_SPKI_print}
  function NETSCAPE_SPKI_print(out_: PBIO; spki: PNETSCAPE_SPKI): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_signature_dump}
  function X509_signature_dump(bp: PBIO; const sig: PASN1_STRING; indent: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_signature_print}
  function X509_signature_print(bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_sign}
  function X509_sign(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_sign_ctx}
  function X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TIdC_INT cdecl; external CLibCrypto;


  {$EXTERNALSYM X509_REQ_sign}
  function X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_sign_ctx}
  function X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_sign}
  function X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_sign_ctx}
  function X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TIdC_INT cdecl; external CLibCrypto;


  {$EXTERNALSYM NETSCAPE_SPKI_sign}
  function NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_pubkey_digest}
  function X509_pubkey_digest(const data: PX509; const type_: PEVP_MD; md: PByte; len: PIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_digest}
  function X509_digest(const data: PX509; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_digest}
  function X509_CRL_digest(const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_digest}
  function X509_REQ_digest(const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_digest}
  function X509_NAME_digest(const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  //# ifndef OPENSSL_NO_STDIO
  //X509 *d2i_X509_fp(FILE *fp, X509 **x509);
  //TIdC_INT i2d_X509_fp(FILE *fp, X509 *x509);
  //X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl);
  //TIdC_INT i2d_X509_CRL_fp(FILE *fp, X509_CRL *crl);
  //X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req);
  //TIdC_INT i2d_X509_REQ_fp(FILE *fp, X509_REQ *req);
  //#  ifndef OPENSSL_NO_RSA
  //RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa);
  //#  endif
  //#  ifndef OPENSSL_NO_DSA
  //DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
  //DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
  //#  endif
  //#  ifndef OPENSSL_NO_EC
  //EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
  //EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
  //#  endif
  //X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8);
  //TIdC_INT i2d_PKCS8_fp(FILE *fp, X509_SIG *p8);
  //PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
  //                                                PKCS8_PRIV_KEY_INFO **p8inf);
  //TIdC_INT i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf);
  //TIdC_INT i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
  //TIdC_INT i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
  //TIdC_INT i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
  //# endif

  {$EXTERNALSYM d2i_X509_bio}
  function d2i_X509_bio(bp: PBIO; x509: PPX509): PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_bio}
  function i2d_X509_bio(bp: PBIO; x509: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_CRL_bio}
  function d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_CRL_bio}
  function i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_REQ_bio}
  function d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_REQ_bio}
  function i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_RSAPrivateKey_bio}
  function d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_RSAPrivateKey_bio}
  function i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_RSAPublicKey_bio}
  function d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_RSAPublicKey_bio}
  function i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_RSA_PUBKEY_bio}
  function d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_RSA_PUBKEY_bio}
  function i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_DSA_PUBKEY_bio}
  function d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): PDSA cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DSA_PUBKEY_bio}
  function i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_DSAPrivateKey_bio}
  function d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DSAPrivateKey_bio}
  function i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_EC_PUBKEY_bio}
  function d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_EC_PUBKEY_bio}
  function i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ECPrivateKey_bio}
  function d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ECPrivateKey_bio}
  function i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_PKCS8_bio}
  function d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PKCS8_bio}
  function i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PKCS8_PRIV_KEY_INFO_bio}
  function d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PKCS8_PRIV_KEY_INFO_bio}
  function i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PKCS8PrivateKeyInfo_bio}
  function i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PrivateKey_bio}
  function i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PrivateKey_bio}
  function d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PrivateKey_ex_bio}
  function d2i_PrivateKey_ex_bio(bp : PBIO; a :PPEVP_PKEY;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto;

  {$EXTERNALSYM i2d_PUBKEY_bio}
  function i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PUBKEY_bio}
  function d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_dup}
  function X509_dup(x509: PX509): PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_dup}
  function X509_ATTRIBUTE_dup(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_dup}
  function X509_EXTENSION_dup(ex: PX509_EXTENSION): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_dup}
  function X509_CRL_dup(crl: PX509_CRL): PX509_CRL cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_dup}
  function X509_REVOKED_dup(rev: PX509_REVOKED): PX509_REVOKED cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_dup}
  function X509_REQ_dup(req: PX509_REQ): PX509_REQ cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ALGOR_dup}
  function X509_ALGOR_dup(xn: PX509_ALGOR): PX509_ALGOR cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ALGOR_set0}
  function X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ALGOR_get0}
  procedure X509_ALGOR_get0(const paobj: PPASN1_OBJECT; pptype: PIdC_INT; const ppval: PPointer; const algor: PX509_ALGOR) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ALGOR_set_md}
  procedure X509_ALGOR_set_md(alg: PX509_ALGOR; const md: PEVP_MD) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ALGOR_cmp}
  function X509_ALGOR_cmp(const a: PX509_ALGOR; const b: PX509_ALGOR): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_NAME_dup}
  function X509_NAME_dup(xn: PX509_NAME): PX509_NAME cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_dup}
  function X509_NAME_ENTRY_dup(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_cmp_time}
  function X509_cmp_time(const s: PASN1_TIME; t: PIdC_TIMET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_cmp_current_time}
  function X509_cmp_current_time(const s: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_cmp_timeframe}
  function X509_cmp_timeframe(const vpm : PX509_VERIFY_PARAM; start, _end : PASN1_TIME ) : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_check_certificate_times}
  function X509_check_certificate_times(const vpm : PX509_VERIFY_PARAM; X : PX509; _error : TIdC_INT) : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_time_adj}
  function X509_time_adj(s: PASN1_TIME; adj: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_time_adj_ex}
  function X509_time_adj_ex(s: PASN1_TIME; offset_day: TIdC_INT; offset_sec: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_gmtime_adj}
  function X509_gmtime_adj(s: PASN1_TIME; adj: TIdC_LONG): PASN1_TIME cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_get_default_cert_area}
  function X509_get_default_cert_area: PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_default_cert_dir}
  function X509_get_default_cert_dir: PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_default_cert_file}
  function X509_get_default_cert_file: PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_default_cert_dir_env}
  function X509_get_default_cert_dir_env: PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_default_cert_file_env}
  function X509_get_default_cert_file_env: PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_default_private_dir}
  function X509_get_default_private_dir: PIdAnsiChar cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_to_X509_REQ}
  function X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_to_X509}
  function X509_REQ_to_X509(r: PX509_REQ; days: TIdC_INT; pkey: PEVP_PKEY): PX509 cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_ALGOR_new}
  function X509_ALGOR_new: PX509_ALGOR cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ALGOR_free}
  procedure X509_ALGOR_free(v1: PX509_ALGOR) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_ALGOR}
  function d2i_X509_ALGOR(a: PPX509_ALGOR; const in_: PPByte; len: TIdC_LONG): PX509_ALGOR cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_ALGOR}
  function i2d_X509_ALGOR(a: PX509_ALGOR; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_ALGORS, X509_ALGORS, X509_ALGORS)
  {$EXTERNALSYM X509_VAL_new}
  function X509_VAL_new: PX509_VAL cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_VAL_free}
  procedure X509_VAL_free(v1: PX509_VAL) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_VAL}
  function d2i_X509_VAL(a: PPX509_VAL; const in_: PPByte; len: TIdC_LONG): PX509_VAL cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_VAL}
  function i2d_X509_VAL(a: PX509_VAL; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_PUBKEY_new}
  function X509_PUBKEY_new: PX509_PUBKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PUBKEY_free}
  procedure X509_PUBKEY_free(v1: PX509_PUBKEY) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_PUBKEY}
  function d2i_X509_PUBKEY(a: PPX509_PUBKEY; const in_: PPByte; len: TIdC_LONG): PX509_PUBKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_PUBKEY}
  function i2d_X509_PUBKEY(a: PX509_PUBKEY; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_PUBKEY_set}
  function X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PUBKEY_get0}
  function X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_PUBKEY_get}
  function X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY cdecl; external CLibCrypto;
//  function X509_get_pubkey_parameters(pkey: PEVP_PKEY; chain: P STACK_OF(X509)): TIdC_INT;
  {$EXTERNALSYM X509_get_pathlen}
  function X509_get_pathlen(x: PX509): TIdC_LONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM i2d_PUBKEY}
  function i2d_PUBKEY(a: PEVP_PKEY; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PUBKEY}
  function d2i_PUBKEY(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY cdecl; external CLibCrypto;

  {$EXTERNALSYM i2d_RSA_PUBKEY}
  function i2d_RSA_PUBKEY(a: PRSA; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_RSA_PUBKEY}
  function d2i_RSA_PUBKEY(a: PPRSA; const pp: PPByte; _length: TIdC_LONG): PRSA cdecl; external CLibCrypto;

  {$EXTERNALSYM i2d_DSA_PUBKEY}
  function i2d_DSA_PUBKEY(a: PDSA; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_DSA_PUBKEY}
  function d2i_DSA_PUBKEY(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA cdecl; external CLibCrypto;

  {$EXTERNALSYM i2d_EC_PUBKEY}
  function i2d_EC_PUBKEY(a: PEC_KEY; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_EC_PUBKEY}
  function d2i_EC_PUBKEY(a: PPEC_KEY; const pp: PPByte; _length: TIdC_LONG): PEC_KEY cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_SIG_new}
  function X509_SIG_new: PX509_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_SIG_free}
  procedure X509_SIG_free(v1: PX509_SIG) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_SIG}
  function d2i_X509_SIG(a: PPX509_SIG; const in_: PPByte; len: TIdC_LONG): PX509_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_SIG}
  function i2d_X509_SIG(a: PX509_SIG; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_SIG_get0}
  procedure X509_SIG_get0(const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_SIG_getm}
  procedure X509_SIG_getm(sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_REQ_INFO_new}
  function X509_REQ_INFO_new: PX509_REQ_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_INFO_free}
  procedure X509_REQ_INFO_free(v1: PX509_REQ_INFO) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_REQ_INFO}
  function d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; const in_: PPByte; len: TIdC_LONG): PX509_REQ_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_REQ_INFO}
  function i2d_X509_REQ_INFO(a: PX509_REQ_INFO; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_REQ_new}
  function X509_REQ_new: PX509_REQ cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_free}
  procedure X509_REQ_free(v1: PX509_REQ) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_REQ}
  function d2i_X509_REQ(a: PPX509_REQ; const in_: PPByte; len: TIdC_LONG): PX509_REQ cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_REQ}
  function i2d_X509_REQ(a: PX509_REQ; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_ATTRIBUTE_new}
  function X509_ATTRIBUTE_new: PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_free}
  procedure X509_ATTRIBUTE_free(v1: PX509_ATTRIBUTE) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_ATTRIBUTE}
  function d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; const in_: PPByte; len: TIdC_LONG): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_ATTRIBUTE}
  function i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_create}
  function X509_ATTRIBUTE_create(nid: TIdC_INT; trtype: TIdC_INT; value: Pointer): PX509_ATTRIBUTE cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_EXTENSION_new}
  function X509_EXTENSION_new: PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_free}
  procedure X509_EXTENSION_free(v1: PX509_EXTENSION) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_EXTENSION}
  function d2i_X509_EXTENSION(a: PPX509_EXTENSION; const in_: PPByte; len: TIdC_LONG): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_EXTENSION}
  function i2d_X509_EXTENSION(a: PX509_EXTENSION; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)

  {$EXTERNALSYM X509_NAME_ENTRY_new}
  function X509_NAME_ENTRY_new: PX509_NAME_ENTRY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_free}
  procedure X509_NAME_ENTRY_free(v1: PX509_NAME_ENTRY) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_NAME_ENTRY}
  function d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; const in_: PPByte; len: TIdC_LONG): PX509_NAME_ENTRY cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_NAME_ENTRY}
  function i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_NAME_new}
  function X509_NAME_new: PX509_NAME cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_free}
  procedure X509_NAME_free(v1: PX509_NAME) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_NAME}
  function d2i_X509_NAME(a: PPX509_NAME; const in_: PPByte; len: TIdC_LONG): PX509_NAME cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_NAME}
  function i2d_X509_NAME(a: PX509_NAME; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_NAME_set}
  function X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;

  //DECLARE_ASN1_FUNCTIONS(X509_CINF)

  {$EXTERNALSYM X509_new}
  function X509_new: PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_free}
  procedure X509_free(v1: PX509) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509}
  function d2i_X509(a: PPX509; const in_: PPByte; len: TIdC_LONG): PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509}
  function i2d_X509(a: PX509; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  //DECLARE_ASN1_FUNCTIONS(X509_CERT_AUX)
  //
  //#define X509_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef)
  {$EXTERNALSYM X509_set_ex_data}
  function X509_set_ex_data(r: PX509; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_ex_data}
  function X509_get_ex_data(r: PX509; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_AUX}
  function i2d_X509_AUX(a: PX509; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_AUX}
  function d2i_X509_AUX(a: PPX509; const pp: PPByte; _length: TIdC_LONG): PX509 cdecl; external CLibCrypto;

  {$EXTERNALSYM i2d_re_X509_tbs}
  function i2d_re_X509_tbs(x: PX509; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_SIG_INFO_get}
  function X509_SIG_INFO_get(const siginf: PX509_SIG_INFO; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_SIG_INFO_set}
  procedure X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TIdC_INT; pknid: TIdC_INT; secbits: TIdC_INT; flags: TIdC_UINT32) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_get_signature_info}
  function X509_get_signature_info(x: PX509; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_get0_signature}
  procedure X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_get_signature_nid}
  function X509_get_signature_nid(const x: PX509): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_trusted}
  function X509_trusted(const x: PX509): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_alias_set1}
  function X509_alias_set1(x: PX509; const name: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_keyid_set1}
  function X509_keyid_set1(x: PX509; const id: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_alias_get0}
  function X509_alias_get0(x: PX509; len: PIdC_INT): PByte cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_keyid_get0}
  function X509_keyid_get0(x: PX509; len: PIdC_INT): PByte cdecl; external CLibCrypto;
//  TIdC_INT (*X509_TRUST_set_default(TIdC_INT (*trust) (TIdC_INT, X509 *, TIdC_INT))) (TIdC_INT, X509 *,
//                                                                  TIdC_INT);
  {$EXTERNALSYM X509_TRUST_set}
  function X509_TRUST_set(t: PIdC_INT; trust: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_add1_trust_object}
  function X509_add1_trust_object(x: PX509; const obj: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_add1_reject_object}
  function X509_add1_reject_object(x: PX509; const obj: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_trust_clear}
  procedure X509_trust_clear(x: PX509) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_reject_clear}
  procedure X509_reject_clear(x: PX509) cdecl; external CLibCrypto;

  //STACK_OF(ASN1_OBJECT) *X509_get0_trust_objects(X509 *x);
  //STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x);
  //
  {$EXTERNALSYM X509_REVOKED_new}
  function X509_REVOKED_new: PX509_REVOKED cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_free}
  procedure X509_REVOKED_free(v1: PX509_REVOKED) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_REVOKED}
  function d2i_X509_REVOKED(a: PPX509_REVOKED; const in_: PPByte; len: TIdC_LONG): PX509_REVOKED cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_REVOKED}
  function i2d_X509_REVOKED(a: PX509_REVOKED; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_INFO_new}
  function X509_CRL_INFO_new: PX509_CRL_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_INFO_free}
  procedure X509_CRL_INFO_free(v1: PX509_CRL_INFO) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_CRL_INFO}
  function d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; const in_: PPByte; len: TIdC_LONG): PX509_CRL_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_CRL_INFO}
  function i2d_X509_CRL_INFO(a: PX509_CRL_INFO; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_new}
  function X509_CRL_new: PX509_CRL cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_free}
  procedure X509_CRL_free(v1: PX509_CRL) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_X509_CRL}
  function d2i_X509_CRL(a: PPX509_CRL; const in_: PPByte; len: TIdC_LONG): PX509_CRL cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_X509_CRL}
  function i2d_X509_CRL(a: PX509_CRL; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_CRL_add0_revoked}
  function X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get0_by_serial}
  function X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get0_by_cert}
  function X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_PKEY_new}
  function X509_PKEY_new: PX509_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PKEY_free}
  procedure X509_PKEY_free(a: PX509_PKEY) cdecl; external CLibCrypto;

  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKI)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKAC)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)

  {$EXTERNALSYM X509_INFO_new}
  function X509_INFO_new: PX509_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_INFO_free}
  procedure X509_INFO_free(a: PX509_INFO) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_oneline}
  function X509_NAME_oneline(const a: PX509_NAME; buf: PIdAnsiChar; size: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto;

//  function ASN1_verify(i2d: Pi2d_of_void; algor1: PX509_ALGOR;
//    signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT;

//  TIdC_INT ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
//                  unsigned char *md, unsigned TIdC_INT *len);

//  TIdC_INT ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1,
//                X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
//                char *data, EVP_PKEY *pkey, const EVP_MD *type);

  {$EXTERNALSYM ASN1_item_digest}
  function ASN1_item_digest(const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: PIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_item_verify}
  function ASN1_item_verify(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ASN1_item_sign}
  function ASN1_item_sign(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ASN1_item_sign_ctx}
  function ASN1_item_sign_ctx(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_get_version}
  function X509_get_version(const x: PX509): TIdC_LONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_set_version}
  function X509_set_version(x: PX509; version: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_set_serialNumber}
  function X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_serialNumber}
  function X509_get_serialNumber(x: PX509): PASN1_INTEGER cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get0_serialNumber}
  function X509_get0_serialNumber(const x: PX509): PASN1_INTEGER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_set_issuer_name}
  function X509_set_issuer_name(x: PX509; name: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_issuer_name}
  function X509_get_issuer_name(const a: PX509): PX509_NAME cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_set_subject_name}
  function X509_set_subject_name(x: PX509; name: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_subject_name}
  function X509_get_subject_name(const a: PX509): PX509_NAME cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get0_notBefore}
  function X509_get0_notBefore(const x: PX509): PASN1_TIME cdecl; external CLibCrypto;  {introduced 1.1.0}
  {$EXTERNALSYM X509_getm_notBefore}
  function X509_getm_notBefore(const x: PX509): PASN1_TIME cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_set1_notBefore}
  function X509_set1_notBefore(x: PX509; const tm: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_get0_notAfter}
  function X509_get0_notAfter(const x: PX509): PASN1_TIME cdecl; external CLibCrypto;  {introduced 1.1.0}
  {$EXTERNALSYM X509_getm_notAfter}
  function X509_getm_notAfter(const x: PX509): PASN1_TIME cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_set1_notAfter}
  function X509_set1_notAfter(x: PX509; const tm: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_set_pubkey}
  function X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_up_ref}
  function X509_up_ref(x: PX509): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_get_signature_type}
  function X509_get_signature_type(const x: PX509): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  (*
   * This one is only used so that a binary form can output, as in
   * i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &buf)
   *)
  {$EXTERNALSYM X509_get_X509_PUBKEY}
  function X509_get_X509_PUBKEY(const x: PX509): PX509_PUBKEY cdecl; external CLibCrypto; {introduced 1.1.0}
//  const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x);
  {$EXTERNALSYM X509_get0_uids}
  procedure X509_get0_uids(const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_get0_tbs_sigalg}
  function X509_get0_tbs_sigalg(const x: PX509): PX509_ALGOR cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_get0_pubkey}
  function X509_get0_pubkey(const x: PX509): PEVP_PKEY cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_get_pubkey}
  function X509_get_pubkey(x: PX509): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get0_pubkey_bitstr}
  function X509_get0_pubkey_bitstr(const x: PX509): PASN1_BIT_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_certificate_type}
  function X509_certificate_type(const x: PX509; const pubkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_REQ_get_version}
  function X509_REQ_get_version(const req: PX509_REQ): TIdC_LONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_set_version}
  function X509_REQ_set_version(x: PX509_REQ; version: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_subject_name}
  function X509_REQ_get_subject_name(const req: PX509_REQ): PX509_NAME cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_set_subject_name}
  function X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get0_signature}
  procedure X509_REQ_get0_signature(const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR) cdecl; external CLibCrypto; {introduced 1.1.0} 
  {$EXTERNALSYM X509_REQ_get_signature_nid}
  function X509_REQ_get_signature_nid(const req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM i2d_re_X509_REQ_tbs}
  function i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPByte): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_set_pubkey}
  function X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_pubkey}
  function X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get0_pubkey}
  function X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_get_X509_PUBKEY}
  function X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_REQ_extension_nid}
  function X509_REQ_extension_nid(nid: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_extension_nids}
  function X509_REQ_get_extension_nids: PIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_set_extension_nids}
  procedure X509_REQ_set_extension_nids(nids: PIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_extensions}
  function X509_REQ_get_extensions(req : PX509_REQ) : PSTACK_OF_X509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_add_extensions_nid}
  function X509_REQ_add_extensions_nid(req : PX509_REQ; exts : PSTACK_OF_X509_EXTENSION;
                                       nid : TIdC_INT) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_add_extensions}
  function X509_REQ_add_extensions(req : PX509_REQ; exts : PSTACK_OF_X509_EXTENSION) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_attr_count}
  function X509_REQ_get_attr_count(const req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_attr_by_NID}
  function X509_REQ_get_attr_by_NID(const req: PX509_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_attr_by_OBJ}
  function X509_REQ_get_attr_by_OBJ(const req: PX509_REQ; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get_attr}
  function X509_REQ_get_attr(const req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_delete_attr}
  function X509_REQ_delete_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_add1_attr}
  function X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_add1_attr_by_OBJ}
  function X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_add1_attr_by_NID}
  function X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_add1_attr_by_txt}
  function X509_REQ_add1_attr_by_txt(req: PX509_REQ; const attrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_CRL_set_version}
  function X509_CRL_set_version(x: PX509_CRL; version: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_set_issuer_name}
  function X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_set1_lastUpdate}
  function X509_CRL_set1_lastUpdate(x: PX509_CRL; const tm: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_set1_nextUpdate}
  function X509_CRL_set1_nextUpdate(x: PX509_CRL; const tm: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_sort}
  function X509_CRL_sort(crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_up_ref}
  function X509_CRL_up_ref(crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_CRL_get_version}
  function X509_CRL_get_version(const crl: PX509_CRL): TIdC_LONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get0_lastUpdate}
  function X509_CRL_get0_lastUpdate(const crl: PX509_CRL): PASN1_TIME cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get0_nextUpdate}
  function X509_CRL_get0_nextUpdate(const crl: PX509_CRL): PASN1_TIME cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get_issuer}
  function X509_CRL_get_issuer(const crl: PX509_CRL): PX509_NAME cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get0_extensions}
  function X509_CRL_get0_extensions(const crl : PX509_CRL) : PSTACK_OF_X509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get_REVOKED}
  function X509_CRL_get_REVOKED(crl : PX509_CRL) : PSTACK_OF_X509_REVOKED cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get0_signature}
  procedure X509_CRL_get0_signature(const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_get_signature_nid}
  function X509_CRL_get_signature_nid(const crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM i2d_re_X509_CRL_tbs}
  function i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPByte): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_REVOKED_get0_serialNumber}
  function X509_REVOKED_get0_serialNumber(const x: PX509_REVOKED): PASN1_INTEGER cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_REVOKED_set_serialNumber}
  function X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_get0_revocationDate}
  function X509_REVOKED_get0_revocationDate(const x: PX509_REVOKED): PASN1_TIME cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_REVOKED_set_revocationDate}
  function X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_get0_extensions}
  function X509_REVOKED_get0_extensions(const  r : PX509_REVOKED) : PSTACK_OF_X509_EXTENSION cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_CRL_diff}
  function X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_UINT): PX509_CRL cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_REQ_check_private_key}
  function X509_REQ_check_private_key(x509: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_check_private_key}
  function X509_check_private_key(const x509: PX509; const pkey: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  //TIdC_INT X509_chain_check_suiteb(TIdC_INT *perror_depth,
  //                            X509 *x, STACK_OF(X509) *chain,
  //                            unsigned TIdC_LONG flags);
  {$EXTERNALSYM X509_CRL_check_suiteb}
  function X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  //STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *chain);

  {$EXTERNALSYM X509_issuer_and_serial_cmp}
  function X509_issuer_and_serial_cmp(const a: PX509; const b: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_issuer_and_serial_hash}
  function X509_issuer_and_serial_hash(a: PX509): TIdC_ULONG cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_issuer_name_cmp}
  function X509_issuer_name_cmp(const a: PX509; const b: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_issuer_name_hash}
  function X509_issuer_name_hash(a: PX509): TIdC_uLONG cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_subject_name_cmp}
  function X509_subject_name_cmp(const a: PX509; const b: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_subject_name_hash}
  function X509_subject_name_hash(x: PX509): TIdC_ULONG cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_cmp}
  function X509_cmp(const a: PX509; const b: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_cmp}
  function X509_NAME_cmp(const a: PX509_NAME; const b: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_hash_old}
  function X509_NAME_hash_old(x: PX509_NAME): TIdC_ULONG cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_CRL_cmp}
  function X509_CRL_cmp(const a: PX509_CRL; const b: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_match}
  function X509_CRL_match(const a: PX509_CRL; const b: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_aux_print}
  function X509_aux_print(out_: PBIO; x: PX509; indent: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  //# ifndef OPENSSL_NO_STDIO
  //TIdC_INT X509_print_ex_fp(FILE *bp, X509 *x, unsigned TIdC_LONG nmflag,
  //                     unsigned TIdC_LONG cflag);
  //TIdC_INT X509_print_fp(FILE *bp, X509 *x);
  //TIdC_INT X509_CRL_print_fp(FILE *bp, X509_CRL *x);
  //TIdC_INT X509_REQ_print_fp(FILE *bp, X509_REQ *req);
  //TIdC_INT X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, TIdC_INT indent,
  //                          unsigned TIdC_LONG flags);
  //# endif

  {$EXTERNALSYM X509_NAME_print}
  function X509_NAME_print(bp: PBIO; const name: PX509_NAME; obase: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_print_ex}
  function X509_NAME_print_ex(out_: PBIO; const nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_print_ex}
  function X509_print_ex(bp: PBIO; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_print}
  function X509_print(bp: PBIO; x: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ocspid_print}
  function X509_ocspid_print(bp: PBIO; x: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_print_ex}
  function X509_CRL_print_ex(out_: PBIO; x: PX509_CRL; nmflag: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM X509_CRL_print}
  function X509_CRL_print(bp: PBIO; x: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_print_ex}
  function X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_print}
  function X509_REQ_print(bp: PBIO; req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_NAME_entry_count}
  function X509_NAME_entry_count(const name: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_get_text_by_NID}
  function X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TIdC_INT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_get_text_by_OBJ}
  function X509_NAME_get_text_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (*
   * NOTE: you should be passing -1, not 0 as lastpos. The functions that use
   * lastpos, search after that position on.
   *)
  {$EXTERNALSYM X509_NAME_get_index_by_NID}
  function X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_get_index_by_OBJ}
  function X509_NAME_get_index_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_get_entry}
  function X509_NAME_get_entry(const name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_delete_entry}
  function X509_NAME_delete_entry(name: PX509_NAME; loc: TIdC_INT): pX509_NAME_ENTRY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_add_entry}
  function X509_NAME_add_entry(name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_add_entry_by_OBJ}
  function X509_NAME_add_entry_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_add_entry_by_NID}
  function X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_txt}
  function X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; const field: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_NID}
  function X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_add_entry_by_txt}
  function X509_NAME_add_entry_by_txt(name: PX509_NAME; const field: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_OBJ}
  function X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_set_object}
  function X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_set_data}
  function X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_get_object}
  function X509_NAME_ENTRY_get_object(const ne: PX509_NAME_ENTRY): PASN1_OBJECT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_get_data}
  function X509_NAME_ENTRY_get_data(const ne: PX509_NAME_ENTRY): PASN1_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_NAME_ENTRY_set}
  function X509_NAME_ENTRY_set(const ne: PX509_NAME_ENTRY): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_NAME_get0_der}
  function X509_NAME_get0_der(nm: PX509_NAME; const pder: PPByte; pderlen: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  //TIdC_INT X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x);
  //TIdC_INT X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x,
  //                          TIdC_INT nid, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *x,
  //                          const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *x,
  //                               TIdC_INT crit, TIdC_INT lastpos);
  //X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x,
  //                                         X509_EXTENSION *ex, TIdC_INT loc);

  {$EXTERNALSYM X509_get_ext_count}
  function X509_get_ext_count(const x: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_ext_by_NID}
  function X509_get_ext_by_NID(const x: PX509; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_ext_by_OBJ}
  function X509_get_ext_by_OBJ(const x: PX509; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_ext_by_critical}
  function X509_get_ext_by_critical(const x: PX509; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_ext}
  function X509_get_ext(const x: PX509; loc: TIdC_INT): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_delete_ext}
  function X509_delete_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_add_ext}
  function X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_ext_d2i}
  function X509_get_ext_d2i(const x: PX509; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_add1_ext_i2d}
  function X509_add1_ext_i2d(x: PX509; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_CRL_get_ext_count}
  function X509_CRL_get_ext_count(const x: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get_ext_by_NID}
  function X509_CRL_get_ext_by_NID(const x: PX509_CRL; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get_ext_by_OBJ}
  function X509_CRL_get_ext_by_OBJ(const x: PX509_CRL; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get_ext_by_critical}
  function X509_CRL_get_ext_by_critical(const x: PX509_CRL; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get_ext}
  function X509_CRL_get_ext(const x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_delete_ext}
  function X509_CRL_delete_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_add_ext}
  function X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_get_ext_d2i}
  function X509_CRL_get_ext_d2i(const x: PX509_CRL; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_CRL_add1_ext_i2d}
  function X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_REVOKED_get_ext_count}
  function X509_REVOKED_get_ext_count(const x: PX509_REVOKED): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_NID}
  function X509_REVOKED_get_ext_by_NID(const x: PX509_REVOKED; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_OBJ}
  function X509_REVOKED_get_ext_by_OBJ(const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_critical}
  function X509_REVOKED_get_ext_by_critical(const x: PX509_REVOKED; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_get_ext}
  function X509_REVOKED_get_ext(const x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_delete_ext}
  function X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_add_ext}
  function X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_get_ext_d2i}
  function X509_REVOKED_get_ext_d2i(const x: PX509_REVOKED; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REVOKED_add1_ext_i2d}
  function X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_EXTENSION_create_by_NID}
  function X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TIdC_INT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_create_by_OBJ}
  function X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_set_object}
  function X509_EXTENSION_set_object(ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_set_critical}
  function X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_set_data}
  function X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_get_object}
  function X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_get_data}
  function X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_EXTENSION_get_critical}
  function X509_EXTENSION_get_critical(const ex: PX509_EXTENSION): TIdC_INT cdecl; external CLibCrypto;

  //TIdC_INT X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
  //TIdC_INT X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT nid,
  //                           TIdC_INT lastpos);
  //TIdC_INT X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk,
  //                           const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //X509_ATTRIBUTE *X509at_get_attr(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
  //                                           X509_ATTRIBUTE *attr);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const ASN1_OBJECT *obj,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, TIdC_INT nid, TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const PIdAnsiChar *attrname,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //void *X509at_get0_data_by_OBJ(STACK_OF(X509_ATTRIBUTE) *x,
  //                              const ASN1_OBJECT *obj, TIdC_INT lastpos, TIdC_INT type);
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_NID}
  function X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TIdC_INT; atrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_OBJ}
  function X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_txt}
  function X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; const atrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_set1_object}
  function X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_set1_data}
  function X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_data}
  function X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TIdC_INT; atrtype: TIdC_INT; data: Pointer): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_count}
  function X509_ATTRIBUTE_count(const attr: PX509_ATTRIBUTE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_object}
  function X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_type}
  function X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TIdC_INT): PASN1_TYPE cdecl; external CLibCrypto;

  {$EXTERNALSYM EVP_PKEY_get_attr_count}
  function EVP_PKEY_get_attr_count(const key: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get_attr_by_NID}
  function EVP_PKEY_get_attr_by_NID(const key: PEVP_PKEY; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get_attr_by_OBJ}
  function EVP_PKEY_get_attr_by_OBJ(const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_get_attr}
  function EVP_PKEY_get_attr(const key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_delete_attr}
  function EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_add1_attr}
  function EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_OBJ}
  function EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_NID}
  function EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_txt}
  function EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; const attrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_verify_cert}
  function X509_verify_cert(ctx: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;

  (* lookup a cert from a X509 STACK *)
//  function X509_find_by_issuer_and_serial(sk: P STACK_OF(X509); name: PX509_NAME; serial: PASN1_INTEGER): PX509;
//  X509 *X509_find_by_subject(STACK_OF(X509) *sk, X509_NAME *name);

  //DECLARE_ASN1_FUNCTIONS(PBEPARAM)
  //DECLARE_ASN1_FUNCTIONS(PBE2PARAM)
  //DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)
  //#ifndef OPENSSL_NO_SCRYPT
  //DECLARE_ASN1_FUNCTIONS(SCRYPT_PARAMS)
  //#endif

  {$EXTERNALSYM PKCS5_pbe_set0_algor}
  function PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; const salt: PByte; saltlen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM PKCS5_pbe_set}
  function PKCS5_pbe_set(alg: TIdC_INT; iter: TIdC_INT; const salt: PByte; saltlen: TIdC_INT): PX509_ALGOR cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS5_pbe2_set}
  function PKCS5_pbe2_set(const cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT): PX509_ALGOR cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS5_pbe2_set_iv}
  function PKCS5_pbe2_set_iv(const cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; aiv: PByte; prf_nid: TIdC_INT): PX509_ALGOR cdecl; external CLibCrypto;

  {$EXTERNALSYM PKCS5_pbe2_set_scrypt}
  function PKCS5_pbe2_set_scrypt(const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TIdC_INT; aiv: PByte; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64): PX509_ALGOR cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS5_pbkdf2_set}
  function PKCS5_pbkdf2_set(iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT): PX509_ALGOR cdecl; external CLibCrypto;

  (* PKCS#8 utilities *)

  //DECLARE_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)

  {$EXTERNALSYM EVP_PKCS82PKEY}
  function EVP_PKCS82PKEY(const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM EVP_PKEY2PKCS8}
  function EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO cdecl; external CLibCrypto;

  {$EXTERNALSYM PKCS8_pkey_set0}
  function PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TIdC_INT; ptype: TIdC_INT; pval: Pointer; penc: PByte; penclen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS8_pkey_get0}
  function PKCS8_pkey_get0(const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: PIdC_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TIdC_INT cdecl; external CLibCrypto;

  //const STACK_OF(X509_ATTRIBUTE) *
  //PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8);
  {$EXTERNALSYM PKCS8_pkey_add1_attr_by_NID}
  function PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM X509_PUBKEY_set0_param}
  function X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer; penc: PByte; penclen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PUBKEY_get0_param}
  function X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: PIdC_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_check_trust}
  function X509_check_trust(x: PX509; id: TIdC_INT; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_TRUST_get_count}
  function X509_TRUST_get_count: TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_TRUST_get0}
  function X509_TRUST_get0(idx: TIdC_INT): PX509_TRUST cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_TRUST_get_by_id}
  function X509_TRUST_get_by_id(id: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509_TRUST_add(TIdC_INT id, TIdC_INT flags, TIdC_INT (*ck) (X509_TRUST *, X509 *, TIdC_INT),
//                     const PIdAnsiChar *name, TIdC_INT arg1, void *arg2);
  {$EXTERNALSYM X509_TRUST_cleanup}
  procedure X509_TRUST_cleanup cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_TRUST_get_flags}
  function X509_TRUST_get_flags(const xp: PX509_TRUST): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_TRUST_get0_name}
  function X509_TRUST_get0_name(const xp: PX509_TRUST): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_TRUST_get_trust}
  function X509_TRUST_get_trust(const xp: PX509_TRUST): TIdC_INT cdecl; external CLibCrypto;

//  unsigned long X509_NAME_hash_ex(const X509_NAME *x, OSSL_LIB_CTX *libctx,
//                                const char *propq, int *ok);
  {$EXTERNALSYM X509_NAME_hash_ex}
  function X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PIdAnsiChar; ok: PIdC_INT): TIdC_ULONG cdecl; external CLibCrypto; {introduced 3.0.0}


  {$EXTERNALSYM X509_NAME_hash}
  function X509_NAME_hash(x: PX509_NAME): TIdC_ULONG; {removed 3.0.0}
{$ENDIF}

  {$EXTERNALSYM X509_get_ex_new_index}
function X509_get_ex_new_index(l : TIdC_LONG; p : PX509;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

  //#define X509_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef)
function X509_get_ex_new_index(l : TIdC_LONG; p : PX509;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef);
end;

const
  X509_PUBKEY_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get_pathlen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_SIG_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_SIG_getm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_SIG_INFO_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_SIG_INFO_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get_signature_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_trusted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get0_serialNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get0_notBefore_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_getm_notBefore_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_set1_notBefore_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get0_notAfter_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_getm_notAfter_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_set1_notAfter_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get_signature_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get_X509_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get0_uids_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get0_tbs_sigalg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_get0_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_REQ_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_REQ_get_subject_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_REQ_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0); 
  X509_REQ_get_signature_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_re_X509_REQ_tbs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_REQ_get0_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_REQ_get_X509_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_set1_lastUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_set1_nextUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_get0_lastUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_get0_nextUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_get_signature_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_re_X509_CRL_tbs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_REVOKED_get0_serialNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_REVOKED_get0_revocationDate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_aux_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_CRL_print_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_NAME_ENTRY_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_NAME_get0_der_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS5_pbe2_set_scrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS8_pkey_add1_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_NAME_hash_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  X509_http_nbio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  X509_CRL_http_nbio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  X509_NAME_hash_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  d2i_PrivateKey_ex_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  X509_cmp_timeframe_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_check_certificate_times_introduced = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);

//# define X509_NAME_hash(x) X509_NAME_hash_ex(x, NULL, NULL, NULL)
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  X509_CRL_set_default_method_procname = 'X509_CRL_set_default_method';
//  function X509_CRL_METHOD_new(crl_init: function(crl: X509_CRL): TIdC_INT;
//    crl_free: function(crl: PX509_CRL): TIdC_INT;
//    crl_lookup: function(crl: PX509_CRL; ret: PPX509_REVOKED; ser: PASN1_INTEGER; issuer: PX509_NAME): TIdC_INT;
//    crl_verify: function(crl: PX509_CRL, pk: PEVP_PKEY): TIdC_INT): PX509_CRL_METHOD;
  X509_CRL_METHOD_free_procname = 'X509_CRL_METHOD_free';

  X509_CRL_set_meth_data_procname = 'X509_CRL_set_meth_data';
  X509_CRL_get_meth_data_procname = 'X509_CRL_get_meth_data';

  X509_verify_cert_error_string_procname = 'X509_verify_cert_error_string';

  X509_verify_procname = 'X509_verify';

  X509_REQ_verify_procname = 'X509_REQ_verify';
  X509_CRL_verify_procname = 'X509_CRL_verify';
  NETSCAPE_SPKI_verify_procname = 'NETSCAPE_SPKI_verify';

  NETSCAPE_SPKI_b64_decode_procname = 'NETSCAPE_SPKI_b64_decode';
  NETSCAPE_SPKI_b64_encode_procname = 'NETSCAPE_SPKI_b64_encode';
  NETSCAPE_SPKI_get_pubkey_procname = 'NETSCAPE_SPKI_get_pubkey';
  NETSCAPE_SPKI_set_pubkey_procname = 'NETSCAPE_SPKI_set_pubkey';

  NETSCAPE_SPKI_print_procname = 'NETSCAPE_SPKI_print';

  X509_signature_dump_procname = 'X509_signature_dump';
  X509_signature_print_procname = 'X509_signature_print';

  X509_sign_procname = 'X509_sign';
  X509_sign_ctx_procname = 'X509_sign_ctx';

  X509_http_nbio_procname = 'X509_http_nbio'; {removed 3.0.0}

  X509_REQ_sign_procname = 'X509_REQ_sign';
  X509_REQ_sign_ctx_procname = 'X509_REQ_sign_ctx';
  X509_CRL_sign_procname = 'X509_CRL_sign';
  X509_CRL_sign_ctx_procname = 'X509_CRL_sign_ctx';

  X509_CRL_http_nbio_procname = 'X509_CRL_http_nbio'; {removed 3.0.0}

  NETSCAPE_SPKI_sign_procname = 'NETSCAPE_SPKI_sign';

  X509_pubkey_digest_procname = 'X509_pubkey_digest';
  X509_digest_procname = 'X509_digest';
  X509_CRL_digest_procname = 'X509_CRL_digest';
  X509_REQ_digest_procname = 'X509_REQ_digest';
  X509_NAME_digest_procname = 'X509_NAME_digest';

  //# ifndef OPENSSL_NO_STDIO
  //X509 *d2i_X509_fp(FILE *fp, X509 **x509);
  //TIdC_INT i2d_X509_fp(FILE *fp, X509 *x509);
  //X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl);
  //TIdC_INT i2d_X509_CRL_fp(FILE *fp, X509_CRL *crl);
  //X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req);
  //TIdC_INT i2d_X509_REQ_fp(FILE *fp, X509_REQ *req);
  //#  ifndef OPENSSL_NO_RSA
  //RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa);
  //#  endif
  //#  ifndef OPENSSL_NO_DSA
  //DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
  //DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
  //#  endif
  //#  ifndef OPENSSL_NO_EC
  //EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
  //EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
  //#  endif
  //X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8);
  //TIdC_INT i2d_PKCS8_fp(FILE *fp, X509_SIG *p8);
  //PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
  //                                                PKCS8_PRIV_KEY_INFO **p8inf);
  //TIdC_INT i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf);
  //TIdC_INT i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
  //TIdC_INT i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
  //TIdC_INT i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
  //# endif

  d2i_X509_bio_procname = 'd2i_X509_bio';
  i2d_X509_bio_procname = 'i2d_X509_bio';
  d2i_X509_CRL_bio_procname = 'd2i_X509_CRL_bio';
  i2d_X509_CRL_bio_procname = 'i2d_X509_CRL_bio';
  d2i_X509_REQ_bio_procname = 'd2i_X509_REQ_bio';
  i2d_X509_REQ_bio_procname = 'i2d_X509_REQ_bio';

  d2i_RSAPrivateKey_bio_procname = 'd2i_RSAPrivateKey_bio';
  i2d_RSAPrivateKey_bio_procname = 'i2d_RSAPrivateKey_bio';
  d2i_RSAPublicKey_bio_procname = 'd2i_RSAPublicKey_bio';
  i2d_RSAPublicKey_bio_procname = 'i2d_RSAPublicKey_bio';
  d2i_RSA_PUBKEY_bio_procname = 'd2i_RSA_PUBKEY_bio';
  i2d_RSA_PUBKEY_bio_procname = 'i2d_RSA_PUBKEY_bio';

  d2i_DSA_PUBKEY_bio_procname = 'd2i_DSA_PUBKEY_bio';
  i2d_DSA_PUBKEY_bio_procname = 'i2d_DSA_PUBKEY_bio';
  d2i_DSAPrivateKey_bio_procname = 'd2i_DSAPrivateKey_bio';
  i2d_DSAPrivateKey_bio_procname = 'i2d_DSAPrivateKey_bio';

  d2i_EC_PUBKEY_bio_procname = 'd2i_EC_PUBKEY_bio';
  i2d_EC_PUBKEY_bio_procname = 'i2d_EC_PUBKEY_bio';
  d2i_ECPrivateKey_bio_procname = 'd2i_ECPrivateKey_bio';
  i2d_ECPrivateKey_bio_procname = 'i2d_ECPrivateKey_bio';

  d2i_PKCS8_bio_procname = 'd2i_PKCS8_bio';
  i2d_PKCS8_bio_procname = 'i2d_PKCS8_bio';
  d2i_PKCS8_PRIV_KEY_INFO_bio_procname = 'd2i_PKCS8_PRIV_KEY_INFO_bio';
  i2d_PKCS8_PRIV_KEY_INFO_bio_procname = 'i2d_PKCS8_PRIV_KEY_INFO_bio';
  i2d_PKCS8PrivateKeyInfo_bio_procname = 'i2d_PKCS8PrivateKeyInfo_bio';
  i2d_PrivateKey_bio_procname = 'i2d_PrivateKey_bio';
  d2i_PrivateKey_bio_procname = 'd2i_PrivateKey_bio';
  d2i_PrivateKey_ex_bio_procname = 'd2i_PrivateKey_ex_bio';
  i2d_PUBKEY_bio_procname = 'i2d_PUBKEY_bio';
  d2i_PUBKEY_bio_procname = 'd2i_PUBKEY_bio';

  X509_dup_procname = 'X509_dup';
  X509_ATTRIBUTE_dup_procname = 'X509_ATTRIBUTE_dup';
  X509_EXTENSION_dup_procname = 'X509_EXTENSION_dup';
  X509_CRL_dup_procname = 'X509_CRL_dup';
  X509_REVOKED_dup_procname = 'X509_REVOKED_dup';
  X509_REQ_dup_procname = 'X509_REQ_dup';
  X509_ALGOR_dup_procname = 'X509_ALGOR_dup';
  X509_ALGOR_set0_procname = 'X509_ALGOR_set0';
  X509_ALGOR_get0_procname = 'X509_ALGOR_get0';
  X509_ALGOR_set_md_procname = 'X509_ALGOR_set_md';
  X509_ALGOR_cmp_procname = 'X509_ALGOR_cmp';

  X509_NAME_dup_procname = 'X509_NAME_dup';
  X509_NAME_ENTRY_dup_procname = 'X509_NAME_ENTRY_dup';

  X509_cmp_time_procname = 'X509_cmp_time';
  X509_cmp_current_time_procname = 'X509_cmp_current_time';
  X509_cmp_timeframe_procname = 'X509_cmp_timeframe';

  X509_check_certificate_times_procname = 'X509_check_certificate_times';

  X509_time_adj_procname = 'X509_time_adj';
  X509_time_adj_ex_procname = 'X509_time_adj_ex';
  X509_gmtime_adj_procname = 'X509_gmtime_adj';

  X509_get_default_cert_area_procname = 'X509_get_default_cert_area';
  X509_get_default_cert_dir_procname = 'X509_get_default_cert_dir';
  X509_get_default_cert_file_procname = 'X509_get_default_cert_file';
  X509_get_default_cert_dir_env_procname = 'X509_get_default_cert_dir_env';
  X509_get_default_cert_file_env_procname = 'X509_get_default_cert_file_env';
  X509_get_default_private_dir_procname = 'X509_get_default_private_dir';

  X509_to_X509_REQ_procname = 'X509_to_X509_REQ';
  X509_REQ_to_X509_procname = 'X509_REQ_to_X509';

  X509_ALGOR_new_procname = 'X509_ALGOR_new';
  X509_ALGOR_free_procname = 'X509_ALGOR_free';
  d2i_X509_ALGOR_procname = 'd2i_X509_ALGOR';
  i2d_X509_ALGOR_procname = 'i2d_X509_ALGOR';
  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_ALGORS, X509_ALGORS, X509_ALGORS)
  X509_VAL_new_procname = 'X509_VAL_new';
  X509_VAL_free_procname = 'X509_VAL_free';
  d2i_X509_VAL_procname = 'd2i_X509_VAL';
  i2d_X509_VAL_procname = 'i2d_X509_VAL';

  X509_PUBKEY_new_procname = 'X509_PUBKEY_new';
  X509_PUBKEY_free_procname = 'X509_PUBKEY_free';
  d2i_X509_PUBKEY_procname = 'd2i_X509_PUBKEY';
  i2d_X509_PUBKEY_procname = 'i2d_X509_PUBKEY';

  X509_PUBKEY_set_procname = 'X509_PUBKEY_set';
  X509_PUBKEY_get0_procname = 'X509_PUBKEY_get0'; {introduced 1.1.0}
  X509_PUBKEY_get_procname = 'X509_PUBKEY_get';
//  function X509_get_pubkey_parameters(pkey: PEVP_PKEY; chain: P STACK_OF(X509)): TIdC_INT;
  X509_get_pathlen_procname = 'X509_get_pathlen'; {introduced 1.1.0}
  i2d_PUBKEY_procname = 'i2d_PUBKEY';
  d2i_PUBKEY_procname = 'd2i_PUBKEY';

  i2d_RSA_PUBKEY_procname = 'i2d_RSA_PUBKEY';
  d2i_RSA_PUBKEY_procname = 'd2i_RSA_PUBKEY';

  i2d_DSA_PUBKEY_procname = 'i2d_DSA_PUBKEY';
  d2i_DSA_PUBKEY_procname = 'd2i_DSA_PUBKEY';

  i2d_EC_PUBKEY_procname = 'i2d_EC_PUBKEY';
  d2i_EC_PUBKEY_procname = 'd2i_EC_PUBKEY';

  X509_SIG_new_procname = 'X509_SIG_new';
  X509_SIG_free_procname = 'X509_SIG_free';
  d2i_X509_SIG_procname = 'd2i_X509_SIG';
  i2d_X509_SIG_procname = 'i2d_X509_SIG';
  X509_SIG_get0_procname = 'X509_SIG_get0'; {introduced 1.1.0}
  X509_SIG_getm_procname = 'X509_SIG_getm'; {introduced 1.1.0}

  X509_REQ_INFO_new_procname = 'X509_REQ_INFO_new';
  X509_REQ_INFO_free_procname = 'X509_REQ_INFO_free';
  d2i_X509_REQ_INFO_procname = 'd2i_X509_REQ_INFO';
  i2d_X509_REQ_INFO_procname = 'i2d_X509_REQ_INFO';

  X509_REQ_new_procname = 'X509_REQ_new';
  X509_REQ_free_procname = 'X509_REQ_free';
  d2i_X509_REQ_procname = 'd2i_X509_REQ';
  i2d_X509_REQ_procname = 'i2d_X509_REQ';

  X509_ATTRIBUTE_new_procname = 'X509_ATTRIBUTE_new';
  X509_ATTRIBUTE_free_procname = 'X509_ATTRIBUTE_free';
  d2i_X509_ATTRIBUTE_procname = 'd2i_X509_ATTRIBUTE';
  i2d_X509_ATTRIBUTE_procname = 'i2d_X509_ATTRIBUTE';
  X509_ATTRIBUTE_create_procname = 'X509_ATTRIBUTE_create';

  X509_EXTENSION_new_procname = 'X509_EXTENSION_new';
  X509_EXTENSION_free_procname = 'X509_EXTENSION_free';
  d2i_X509_EXTENSION_procname = 'd2i_X509_EXTENSION';
  i2d_X509_EXTENSION_procname = 'i2d_X509_EXTENSION';
  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)

  X509_NAME_ENTRY_new_procname = 'X509_NAME_ENTRY_new';
  X509_NAME_ENTRY_free_procname = 'X509_NAME_ENTRY_free';
  d2i_X509_NAME_ENTRY_procname = 'd2i_X509_NAME_ENTRY';
  i2d_X509_NAME_ENTRY_procname = 'i2d_X509_NAME_ENTRY';

  X509_NAME_new_procname = 'X509_NAME_new';
  X509_NAME_free_procname = 'X509_NAME_free';
  d2i_X509_NAME_procname = 'd2i_X509_NAME';
  i2d_X509_NAME_procname = 'i2d_X509_NAME';

  X509_NAME_set_procname = 'X509_NAME_set';

  //DECLARE_ASN1_FUNCTIONS(X509_CINF)

  X509_new_procname = 'X509_new';
  X509_free_procname = 'X509_free';
  d2i_X509_procname = 'd2i_X509';
  i2d_X509_procname = 'i2d_X509';

  //DECLARE_ASN1_FUNCTIONS(X509_CERT_AUX)
  //
  //#define X509_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef)
  X509_set_ex_data_procname = 'X509_set_ex_data';
  X509_get_ex_data_procname = 'X509_get_ex_data';
  i2d_X509_AUX_procname = 'i2d_X509_AUX';
  d2i_X509_AUX_procname = 'd2i_X509_AUX';

  i2d_re_X509_tbs_procname = 'i2d_re_X509_tbs';

  X509_SIG_INFO_get_procname = 'X509_SIG_INFO_get'; {introduced 1.1.0}
  X509_SIG_INFO_set_procname = 'X509_SIG_INFO_set'; {introduced 1.1.0}

  X509_get_signature_info_procname = 'X509_get_signature_info'; {introduced 1.1.0}

  X509_get0_signature_procname = 'X509_get0_signature'; {introduced 1.1.0}
  X509_get_signature_nid_procname = 'X509_get_signature_nid';

  X509_trusted_procname = 'X509_trusted'; {introduced 1.1.0}
  X509_alias_set1_procname = 'X509_alias_set1';
  X509_keyid_set1_procname = 'X509_keyid_set1';
  X509_alias_get0_procname = 'X509_alias_get0';
  X509_keyid_get0_procname = 'X509_keyid_get0';
//  TIdC_INT (*X509_TRUST_set_default(TIdC_INT (*trust) (TIdC_INT, X509 *, TIdC_INT))) (TIdC_INT, X509 *,
//                                                                  TIdC_INT);
  X509_TRUST_set_procname = 'X509_TRUST_set';
  X509_add1_trust_object_procname = 'X509_add1_trust_object';
  X509_add1_reject_object_procname = 'X509_add1_reject_object';
  X509_trust_clear_procname = 'X509_trust_clear';
  X509_reject_clear_procname = 'X509_reject_clear';

  //STACK_OF(ASN1_OBJECT) *X509_get0_trust_objects(X509 *x);
  //STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x);
  //
  X509_REVOKED_new_procname = 'X509_REVOKED_new';
  X509_REVOKED_free_procname = 'X509_REVOKED_free';
  d2i_X509_REVOKED_procname = 'd2i_X509_REVOKED';
  i2d_X509_REVOKED_procname = 'i2d_X509_REVOKED';
  X509_CRL_INFO_new_procname = 'X509_CRL_INFO_new';
  X509_CRL_INFO_free_procname = 'X509_CRL_INFO_free';
  d2i_X509_CRL_INFO_procname = 'd2i_X509_CRL_INFO';
  i2d_X509_CRL_INFO_procname = 'i2d_X509_CRL_INFO';
  X509_CRL_new_procname = 'X509_CRL_new';
  X509_CRL_free_procname = 'X509_CRL_free';
  d2i_X509_CRL_procname = 'd2i_X509_CRL';
  i2d_X509_CRL_procname = 'i2d_X509_CRL';

  X509_CRL_add0_revoked_procname = 'X509_CRL_add0_revoked';
  X509_CRL_get0_by_serial_procname = 'X509_CRL_get0_by_serial';
  X509_CRL_get0_by_cert_procname = 'X509_CRL_get0_by_cert';

  X509_PKEY_new_procname = 'X509_PKEY_new';
  X509_PKEY_free_procname = 'X509_PKEY_free';

  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKI)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKAC)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)

  X509_INFO_new_procname = 'X509_INFO_new';
  X509_INFO_free_procname = 'X509_INFO_free';
  X509_NAME_oneline_procname = 'X509_NAME_oneline';

//  function ASN1_verify(i2d: Pi2d_of_void; algor1: PX509_ALGOR;
//    signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT;

//  TIdC_INT ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
//                  unsigned char *md, unsigned TIdC_INT *len);

//  TIdC_INT ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1,
//                X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
//                char *data, EVP_PKEY *pkey, const EVP_MD *type);

  ASN1_item_digest_procname = 'ASN1_item_digest';

  ASN1_item_verify_procname = 'ASN1_item_verify';

  ASN1_item_sign_procname = 'ASN1_item_sign';
  ASN1_item_sign_ctx_procname = 'ASN1_item_sign_ctx';

  X509_get_version_procname = 'X509_get_version'; {introduced 1.1.0}
  X509_set_version_procname = 'X509_set_version';
  X509_set_serialNumber_procname = 'X509_set_serialNumber';
  X509_get_serialNumber_procname = 'X509_get_serialNumber';
  X509_get0_serialNumber_procname = 'X509_get0_serialNumber'; {introduced 1.1.0}
  X509_set_issuer_name_procname = 'X509_set_issuer_name';
  X509_get_issuer_name_procname = 'X509_get_issuer_name';
  X509_set_subject_name_procname = 'X509_set_subject_name';
  X509_get_subject_name_procname = 'X509_get_subject_name';
  X509_get0_notBefore_procname = 'X509_get0_notBefore';  {introduced 1.1.0}
  X509_getm_notBefore_procname = 'X509_getm_notBefore'; {introduced 1.1.0}
  X509_set1_notBefore_procname = 'X509_set1_notBefore'; {introduced 1.1.0}
  X509_get0_notAfter_procname = 'X509_get0_notAfter';  {introduced 1.1.0}
  X509_getm_notAfter_procname = 'X509_getm_notAfter'; {introduced 1.1.0}
  X509_set1_notAfter_procname = 'X509_set1_notAfter'; {introduced 1.1.0}
  X509_set_pubkey_procname = 'X509_set_pubkey';
  X509_up_ref_procname = 'X509_up_ref'; {introduced 1.1.0}
  X509_get_signature_type_procname = 'X509_get_signature_type'; {introduced 1.1.0}

  (*
   * This one is only used so that a binary form can output, as in
   * i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &buf)
   *)
  X509_get_X509_PUBKEY_procname = 'X509_get_X509_PUBKEY'; {introduced 1.1.0}
//  const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x);
  X509_get0_uids_procname = 'X509_get0_uids'; {introduced 1.1.0}
  X509_get0_tbs_sigalg_procname = 'X509_get0_tbs_sigalg'; {introduced 1.1.0}

  X509_get0_pubkey_procname = 'X509_get0_pubkey'; {introduced 1.1.0}
  X509_get_pubkey_procname = 'X509_get_pubkey';
  X509_get0_pubkey_bitstr_procname = 'X509_get0_pubkey_bitstr';
  X509_certificate_type_procname = 'X509_certificate_type';

  X509_REQ_get_version_procname = 'X509_REQ_get_version'; {introduced 1.1.0}
  X509_REQ_set_version_procname = 'X509_REQ_set_version';
  X509_REQ_get_subject_name_procname = 'X509_REQ_get_subject_name'; {introduced 1.1.0}
  X509_REQ_set_subject_name_procname = 'X509_REQ_set_subject_name';
  X509_REQ_get0_signature_procname = 'X509_REQ_get0_signature'; {introduced 1.1.0} 
  X509_REQ_get_signature_nid_procname = 'X509_REQ_get_signature_nid'; {introduced 1.1.0}
  i2d_re_X509_REQ_tbs_procname = 'i2d_re_X509_REQ_tbs'; {introduced 1.1.0}
  X509_REQ_set_pubkey_procname = 'X509_REQ_set_pubkey';
  X509_REQ_get_pubkey_procname = 'X509_REQ_get_pubkey';
  X509_REQ_get0_pubkey_procname = 'X509_REQ_get0_pubkey'; {introduced 1.1.0}
  X509_REQ_get_X509_PUBKEY_procname = 'X509_REQ_get_X509_PUBKEY'; {introduced 1.1.0}
  X509_REQ_extension_nid_procname = 'X509_REQ_extension_nid';
  X509_REQ_get_extension_nids_procname = 'X509_REQ_get_extension_nids';
  X509_REQ_set_extension_nids_procname = 'X509_REQ_set_extension_nids';
  X509_REQ_get_extensions_procname = 'X509_REQ_get_extensions';
  X509_REQ_add_extensions_nid_procname = 'X509_REQ_add_extensions_nid';
  X509_REQ_add_extensions_procname = 'X509_REQ_add_extensions';
  X509_REQ_get_attr_count_procname = 'X509_REQ_get_attr_count';
  X509_REQ_get_attr_by_NID_procname = 'X509_REQ_get_attr_by_NID';
  X509_REQ_get_attr_by_OBJ_procname = 'X509_REQ_get_attr_by_OBJ';
  X509_REQ_get_attr_procname = 'X509_REQ_get_attr';
  X509_REQ_delete_attr_procname = 'X509_REQ_delete_attr';
  X509_REQ_add1_attr_procname = 'X509_REQ_add1_attr';
  X509_REQ_add1_attr_by_OBJ_procname = 'X509_REQ_add1_attr_by_OBJ';
  X509_REQ_add1_attr_by_NID_procname = 'X509_REQ_add1_attr_by_NID';
  X509_REQ_add1_attr_by_txt_procname = 'X509_REQ_add1_attr_by_txt';

  X509_CRL_set_version_procname = 'X509_CRL_set_version';
  X509_CRL_set_issuer_name_procname = 'X509_CRL_set_issuer_name';
  X509_CRL_set1_lastUpdate_procname = 'X509_CRL_set1_lastUpdate'; {introduced 1.1.0}
  X509_CRL_set1_nextUpdate_procname = 'X509_CRL_set1_nextUpdate'; {introduced 1.1.0}
  X509_CRL_sort_procname = 'X509_CRL_sort';
  X509_CRL_up_ref_procname = 'X509_CRL_up_ref'; {introduced 1.1.0}

  X509_CRL_get_version_procname = 'X509_CRL_get_version'; {introduced 1.1.0}
  X509_CRL_get0_lastUpdate_procname = 'X509_CRL_get0_lastUpdate'; {introduced 1.1.0}
  X509_CRL_get0_nextUpdate_procname = 'X509_CRL_get0_nextUpdate'; {introduced 1.1.0}
  X509_CRL_get_issuer_procname = 'X509_CRL_get_issuer'; {introduced 1.1.0}
  X509_CRL_get0_extensions_procname = 'X509_CRL_get0_extensions';
  X509_CRL_get_REVOKED_procname = 'X509_CRL_get_REVOKED';
  X509_CRL_get0_signature_procname = 'X509_CRL_get0_signature'; {introduced 1.1.0}
  X509_CRL_get_signature_nid_procname = 'X509_CRL_get_signature_nid'; {introduced 1.1.0}
  i2d_re_X509_CRL_tbs_procname = 'i2d_re_X509_CRL_tbs'; {introduced 1.1.0}

  X509_REVOKED_get0_serialNumber_procname = 'X509_REVOKED_get0_serialNumber'; {introduced 1.1.0}
  X509_REVOKED_set_serialNumber_procname = 'X509_REVOKED_set_serialNumber';
  X509_REVOKED_get0_revocationDate_procname = 'X509_REVOKED_get0_revocationDate'; {introduced 1.1.0}
  X509_REVOKED_set_revocationDate_procname = 'X509_REVOKED_set_revocationDate';
  X509_REVOKED_get0_extensions_procname = 'X509_REVOKED_get0_extensions';

  X509_CRL_diff_procname = 'X509_CRL_diff';

  X509_REQ_check_private_key_procname = 'X509_REQ_check_private_key';

  X509_check_private_key_procname = 'X509_check_private_key';
  //TIdC_INT X509_chain_check_suiteb(TIdC_INT *perror_depth,
  //                            X509 *x, STACK_OF(X509) *chain,
  //                            unsigned TIdC_LONG flags);
  X509_CRL_check_suiteb_procname = 'X509_CRL_check_suiteb';
  //STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *chain);

  X509_issuer_and_serial_cmp_procname = 'X509_issuer_and_serial_cmp';
  X509_issuer_and_serial_hash_procname = 'X509_issuer_and_serial_hash';

  X509_issuer_name_cmp_procname = 'X509_issuer_name_cmp';
  X509_issuer_name_hash_procname = 'X509_issuer_name_hash';

  X509_subject_name_cmp_procname = 'X509_subject_name_cmp';
  X509_subject_name_hash_procname = 'X509_subject_name_hash';

  X509_cmp_procname = 'X509_cmp';
  X509_NAME_cmp_procname = 'X509_NAME_cmp';
  X509_NAME_hash_procname = 'X509_NAME_hash'; {removed 3.0.0}
  X509_NAME_hash_old_procname = 'X509_NAME_hash_old';

  X509_CRL_cmp_procname = 'X509_CRL_cmp';
  X509_CRL_match_procname = 'X509_CRL_match';
  X509_aux_print_procname = 'X509_aux_print'; {introduced 1.1.0}
  //# ifndef OPENSSL_NO_STDIO
  //TIdC_INT X509_print_ex_fp(FILE *bp, X509 *x, unsigned TIdC_LONG nmflag,
  //                     unsigned TIdC_LONG cflag);
  //TIdC_INT X509_print_fp(FILE *bp, X509 *x);
  //TIdC_INT X509_CRL_print_fp(FILE *bp, X509_CRL *x);
  //TIdC_INT X509_REQ_print_fp(FILE *bp, X509_REQ *req);
  //TIdC_INT X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, TIdC_INT indent,
  //                          unsigned TIdC_LONG flags);
  //# endif

  X509_NAME_print_procname = 'X509_NAME_print';
  X509_NAME_print_ex_procname = 'X509_NAME_print_ex';
  X509_print_ex_procname = 'X509_print_ex';
  X509_print_procname = 'X509_print';
  X509_ocspid_print_procname = 'X509_ocspid_print';
  X509_CRL_print_ex_procname = 'X509_CRL_print_ex'; {introduced 1.1.0}
  X509_CRL_print_procname = 'X509_CRL_print';
  X509_REQ_print_ex_procname = 'X509_REQ_print_ex';
  X509_REQ_print_procname = 'X509_REQ_print';

  X509_NAME_entry_count_procname = 'X509_NAME_entry_count';
  X509_NAME_get_text_by_NID_procname = 'X509_NAME_get_text_by_NID';
  X509_NAME_get_text_by_OBJ_procname = 'X509_NAME_get_text_by_OBJ';

  (*
   * NOTE: you should be passing -1, not 0 as lastpos. The functions that use
   * lastpos, search after that position on.
   *)
  X509_NAME_get_index_by_NID_procname = 'X509_NAME_get_index_by_NID';
  X509_NAME_get_index_by_OBJ_procname = 'X509_NAME_get_index_by_OBJ';
  X509_NAME_get_entry_procname = 'X509_NAME_get_entry';
  X509_NAME_delete_entry_procname = 'X509_NAME_delete_entry';
  X509_NAME_add_entry_procname = 'X509_NAME_add_entry';
  X509_NAME_add_entry_by_OBJ_procname = 'X509_NAME_add_entry_by_OBJ';
  X509_NAME_add_entry_by_NID_procname = 'X509_NAME_add_entry_by_NID';
  X509_NAME_ENTRY_create_by_txt_procname = 'X509_NAME_ENTRY_create_by_txt';
  X509_NAME_ENTRY_create_by_NID_procname = 'X509_NAME_ENTRY_create_by_NID';
  X509_NAME_add_entry_by_txt_procname = 'X509_NAME_add_entry_by_txt';
  X509_NAME_ENTRY_create_by_OBJ_procname = 'X509_NAME_ENTRY_create_by_OBJ';
  X509_NAME_ENTRY_set_object_procname = 'X509_NAME_ENTRY_set_object';
  X509_NAME_ENTRY_set_data_procname = 'X509_NAME_ENTRY_set_data';
  X509_NAME_ENTRY_get_object_procname = 'X509_NAME_ENTRY_get_object';
  X509_NAME_ENTRY_get_data_procname = 'X509_NAME_ENTRY_get_data';
  X509_NAME_ENTRY_set_procname = 'X509_NAME_ENTRY_set'; {introduced 1.1.0}

  X509_NAME_get0_der_procname = 'X509_NAME_get0_der'; {introduced 1.1.0}

  //TIdC_INT X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x);
  //TIdC_INT X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x,
  //                          TIdC_INT nid, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *x,
  //                          const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *x,
  //                               TIdC_INT crit, TIdC_INT lastpos);
  //X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x,
  //                                         X509_EXTENSION *ex, TIdC_INT loc);

  X509_get_ext_count_procname = 'X509_get_ext_count';
  X509_get_ext_by_NID_procname = 'X509_get_ext_by_NID';
  X509_get_ext_by_OBJ_procname = 'X509_get_ext_by_OBJ';
  X509_get_ext_by_critical_procname = 'X509_get_ext_by_critical';
  X509_get_ext_procname = 'X509_get_ext';
  X509_delete_ext_procname = 'X509_delete_ext';
  X509_add_ext_procname = 'X509_add_ext';
  X509_get_ext_d2i_procname = 'X509_get_ext_d2i';
  X509_add1_ext_i2d_procname = 'X509_add1_ext_i2d';

  X509_CRL_get_ext_count_procname = 'X509_CRL_get_ext_count';
  X509_CRL_get_ext_by_NID_procname = 'X509_CRL_get_ext_by_NID';
  X509_CRL_get_ext_by_OBJ_procname = 'X509_CRL_get_ext_by_OBJ';
  X509_CRL_get_ext_by_critical_procname = 'X509_CRL_get_ext_by_critical';
  X509_CRL_get_ext_procname = 'X509_CRL_get_ext';
  X509_CRL_delete_ext_procname = 'X509_CRL_delete_ext';
  X509_CRL_add_ext_procname = 'X509_CRL_add_ext';
  X509_CRL_get_ext_d2i_procname = 'X509_CRL_get_ext_d2i';
  X509_CRL_add1_ext_i2d_procname = 'X509_CRL_add1_ext_i2d';

  X509_REVOKED_get_ext_count_procname = 'X509_REVOKED_get_ext_count';
  X509_REVOKED_get_ext_by_NID_procname = 'X509_REVOKED_get_ext_by_NID';
  X509_REVOKED_get_ext_by_OBJ_procname = 'X509_REVOKED_get_ext_by_OBJ';
  X509_REVOKED_get_ext_by_critical_procname = 'X509_REVOKED_get_ext_by_critical';
  X509_REVOKED_get_ext_procname = 'X509_REVOKED_get_ext';
  X509_REVOKED_delete_ext_procname = 'X509_REVOKED_delete_ext';
  X509_REVOKED_add_ext_procname = 'X509_REVOKED_add_ext';
  X509_REVOKED_get_ext_d2i_procname = 'X509_REVOKED_get_ext_d2i';
  X509_REVOKED_add1_ext_i2d_procname = 'X509_REVOKED_add1_ext_i2d';

  X509_EXTENSION_create_by_NID_procname = 'X509_EXTENSION_create_by_NID';
  X509_EXTENSION_create_by_OBJ_procname = 'X509_EXTENSION_create_by_OBJ';
  X509_EXTENSION_set_object_procname = 'X509_EXTENSION_set_object';
  X509_EXTENSION_set_critical_procname = 'X509_EXTENSION_set_critical';
  X509_EXTENSION_set_data_procname = 'X509_EXTENSION_set_data';
  X509_EXTENSION_get_object_procname = 'X509_EXTENSION_get_object';
  X509_EXTENSION_get_data_procname = 'X509_EXTENSION_get_data';
  X509_EXTENSION_get_critical_procname = 'X509_EXTENSION_get_critical';

  //TIdC_INT X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
  //TIdC_INT X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT nid,
  //                           TIdC_INT lastpos);
  //TIdC_INT X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk,
  //                           const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //X509_ATTRIBUTE *X509at_get_attr(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
  //                                           X509_ATTRIBUTE *attr);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const ASN1_OBJECT *obj,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, TIdC_INT nid, TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const PIdAnsiChar *attrname,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //void *X509at_get0_data_by_OBJ(STACK_OF(X509_ATTRIBUTE) *x,
  //                              const ASN1_OBJECT *obj, TIdC_INT lastpos, TIdC_INT type);
  X509_ATTRIBUTE_create_by_NID_procname = 'X509_ATTRIBUTE_create_by_NID';
  X509_ATTRIBUTE_create_by_OBJ_procname = 'X509_ATTRIBUTE_create_by_OBJ';
  X509_ATTRIBUTE_create_by_txt_procname = 'X509_ATTRIBUTE_create_by_txt';
  X509_ATTRIBUTE_set1_object_procname = 'X509_ATTRIBUTE_set1_object';
  X509_ATTRIBUTE_set1_data_procname = 'X509_ATTRIBUTE_set1_data';
  X509_ATTRIBUTE_get0_data_procname = 'X509_ATTRIBUTE_get0_data';
  X509_ATTRIBUTE_count_procname = 'X509_ATTRIBUTE_count';
  X509_ATTRIBUTE_get0_object_procname = 'X509_ATTRIBUTE_get0_object';
  X509_ATTRIBUTE_get0_type_procname = 'X509_ATTRIBUTE_get0_type';

  EVP_PKEY_get_attr_count_procname = 'EVP_PKEY_get_attr_count';
  EVP_PKEY_get_attr_by_NID_procname = 'EVP_PKEY_get_attr_by_NID';
  EVP_PKEY_get_attr_by_OBJ_procname = 'EVP_PKEY_get_attr_by_OBJ';
  EVP_PKEY_get_attr_procname = 'EVP_PKEY_get_attr';
  EVP_PKEY_delete_attr_procname = 'EVP_PKEY_delete_attr';
  EVP_PKEY_add1_attr_procname = 'EVP_PKEY_add1_attr';
  EVP_PKEY_add1_attr_by_OBJ_procname = 'EVP_PKEY_add1_attr_by_OBJ';
  EVP_PKEY_add1_attr_by_NID_procname = 'EVP_PKEY_add1_attr_by_NID';
  EVP_PKEY_add1_attr_by_txt_procname = 'EVP_PKEY_add1_attr_by_txt';

  X509_verify_cert_procname = 'X509_verify_cert';

  (* lookup a cert from a X509 STACK *)
//  function X509_find_by_issuer_and_serial(sk: P STACK_OF(X509); name: PX509_NAME; serial: PASN1_INTEGER): PX509;
//  X509 *X509_find_by_subject(STACK_OF(X509) *sk, X509_NAME *name);

  //DECLARE_ASN1_FUNCTIONS(PBEPARAM)
  //DECLARE_ASN1_FUNCTIONS(PBE2PARAM)
  //DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)
  //#ifndef OPENSSL_NO_SCRYPT
  //DECLARE_ASN1_FUNCTIONS(SCRYPT_PARAMS)
  //#endif

  PKCS5_pbe_set0_algor_procname = 'PKCS5_pbe_set0_algor';

  PKCS5_pbe_set_procname = 'PKCS5_pbe_set';
  PKCS5_pbe2_set_procname = 'PKCS5_pbe2_set';
  PKCS5_pbe2_set_iv_procname = 'PKCS5_pbe2_set_iv';

  PKCS5_pbe2_set_scrypt_procname = 'PKCS5_pbe2_set_scrypt'; {introduced 1.1.0}

  PKCS5_pbkdf2_set_procname = 'PKCS5_pbkdf2_set';

  (* PKCS#8 utilities *)

  //DECLARE_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)

  EVP_PKCS82PKEY_procname = 'EVP_PKCS82PKEY';
  EVP_PKEY2PKCS8_procname = 'EVP_PKEY2PKCS8';

  PKCS8_pkey_set0_procname = 'PKCS8_pkey_set0';
  PKCS8_pkey_get0_procname = 'PKCS8_pkey_get0';

  //const STACK_OF(X509_ATTRIBUTE) *
  //PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8);
  PKCS8_pkey_add1_attr_by_NID_procname = 'PKCS8_pkey_add1_attr_by_NID'; {introduced 1.1.0}

  X509_PUBKEY_set0_param_procname = 'X509_PUBKEY_set0_param';
  X509_PUBKEY_get0_param_procname = 'X509_PUBKEY_get0_param';

  X509_check_trust_procname = 'X509_check_trust';
  X509_TRUST_get_count_procname = 'X509_TRUST_get_count';
  X509_TRUST_get0_procname = 'X509_TRUST_get0';
  X509_TRUST_get_by_id_procname = 'X509_TRUST_get_by_id';
//  TIdC_INT X509_TRUST_add(TIdC_INT id, TIdC_INT flags, TIdC_INT (*ck) (X509_TRUST *, X509 *, TIdC_INT),
//                     const PIdAnsiChar *name, TIdC_INT arg1, void *arg2);
  X509_TRUST_cleanup_procname = 'X509_TRUST_cleanup';
  X509_TRUST_get_flags_procname = 'X509_TRUST_get_flags';
  X509_TRUST_get0_name_procname = 'X509_TRUST_get0_name';
  X509_TRUST_get_trust_procname = 'X509_TRUST_get_trust';

//  unsigned long X509_NAME_hash_ex(const X509_NAME *x, OSSL_LIB_CTX *libctx,
//                                const char *propq, int *ok);
  X509_NAME_hash_ex_procname = 'X509_NAME_hash_ex'; {introduced 3.0.0}


  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSUnusedParamOff.inc}
//# define X509_NAME_hash(x) X509_NAME_hash_ex(x, NULL, NULL, NULL)
function  _X509_NAME_hash(x: PX509_NAME): TIdC_ULONG; cdecl;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := X509_NAME_hash_ex(x,nil,nil,nil);
end;

function FC_d2i_PrivateKey_ex_bio(bp : PBIO; a :PPEVP_PKEY;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar): PEVP_PKEY;  cdecl;
begin
  Result := d2i_PrivateKey_bio(bp,a);
end;

{$I TaurusTLSUnusedParamOn.inc}
{/forward_compatibility}
  {$I TaurusTLSNoRetValOff.inc}

procedure  ERR_X509_CRL_set_default_method(const meth: PX509_CRL_METHOD); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_default_method_procname);
end;


//  function X509_CRL_METHOD_new(crl_init: function(crl: X509_CRL): TIdC_INT;
//    crl_free: function(crl: PX509_CRL): TIdC_INT;
//    crl_lookup: function(crl: PX509_CRL; ret: PPX509_REVOKED; ser: PASN1_INTEGER; issuer: PX509_NAME): TIdC_INT;
//    crl_verify: function(crl: PX509_CRL, pk: PEVP_PKEY): TIdC_INT): PX509_CRL_METHOD;
procedure  ERR_X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_METHOD_free_procname);
end;



procedure  ERR_X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_meth_data_procname);
end;


function  ERR_X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_meth_data_procname);
end;



function  ERR_X509_verify_cert_error_string(n: TIdC_LONG): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_verify_cert_error_string_procname);
end;



function  ERR_X509_verify(a: PX509; r: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_verify_procname);
end;



function  ERR_X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_verify_procname);
end;


function  ERR_X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_verify_procname);
end;


function  ERR_NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_verify_procname);
end;



function  ERR_NETSCAPE_SPKI_b64_decode(const _str: PIdAnsiChar; len: TIdC_INT): PNETSCAPE_SPKI;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_b64_decode_procname);
end;


function  ERR_NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_b64_encode_procname);
end;


function  ERR_NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_get_pubkey_procname);
end;


function  ERR_NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_set_pubkey_procname);
end;



function  ERR_NETSCAPE_SPKI_print(out_: PBIO; spki: PNETSCAPE_SPKI): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_print_procname);
end;



function  ERR_X509_signature_dump(bp: PBIO; const sig: PASN1_STRING; indent: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_signature_dump_procname);
end;

function  ERR_X509_signature_print(bp: PBIO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_signature_print_procname);
end;

function  ERR_X509_sign(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_sign_procname);
end;

function  ERR_X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_sign_ctx_procname);
end;

function  ERR_X509_http_nbio(rctx: POCSP_REQ_CTX; pcert: PPX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_http_nbio_procname);
end;

function  ERR_X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_sign_procname);
end;

function  ERR_X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_sign_ctx_procname);
end;

function  ERR_X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_sign_procname);
end;

function  ERR_X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_sign_ctx_procname);
end;

function  ERR_X509_CRL_http_nbio(rctx: POCSP_REQ_CTX; pcrl: PPX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_http_nbio_procname);
end;

function  ERR_NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_sign_procname);
end;

function  ERR_X509_pubkey_digest(const data: PX509; const type_: PEVP_MD; md: PByte; len: PIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_pubkey_digest_procname);
end;

function  ERR_X509_digest(const data: PX509; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_digest_procname);
end;

function  ERR_X509_CRL_digest(const data: PX509_CRL; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_digest_procname);
end;

function  ERR_X509_REQ_digest(const data: PX509_REQ; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_digest_procname);
end;

function  ERR_X509_NAME_digest(const data: PX509_NAME; const type_: PEVP_MD; md: PByte; var len: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_digest_procname);
end;

  //# ifndef OPENSSL_NO_STDIO
  //X509 *d2i_X509_fp(FILE *fp, X509 **x509);
  //TIdC_INT i2d_X509_fp(FILE *fp, X509 *x509);
  //X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl);
  //TIdC_INT i2d_X509_CRL_fp(FILE *fp, X509_CRL *crl);
  //X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req);
  //TIdC_INT i2d_X509_REQ_fp(FILE *fp, X509_REQ *req);
  //#  ifndef OPENSSL_NO_RSA
  //RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa);
  //RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
  //TIdC_INT i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa);
  //#  endif
  //#  ifndef OPENSSL_NO_DSA
  //DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
  //DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
  //TIdC_INT i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
  //#  endif
  //#  ifndef OPENSSL_NO_EC
  //EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
  //EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
  //TIdC_INT i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
  //#  endif
  //X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8);
  //TIdC_INT i2d_PKCS8_fp(FILE *fp, X509_SIG *p8);
  //PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
  //                                                PKCS8_PRIV_KEY_INFO **p8inf);
  //TIdC_INT i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf);
  //TIdC_INT i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
  //TIdC_INT i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
  //TIdC_INT i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
  //EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
  //# endif

function  ERR_d2i_X509_bio(bp: PBIO; x509: PPX509): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_bio_procname);
end;

function  ERR_i2d_X509_bio(bp: PBIO; x509: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_bio_procname);
end;

function  ERR_d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CRL_bio_procname);
end;

function  ERR_i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CRL_bio_procname);
end;

function  ERR_d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REQ_bio_procname);
end;

function  ERR_i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REQ_bio_procname);
end;

function  ERR_d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPrivateKey_bio_procname);
end;

function  ERR_i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPrivateKey_bio_procname);
end;

function  ERR_d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPublicKey_bio_procname);
end;

function  ERR_i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPublicKey_bio_procname);
end;

function  ERR_d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSA_PUBKEY_bio_procname);
end;

function  ERR_i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSA_PUBKEY_bio_procname);
end;

function  ERR_d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSA_PUBKEY_bio_procname);
end;

function  ERR_i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSA_PUBKEY_bio_procname);
end;

function  ERR_d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSAPrivateKey_bio_procname);
end;

function  ERR_i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSAPrivateKey_bio_procname);
end;

function  ERR_d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_EC_PUBKEY_bio_procname);
end;

function  ERR_i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_EC_PUBKEY_bio_procname);
end;

function  ERR_d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECPrivateKey_bio_procname);
end;


function  ERR_i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECPrivateKey_bio_procname);
end;



function  ERR_d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8_bio_procname);
end;


function  ERR_i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8_bio_procname);
end;


function  ERR_d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8_PRIV_KEY_INFO_bio_procname);
end;


function  ERR_i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8_PRIV_KEY_INFO_bio_procname);
end;


function  ERR_i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKeyInfo_bio_procname);
end;


function  ERR_i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PrivateKey_bio_procname);
end;


function  ERR_d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PrivateKey_bio_procname);
end;

function ERR_d2i_PrivateKey_ex_bio(bp : PBIO; a :PPEVP_PKEY;
    libctx : POSSL_LIB_CTX; const propq : PIdAnsiChar): PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PrivateKey_ex_bio_procname);
end;


function  ERR_i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PUBKEY_bio_procname);
end;


function  ERR_d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_bio_procname);
end;



function  ERR_X509_dup(x509: PX509): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_dup_procname);
end;


function  ERR_X509_ATTRIBUTE_dup(xa: PX509_ATTRIBUTE): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_dup_procname);
end;


function  ERR_X509_EXTENSION_dup(ex: PX509_EXTENSION): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_dup_procname);
end;


function  ERR_X509_CRL_dup(crl: PX509_CRL): PX509_CRL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_dup_procname);
end;


function  ERR_X509_REVOKED_dup(rev: PX509_REVOKED): PX509_REVOKED;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_dup_procname);
end;


function  ERR_X509_REQ_dup(req: PX509_REQ): PX509_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_dup_procname);
end;


function  ERR_X509_ALGOR_dup(xn: PX509_ALGOR): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_dup_procname);
end;


function  ERR_X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_set0_procname);
end;


procedure  ERR_X509_ALGOR_get0(const paobj: PPASN1_OBJECT; pptype: PIdC_INT; const ppval: PPointer; const algor: PX509_ALGOR);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_get0_procname);
end;


procedure  ERR_X509_ALGOR_set_md(alg: PX509_ALGOR; const md: PEVP_MD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_set_md_procname);
end;


function  ERR_X509_ALGOR_cmp(const a: PX509_ALGOR; const b: PX509_ALGOR): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_cmp_procname);
end;



function  ERR_X509_NAME_dup(xn: PX509_NAME): PX509_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_dup_procname);
end;


function  ERR_X509_NAME_ENTRY_dup(ne: PX509_NAME_ENTRY): PX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_dup_procname);
end;



function  ERR_X509_cmp_time(const s: PASN1_TIME; t: PIdC_TIMET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_time_procname);
end;


function  ERR_X509_cmp_current_time(const s: PASN1_TIME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_current_time_procname);
end;

function ERR_X509_cmp_timeframe(const vpm : PX509_VERIFY_PARAM; start, _end : PASN1_TIME ) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_timeframe_procname);
end;

function ERR_X509_check_certificate_times(const vpm : PX509_VERIFY_PARAM; X : PX509; _error : TIdC_INT) : TIdC_INT cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_certificate_times_procname);
end;

function  ERR_X509_time_adj(s: PASN1_TIME; adj: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_time_adj_procname);
end;


function  ERR_X509_time_adj_ex(s: PASN1_TIME; offset_day: TIdC_INT; offset_sec: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_time_adj_ex_procname);
end;


function  ERR_X509_gmtime_adj(s: PASN1_TIME; adj: TIdC_LONG): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_gmtime_adj_procname);
end;



function  ERR_X509_get_default_cert_area: PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_area_procname);
end;


function  ERR_X509_get_default_cert_dir: PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_dir_procname);
end;


function  ERR_X509_get_default_cert_file: PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_file_procname);
end;


function  ERR_X509_get_default_cert_dir_env: PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_dir_env_procname);
end;


function  ERR_X509_get_default_cert_file_env: PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_file_env_procname);
end;


function  ERR_X509_get_default_private_dir: PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_private_dir_procname);
end;



function  ERR_X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; const md: PEVP_MD): PX509_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_to_X509_REQ_procname);
end;


function  ERR_X509_REQ_to_X509(r: PX509_REQ; days: TIdC_INT; pkey: PEVP_PKEY): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_to_X509_procname);
end;



function  ERR_X509_ALGOR_new: PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_new_procname);
end;


procedure  ERR_X509_ALGOR_free(v1: PX509_ALGOR);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_free_procname);
end;


function  ERR_d2i_X509_ALGOR(a: PPX509_ALGOR; const in_: PPByte; len: TIdC_LONG): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ALGOR_procname);
end;


function  ERR_i2d_X509_ALGOR(a: PX509_ALGOR; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ALGOR_procname);
end;


  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_ALGORS, X509_ALGORS, X509_ALGORS)
function  ERR_X509_VAL_new: PX509_VAL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VAL_new_procname);
end;


procedure  ERR_X509_VAL_free(v1: PX509_VAL);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VAL_free_procname);
end;


function  ERR_d2i_X509_VAL(a: PPX509_VAL; const in_: PPByte; len: TIdC_LONG): PX509_VAL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_VAL_procname);
end;


function  ERR_i2d_X509_VAL(a: PX509_VAL; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_VAL_procname);
end;



function  ERR_X509_PUBKEY_new: PX509_PUBKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_new_procname);
end;


procedure  ERR_X509_PUBKEY_free(v1: PX509_PUBKEY);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_free_procname);
end;


function  ERR_d2i_X509_PUBKEY(a: PPX509_PUBKEY; const in_: PPByte; len: TIdC_LONG): PX509_PUBKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_PUBKEY_procname);
end;


function  ERR_i2d_X509_PUBKEY(a: PX509_PUBKEY; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_PUBKEY_procname);
end;



function  ERR_X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_set_procname);
end;


function  ERR_X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_get0_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_get_procname);
end;


//  function X509_get_pubkey_parameters(pkey: PEVP_PKEY; chain: P STACK_OF(X509)): TIdC_INT;
function  ERR_X509_get_pathlen(x: PX509): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_pathlen_procname);
end;

 {introduced 1.1.0}
function  ERR_i2d_PUBKEY(a: PEVP_PKEY; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PUBKEY_procname);
end;


function  ERR_d2i_PUBKEY(a: PPEVP_PKEY; const pp: PPByte; _length: TIdC_LONG): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_procname);
end;



function  ERR_i2d_RSA_PUBKEY(a: PRSA; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSA_PUBKEY_procname);
end;


function  ERR_d2i_RSA_PUBKEY(a: PPRSA; const pp: PPByte; _length: TIdC_LONG): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSA_PUBKEY_procname);
end;



function  ERR_i2d_DSA_PUBKEY(a: PDSA; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSA_PUBKEY_procname);
end;


function  ERR_d2i_DSA_PUBKEY(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSA_PUBKEY_procname);
end;



function  ERR_i2d_EC_PUBKEY(a: PEC_KEY; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_EC_PUBKEY_procname);
end;


function  ERR_d2i_EC_PUBKEY(a: PPEC_KEY; const pp: PPByte; _length: TIdC_LONG): PEC_KEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_EC_PUBKEY_procname);
end;



function  ERR_X509_SIG_new: PX509_SIG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_new_procname);
end;


procedure  ERR_X509_SIG_free(v1: PX509_SIG);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_free_procname);
end;


function  ERR_d2i_X509_SIG(a: PPX509_SIG; const in_: PPByte; len: TIdC_LONG): PX509_SIG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_SIG_procname);
end;


function  ERR_i2d_X509_SIG(a: PX509_SIG; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_SIG_procname);
end;


procedure  ERR_X509_SIG_get0(const sig: PX509_SIG; const palg: PPX509_ALGOR; const pdigest: PPASN1_OCTET_STRING);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_get0_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_SIG_getm(sig: X509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_getm_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_REQ_INFO_new: PX509_REQ_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_INFO_new_procname);
end;


procedure  ERR_X509_REQ_INFO_free(v1: PX509_REQ_INFO);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_INFO_free_procname);
end;


function  ERR_d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; const in_: PPByte; len: TIdC_LONG): PX509_REQ_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REQ_INFO_procname);
end;


function  ERR_i2d_X509_REQ_INFO(a: PX509_REQ_INFO; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REQ_INFO_procname);
end;



function  ERR_X509_REQ_new: PX509_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_new_procname);
end;


procedure  ERR_X509_REQ_free(v1: PX509_REQ);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_free_procname);
end;


function  ERR_d2i_X509_REQ(a: PPX509_REQ; const in_: PPByte; len: TIdC_LONG): PX509_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REQ_procname);
end;


function  ERR_i2d_X509_REQ(a: PX509_REQ; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REQ_procname);
end;



function  ERR_X509_ATTRIBUTE_new: PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_new_procname);
end;


procedure  ERR_X509_ATTRIBUTE_free(v1: PX509_ATTRIBUTE);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_free_procname);
end;


function  ERR_d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; const in_: PPByte; len: TIdC_LONG): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ATTRIBUTE_procname);
end;


function  ERR_i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ATTRIBUTE_procname);
end;


function  ERR_X509_ATTRIBUTE_create(nid: TIdC_INT; trtype: TIdC_INT; value: Pointer): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_procname);
end;



function  ERR_X509_EXTENSION_new: PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_new_procname);
end;


procedure  ERR_X509_EXTENSION_free(v1: PX509_EXTENSION);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_free_procname);
end;


function  ERR_d2i_X509_EXTENSION(a: PPX509_EXTENSION; const in_: PPByte; len: TIdC_LONG): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_EXTENSION_procname);
end;


function  ERR_i2d_X509_EXTENSION(a: PX509_EXTENSION; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_EXTENSION_procname);
end;


  //DECLARE_ASN1_ENCODE_FUNCTIONS(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)

function  ERR_X509_NAME_ENTRY_new: PX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_new_procname);
end;


procedure  ERR_X509_NAME_ENTRY_free(v1: PX509_NAME_ENTRY);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_free_procname);
end;


function  ERR_d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; const in_: PPByte; len: TIdC_LONG): PX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_NAME_ENTRY_procname);
end;


function  ERR_i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_NAME_ENTRY_procname);
end;



function  ERR_X509_NAME_new: PX509_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_new_procname);
end;


procedure  ERR_X509_NAME_free(v1: PX509_NAME);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_free_procname);
end;


function  ERR_d2i_X509_NAME(a: PPX509_NAME; const in_: PPByte; len: TIdC_LONG): PX509_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_NAME_procname);
end;


function  ERR_i2d_X509_NAME(a: PX509_NAME; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_NAME_procname);
end;



function  ERR_X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_set_procname);
end;



  //DECLARE_ASN1_FUNCTIONS(X509_CINF)

function  ERR_X509_new: PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_new_procname);
end;


procedure  ERR_X509_free(v1: PX509);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_free_procname);
end;


function  ERR_d2i_X509(a: PPX509; const in_: PPByte; len: TIdC_LONG): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_procname);
end;


function  ERR_i2d_X509(a: PX509; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_procname);
end;



  //DECLARE_ASN1_FUNCTIONS(X509_CERT_AUX)
  //
  //#define X509_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef)
function  ERR_X509_set_ex_data(r: PX509; idx: TIdC_INT; arg: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_ex_data_procname);
end;


function  ERR_X509_get_ex_data(r: PX509; idx: TIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ex_data_procname);
end;


function  ERR_i2d_X509_AUX(a: PX509; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_AUX_procname);
end;


function  ERR_d2i_X509_AUX(a: PPX509; const pp: PPByte; _length: TIdC_LONG): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_AUX_procname);
end;



function  ERR_i2d_re_X509_tbs(x: PX509; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_re_X509_tbs_procname);
end;



function  ERR_X509_SIG_INFO_get(const siginf: PX509_SIG_INFO; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_INFO_get_procname);
end;

 {introduced 1.1.0}
procedure  ERR_X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TIdC_INT; pknid: TIdC_INT; secbits: TIdC_INT; flags: TIdC_UINT32);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_INFO_set_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_get_signature_info(x: PX509; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_signature_info_procname);
end;

 {introduced 1.1.0}

procedure  ERR_X509_get0_signature(var sig: PASN1_BIT_STRING; var alg: PX509_ALGOR; const x: PX509);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_signature_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_get_signature_nid(const x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_signature_nid_procname);
end;



function  ERR_X509_trusted(const x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_trusted_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_alias_set1(x: PX509; const name: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_alias_set1_procname);
end;


function  ERR_X509_keyid_set1(x: PX509; const id: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_keyid_set1_procname);
end;


function  ERR_X509_alias_get0(x: PX509; len: PIdC_INT): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_alias_get0_procname);
end;


function  ERR_X509_keyid_get0(x: PX509; len: PIdC_INT): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_keyid_get0_procname);
end;


//  TIdC_INT (*X509_TRUST_set_default(TIdC_INT (*trust) (TIdC_INT, X509 *, TIdC_INT))) (TIdC_INT, X509 *,
//                                                                  TIdC_INT);
function  ERR_X509_TRUST_set(t: PIdC_INT; trust: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_set_procname);
end;


function  ERR_X509_add1_trust_object(x: PX509; const obj: PASN1_OBJECT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add1_trust_object_procname);
end;


function  ERR_X509_add1_reject_object(x: PX509; const obj: PASN1_OBJECT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add1_reject_object_procname);
end;


procedure  ERR_X509_trust_clear(x: PX509);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_trust_clear_procname);
end;


procedure  ERR_X509_reject_clear(x: PX509);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_reject_clear_procname);
end;



  //STACK_OF(ASN1_OBJECT) *X509_get0_trust_objects(X509 *x);
  //STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x);
  //
function  ERR_X509_REVOKED_new: PX509_REVOKED;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_new_procname);
end;


procedure  ERR_X509_REVOKED_free(v1: PX509_REVOKED);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_free_procname);
end;


function  ERR_d2i_X509_REVOKED(a: PPX509_REVOKED; const in_: PPByte; len: TIdC_LONG): PX509_REVOKED;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REVOKED_procname);
end;


function  ERR_i2d_X509_REVOKED(a: PX509_REVOKED; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REVOKED_procname);
end;


function  ERR_X509_CRL_INFO_new: PX509_CRL_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_INFO_new_procname);
end;


procedure  ERR_X509_CRL_INFO_free(v1: PX509_CRL_INFO);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_INFO_free_procname);
end;


function  ERR_d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; const in_: PPByte; len: TIdC_LONG): PX509_CRL_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CRL_INFO_procname);
end;


function  ERR_i2d_X509_CRL_INFO(a: PX509_CRL_INFO; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CRL_INFO_procname);
end;


function  ERR_X509_CRL_new: PX509_CRL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_new_procname);
end;


procedure  ERR_X509_CRL_free(v1: PX509_CRL);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_free_procname);
end;


function  ERR_d2i_X509_CRL(a: PPX509_CRL; const in_: PPByte; len: TIdC_LONG): PX509_CRL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CRL_procname);
end;


function  ERR_i2d_X509_CRL(a: PX509_CRL; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CRL_procname);
end;



function  ERR_X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_add0_revoked_procname);
end;


function  ERR_X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_by_serial_procname);
end;


function  ERR_X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_by_cert_procname);
end;



function  ERR_X509_PKEY_new: PX509_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PKEY_new_procname);
end;


procedure  ERR_X509_PKEY_free(a: PX509_PKEY);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PKEY_free_procname);
end;

  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKI)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKAC)
  //DECLARE_ASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)

function  ERR_X509_INFO_new: PX509_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_INFO_new_procname);
end;


procedure  ERR_X509_INFO_free(a: PX509_INFO);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_INFO_free_procname);
end;


function  ERR_X509_NAME_oneline(const a: PX509_NAME; buf: PIdAnsiChar; size: TIdC_INT): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_oneline_procname);
end;



//  function ASN1_verify(i2d: Pi2d_of_void; algor1: PX509_ALGOR;
//    signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT;

//  TIdC_INT ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
//                  unsigned char *md, unsigned TIdC_INT *len);

//  TIdC_INT ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1,
//                X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
//                char *data, EVP_PKEY *pkey, const EVP_MD *type);

function  ERR_ASN1_item_digest(const it: PASN1_ITEM; const type_: PEVP_MD; data: Pointer; md: PByte; len: PIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_digest_procname);
end;



function  ERR_ASN1_item_verify(const it: PASN1_ITEM; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_verify_procname);
end;



function  ERR_ASN1_item_sign(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; const type_: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_sign_procname);
end;


function  ERR_ASN1_item_sign_ctx(const it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; asn: Pointer; ctx: PEVP_MD_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_sign_ctx_procname);
end;



function  ERR_X509_get_version(const x: PX509): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_version_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_set_version(x: PX509; version: TIdC_LONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_version_procname);
end;


function  ERR_X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_serialNumber_procname);
end;


function  ERR_X509_get_serialNumber(x: PX509): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_serialNumber_procname);
end;


function  ERR_X509_get0_serialNumber(const x: PX509): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_serialNumber_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_set_issuer_name(x: PX509; name: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_issuer_name_procname);
end;


function  ERR_X509_get_issuer_name(const a: PX509): PX509_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_issuer_name_procname);
end;


function  ERR_X509_set_subject_name(x: PX509; name: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_subject_name_procname);
end;


function  ERR_X509_get_subject_name(const a: PX509): PX509_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_subject_name_procname);
end;


function  ERR_X509_get0_notBefore(const x: PX509): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_notBefore_procname);
end;

  {introduced 1.1.0}
function  ERR_X509_getm_notBefore(const x: PX509): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_getm_notBefore_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_set1_notBefore(x: PX509; const tm: PASN1_TIME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set1_notBefore_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_get0_notAfter(const x: PX509): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_notAfter_procname);
end;

  {introduced 1.1.0}
function  ERR_X509_getm_notAfter(const x: PX509): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_getm_notAfter_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_set1_notAfter(x: PX509; const tm: PASN1_TIME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set1_notAfter_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_pubkey_procname);
end;


function  ERR_X509_up_ref(x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_up_ref_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_get_signature_type(const x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_signature_type_procname);
end;

 {introduced 1.1.0}

  (*
   * This one is only used so that a binary form can output, as in
   * i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &buf)
   *)
function  ERR_X509_get_X509_PUBKEY(const x: PX509): PX509_PUBKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_X509_PUBKEY_procname);
end;

 {introduced 1.1.0}
//  const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x);
procedure  ERR_X509_get0_uids(const x: PX509; const piuid: PPASN1_BIT_STRING; const psuid: PPASN1_BIT_STRING);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_uids_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_get0_tbs_sigalg(const x: PX509): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_tbs_sigalg_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_get0_pubkey(const x: PX509): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_pubkey_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_get_pubkey(x: PX509): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_pubkey_procname);
end;


function  ERR_X509_get0_pubkey_bitstr(const x: PX509): PASN1_BIT_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_pubkey_bitstr_procname);
end;


function  ERR_X509_certificate_type(const x: PX509; const pubkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_certificate_type_procname);
end;



function  ERR_X509_REQ_get_version(const req: PX509_REQ): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_version_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REQ_set_version(x: PX509_REQ; version: TIdC_LONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_version_procname);
end;


function  ERR_X509_REQ_get_subject_name(const req: PX509_REQ): PX509_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_subject_name_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_subject_name_procname);
end;


procedure  ERR_X509_REQ_get0_signature(const req: PX509_REQ; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get0_signature_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REQ_get_signature_nid(const req: PX509_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_signature_nid_procname);
end;

 {introduced 1.1.0}
function  ERR_i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_re_X509_REQ_tbs_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_pubkey_procname);
end;


function  ERR_X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_pubkey_procname);
end;


function  ERR_X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get0_pubkey_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_X509_PUBKEY_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REQ_extension_nid(nid: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_extension_nid_procname);
end;


function  ERR_X509_REQ_get_extension_nids: PIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_extension_nids_procname);
end;


procedure  ERR_X509_REQ_set_extension_nids(nids: PIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_extension_nids_procname);
end;


function  ERR_X509_REQ_get_extensions(req : PX509_REQ) : PSTACK_OF_X509_EXTENSION; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_extensions_procname);
end;

function  ERR_X509_REQ_add_extensions_nid(req : PX509_REQ; exts :PSTACK_OF_X509_EXTENSION;
                                  nid : TIdC_INT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add_extensions_nid_procname);
end;

function ERR_X509_REQ_add_extensions(req : PX509_REQ; exts : PSTACK_OF_X509_EXTENSION) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add_extensions_procname);
end;

function  ERR_X509_REQ_get_attr_count(const req: PX509_REQ): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_count_procname);
end;


function  ERR_X509_REQ_get_attr_by_NID(const req: PX509_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_by_NID_procname);
end;


function  ERR_X509_REQ_get_attr_by_OBJ(const req: PX509_REQ; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_by_OBJ_procname);
end;


function  ERR_X509_REQ_get_attr(const req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_procname);
end;


function  ERR_X509_REQ_delete_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_delete_attr_procname);
end;


function  ERR_X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_procname);
end;


function  ERR_X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_by_OBJ_procname);
end;


function  ERR_X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_by_NID_procname);
end;


function  ERR_X509_REQ_add1_attr_by_txt(req: PX509_REQ; const attrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_by_txt_procname);
end;



function  ERR_X509_CRL_set_version(x: PX509_CRL; version: TIdC_LONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_version_procname);
end;


function  ERR_X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_issuer_name_procname);
end;


function  ERR_X509_CRL_set1_lastUpdate(x: PX509_CRL; const tm: PASN1_TIME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set1_lastUpdate_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_set1_nextUpdate(x: PX509_CRL; const tm: PASN1_TIME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set1_nextUpdate_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_sort(crl: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_sort_procname);
end;


function  ERR_X509_CRL_up_ref(crl: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_up_ref_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_CRL_get_version(const crl: PX509_CRL): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_version_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_get0_lastUpdate(const crl: PX509_CRL): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_lastUpdate_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_get0_nextUpdate(const crl: PX509_CRL): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_nextUpdate_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_get_issuer(const crl: PX509_CRL): PX509_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_issuer_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_get0_extensions(const crl : PX509_CRL) : PSTACK_OF_X509_EXTENSION; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_extensions_procname);
end;

function ERR_X509_CRL_get_REVOKED(crl : PX509_CRL) : PSTACK_OF_X509_REVOKED; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_REVOKED_procname);
end;

procedure  ERR_X509_CRL_get0_signature(const crl: PX509_CRL; const psig: PPASN1_BIT_STRING; const palg: PPX509_ALGOR);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_signature_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_get_signature_nid(const crl: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_signature_nid_procname);
end;

 {introduced 1.1.0}
function  ERR_i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_re_X509_CRL_tbs_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_REVOKED_get0_serialNumber(const x: PX509_REVOKED): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get0_serialNumber_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_set_serialNumber_procname);
end;


function  ERR_X509_REVOKED_get0_revocationDate(const x: PX509_REVOKED): PASN1_TIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get0_revocationDate_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_set_revocationDate_procname);
end;

function ERR_X509_REVOKED_get0_extensions(const r : PX509_REVOKED) : PSTACK_OF_X509_EXTENSION; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get0_extensions_procname);
end;

function  ERR_X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; const md: PEVP_MD; flags: TIdC_UINT): PX509_CRL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_diff_procname);
end;



function  ERR_X509_REQ_check_private_key(x509: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_check_private_key_procname);
end;



function  ERR_X509_check_private_key(const x509: PX509; const pkey: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_private_key_procname);
end;


  //TIdC_INT X509_chain_check_suiteb(TIdC_INT *perror_depth,
  //                            X509 *x, STACK_OF(X509) *chain,
  //                            unsigned TIdC_LONG flags);
function  ERR_X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_check_suiteb_procname);
end;


  //STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *chain);

function  ERR_X509_issuer_and_serial_cmp(const a: PX509; const b: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_and_serial_cmp_procname);
end;


function  ERR_X509_issuer_and_serial_hash(a: PX509): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_and_serial_hash_procname);
end;



function  ERR_X509_issuer_name_cmp(const a: PX509; const b: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_name_cmp_procname);
end;


function  ERR_X509_issuer_name_hash(a: PX509): TIdC_uLONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_name_hash_procname);
end;



function  ERR_X509_subject_name_cmp(const a: PX509; const b: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_subject_name_cmp_procname);
end;


function  ERR_X509_subject_name_hash(x: PX509): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_subject_name_hash_procname);
end;



function  ERR_X509_cmp(const a: PX509; const b: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_procname);
end;


function  ERR_X509_NAME_cmp(const a: PX509_NAME; const b: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_cmp_procname);
end;


function  ERR_X509_NAME_hash(x: PX509_NAME): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_hash_procname);
end;


function  ERR_X509_NAME_hash_old(x: PX509_NAME): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_hash_old_procname);
end;



function  ERR_X509_CRL_cmp(const a: PX509_CRL; const b: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_cmp_procname);
end;


function  ERR_X509_CRL_match(const a: PX509_CRL; const b: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_match_procname);
end;


function  ERR_X509_aux_print(out_: PBIO; x: PX509; indent: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_aux_print_procname);
end;

 {introduced 1.1.0}
  //# ifndef OPENSSL_NO_STDIO
  //TIdC_INT X509_print_ex_fp(FILE *bp, X509 *x, unsigned TIdC_LONG nmflag,
  //                     unsigned TIdC_LONG cflag);
  //TIdC_INT X509_print_fp(FILE *bp, X509 *x);
  //TIdC_INT X509_CRL_print_fp(FILE *bp, X509_CRL *x);
  //TIdC_INT X509_REQ_print_fp(FILE *bp, X509_REQ *req);
  //TIdC_INT X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, TIdC_INT indent,
  //                          unsigned TIdC_LONG flags);
  //# endif

function  ERR_X509_NAME_print(bp: PBIO; const name: PX509_NAME; obase: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_print_procname);
end;


function  ERR_X509_NAME_print_ex(out_: PBIO; const nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_print_ex_procname);
end;


function  ERR_X509_print_ex(bp: PBIO; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_print_ex_procname);
end;


function  ERR_X509_print(bp: PBIO; x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_print_procname);
end;


function  ERR_X509_ocspid_print(bp: PBIO; x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ocspid_print_procname);
end;


function  ERR_X509_CRL_print_ex(out_: PBIO; x: PX509_CRL; nmflag: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_print_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_X509_CRL_print(bp: PBIO; x: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_print_procname);
end;


function  ERR_X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_print_ex_procname);
end;


function  ERR_X509_REQ_print(bp: PBIO; req: PX509_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_print_procname);
end;



function  ERR_X509_NAME_entry_count(const name: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_entry_count_procname);
end;


function  ERR_X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TIdC_INT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_text_by_NID_procname);
end;


function  ERR_X509_NAME_get_text_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_text_by_OBJ_procname);
end;



  (*
   * NOTE: you should be passing -1, not 0 as lastpos. The functions that use
   * lastpos, search after that position on.
   *)
function  ERR_X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_index_by_NID_procname);
end;


function  ERR_X509_NAME_get_index_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_index_by_OBJ_procname);
end;


function  ERR_X509_NAME_get_entry(const name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_entry_procname);
end;


function  ERR_X509_NAME_delete_entry(name: PX509_NAME; loc: TIdC_INT): pX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_delete_entry_procname);
end;


function  ERR_X509_NAME_add_entry(name: PX509_NAME; const ne: PX509_NAME_ENTRY; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_procname);
end;


function  ERR_X509_NAME_add_entry_by_OBJ(name: PX509_NAME; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_by_OBJ_procname);
end;


function  ERR_X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_by_NID_procname);
end;


function  ERR_X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; const field: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_create_by_txt_procname);
end;


function  ERR_X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_create_by_NID_procname);
end;


function  ERR_X509_NAME_add_entry_by_txt(name: PX509_NAME; const field: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT; loc: TIdC_INT; set_: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_by_txt_procname);
end;


function  ERR_X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_NAME_ENTRY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_create_by_OBJ_procname);
end;


function  ERR_X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; const obj: PASN1_OBJECT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_set_object_procname);
end;


function  ERR_X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_set_data_procname);
end;


function  ERR_X509_NAME_ENTRY_get_object(const ne: PX509_NAME_ENTRY): PASN1_OBJECT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_get_object_procname);
end;


function  ERR_X509_NAME_ENTRY_get_data(const ne: PX509_NAME_ENTRY): PASN1_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_get_data_procname);
end;


function  ERR_X509_NAME_ENTRY_set(const ne: PX509_NAME_ENTRY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_set_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_NAME_get0_der(nm: PX509_NAME; const pder: PPByte; pderlen: PIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get0_der_procname);
end;

 {introduced 1.1.0}

  //TIdC_INT X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x);
  //TIdC_INT X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x,
  //                          TIdC_INT nid, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *x,
  //                          const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //TIdC_INT X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *x,
  //                               TIdC_INT crit, TIdC_INT lastpos);
  //X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, TIdC_INT loc);
  //STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x,
  //                                         X509_EXTENSION *ex, TIdC_INT loc);

function  ERR_X509_get_ext_count(const x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_count_procname);
end;


function  ERR_X509_get_ext_by_NID(const x: PX509; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_by_NID_procname);
end;


function  ERR_X509_get_ext_by_OBJ(const x: PX509; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_by_OBJ_procname);
end;


function  ERR_X509_get_ext_by_critical(const x: PX509; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_by_critical_procname);
end;


function  ERR_X509_get_ext(const x: PX509; loc: TIdC_INT): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_procname);
end;


function  ERR_X509_delete_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_delete_ext_procname);
end;


function  ERR_X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add_ext_procname);
end;


function  ERR_X509_get_ext_d2i(const x: PX509; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_d2i_procname);
end;


function  ERR_X509_add1_ext_i2d(x: PX509; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add1_ext_i2d_procname);
end;



function  ERR_X509_CRL_get_ext_count(const x: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_count_procname);
end;


function  ERR_X509_CRL_get_ext_by_NID(const x: PX509_CRL; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_by_NID_procname);
end;


function  ERR_X509_CRL_get_ext_by_OBJ(const x: PX509_CRL; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_by_OBJ_procname);
end;


function  ERR_X509_CRL_get_ext_by_critical(const x: PX509_CRL; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_by_critical_procname);
end;


function  ERR_X509_CRL_get_ext(const x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_procname);
end;


function  ERR_X509_CRL_delete_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_delete_ext_procname);
end;


function  ERR_X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_add_ext_procname);
end;


function  ERR_X509_CRL_get_ext_d2i(const x: PX509_CRL; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_d2i_procname);
end;


function  ERR_X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_add1_ext_i2d_procname);
end;



function  ERR_X509_REVOKED_get_ext_count(const x: PX509_REVOKED): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_count_procname);
end;


function  ERR_X509_REVOKED_get_ext_by_NID(const x: PX509_REVOKED; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_by_NID_procname);
end;


function  ERR_X509_REVOKED_get_ext_by_OBJ(const x: PX509_REVOKED; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_by_OBJ_procname);
end;


function  ERR_X509_REVOKED_get_ext_by_critical(const x: PX509_REVOKED; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_by_critical_procname);
end;


function  ERR_X509_REVOKED_get_ext(const x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_procname);
end;


function  ERR_X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_delete_ext_procname);
end;


function  ERR_X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_add_ext_procname);
end;


function  ERR_X509_REVOKED_get_ext_d2i(const x: PX509_REVOKED; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_d2i_procname);
end;


function  ERR_X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_add1_ext_i2d_procname);
end;



function  ERR_X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TIdC_INT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_create_by_NID_procname);
end;


function  ERR_X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; const obj: PASN1_OBJECT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_create_by_OBJ_procname);
end;


function  ERR_X509_EXTENSION_set_object(ex: PX509_EXTENSION; const obj: PASN1_OBJECT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_set_object_procname);
end;


function  ERR_X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_set_critical_procname);
end;


function  ERR_X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_set_data_procname);
end;


function  ERR_X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_get_object_procname);
end;


function  ERR_X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_get_data_procname);
end;


function  ERR_X509_EXTENSION_get_critical(const ex: PX509_EXTENSION): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_get_critical_procname);
end;



  //TIdC_INT X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
  //TIdC_INT X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT nid,
  //                           TIdC_INT lastpos);
  //TIdC_INT X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk,
  //                           const ASN1_OBJECT *obj, TIdC_INT lastpos);
  //X509_ATTRIBUTE *X509at_get_attr(const STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, TIdC_INT loc);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
  //                                           X509_ATTRIBUTE *attr);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const ASN1_OBJECT *obj,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, TIdC_INT nid, TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE)
  //                                                  **x, const PIdAnsiChar *attrname,
  //                                                  TIdC_INT type,
  //                                                  const unsigned char *bytes,
  //                                                  TIdC_INT len);
  //void *X509at_get0_data_by_OBJ(STACK_OF(X509_ATTRIBUTE) *x,
  //                              const ASN1_OBJECT *obj, TIdC_INT lastpos, TIdC_INT type);
function  ERR_X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TIdC_INT; atrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_by_NID_procname);
end;


function  ERR_X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; const obj: PASN1_OBJECT; atrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_by_OBJ_procname);
end;


function  ERR_X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; const atrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_by_txt_procname);
end;


function  ERR_X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; const obj: PASN1_OBJECT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_set1_object_procname);
end;


function  ERR_X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TIdC_INT; const data: Pointer; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_set1_data_procname);
end;


function  ERR_X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TIdC_INT; atrtype: TIdC_INT; data: Pointer): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_get0_data_procname);
end;


function  ERR_X509_ATTRIBUTE_count(const attr: PX509_ATTRIBUTE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_count_procname);
end;


function  ERR_X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_get0_object_procname);
end;


function  ERR_X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TIdC_INT): PASN1_TYPE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_get0_type_procname);
end;



function  ERR_EVP_PKEY_get_attr_count(const key: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_count_procname);
end;


function  ERR_EVP_PKEY_get_attr_by_NID(const key: PEVP_PKEY; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_by_NID_procname);
end;


function  ERR_EVP_PKEY_get_attr_by_OBJ(const key: PEVP_PKEY; const obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_by_OBJ_procname);
end;


function  ERR_EVP_PKEY_get_attr(const key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_procname);
end;


function  ERR_EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_delete_attr_procname);
end;


function  ERR_EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_procname);
end;


function  ERR_EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; const obj: PASN1_OBJECT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_by_OBJ_procname);
end;


function  ERR_EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_by_NID_procname);
end;


function  ERR_EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; const attrname: PIdAnsiChar; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_by_txt_procname);
end;



function  ERR_X509_verify_cert(ctx: PX509_STORE_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_verify_cert_procname);
end;



  (* lookup a cert from a X509 STACK *)
//  function X509_find_by_issuer_and_serial(sk: P STACK_OF(X509); name: PX509_NAME; serial: PASN1_INTEGER): PX509;
//  X509 *X509_find_by_subject(STACK_OF(X509) *sk, X509_NAME *name);

  //DECLARE_ASN1_FUNCTIONS(PBEPARAM)
  //DECLARE_ASN1_FUNCTIONS(PBE2PARAM)
  //DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)
  //#ifndef OPENSSL_NO_SCRYPT
  //DECLARE_ASN1_FUNCTIONS(SCRYPT_PARAMS)
  //#endif

function  ERR_PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; const salt: PByte; saltlen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe_set0_algor_procname);
end;



function  ERR_PKCS5_pbe_set(alg: TIdC_INT; iter: TIdC_INT; const salt: PByte; saltlen: TIdC_INT): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe_set_procname);
end;


function  ERR_PKCS5_pbe2_set(const cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe2_set_procname);
end;


function  ERR_PKCS5_pbe2_set_iv(const cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; aiv: PByte; prf_nid: TIdC_INT): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe2_set_iv_procname);
end;



function  ERR_PKCS5_pbe2_set_scrypt(const cipher: PEVP_CIPHER; const salt: PByte; saltlen: TIdC_INT; aiv: PByte; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe2_set_scrypt_procname);
end;

 {introduced 1.1.0}

function  ERR_PKCS5_pbkdf2_set(iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT): PX509_ALGOR;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbkdf2_set_procname);
end;



  (* PKCS#8 utilities *)

  //DECLARE_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)

function  ERR_EVP_PKCS82PKEY(const p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKCS82PKEY_procname);
end;


function  ERR_EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PKCS8_PRIV_KEY_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY2PKCS8_procname);
end;



function  ERR_PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TIdC_INT; ptype: TIdC_INT; pval: Pointer; penc: PByte; penclen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_set0_procname);
end;


function  ERR_PKCS8_pkey_get0(const ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: PIdC_INT; const pa: PPX509_ALGOR; const p8: PPKCS8_PRIV_KEY_INFO): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_get0_procname);
end;



  //const STACK_OF(X509_ATTRIBUTE) *
  //PKCS8_pkey_get0_attrs(const PKCS8_PRIV_KEY_INFO *p8);
function  ERR_PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TIdC_INT; type_: TIdC_INT; const bytes: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_add1_attr_by_NID_procname);
end;

 {introduced 1.1.0}

function  ERR_X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer; penc: PByte; penclen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_set0_param_procname);
end;


function  ERR_X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; const pk: PPByte; ppklen: PIdC_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_get0_param_procname);
end;



function  ERR_X509_check_trust(x: PX509; id: TIdC_INT; flags: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_trust_procname);
end;


function  ERR_X509_TRUST_get_count: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_count_procname);
end;


function  ERR_X509_TRUST_get0(idx: TIdC_INT): PX509_TRUST;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get0_procname);
end;


function  ERR_X509_TRUST_get_by_id(id: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_by_id_procname);
end;


//  TIdC_INT X509_TRUST_add(TIdC_INT id, TIdC_INT flags, TIdC_INT (*ck) (X509_TRUST *, X509 *, TIdC_INT),
//                     const PIdAnsiChar *name, TIdC_INT arg1, void *arg2);
procedure  ERR_X509_TRUST_cleanup;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_cleanup_procname);
end;


function  ERR_X509_TRUST_get_flags(const xp: PX509_TRUST): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_flags_procname);
end;


function  ERR_X509_TRUST_get0_name(const xp: PX509_TRUST): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get0_name_procname);
end;


function  ERR_X509_TRUST_get_trust(const xp: PX509_TRUST): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_trust_procname);
end;



//  unsigned long X509_NAME_hash_ex(const X509_NAME *x, OSSL_LIB_CTX *libctx,
//                                const char *propq, int *ok);
function  ERR_X509_NAME_hash_ex(const x: PX509_NAME; libctx: POSSL_LIB_CTX; const propq: PIdAnsiChar; ok: PIdC_INT): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_hash_ex_procname);
end;

 {introduced 3.0.0}


  {$I TaurusTLSNoRetValOn.inc} 

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

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


  X509_http_nbio := LoadLibFunction(ADllHandle, X509_http_nbio_procname);
  FuncLoadError := not assigned(X509_http_nbio);
  if FuncLoadError then
  begin
    {$if not defined(X509_http_nbio_allownil)}
    X509_http_nbio := ERR_X509_http_nbio;
    {$ifend}
    {$if declared(X509_http_nbio_introduced)}
    if LibVersion < X509_http_nbio_introduced then
    begin
      {$if declared(FC_X509_http_nbio)}
      X509_http_nbio := FC_X509_http_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_http_nbio_removed)}
    if X509_http_nbio_removed <= LibVersion then
    begin
      {$if declared(_X509_http_nbio)}
      X509_http_nbio := _X509_http_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_http_nbio_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_http_nbio');
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


  X509_CRL_http_nbio := LoadLibFunction(ADllHandle, X509_CRL_http_nbio_procname);
  FuncLoadError := not assigned(X509_CRL_http_nbio);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_http_nbio_allownil)}
    X509_CRL_http_nbio := ERR_X509_CRL_http_nbio;
    {$ifend}
    {$if declared(X509_CRL_http_nbio_introduced)}
    if LibVersion < X509_CRL_http_nbio_introduced then
    begin
      {$if declared(FC_X509_CRL_http_nbio)}
      X509_CRL_http_nbio := FC_X509_CRL_http_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_http_nbio_removed)}
    if X509_CRL_http_nbio_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_http_nbio)}
      X509_CRL_http_nbio := _X509_CRL_http_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_http_nbio_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_http_nbio');
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


  X509_check_certificate_times := LoadLibFunction(ADllHandle, X509_check_certificate_times_procname);
  FuncLoadError := not assigned(X509_check_certificate_times);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_certificate_times_allownil)}
    X509_check_certificate_times := ERR_X509_check_certificate_times;
    {$ifend}
    {$if declared(X509_check_certificate_times_introduced)}
    if LibVersion < X509_check_certificate_times_introduced then
    begin
      {$if declared(FC_X509_check_certificate_times)}
      X509_check_certificate_times := FC_X509_check_certificate_times;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_certificate_times_removed)}
    if X509_check_certificate_times_removed <= LibVersion then
    begin
      {$if declared(_X509_check_certificate_times)}
      X509_check_certificate_times := _X509_check_certificate_times;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_certificate_times_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_certificate_times');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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


  X509_trusted := LoadLibFunction(ADllHandle, X509_trusted_procname);
  FuncLoadError := not assigned(X509_trusted);
  if FuncLoadError then
  begin
    {$if not defined(X509_trusted_allownil)}
    X509_trusted := ERR_X509_trusted;
    {$ifend}
    {$if declared(X509_trusted_introduced)}
    if LibVersion < X509_trusted_introduced then
    begin
      {$if declared(FC_X509_trusted)}
      X509_trusted := FC_X509_trusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_trusted_removed)}
    if X509_trusted_removed <= LibVersion then
    begin
      {$if declared(_X509_trusted)}
      X509_trusted := _X509_trusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_trusted_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_trusted');
    {$ifend}
  end;

 {introduced 1.1.0}
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


  X509_TRUST_set := LoadLibFunction(ADllHandle, X509_TRUST_set_procname);
  FuncLoadError := not assigned(X509_TRUST_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_set_allownil)}
    X509_TRUST_set := ERR_X509_TRUST_set;
    {$ifend}
    {$if declared(X509_TRUST_set_introduced)}
    if LibVersion < X509_TRUST_set_introduced then
    begin
      {$if declared(FC_X509_TRUST_set)}
      X509_TRUST_set := FC_X509_TRUST_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_set_removed)}
    if X509_TRUST_set_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_set)}
      X509_TRUST_set := _X509_TRUST_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_set');
    {$ifend}
  end;


  X509_add1_trust_object := LoadLibFunction(ADllHandle, X509_add1_trust_object_procname);
  FuncLoadError := not assigned(X509_add1_trust_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_add1_trust_object_allownil)}
    X509_add1_trust_object := ERR_X509_add1_trust_object;
    {$ifend}
    {$if declared(X509_add1_trust_object_introduced)}
    if LibVersion < X509_add1_trust_object_introduced then
    begin
      {$if declared(FC_X509_add1_trust_object)}
      X509_add1_trust_object := FC_X509_add1_trust_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_add1_trust_object_removed)}
    if X509_add1_trust_object_removed <= LibVersion then
    begin
      {$if declared(_X509_add1_trust_object)}
      X509_add1_trust_object := _X509_add1_trust_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_add1_trust_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_add1_trust_object');
    {$ifend}
  end;


  X509_add1_reject_object := LoadLibFunction(ADllHandle, X509_add1_reject_object_procname);
  FuncLoadError := not assigned(X509_add1_reject_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_add1_reject_object_allownil)}
    X509_add1_reject_object := ERR_X509_add1_reject_object;
    {$ifend}
    {$if declared(X509_add1_reject_object_introduced)}
    if LibVersion < X509_add1_reject_object_introduced then
    begin
      {$if declared(FC_X509_add1_reject_object)}
      X509_add1_reject_object := FC_X509_add1_reject_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_add1_reject_object_removed)}
    if X509_add1_reject_object_removed <= LibVersion then
    begin
      {$if declared(_X509_add1_reject_object)}
      X509_add1_reject_object := _X509_add1_reject_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_add1_reject_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_add1_reject_object');
    {$ifend}
  end;


  X509_trust_clear := LoadLibFunction(ADllHandle, X509_trust_clear_procname);
  FuncLoadError := not assigned(X509_trust_clear);
  if FuncLoadError then
  begin
    {$if not defined(X509_trust_clear_allownil)}
    X509_trust_clear := ERR_X509_trust_clear;
    {$ifend}
    {$if declared(X509_trust_clear_introduced)}
    if LibVersion < X509_trust_clear_introduced then
    begin
      {$if declared(FC_X509_trust_clear)}
      X509_trust_clear := FC_X509_trust_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_trust_clear_removed)}
    if X509_trust_clear_removed <= LibVersion then
    begin
      {$if declared(_X509_trust_clear)}
      X509_trust_clear := _X509_trust_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_trust_clear_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_trust_clear');
    {$ifend}
  end;


  X509_reject_clear := LoadLibFunction(ADllHandle, X509_reject_clear_procname);
  FuncLoadError := not assigned(X509_reject_clear);
  if FuncLoadError then
  begin
    {$if not defined(X509_reject_clear_allownil)}
    X509_reject_clear := ERR_X509_reject_clear;
    {$ifend}
    {$if declared(X509_reject_clear_introduced)}
    if LibVersion < X509_reject_clear_introduced then
    begin
      {$if declared(FC_X509_reject_clear)}
      X509_reject_clear := FC_X509_reject_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_reject_clear_removed)}
    if X509_reject_clear_removed <= LibVersion then
    begin
      {$if declared(_X509_reject_clear)}
      X509_reject_clear := _X509_reject_clear;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_reject_clear_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_reject_clear');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

  {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

  {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0} 
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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
      {$if declared(FC_X509_REQ_get_extensions)}
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
    {$if not defined(X509_REQ_add_extensions_nid_allownil)}
    X509_REQ_add_extensions := ERR_X509_REQ_add_extensions;
    {$ifend}
    {$if declared(X509_REQ_add_extensions_nid_introduced)}
    if LibVersion < X509_REQ_add_extensions_introduced then
    begin
      {$if declared(FC_X509_REQ_get_extensions)}
      X509_REQ_add_extensions := FC_X509_REQ_add_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_add_extensions_removed)}
    if X509_REQ_add_extensions_nid_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_add_extensions_nid)}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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
      {$if declared(FC_X509_CRL_get_issuer)}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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


  X509_NAME_hash := LoadLibFunction(ADllHandle, X509_NAME_hash_procname);
  FuncLoadError := not assigned(X509_NAME_hash);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_hash_allownil)}
    X509_NAME_hash := ERR_X509_NAME_hash;
    {$ifend}
    {$if declared(X509_NAME_hash_introduced)}
    if LibVersion < X509_NAME_hash_introduced then
    begin
      {$if declared(FC_X509_NAME_hash)}
      X509_NAME_hash := FC_X509_NAME_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_hash_removed)}
    if X509_NAME_hash_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_hash)}
      X509_NAME_hash := _X509_NAME_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_hash_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_hash');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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


  X509_verify_cert := LoadLibFunction(ADllHandle, X509_verify_cert_procname);
  FuncLoadError := not assigned(X509_verify_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_verify_cert_allownil)}
    X509_verify_cert := ERR_X509_verify_cert;
    {$ifend}
    {$if declared(X509_verify_cert_introduced)}
    if LibVersion < X509_verify_cert_introduced then
    begin
      {$if declared(FC_X509_verify_cert)}
      X509_verify_cert := FC_X509_verify_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_verify_cert_removed)}
    if X509_verify_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_verify_cert)}
      X509_verify_cert := _X509_verify_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_verify_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_verify_cert');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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


  X509_check_trust := LoadLibFunction(ADllHandle, X509_check_trust_procname);
  FuncLoadError := not assigned(X509_check_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_trust_allownil)}
    X509_check_trust := ERR_X509_check_trust;
    {$ifend}
    {$if declared(X509_check_trust_introduced)}
    if LibVersion < X509_check_trust_introduced then
    begin
      {$if declared(FC_X509_check_trust)}
      X509_check_trust := FC_X509_check_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_trust_removed)}
    if X509_check_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_check_trust)}
      X509_check_trust := _X509_check_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_trust');
    {$ifend}
  end;


  X509_TRUST_get_count := LoadLibFunction(ADllHandle, X509_TRUST_get_count_procname);
  FuncLoadError := not assigned(X509_TRUST_get_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_get_count_allownil)}
    X509_TRUST_get_count := ERR_X509_TRUST_get_count;
    {$ifend}
    {$if declared(X509_TRUST_get_count_introduced)}
    if LibVersion < X509_TRUST_get_count_introduced then
    begin
      {$if declared(FC_X509_TRUST_get_count)}
      X509_TRUST_get_count := FC_X509_TRUST_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_get_count_removed)}
    if X509_TRUST_get_count_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_get_count)}
      X509_TRUST_get_count := _X509_TRUST_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_get_count');
    {$ifend}
  end;


  X509_TRUST_get0 := LoadLibFunction(ADllHandle, X509_TRUST_get0_procname);
  FuncLoadError := not assigned(X509_TRUST_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_get0_allownil)}
    X509_TRUST_get0 := ERR_X509_TRUST_get0;
    {$ifend}
    {$if declared(X509_TRUST_get0_introduced)}
    if LibVersion < X509_TRUST_get0_introduced then
    begin
      {$if declared(FC_X509_TRUST_get0)}
      X509_TRUST_get0 := FC_X509_TRUST_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_get0_removed)}
    if X509_TRUST_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_get0)}
      X509_TRUST_get0 := _X509_TRUST_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_get0');
    {$ifend}
  end;


  X509_TRUST_get_by_id := LoadLibFunction(ADllHandle, X509_TRUST_get_by_id_procname);
  FuncLoadError := not assigned(X509_TRUST_get_by_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_get_by_id_allownil)}
    X509_TRUST_get_by_id := ERR_X509_TRUST_get_by_id;
    {$ifend}
    {$if declared(X509_TRUST_get_by_id_introduced)}
    if LibVersion < X509_TRUST_get_by_id_introduced then
    begin
      {$if declared(FC_X509_TRUST_get_by_id)}
      X509_TRUST_get_by_id := FC_X509_TRUST_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_get_by_id_removed)}
    if X509_TRUST_get_by_id_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_get_by_id)}
      X509_TRUST_get_by_id := _X509_TRUST_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_get_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_get_by_id');
    {$ifend}
  end;


  X509_TRUST_cleanup := LoadLibFunction(ADllHandle, X509_TRUST_cleanup_procname);
  FuncLoadError := not assigned(X509_TRUST_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_cleanup_allownil)}
    X509_TRUST_cleanup := ERR_X509_TRUST_cleanup;
    {$ifend}
    {$if declared(X509_TRUST_cleanup_introduced)}
    if LibVersion < X509_TRUST_cleanup_introduced then
    begin
      {$if declared(FC_X509_TRUST_cleanup)}
      X509_TRUST_cleanup := FC_X509_TRUST_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_cleanup_removed)}
    if X509_TRUST_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_cleanup)}
      X509_TRUST_cleanup := _X509_TRUST_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_cleanup');
    {$ifend}
  end;


  X509_TRUST_get_flags := LoadLibFunction(ADllHandle, X509_TRUST_get_flags_procname);
  FuncLoadError := not assigned(X509_TRUST_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_get_flags_allownil)}
    X509_TRUST_get_flags := ERR_X509_TRUST_get_flags;
    {$ifend}
    {$if declared(X509_TRUST_get_flags_introduced)}
    if LibVersion < X509_TRUST_get_flags_introduced then
    begin
      {$if declared(FC_X509_TRUST_get_flags)}
      X509_TRUST_get_flags := FC_X509_TRUST_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_get_flags_removed)}
    if X509_TRUST_get_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_get_flags)}
      X509_TRUST_get_flags := _X509_TRUST_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_get_flags');
    {$ifend}
  end;


  X509_TRUST_get0_name := LoadLibFunction(ADllHandle, X509_TRUST_get0_name_procname);
  FuncLoadError := not assigned(X509_TRUST_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_get0_name_allownil)}
    X509_TRUST_get0_name := ERR_X509_TRUST_get0_name;
    {$ifend}
    {$if declared(X509_TRUST_get0_name_introduced)}
    if LibVersion < X509_TRUST_get0_name_introduced then
    begin
      {$if declared(FC_X509_TRUST_get0_name)}
      X509_TRUST_get0_name := FC_X509_TRUST_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_get0_name_removed)}
    if X509_TRUST_get0_name_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_get0_name)}
      X509_TRUST_get0_name := _X509_TRUST_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_get0_name');
    {$ifend}
  end;


  X509_TRUST_get_trust := LoadLibFunction(ADllHandle, X509_TRUST_get_trust_procname);
  FuncLoadError := not assigned(X509_TRUST_get_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_get_trust_allownil)}
    X509_TRUST_get_trust := ERR_X509_TRUST_get_trust;
    {$ifend}
    {$if declared(X509_TRUST_get_trust_introduced)}
    if LibVersion < X509_TRUST_get_trust_introduced then
    begin
      {$if declared(FC_X509_TRUST_get_trust)}
      X509_TRUST_get_trust := FC_X509_TRUST_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_get_trust_removed)}
    if X509_TRUST_get_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_get_trust)}
      X509_TRUST_get_trust := _X509_TRUST_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_get_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_get_trust');
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

  {stack of macros}
  //ensure that the stack of functions ALWAYS load before they are assigned
  //through typecast procedureal pointers.
  LoadStackFunctions(ADllHandle,libVersion,AFailed);
  //Disable PAL warnings for Bad Typecast
   sk_X509_new:= Tsk_X509_new ( sk_new);  //PALOFF
  sk_X509_new_null := Tsk_X509_new_null(sk_new_null); //PALOFF
  sk_X509_free := Tsk_X509_free( sk_free );  //PALOFF
  sk_X509_num := Tsk_X509_num(sk_num);  //PALOFF
  sk_X509_value := Tsk_X509_value(sk_value);  //PALOFF
  sk_X509_push := Tsk_X509_push( sk_push);  //PALOFF
  sk_X509_dup := Tsk_X509_dup( sk_dup); //PALOFF
  sk_X509_find := Tsk_X509_find(sk_find); //PALOFF
  sk_X509_pop_free :=  Tsk_X509_pop_free( sk_pop_free); //PALOFF
  sk_X509_NAME_new:= Tsk_X509_NAME_new( sk_new);  //PALOFF
  sk_X509_NAME_new_null := Tsk_X509_NAME_new_null( sk_new_null);  //PALOFF
  sk_X509_NAME_free := Tsk_X509_NAME_free(sk_free); //PALOFF
  sk_X509_NAME_num := Tsk_X509_NAME_num(sk_num); //PALOFF
  sk_X509_NAME_value := Tsk_X509_NAME_value(sk_value); //PALOFF
  sk_X509_NAME_push := Tsk_X509_NAME_push(sk_push); //PALOFF
  sk_X509_NAME_dup := Tsk_X509_NAME_dup(sk_dup);  //PALOFF
  sk_X509_NAME_find := Tsk_X509_NAME_find(sk_find);  //PALOFF
  sk_X509_NAME_pop_free :=  Tsk_X509_NAME_pop_free(sk_pop_free);  //PALOFF
  sk_X509_NAME_ENTRY_new:= Tsk_X509_NAME_ENTRY_new(sk_new); //PALOFF
  sk_X509_NAME_ENTRY_new_null := Tsk_X509_NAME_ENTRY_new_null(sk_new_null);  //PALOFF
  sk_X509_NAME_ENTRY_free := Tsk_X509_NAME_ENTRY_free( sk_free );  //PALOFF
  sk_X509_NAME_ENTRY_num := Tsk_X509_NAME_ENTRY_num( sk_num);  //PALOFF
  sk_X509_NAME_ENTRY_value := Tsk_X509_NAME_ENTRY_value(sk_value); //PALOFF
  sk_X509_NAME_ENTRY_push := Tsk_X509_NAME_ENTRY_push( sk_push);  //PALOFF
  sk_X509_NAME_ENTRY_dup := Tsk_X509_NAME_ENTRY_dup( sk_dup);  //PALOFF
  sk_X509_NAME_ENTRY_find := Tsk_X509_NAME_ENTRY_find (sk_find);  //PALOFF
  sk_X509_NAME_ENTRY_pop_free :=  Tsk_X509_NAME_ENTRY_pop_free(sk_pop_free);  //PALOFF
  sk_X509_INFO_new:= Tsk_X509_INFO_new( sk_new); //PALOFF
  sk_X509_INFO_new_null := Tsk_X509_INFO_new_null(sk_new_null); //PALOFF
  sk_X509_INFO_free := Tsk_X509_INFO_free( sk_free);  //PALOFF
  sk_X509_INFO_num := Tsk_X509_INFO_num( sk_num);  //PALOFF
  sk_X509_INFO_value := Tsk_X509_INFO_value (sk_value);  //PALOFF
  sk_X509_INFO_push := Tsk_X509_INFO_push (sk_push);  //PALOFF
  sk_X509_INFO_dup := Tsk_X509_INFO_dup (sk_dup);  //PALOFF
  sk_X509_INFO_find := Tsk_X509_INFO_find (sk_find); //PALOFF
  sk_X509_INFO_pop_free := Tsk_X509_INFO_pop_free (sk_pop_free); //PALOFF
  sk_X509_EXTENSION_new := Tsk_X509_EXTENSION_new(sk_new);  //PALOFF
  sk_X509_EXTENSION_new_null := Tsk_X509_EXTENSION_new_null(sk_new_null); //PALOFF
  sk_X509_EXTENSION_free := Tsk_X509_EXTENSION_free(sk_free);  //PALOFF
  sk_X509_EXTENSION_num := Tsk_X509_EXTENSION_num(sk_num); //PALOFF
  sk_X509_EXTENSION_value := Tsk_X509_EXTENSION_value(sk_value); //PALOFF
  sk_X509_EXTENSION_push := Tsk_X509_EXTENSION_push(sk_push);  //PALOFF
  sk_X509_EXTENSION_dup := Tsk_X509_EXTENSION_dup(sk_dup); //PALOFF
  sk_X509_EXTENSION_find := Tsk_X509_EXTENSION_find(sk_find);  //PALOFF
  sk_X509_EXTENSION_pop_free := Tsk_X509_EXTENSION_pop_free(sk_pop_free); //PALOFF
  sk_X509_TRUST_new:= Tsk_X509_TRUST_new(sk_new);  //PALOFF
  sk_X509_TRUST_new_null := Tsk_X509_TRUST_new_null(sk_new_null);  //PALOFF
  sk_X509_TRUST_free := Tsk_X509_TRUST_free(sk_free);  //PALOFF
  sk_X509_TRUST_num := Tsk_X509_TRUST_num(sk_num);  //PALOFF
  sk_X509_TRUST_value := Tsk_X509_TRUST_value(sk_value); //PALOFF
  sk_X509_TRUST_push := Tsk_X509_TRUST_push(sk_push);  //PALOFF
  sk_X509_TRUST_dup := Tsk_X509_TRUST_dup(sk_dup);  //PALOFF
  sk_X509_TRUST_find := Tsk_X509_TRUST_find(sk_find); //PALOFF
  sk_X509_TRUST_pop_free :=  Tsk_X509_TRUST_pop_free(sk_pop_free);  //PALOFF
  sk_X509_REVOKED_new:= Tsk_X509_REVOKED_new(sk_new);  //PALOFF
  sk_X509_REVOKED_new_null := Tsk_X509_REVOKED_new_null(sk_new_null); //PALOFF
  sk_X509_REVOKED_free := Tsk_X509_REVOKED_free(sk_free);  //PALOFF
  sk_X509_REVOKED_num := Tsk_X509_REVOKED_num(sk_num);  //PALOFF
  sk_X509_REVOKED_value := Tsk_X509_REVOKED_value(sk_value); //PALOFF
  sk_X509_REVOKED_push := Tsk_X509_REVOKED_push(sk_push);  //PALOFF
  sk_X509_REVOKED_dup := Tsk_X509_REVOKED_dup(sk_dup); //PALOFF
  sk_X509_REVOKED_find := Tsk_X509_REVOKED_find(sk_find); //PALOFF
  sk_X509_REVOKED_pop_free := Tsk_X509_REVOKED_pop_free(sk_pop_free); //PALOFF
  sk_X509_CRL_new:= Tsk_X509_CRL_new(sk_new); //PALOFF
  sk_X509_CRL_new_null := Tsk_X509_CRL_new_null(sk_new_null); //PALOFF
  sk_X509_CRL_free := Tsk_X509_CRL_free(sk_free);  //PALOFF
  sk_X509_CRL_num := Tsk_X509_CRL_num(sk_num);  //PALOFF
  sk_X509_CRL_value := Tsk_X509_CRL_value(sk_value);  //PALOFF
  sk_X509_CRL_push := Tsk_X509_CRL_push(sk_push);  //PALOFF
  sk_X509_CRL_dup := Tsk_X509_CRL_dup(sk_dup);  //PALOFF
  sk_X509_CRL_find := Tsk_X509_CRL_find(sk_find); //PALOFF
  sk_X509_CRL_pop_free := Tsk_X509_CRL_pop_free(sk_pop_free);  //PALOFF
  sk_X509_ATTRIBUTE_new:= Tsk_X509_ATTRIBUTE_new(sk_new);  //PALOFF
  sk_X509_ATTRIBUTE_new_null := Tsk_X509_ATTRIBUTE_new_null(sk_new_null); //PALOFF
  sk_X509_ATTRIBUTE_free := Tsk_X509_ATTRIBUTE_free(sk_free);  //PALOFF
  sk_X509_ATTRIBUTE_num := Tsk_X509_ATTRIBUTE_num(sk_num);  //PALOFF
  sk_X509_ATTRIBUTE_value := Tsk_X509_ATTRIBUTE_value(sk_value); //PALOFF
  sk_X509_ATTRIBUTE_push := Tsk_X509_ATTRIBUTE_push(sk_push);  //PALOFF
  sk_X509_ATTRIBUTE_dup := Tsk_X509_ATTRIBUTE_dup(sk_dup);  //PALOFF
  sk_X509_ATTRIBUTE_find := Tsk_X509_ATTRIBUTE_find(sk_find);  //PALOFF
  sk_X509_ATTRIBUTE_pop_free := Tsk_X509_ATTRIBUTE_pop_free(sk_pop_free);  //PALOFF

end;

procedure Unload;
begin
  X509_CRL_set_default_method := nil;
  X509_CRL_METHOD_free := nil;
  X509_CRL_set_meth_data := nil;
  X509_CRL_get_meth_data := nil;
  X509_verify_cert_error_string := nil;
  X509_verify := nil;
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
  X509_http_nbio := nil; {removed 3.0.0}
  X509_REQ_sign := nil;
  X509_REQ_sign_ctx := nil;
  X509_CRL_sign := nil;
  X509_CRL_sign_ctx := nil;
  X509_CRL_http_nbio := nil; {removed 3.0.0}
  NETSCAPE_SPKI_sign := nil;
  X509_pubkey_digest := nil;
  X509_digest := nil;
  X509_CRL_digest := nil;
  X509_REQ_digest := nil;
  X509_NAME_digest := nil;
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
  d2i_PKCS8_PRIV_KEY_INFO_bio := nil;
  i2d_PKCS8_PRIV_KEY_INFO_bio := nil;
  i2d_PKCS8PrivateKeyInfo_bio := nil;
  i2d_PrivateKey_bio := nil;
  d2i_PrivateKey_bio := nil;
  i2d_PUBKEY_bio := nil;
  d2i_PUBKEY_bio := nil;
  X509_dup := nil;
  X509_ATTRIBUTE_dup := nil;
  X509_EXTENSION_dup := nil;
  X509_CRL_dup := nil;
  X509_REVOKED_dup := nil;
  X509_REQ_dup := nil;
  X509_ALGOR_dup := nil;
  X509_ALGOR_set0 := nil;
  X509_ALGOR_get0 := nil;
  X509_ALGOR_set_md := nil;
  X509_ALGOR_cmp := nil;
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
  X509_VAL_new := nil;
  X509_VAL_free := nil;
  d2i_X509_VAL := nil;
  i2d_X509_VAL := nil;
  X509_PUBKEY_new := nil;
  X509_PUBKEY_free := nil;
  d2i_X509_PUBKEY := nil;
  i2d_X509_PUBKEY := nil;
  X509_PUBKEY_set := nil;
  X509_PUBKEY_get0 := nil; {introduced 1.1.0}
  X509_PUBKEY_get := nil;
  X509_get_pathlen := nil; {introduced 1.1.0}
  i2d_PUBKEY := nil;
  d2i_PUBKEY := nil;
  i2d_RSA_PUBKEY := nil;
  d2i_RSA_PUBKEY := nil;
  i2d_DSA_PUBKEY := nil;
  d2i_DSA_PUBKEY := nil;
  i2d_EC_PUBKEY := nil;
  d2i_EC_PUBKEY := nil;
  X509_SIG_new := nil;
  X509_SIG_free := nil;
  d2i_X509_SIG := nil;
  i2d_X509_SIG := nil;
  X509_SIG_get0 := nil; {introduced 1.1.0}
  X509_SIG_getm := nil; {introduced 1.1.0}
  X509_REQ_INFO_new := nil;
  X509_REQ_INFO_free := nil;
  d2i_X509_REQ_INFO := nil;
  i2d_X509_REQ_INFO := nil;
  X509_REQ_new := nil;
  X509_REQ_free := nil;
  d2i_X509_REQ := nil;
  i2d_X509_REQ := nil;
  X509_ATTRIBUTE_new := nil;
  X509_ATTRIBUTE_free := nil;
  d2i_X509_ATTRIBUTE := nil;
  i2d_X509_ATTRIBUTE := nil;
  X509_ATTRIBUTE_create := nil;
  X509_EXTENSION_new := nil;
  X509_EXTENSION_free := nil;
  d2i_X509_EXTENSION := nil;
  i2d_X509_EXTENSION := nil;
  X509_NAME_ENTRY_new := nil;
  X509_NAME_ENTRY_free := nil;
  d2i_X509_NAME_ENTRY := nil;
  i2d_X509_NAME_ENTRY := nil;
  X509_NAME_new := nil;
  X509_NAME_free := nil;
  d2i_X509_NAME := nil;
  i2d_X509_NAME := nil;
  X509_NAME_set := nil;
  X509_new := nil;
  X509_free := nil;
  d2i_X509 := nil;
  i2d_X509 := nil;
  X509_set_ex_data := nil;
  X509_get_ex_data := nil;
  i2d_X509_AUX := nil;
  d2i_X509_AUX := nil;
  i2d_re_X509_tbs := nil;
  X509_SIG_INFO_get := nil; {introduced 1.1.0}
  X509_SIG_INFO_set := nil; {introduced 1.1.0}
  X509_get_signature_info := nil; {introduced 1.1.0}
  X509_get0_signature := nil; {introduced 1.1.0}
  X509_get_signature_nid := nil;
  X509_trusted := nil; {introduced 1.1.0}
  X509_alias_set1 := nil;
  X509_keyid_set1 := nil;
  X509_alias_get0 := nil;
  X509_keyid_get0 := nil;
  X509_TRUST_set := nil;
  X509_add1_trust_object := nil;
  X509_add1_reject_object := nil;
  X509_trust_clear := nil;
  X509_reject_clear := nil;
  X509_REVOKED_new := nil;
  X509_REVOKED_free := nil;
  d2i_X509_REVOKED := nil;
  i2d_X509_REVOKED := nil;
  X509_CRL_INFO_new := nil;
  X509_CRL_INFO_free := nil;
  d2i_X509_CRL_INFO := nil;
  i2d_X509_CRL_INFO := nil;
  X509_CRL_new := nil;
  X509_CRL_free := nil;
  d2i_X509_CRL := nil;
  i2d_X509_CRL := nil;
  X509_CRL_add0_revoked := nil;
  X509_CRL_get0_by_serial := nil;
  X509_CRL_get0_by_cert := nil;
  X509_PKEY_new := nil;
  X509_PKEY_free := nil;
  X509_INFO_new := nil;
  X509_INFO_free := nil;
  X509_NAME_oneline := nil;
  ASN1_item_digest := nil;
  ASN1_item_verify := nil;
  ASN1_item_sign := nil;
  ASN1_item_sign_ctx := nil;
  X509_get_version := nil; {introduced 1.1.0}
  X509_set_version := nil;
  X509_set_serialNumber := nil;
  X509_get_serialNumber := nil;
  X509_get0_serialNumber := nil; {introduced 1.1.0}
  X509_set_issuer_name := nil;
  X509_get_issuer_name := nil;
  X509_set_subject_name := nil;
  X509_get_subject_name := nil;
  X509_get0_notBefore := nil;  {introduced 1.1.0}
  X509_getm_notBefore := nil; {introduced 1.1.0}
  X509_set1_notBefore := nil; {introduced 1.1.0}
  X509_get0_notAfter := nil;  {introduced 1.1.0}
  X509_getm_notAfter := nil; {introduced 1.1.0}
  X509_set1_notAfter := nil; {introduced 1.1.0}
  X509_set_pubkey := nil;
  X509_up_ref := nil; {introduced 1.1.0}
  X509_get_signature_type := nil; {introduced 1.1.0}
  X509_get_X509_PUBKEY := nil; {introduced 1.1.0}
  X509_get0_uids := nil; {introduced 1.1.0}
  X509_get0_tbs_sigalg := nil; {introduced 1.1.0}
  X509_get0_pubkey := nil; {introduced 1.1.0}
  X509_get_pubkey := nil;
  X509_get0_pubkey_bitstr := nil;
  X509_certificate_type := nil;
  X509_REQ_get_version := nil; {introduced 1.1.0}
  X509_REQ_set_version := nil;
  X509_REQ_get_subject_name := nil; {introduced 1.1.0}
  X509_REQ_set_subject_name := nil;
  X509_REQ_get0_signature := nil; {introduced 1.1.0} 
  X509_REQ_get_signature_nid := nil; {introduced 1.1.0}
  i2d_re_X509_REQ_tbs := nil; {introduced 1.1.0}
  X509_REQ_set_pubkey := nil;
  X509_REQ_get_pubkey := nil;
  X509_REQ_get0_pubkey := nil; {introduced 1.1.0}
  X509_REQ_get_X509_PUBKEY := nil; {introduced 1.1.0}
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
  X509_CRL_set1_lastUpdate := nil; {introduced 1.1.0}
  X509_CRL_set1_nextUpdate := nil; {introduced 1.1.0}
  X509_CRL_sort := nil;
  X509_CRL_up_ref := nil; {introduced 1.1.0}
  X509_CRL_get_version := nil; {introduced 1.1.0}
  X509_CRL_get0_lastUpdate := nil; {introduced 1.1.0}
  X509_CRL_get0_nextUpdate := nil; {introduced 1.1.0}
  X509_CRL_get0_extensions := nil;
  X509_CRL_get_issuer := nil; {introduced 1.1.0}
  X509_CRL_get_REVOKED := nil;
  X509_CRL_get0_signature := nil; {introduced 1.1.0}
  X509_CRL_get_signature_nid := nil; {introduced 1.1.0}
  i2d_re_X509_CRL_tbs := nil; {introduced 1.1.0}
  X509_REVOKED_get0_serialNumber := nil; {introduced 1.1.0}
  X509_REVOKED_set_serialNumber := nil;
  X509_REVOKED_get0_revocationDate := nil; {introduced 1.1.0}
  X509_REVOKED_set_revocationDate := nil;
  X509_REVOKED_get0_extensions := nil;
  X509_CRL_diff := nil;
  X509_REQ_check_private_key := nil;
  X509_check_private_key := nil;
  X509_CRL_check_suiteb := nil;
  X509_issuer_and_serial_cmp := nil;
  X509_issuer_and_serial_hash := nil;
  X509_issuer_name_cmp := nil;
  X509_issuer_name_hash := nil;
  X509_subject_name_cmp := nil;
  X509_subject_name_hash := nil;
  X509_cmp := nil;
  X509_NAME_cmp := nil;
  X509_NAME_hash := nil; {removed 3.0.0}
  X509_NAME_hash_old := nil;
  X509_CRL_cmp := nil;
  X509_CRL_match := nil;
  X509_aux_print := nil; {introduced 1.1.0}
  X509_NAME_print := nil;
  X509_NAME_print_ex := nil;
  X509_print_ex := nil;
  X509_print := nil;
  X509_ocspid_print := nil;
  X509_CRL_print_ex := nil; {introduced 1.1.0}
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
  X509_NAME_ENTRY_set := nil; {introduced 1.1.0}
  X509_NAME_get0_der := nil; {introduced 1.1.0}
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
  X509_verify_cert := nil;
  PKCS5_pbe_set0_algor := nil;
  PKCS5_pbe_set := nil;
  PKCS5_pbe2_set := nil;
  PKCS5_pbe2_set_iv := nil;
  PKCS5_pbe2_set_scrypt := nil; {introduced 1.1.0}
  PKCS5_pbkdf2_set := nil;
  EVP_PKCS82PKEY := nil;
  EVP_PKEY2PKCS8 := nil;
  PKCS8_pkey_set0 := nil;
  PKCS8_pkey_get0 := nil;
  PKCS8_pkey_add1_attr_by_NID := nil; {introduced 1.1.0}
  X509_PUBKEY_set0_param := nil;
  X509_PUBKEY_get0_param := nil;
  X509_check_trust := nil;
  X509_TRUST_get_count := nil;
  X509_TRUST_get0 := nil;
  X509_TRUST_get_by_id := nil;
  X509_TRUST_cleanup := nil;
  X509_TRUST_get_flags := nil;
  X509_TRUST_get0_name := nil;
  X509_TRUST_get_trust := nil;
  X509_NAME_hash_ex := nil; {introduced 3.0.0}

   sk_X509_new:= nil;
  sk_X509_new_null := nil;
  sk_X509_free := nil;
  sk_X509_num := nil;
  sk_X509_value := nil;
  sk_X509_push := nil;
  sk_X509_dup := nil;
  sk_X509_find := nil;
  sk_X509_pop_free := nil;
  sk_X509_NAME_new:= nil;
  sk_X509_NAME_new_null := nil;
  sk_X509_NAME_free := nil;
  sk_X509_NAME_num := nil;
  sk_X509_NAME_value := nil;
  sk_X509_NAME_push := nil;
  sk_X509_NAME_dup := nil;
  sk_X509_NAME_find := nil;
  sk_X509_NAME_pop_free := nil;
  sk_X509_NAME_ENTRY_new:= nil;
  sk_X509_NAME_ENTRY_new_null := nil;
  sk_X509_NAME_ENTRY_free := nil;
  sk_X509_NAME_ENTRY_num := nil;
  sk_X509_NAME_ENTRY_value := nil;
  sk_X509_NAME_ENTRY_push := nil;
  sk_X509_NAME_ENTRY_dup := nil;
  sk_X509_NAME_ENTRY_find := nil;
  sk_X509_NAME_ENTRY_pop_free := nil;
  sk_X509_INFO_new:= nil;
  sk_X509_INFO_new_null := nil;
  sk_X509_INFO_free := nil;
  sk_X509_INFO_num := nil;
  sk_X509_INFO_value := nil;
  sk_X509_INFO_push := nil;
  sk_X509_INFO_dup := nil;
  sk_X509_INFO_find := nil;
  sk_X509_INFO_pop_free := nil;
  sk_X509_EXTENSION_new := nil;
  sk_X509_EXTENSION_new_null := nil;
  sk_X509_EXTENSION_free := nil;
  sk_X509_EXTENSION_num := nil;
  sk_X509_EXTENSION_value := nil;
  sk_X509_EXTENSION_push := nil;
  sk_X509_EXTENSION_dup := nil;
  sk_X509_EXTENSION_find := nil;
  sk_X509_EXTENSION_pop_free := nil;
  sk_X509_TRUST_new:= nil;
  sk_X509_TRUST_new_null := nil;
  sk_X509_TRUST_free := nil;
  sk_X509_TRUST_num := nil;
  sk_X509_TRUST_value := nil;
  sk_X509_TRUST_push := nil;
  sk_X509_TRUST_dup := nil;
  sk_X509_TRUST_find := nil;
  sk_X509_TRUST_pop_free := nil;
  sk_X509_REVOKED_new:= nil;
  sk_X509_REVOKED_new_null := nil;
  sk_X509_REVOKED_free := nil;
  sk_X509_REVOKED_num := nil;
  sk_X509_REVOKED_value := nil;
  sk_X509_REVOKED_push := nil;
  sk_X509_REVOKED_dup := nil;
  sk_X509_REVOKED_find := nil;
  sk_X509_REVOKED_pop_free := nil;
  sk_X509_CRL_new:= nil;
  sk_X509_CRL_new_null := nil;
  sk_X509_CRL_free := nil;
  sk_X509_CRL_num := nil;
  sk_X509_CRL_value := nil;
  sk_X509_CRL_push := nil;
  sk_X509_CRL_dup := nil;
  sk_X509_CRL_find := nil;
  sk_X509_CRL_pop_free := nil;
  sk_X509_ATTRIBUTE_new:= nil;
  sk_X509_ATTRIBUTE_new_null := nil;
  sk_X509_ATTRIBUTE_free := nil;
  sk_X509_ATTRIBUTE_num := nil;
  sk_X509_ATTRIBUTE_value := nil;
  sk_X509_ATTRIBUTE_push := nil;
  sk_X509_ATTRIBUTE_dup := nil;
  sk_X509_ATTRIBUTE_find := nil;
  sk_X509_ATTRIBUTE_pop_free := nil;
end;
  {$ENDIF}
{$ELSE}
function X509_NAME_hash(x: PX509_NAME): TIdC_ULONG;
begin
  Result := X509_NAME_hash_ex(x,nil,nil,nil);
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
