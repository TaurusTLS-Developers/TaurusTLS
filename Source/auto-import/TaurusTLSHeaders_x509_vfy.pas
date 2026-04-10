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

unit TaurusTLSHeaders_x509_vfy;

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
  Px509_trust_st = ^Tx509_trust_st;
  Tx509_trust_st =   record
    trust: TIdC_INT;
    flags: TIdC_INT;
    check_trust: Tsk_X509_VERIFY_PARAM_copyfunc_func_cb;
    name: PIdAnsiChar;
    arg1: TIdC_INT;
    arg2: Pointer;
  end;
  {$EXTERNALSYM Px509_trust_st}

  Pstack_st_X509_POLICY_NODE = ^Tstack_st_X509_POLICY_NODE;
  Tstack_st_X509_POLICY_NODE =   record end;
  {$EXTERNALSYM Pstack_st_X509_POLICY_NODE}

  Pstack_st_POLICYQUALINFO = ^Tstack_st_POLICYQUALINFO;
  Tstack_st_POLICYQUALINFO =   record end;
  {$EXTERNALSYM Pstack_st_POLICYQUALINFO}


// =============================================================================
// ENUM TYPE DECLARATIONS
// =============================================================================
type
  // Enum: X509_LOOKUP_TYPE
  TX509_LOOKUP_TYPE = (
    X509_LU_NONE = 0,
    X509_LU_X509 = 1,
    X509_LU_CRL = 2
  );


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // X509_TRUST_set_default_trust_cb = function(arg1: TIdC_INT; arg2: PX509; arg3: TIdC_INT): TIdC_INT; cdecl;
  TX509_STORE_CTX_verify_cb = function(arg1: TIdC_INT; arg2: PX509_STORE_CTX): TIdC_INT; cdecl;
  TX509_STORE_CTX_verify_fn = function(arg1: PX509_STORE_CTX): TIdC_INT; cdecl;
  TX509_STORE_CTX_get_issuer_fn = function(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT; cdecl;
  TX509_STORE_CTX_check_issued_fn = function(ctx: PX509_STORE_CTX; x: PX509; issuer: PX509): TIdC_INT; cdecl;
  TX509_STORE_CTX_check_revocation_fn = function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
  TX509_STORE_CTX_get_crl_fn = function(ctx: PX509_STORE_CTX; crl: PPX509_CRL; x: PX509): TIdC_INT; cdecl;
  TX509_STORE_CTX_check_crl_fn = function(ctx: PX509_STORE_CTX; crl: PX509_CRL): TIdC_INT; cdecl;
  TX509_STORE_CTX_cert_crl_fn = function(ctx: PX509_STORE_CTX; crl: PX509_CRL; x: PX509): TIdC_INT; cdecl;
  TX509_STORE_CTX_check_policy_fn = function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
  TX509_STORE_CTX_lookup_certs_fn = function(ctx: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl;
  TX509_STORE_CTX_lookup_crls_fn = function(ctx: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl;
  TX509_STORE_CTX_cleanup_fn = function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
  TX509_LOOKUP_ctrl_fn = function(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl;
  TX509_LOOKUP_ctrl_ex_fn = function(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
  TX509_LOOKUP_get_by_subject_fn = function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl;
  TX509_LOOKUP_get_by_subject_ex_fn = function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
  TX509_LOOKUP_get_by_issuer_serial_fn = function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; cdecl;
  TX509_LOOKUP_get_by_fingerprint_fn = function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; bytes: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl;
  TX509_LOOKUP_get_by_alias_fn = function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // X509_LOOKUP_meth_set_new_item_new_item_cb = function(ctx: PX509_LOOKUP): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  X509_LU_RETRY = -1;
  X509_LU_FAIL = 0;
  X509_TRUST_DEFAULT = 0;
  X509_TRUST_COMPAT = 1;
  X509_TRUST_SSL_CLIENT = 2;
  X509_TRUST_SSL_SERVER = 3;
  X509_TRUST_EMAIL = 4;
  X509_TRUST_OBJECT_SIGN = 5;
  X509_TRUST_OCSP_SIGN = 6;
  X509_TRUST_OCSP_REQUEST = 7;
  X509_TRUST_TSA = 8;
  X509_TRUST_MIN = 1;
  X509_TRUST_MAX = 8;
  X509_TRUST_DYNAMIC = (1 shl 0);
  X509_TRUST_DYNAMIC_NAME = (1 shl 1);
  X509_TRUST_NO_SS_COMPAT = (1 shl 2);
  X509_TRUST_DO_SS_COMPAT = (1 shl 3);
  X509_TRUST_OK_ANY_EKU = (1 shl 4);
  X509_TRUST_TRUSTED = 1;
  X509_TRUST_REJECTED = 2;
  X509_TRUST_UNTRUSTED = 3;
  X509_L_FILE_LOAD = 1;
  X509_L_ADD_DIR = 2;
  X509_L_ADD_STORE = 3;
  X509_L_LOAD_STORE = 4;
  X509_V_OK = 0;
  X509_V_ERR_UNSPECIFIED = 1;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2;
  X509_V_ERR_UNABLE_TO_GET_CRL = 3;
  X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4;
  X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5;
  X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6;
  X509_V_ERR_CERT_SIGNATURE_FAILURE = 7;
  X509_V_ERR_CRL_SIGNATURE_FAILURE = 8;
  X509_V_ERR_CERT_NOT_YET_VALID = 9;
  X509_V_ERR_CERT_HAS_EXPIRED = 10;
  X509_V_ERR_CRL_NOT_YET_VALID = 11;
  X509_V_ERR_CRL_HAS_EXPIRED = 12;
  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13;
  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14;
  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15;
  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16;
  X509_V_ERR_OUT_OF_MEM = 17;
  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
  X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;
  X509_V_ERR_CERT_CHAIN_TOO_LONG = 22;
  X509_V_ERR_CERT_REVOKED = 23;
  X509_V_ERR_NO_ISSUER_PUBLIC_KEY = 24;
  X509_V_ERR_PATH_LENGTH_EXCEEDED = 25;
  X509_V_ERR_INVALID_PURPOSE = 26;
  X509_V_ERR_CERT_UNTRUSTED = 27;
  X509_V_ERR_CERT_REJECTED = 28;
  X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29;
  X509_V_ERR_AKID_SKID_MISMATCH = 30;
  X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;
  X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32;
  X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33;
  X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34;
  X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35;
  X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36;
  X509_V_ERR_INVALID_NON_CA = 37;
  X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38;
  X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39;
  X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40;
  X509_V_ERR_INVALID_EXTENSION = 41;
  X509_V_ERR_INVALID_POLICY_EXTENSION = 42;
  X509_V_ERR_NO_EXPLICIT_POLICY = 43;
  X509_V_ERR_DIFFERENT_CRL_SCOPE = 44;
  X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = 45;
  X509_V_ERR_UNNESTED_RESOURCE = 46;
  X509_V_ERR_PERMITTED_VIOLATION = 47;
  X509_V_ERR_EXCLUDED_VIOLATION = 48;
  X509_V_ERR_SUBTREE_MINMAX = 49;
  X509_V_ERR_APPLICATION_VERIFICATION = 50;
  X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = 51;
  X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 52;
  X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = 53;
  X509_V_ERR_CRL_PATH_VALIDATION_ERROR = 54;
  X509_V_ERR_PATH_LOOP = 55;
  X509_V_ERR_SUITE_B_INVALID_VERSION = 56;
  X509_V_ERR_SUITE_B_INVALID_ALGORITHM = 57;
  X509_V_ERR_SUITE_B_INVALID_CURVE = 58;
  X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM = 59;
  X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED = 60;
  X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = 61;
  X509_V_ERR_HOSTNAME_MISMATCH = 62;
  X509_V_ERR_EMAIL_MISMATCH = 63;
  X509_V_ERR_IP_ADDRESS_MISMATCH = 64;
  X509_V_ERR_DANE_NO_MATCH = 65;
  X509_V_ERR_EE_KEY_TOO_SMALL = 66;
  X509_V_ERR_CA_KEY_TOO_SMALL = 67;
  X509_V_ERR_CA_MD_TOO_WEAK = 68;
  X509_V_ERR_INVALID_CALL = 69;
  X509_V_ERR_STORE_LOOKUP = 70;
  X509_V_ERR_NO_VALID_SCTS = 71;
  X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION = 72;
  X509_V_ERR_OCSP_VERIFY_NEEDED = 73;
  X509_V_ERR_OCSP_VERIFY_FAILED = 74;
  X509_V_ERR_OCSP_CERT_UNKNOWN = 75;
  X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM = 76;
  X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH = 77;
  X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY = 78;
  X509_V_ERR_INVALID_CA = 79;
  X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA = 80;
  X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN = 81;
  X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA = 82;
  X509_V_ERR_ISSUER_NAME_EMPTY = 83;
  X509_V_ERR_SUBJECT_NAME_EMPTY = 84;
  X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER = 85;
  X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER = 86;
  X509_V_ERR_EMPTY_SUBJECT_ALT_NAME = 87;
  X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL = 88;
  X509_V_ERR_CA_BCONS_NOT_CRITICAL = 89;
  X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL = 90;
  X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL = 91;
  X509_V_ERR_CA_CERT_MISSING_KEY_USAGE = 92;
  X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 = 93;
  X509_V_ERR_EC_KEY_EXPLICIT_PARAMS = 94;
  X509_V_ERR_RPK_UNTRUSTED = 95;
  X509_V_ERR_OCSP_RESP_INVALID = 96;
  X509_V_ERR_OCSP_SIGNATURE_FAILURE = 97;
  X509_V_ERR_OCSP_NOT_YET_VALID = 98;
  X509_V_ERR_OCSP_HAS_EXPIRED = 99;
  X509_V_ERR_OCSP_NO_RESPONSE = 100;
  X509_V_ERR_CRL_VERIFY_FAILED = 101;
  X509_V_FLAG_CB_ISSUER_CHECK = $0;
  X509_V_FLAG_USE_CHECK_TIME = $2;
  X509_V_FLAG_CRL_CHECK = $4;
  X509_V_FLAG_CRL_CHECK_ALL = $8;
  X509_V_FLAG_IGNORE_CRITICAL = $10;
  X509_V_FLAG_X509_STRICT = $20;
  X509_V_FLAG_ALLOW_PROXY_CERTS = $40;
  X509_V_FLAG_POLICY_CHECK = $80;
  X509_V_FLAG_EXPLICIT_POLICY = $100;
  X509_V_FLAG_INHIBIT_ANY = $200;
  X509_V_FLAG_INHIBIT_MAP = $400;
  X509_V_FLAG_NOTIFY_POLICY = $800;
  X509_V_FLAG_EXTENDED_CRL_SUPPORT = $1000;
  X509_V_FLAG_USE_DELTAS = $2000;
  X509_V_FLAG_CHECK_SS_SIGNATURE = $4000;
  X509_V_FLAG_TRUSTED_FIRST = $8000;
  X509_V_FLAG_SUITEB_128_LOS_ONLY = $10000;
  X509_V_FLAG_SUITEB_192_LOS = $20000;
  X509_V_FLAG_SUITEB_128_LOS = $30000;
  X509_V_FLAG_PARTIAL_CHAIN = $80000;
  X509_V_FLAG_NO_ALT_CHAINS = $100000;
  X509_V_FLAG_NO_CHECK_TIME = $200000;
  X509_V_FLAG_OCSP_RESP_CHECK = $400000;
  X509_V_FLAG_OCSP_RESP_CHECK_ALL = $800000;
  X509_VP_FLAG_DEFAULT = $1;
  X509_VP_FLAG_OVERWRITE = $2;
  X509_VP_FLAG_RESET_FLAGS = $4;
  X509_VP_FLAG_LOCKED = $8;
  X509_VP_FLAG_ONCE = $10;
  X509_V_FLAG_POLICY_MASK = (X509_V_FLAG_POLICY_CHECK or X509_V_FLAG_EXPLICIT_POLICY or X509_V_FLAG_INHIBIT_ANY or X509_V_FLAG_INHIBIT_MAP);
  DANE_FLAG_NO_DANE_EE_NAMECHECKS = (1 shl 0);
  X509_PCY_TREE_FAILURE = -2;
  X509_PCY_TREE_INVALID = -1;
  X509_PCY_TREE_INTERNAL = 0;
  X509_PCY_TREE_VALID = 1;
  X509_PCY_TREE_EMPTY = 2;
  X509_PCY_TREE_EXPLICIT = 4;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  X509_TRUST_set: function(t: PIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_set}

  X509_TRUST_get_count: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_count}

  X509_TRUST_get0: function(idx: TIdC_INT): PX509_TRUST; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get0}

  X509_TRUST_get_by_id: function(id: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_by_id}

  X509_TRUST_add: function(id: TIdC_INT; flags: TIdC_INT; ck: Tsk_X509_VERIFY_PARAM_copyfunc_func_cb; name: PIdAnsiChar; arg1: TIdC_INT; arg2: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_add}

  X509_TRUST_cleanup: function: void; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_cleanup}

  X509_TRUST_get_flags: function(xp: PX509_TRUST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_flags}

  X509_TRUST_get0_name: function(xp: PX509_TRUST): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get0_name}

  X509_TRUST_get_trust: function(xp: PX509_TRUST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_get_trust}

  X509_trusted: function(x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_trusted}

  X509_add1_trust_object: function(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add1_trust_object}

  X509_add1_reject_object: function(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add1_reject_object}

  X509_trust_clear: function(x: PX509): void; cdecl = nil;
  {$EXTERNALSYM X509_trust_clear}

  X509_reject_clear: function(x: PX509): void; cdecl = nil;
  {$EXTERNALSYM X509_reject_clear}

  X509_get0_trust_objects: function(x: PX509): Pstack_st_ASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_get0_trust_objects}

  X509_get0_reject_objects: function(x: PX509): Pstack_st_ASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_get0_reject_objects}

  X509_TRUST_set_default: function(trust: TX509_TRUST_set_default_trust_cb): TX509_TRUST_set_default_trust_cb; cdecl = nil;
  {$EXTERNALSYM X509_TRUST_set_default}

  X509_check_trust: function(x: PX509; id: TIdC_INT; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_trust}

  X509_verify_cert: function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_verify_cert}

  X509_STORE_CTX_verify: function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_verify}

  X509_build_chain: function(target: PX509; certs: Pstack_st_X509; store: PX509_STORE; with_self_signed: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM X509_build_chain}

  X509_STORE_set_depth: function(store: PX509_STORE; depth: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_depth}

  X509_STORE_CTX_print_verify_cb: function(ok: TIdC_INT; ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_print_verify_cb}

  X509_STORE_CTX_set_depth: function(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_depth}

  X509_OBJECT_idx_by_subject: function(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_idx_by_subject}

  X509_OBJECT_retrieve_by_subject: function(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_retrieve_by_subject}

  X509_OBJECT_retrieve_match: function(h: Pstack_st_X509_OBJECT; x: PX509_OBJECT): PX509_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_retrieve_match}

  X509_OBJECT_up_ref_count: function(a: PX509_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_up_ref_count}

  X509_OBJECT_new: function: PX509_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_new}

  X509_OBJECT_free: function(a: PX509_OBJECT): void; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_free}

  X509_OBJECT_get_type: function(a: PX509_OBJECT): TX509_LOOKUP_TYPE; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_get_type}

  X509_OBJECT_get0_X509: function(a: PX509_OBJECT): PX509; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_get0_X509}

  X509_OBJECT_set1_X509: function(a: PX509_OBJECT; obj: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_set1_X509}

  X509_OBJECT_get0_X509_CRL: function(a: PX509_OBJECT): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_get0_X509_CRL}

  X509_OBJECT_set1_X509_CRL: function(a: PX509_OBJECT; obj: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_OBJECT_set1_X509_CRL}

  X509_STORE_new: function: PX509_STORE; cdecl = nil;
  {$EXTERNALSYM X509_STORE_new}

  X509_STORE_free: function(xs: PX509_STORE): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_free}

  X509_STORE_lock: function(xs: PX509_STORE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_lock}

  X509_STORE_unlock: function(xs: PX509_STORE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_unlock}

  X509_STORE_up_ref: function(xs: PX509_STORE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_up_ref}

  X509_STORE_get0_objects: function(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get0_objects}

  X509_STORE_get1_objects: function(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get1_objects}

  X509_STORE_get1_all_certs: function(xs: PX509_STORE): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get1_all_certs}

  X509_STORE_CTX_get1_certs: function(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get1_certs}

  X509_STORE_CTX_get1_crls: function(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get1_crls}

  X509_STORE_set_flags: function(xs: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_flags}

  X509_STORE_set_purpose: function(xs: PX509_STORE; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_purpose}

  X509_STORE_set_trust: function(xs: PX509_STORE; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_trust}

  X509_STORE_set1_param: function(xs: PX509_STORE; pm: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set1_param}

  X509_STORE_get0_param: function(xs: PX509_STORE): PX509_VERIFY_PARAM; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get0_param}

  X509_STORE_set_verify: function(xs: PX509_STORE; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_verify}

  X509_STORE_CTX_set_verify: function(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_verify}

  X509_STORE_get_verify: function(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_verify}

  X509_STORE_set_verify_cb: function(xs: PX509_STORE; verify_cb: TX509_STORE_CTX_verify_cb): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_verify_cb}

  X509_STORE_get_verify_cb: function(xs: PX509_STORE): TX509_STORE_CTX_verify_cb; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_verify_cb}

  X509_STORE_set_get_issuer: function(xs: PX509_STORE; get_issuer: TX509_STORE_CTX_get_issuer_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_get_issuer}

  X509_STORE_get_get_issuer: function(xs: PX509_STORE): TX509_STORE_CTX_get_issuer_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_get_issuer}

  X509_STORE_set_check_issued: function(xs: PX509_STORE; check_issued: TX509_STORE_CTX_check_issued_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_check_issued}

  X509_STORE_get_check_issued: function(s: PX509_STORE): TX509_STORE_CTX_check_issued_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_check_issued}

  X509_STORE_set_check_revocation: function(xs: PX509_STORE; check_revocation: TX509_STORE_CTX_cleanup_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_check_revocation}

  X509_STORE_get_check_revocation: function(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_check_revocation}

  X509_STORE_set_get_crl: function(xs: PX509_STORE; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_get_crl}

  X509_STORE_get_get_crl: function(xs: PX509_STORE): TX509_STORE_CTX_get_crl_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_get_crl}

  X509_STORE_set_check_crl: function(xs: PX509_STORE; check_crl: TX509_STORE_CTX_check_crl_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_check_crl}

  X509_STORE_get_check_crl: function(xs: PX509_STORE): TX509_STORE_CTX_check_crl_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_check_crl}

  X509_STORE_set_cert_crl: function(xs: PX509_STORE; cert_crl: TX509_STORE_CTX_cert_crl_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_cert_crl}

  X509_STORE_get_cert_crl: function(xs: PX509_STORE): TX509_STORE_CTX_cert_crl_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_cert_crl}

  X509_STORE_set_check_policy: function(xs: PX509_STORE; check_policy: TX509_STORE_CTX_cleanup_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_check_policy}

  X509_STORE_get_check_policy: function(s: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_check_policy}

  X509_STORE_set_lookup_certs: function(xs: PX509_STORE; lookup_certs: TX509_STORE_CTX_lookup_certs_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_lookup_certs}

  X509_STORE_get_lookup_certs: function(s: PX509_STORE): TX509_STORE_CTX_lookup_certs_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_lookup_certs}

  X509_STORE_set_lookup_crls: function(xs: PX509_STORE; lookup_crls: TX509_STORE_CTX_lookup_crls_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_lookup_crls}

  X509_STORE_get_lookup_crls: function(xs: PX509_STORE): TX509_STORE_CTX_lookup_crls_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_lookup_crls}

  X509_STORE_set_cleanup: function(xs: PX509_STORE; cleanup: TX509_STORE_CTX_cleanup_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_cleanup}

  X509_STORE_get_cleanup: function(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_cleanup}

  X509_STORE_set_ex_data: function(xs: PX509_STORE; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_ex_data}

  X509_STORE_get_ex_data: function(xs: PX509_STORE; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_STORE_get_ex_data}

  X509_STORE_CTX_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_STORE_CTX; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_new_ex}

  X509_STORE_CTX_new: function: PX509_STORE_CTX; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_new}

  X509_STORE_CTX_get1_issuer: function(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get1_issuer}

  X509_STORE_CTX_free: function(ctx: PX509_STORE_CTX): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_free}

  X509_STORE_CTX_init: function(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; target: PX509; untrusted: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_init}

  X509_STORE_CTX_init_rpk: function(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; rpk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_init_rpk}

  X509_STORE_CTX_set0_trusted_stack: function(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set0_trusted_stack}

  X509_STORE_CTX_cleanup: function(ctx: PX509_STORE_CTX): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_cleanup}

  X509_STORE_CTX_get0_store: function(ctx: PX509_STORE_CTX): PX509_STORE; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_store}

  X509_STORE_CTX_get0_cert: function(ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_cert}

  X509_STORE_CTX_get0_rpk: function(ctx: PX509_STORE_CTX): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_rpk}

  X509_STORE_CTX_get0_untrusted: function(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_untrusted}

  X509_STORE_CTX_set0_untrusted: function(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set0_untrusted}

  X509_STORE_CTX_set_verify_cb: function(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_verify_cb): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_verify_cb}

  X509_STORE_CTX_get_verify_cb: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_verify_cb; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_verify_cb}

  X509_STORE_CTX_get_verify: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_verify}

  X509_STORE_CTX_get_get_issuer: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_issuer_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_get_issuer}

  X509_STORE_CTX_get_check_issued: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_issued_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_check_issued}

  X509_STORE_CTX_get_check_revocation: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_check_revocation}

  X509_STORE_CTX_set_get_crl: function(ctx: PX509_STORE_CTX; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_get_crl}

  X509_STORE_CTX_get_get_crl: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_crl_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_get_crl}

  X509_STORE_CTX_get_check_crl: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_crl_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_check_crl}

  X509_STORE_CTX_get_cert_crl: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cert_crl_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_cert_crl}

  X509_STORE_CTX_get_check_policy: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_check_policy}

  X509_STORE_CTX_get_lookup_certs: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_certs_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_lookup_certs}

  X509_STORE_CTX_get_lookup_crls: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_crls_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_lookup_crls}

  X509_STORE_CTX_get_cleanup: function(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_cleanup}

  X509_STORE_add_lookup: function(xs: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl = nil;
  {$EXTERNALSYM X509_STORE_add_lookup}

  X509_LOOKUP_hash_dir: function: PX509_LOOKUP_METHOD; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_hash_dir}

  X509_LOOKUP_file: function: PX509_LOOKUP_METHOD; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_file}

  X509_LOOKUP_store: function: PX509_LOOKUP_METHOD; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_store}

  X509_LOOKUP_meth_new: function(name: PIdAnsiChar): PX509_LOOKUP_METHOD; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_new}

  X509_LOOKUP_meth_free: function(method: PX509_LOOKUP_METHOD): void; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_free}

  X509_LOOKUP_meth_set_new_item: function(method: PX509_LOOKUP_METHOD; new_item: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_new_item}

  X509_LOOKUP_meth_get_new_item: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_new_item}

  X509_LOOKUP_meth_set_free: function(method: PX509_LOOKUP_METHOD; free_fn: Tsk_X509_LOOKUP_freefunc): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_free}

  X509_LOOKUP_meth_get_free: function(method: PX509_LOOKUP_METHOD): Tsk_X509_LOOKUP_freefunc; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_free}

  X509_LOOKUP_meth_set_init: function(method: PX509_LOOKUP_METHOD; init: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_init}

  X509_LOOKUP_meth_get_init: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_init}

  X509_LOOKUP_meth_set_shutdown: function(method: PX509_LOOKUP_METHOD; shutdown: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_shutdown}

  X509_LOOKUP_meth_get_shutdown: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_shutdown}

  X509_LOOKUP_meth_set_ctrl: function(method: PX509_LOOKUP_METHOD; ctrl_fn: TX509_LOOKUP_ctrl_fn): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_ctrl}

  X509_LOOKUP_meth_get_ctrl: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_ctrl_fn; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_ctrl}

  X509_LOOKUP_meth_set_get_by_subject: function(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_subject_fn): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_subject}

  X509_LOOKUP_meth_get_get_by_subject: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_subject_fn; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_subject}

  X509_LOOKUP_meth_set_get_by_issuer_serial: function(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_issuer_serial_fn): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_issuer_serial}

  X509_LOOKUP_meth_get_get_by_issuer_serial: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_issuer_serial_fn; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_issuer_serial}

  X509_LOOKUP_meth_set_get_by_fingerprint: function(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_fingerprint_fn): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_fingerprint}

  X509_LOOKUP_meth_get_get_by_fingerprint: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_fingerprint_fn; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_fingerprint}

  X509_LOOKUP_meth_set_get_by_alias: function(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_alias_fn): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_set_get_by_alias}

  X509_LOOKUP_meth_get_get_by_alias: function(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_alias_fn; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_meth_get_get_by_alias}

  X509_STORE_add_cert: function(xs: PX509_STORE; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_add_cert}

  X509_STORE_add_crl: function(xs: PX509_STORE; x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_add_crl}

  X509_STORE_CTX_get_by_subject: function(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_by_subject}

  X509_STORE_CTX_get_obj_by_subject: function(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_obj_by_subject}

  X509_LOOKUP_ctrl: function(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_ctrl}

  X509_LOOKUP_ctrl_ex: function(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_ctrl_ex}

  X509_load_cert_file: function(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_load_cert_file}

  X509_load_cert_file_ex: function(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_load_cert_file_ex}

  X509_load_crl_file: function(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_load_crl_file}

  X509_load_cert_crl_file: function(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_load_cert_crl_file}

  X509_load_cert_crl_file_ex: function(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_load_cert_crl_file_ex}

  X509_LOOKUP_new: function(method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_new}

  X509_LOOKUP_free: function(ctx: PX509_LOOKUP): void; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_free}

  X509_LOOKUP_init: function(ctx: PX509_LOOKUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_init}

  X509_LOOKUP_by_subject: function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_by_subject}

  X509_LOOKUP_by_subject_ex: function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_by_subject_ex}

  X509_LOOKUP_by_issuer_serial: function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_by_issuer_serial}

  X509_LOOKUP_by_fingerprint: function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; bytes: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_by_fingerprint}

  X509_LOOKUP_by_alias: function(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_by_alias}

  X509_LOOKUP_set_method_data: function(ctx: PX509_LOOKUP; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_set_method_data}

  X509_LOOKUP_get_method_data: function(ctx: PX509_LOOKUP): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_get_method_data}

  X509_LOOKUP_get_store: function(ctx: PX509_LOOKUP): PX509_STORE; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_get_store}

  X509_LOOKUP_shutdown: function(ctx: PX509_LOOKUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_LOOKUP_shutdown}

  X509_STORE_load_file: function(xs: PX509_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_load_file}

  X509_STORE_load_path: function(xs: PX509_STORE; path: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_load_path}

  X509_STORE_load_store: function(xs: PX509_STORE; store: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_load_store}

  X509_STORE_load_locations: function(s: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_load_locations}

  X509_STORE_set_default_paths: function(xs: PX509_STORE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_default_paths}

  X509_STORE_load_file_ex: function(xs: PX509_STORE; _file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_load_file_ex}

  X509_STORE_load_store_ex: function(xs: PX509_STORE; store: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_load_store_ex}

  X509_STORE_load_locations_ex: function(xs: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_load_locations_ex}

  X509_STORE_set_default_paths_ex: function(xs: PX509_STORE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_set_default_paths_ex}

  X509_STORE_CTX_set_ex_data: function(ctx: PX509_STORE_CTX; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_ex_data}

  X509_STORE_CTX_get_ex_data: function(ctx: PX509_STORE_CTX; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_ex_data}

  X509_STORE_CTX_get_error: function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_error}

  X509_STORE_CTX_set_error: function(ctx: PX509_STORE_CTX; s: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_error}

  X509_STORE_CTX_get_error_depth: function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_error_depth}

  X509_STORE_CTX_set_error_depth: function(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_error_depth}

  X509_STORE_CTX_get_current_cert: function(ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_current_cert}

  X509_STORE_CTX_set_current_cert: function(ctx: PX509_STORE_CTX; x: PX509): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_current_cert}

  X509_STORE_CTX_get0_current_issuer: function(ctx: PX509_STORE_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_current_issuer}

  X509_STORE_CTX_get0_current_crl: function(ctx: PX509_STORE_CTX): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_current_crl}

  X509_STORE_CTX_get0_parent_ctx: function(ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_parent_ctx}

  X509_STORE_CTX_get0_chain: function(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_chain}

  X509_STORE_CTX_get1_chain: function(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get1_chain}

  X509_STORE_CTX_set_cert: function(ctx: PX509_STORE_CTX; target: PX509): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_cert}

  X509_STORE_CTX_set0_rpk: function(ctx: PX509_STORE_CTX; target: PEVP_PKEY): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set0_rpk}

  X509_STORE_CTX_set0_verified_chain: function(c: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set0_verified_chain}

  X509_STORE_CTX_set0_crls: function(ctx: PX509_STORE_CTX; sk: Pstack_st_X509_CRL): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set0_crls}

  X509_STORE_CTX_set_ocsp_resp: function(ctx: PX509_STORE_CTX; sk: Pstack_st_OCSP_RESPONSE): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_ocsp_resp}

  X509_STORE_CTX_set_purpose: function(ctx: PX509_STORE_CTX; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_purpose}

  X509_STORE_CTX_set_trust: function(ctx: PX509_STORE_CTX; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_trust}

  X509_STORE_CTX_purpose_inherit: function(ctx: PX509_STORE_CTX; def_purpose: TIdC_INT; purpose: TIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_purpose_inherit}

  X509_STORE_CTX_set_flags: function(ctx: PX509_STORE_CTX; flags: TIdC_ULONG): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_flags}

  X509_STORE_CTX_set_time: function(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_time}

  X509_STORE_CTX_set_current_reasons: function(ctx: PX509_STORE_CTX; current_reasons: TIdC_UINT): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_current_reasons}

  X509_STORE_CTX_get0_policy_tree: function(ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_policy_tree}

  X509_STORE_CTX_get_explicit_policy: function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_explicit_policy}

  X509_STORE_CTX_get_num_untrusted: function(ctx: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get_num_untrusted}

  X509_STORE_CTX_get0_param: function(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_get0_param}

  X509_STORE_CTX_set0_param: function(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set0_param}

  X509_STORE_CTX_set_default: function(ctx: PX509_STORE_CTX; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set_default}

  X509_STORE_CTX_set0_dane: function(ctx: PX509_STORE_CTX; dane: PSSL_DANE): void; cdecl = nil;
  {$EXTERNALSYM X509_STORE_CTX_set0_dane}

  X509_VERIFY_PARAM_new: function: PX509_VERIFY_PARAM; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_new}

  X509_VERIFY_PARAM_free: function(param: PX509_VERIFY_PARAM): void; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_free}

  X509_VERIFY_PARAM_inherit: function(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_inherit}

  X509_VERIFY_PARAM_set1: function(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set1}

  X509_VERIFY_PARAM_set1_name: function(param: PX509_VERIFY_PARAM; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_name}

  X509_VERIFY_PARAM_set_flags: function(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_flags}

  X509_VERIFY_PARAM_clear_flags: function(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_clear_flags}

  X509_VERIFY_PARAM_get_flags: function(param: PX509_VERIFY_PARAM): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_flags}

  X509_VERIFY_PARAM_set_purpose: function(param: PX509_VERIFY_PARAM; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_purpose}

  X509_VERIFY_PARAM_get_purpose: function(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_purpose}

  X509_VERIFY_PARAM_set_trust: function(param: PX509_VERIFY_PARAM; trust: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_trust}

  X509_VERIFY_PARAM_set_depth: function(param: PX509_VERIFY_PARAM; depth: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_depth}

  X509_VERIFY_PARAM_set_auth_level: function(param: PX509_VERIFY_PARAM; auth_level: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_auth_level}

  X509_VERIFY_PARAM_get_time: function(param: PX509_VERIFY_PARAM): TIdC_TIMET; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_time}

  X509_VERIFY_PARAM_set_time: function(param: PX509_VERIFY_PARAM; t: TIdC_TIMET): void; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_time}

  X509_VERIFY_PARAM_add0_policy: function(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_add0_policy}

  X509_VERIFY_PARAM_set1_policies: function(param: PX509_VERIFY_PARAM; policies: Pstack_st_ASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_policies}

  X509_VERIFY_PARAM_set_inh_flags: function(param: PX509_VERIFY_PARAM; flags: TIdC_UINT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_inh_flags}

  X509_VERIFY_PARAM_get_inh_flags: function(param: PX509_VERIFY_PARAM): TIdC_UINT32; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_inh_flags}

  X509_VERIFY_PARAM_get0_host: function(param: PX509_VERIFY_PARAM; idx: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get0_host}

  X509_VERIFY_PARAM_set1_host: function(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_host}

  X509_VERIFY_PARAM_add1_host: function(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_add1_host}

  X509_VERIFY_PARAM_set_hostflags: function(param: PX509_VERIFY_PARAM; flags: TIdC_UINT): void; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set_hostflags}

  X509_VERIFY_PARAM_get_hostflags: function(param: PX509_VERIFY_PARAM): TIdC_UINT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_hostflags}

  X509_VERIFY_PARAM_get0_peername: function(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get0_peername}

  X509_VERIFY_PARAM_move_peername: function(arg1: PX509_VERIFY_PARAM; arg2: PX509_VERIFY_PARAM): void; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_move_peername}

  X509_VERIFY_PARAM_get0_email: function(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get0_email}

  X509_VERIFY_PARAM_set1_email: function(param: PX509_VERIFY_PARAM; email: PIdAnsiChar; emaillen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_email}

  X509_VERIFY_PARAM_get1_ip_asc: function(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get1_ip_asc}

  X509_VERIFY_PARAM_set1_ip: function(param: PX509_VERIFY_PARAM; ip: PIdAnsiChar; iplen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_ip}

  X509_VERIFY_PARAM_set1_ip_asc: function(param: PX509_VERIFY_PARAM; ipasc: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_set1_ip_asc}

  X509_VERIFY_PARAM_get_depth: function(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_depth}

  X509_VERIFY_PARAM_get_auth_level: function(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_auth_level}

  X509_VERIFY_PARAM_get0_name: function(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get0_name}

  X509_VERIFY_PARAM_add0_table: function(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_add0_table}

  X509_VERIFY_PARAM_get_count: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get_count}

  X509_VERIFY_PARAM_get0: function(id: TIdC_INT): PX509_VERIFY_PARAM; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_get0}

  X509_VERIFY_PARAM_lookup: function(name: PIdAnsiChar): PX509_VERIFY_PARAM; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_lookup}

  X509_VERIFY_PARAM_table_cleanup: function: void; cdecl = nil;
  {$EXTERNALSYM X509_VERIFY_PARAM_table_cleanup}

  X509_policy_check: function(ptree: PPX509_POLICY_TREE; pexplicit_policy: PIdC_INT; certs: Pstack_st_X509; policy_oids: Pstack_st_ASN1_OBJECT; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_policy_check}

  X509_policy_tree_free: function(tree: PX509_POLICY_TREE): void; cdecl = nil;
  {$EXTERNALSYM X509_policy_tree_free}

  X509_policy_tree_level_count: function(tree: PX509_POLICY_TREE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_policy_tree_level_count}

  X509_policy_tree_get0_level: function(tree: PX509_POLICY_TREE; i: TIdC_INT): PX509_POLICY_LEVEL; cdecl = nil;
  {$EXTERNALSYM X509_policy_tree_get0_level}

  X509_policy_tree_get0_policies: function(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl = nil;
  {$EXTERNALSYM X509_policy_tree_get0_policies}

  X509_policy_tree_get0_user_policies: function(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl = nil;
  {$EXTERNALSYM X509_policy_tree_get0_user_policies}

  X509_policy_level_node_count: function(level: PX509_POLICY_LEVEL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_policy_level_node_count}

  X509_policy_level_get0_node: function(level: PX509_POLICY_LEVEL; i: TIdC_INT): PX509_POLICY_NODE; cdecl = nil;
  {$EXTERNALSYM X509_policy_level_get0_node}

  X509_policy_node_get0_policy: function(node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_policy_node_get0_policy}

  X509_policy_node_get0_qualifiers: function(node: PX509_POLICY_NODE): Pstack_st_POLICYQUALINFO; cdecl = nil;
  {$EXTERNALSYM X509_policy_node_get0_qualifiers}

  X509_policy_node_get0_parent: function(node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl = nil;
  {$EXTERNALSYM X509_policy_node_get0_parent}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function X509_TRUST_set(t: PIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl;
function X509_TRUST_get_count: TIdC_INT; cdecl;
function X509_TRUST_get0(idx: TIdC_INT): PX509_TRUST; cdecl;
function X509_TRUST_get_by_id(id: TIdC_INT): TIdC_INT; cdecl;
function X509_TRUST_add(id: TIdC_INT; flags: TIdC_INT; ck: Tsk_X509_VERIFY_PARAM_copyfunc_func_cb; name: PIdAnsiChar; arg1: TIdC_INT; arg2: Pointer): TIdC_INT; cdecl;
function X509_TRUST_cleanup: void; cdecl;
function X509_TRUST_get_flags(xp: PX509_TRUST): TIdC_INT; cdecl;
function X509_TRUST_get0_name(xp: PX509_TRUST): PIdAnsiChar; cdecl;
function X509_TRUST_get_trust(xp: PX509_TRUST): TIdC_INT; cdecl;
function X509_trusted(x: PX509): TIdC_INT; cdecl;
function X509_add1_trust_object(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl;
function X509_add1_reject_object(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl;
function X509_trust_clear(x: PX509): void; cdecl;
function X509_reject_clear(x: PX509): void; cdecl;
function X509_get0_trust_objects(x: PX509): Pstack_st_ASN1_OBJECT; cdecl;
function X509_get0_reject_objects(x: PX509): Pstack_st_ASN1_OBJECT; cdecl;
function X509_TRUST_set_default(trust: TX509_TRUST_set_default_trust_cb): TX509_TRUST_set_default_trust_cb; cdecl;
function X509_check_trust(x: PX509; id: TIdC_INT; flags: TIdC_INT): TIdC_INT; cdecl;
function X509_verify_cert(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509_STORE_CTX_verify(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509_build_chain(target: PX509; certs: Pstack_st_X509; store: PX509_STORE; with_self_signed: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509; cdecl;
function X509_STORE_set_depth(store: PX509_STORE; depth: TIdC_INT): TIdC_INT; cdecl;
function X509_STORE_CTX_print_verify_cb(ok: TIdC_INT; ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509_STORE_CTX_set_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl;
function X509_OBJECT_idx_by_subject(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): TIdC_INT; cdecl;
function X509_OBJECT_retrieve_by_subject(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl;
function X509_OBJECT_retrieve_match(h: Pstack_st_X509_OBJECT; x: PX509_OBJECT): PX509_OBJECT; cdecl;
function X509_OBJECT_up_ref_count(a: PX509_OBJECT): TIdC_INT; cdecl;
function X509_OBJECT_new: PX509_OBJECT; cdecl;
function X509_OBJECT_free(a: PX509_OBJECT): void; cdecl;
function X509_OBJECT_get_type(a: PX509_OBJECT): TX509_LOOKUP_TYPE; cdecl;
function X509_OBJECT_get0_X509(a: PX509_OBJECT): PX509; cdecl;
function X509_OBJECT_set1_X509(a: PX509_OBJECT; obj: PX509): TIdC_INT; cdecl;
function X509_OBJECT_get0_X509_CRL(a: PX509_OBJECT): PX509_CRL; cdecl;
function X509_OBJECT_set1_X509_CRL(a: PX509_OBJECT; obj: PX509_CRL): TIdC_INT; cdecl;
function X509_STORE_new: PX509_STORE; cdecl;
function X509_STORE_free(xs: PX509_STORE): void; cdecl;
function X509_STORE_lock(xs: PX509_STORE): TIdC_INT; cdecl;
function X509_STORE_unlock(xs: PX509_STORE): TIdC_INT; cdecl;
function X509_STORE_up_ref(xs: PX509_STORE): TIdC_INT; cdecl;
function X509_STORE_get0_objects(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl;
function X509_STORE_get1_objects(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl;
function X509_STORE_get1_all_certs(xs: PX509_STORE): Pstack_st_X509; cdecl;
function X509_STORE_CTX_get1_certs(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl;
function X509_STORE_CTX_get1_crls(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl;
function X509_STORE_set_flags(xs: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_STORE_set_purpose(xs: PX509_STORE; purpose: TIdC_INT): TIdC_INT; cdecl;
function X509_STORE_set_trust(xs: PX509_STORE; trust: TIdC_INT): TIdC_INT; cdecl;
function X509_STORE_set1_param(xs: PX509_STORE; pm: PX509_VERIFY_PARAM): TIdC_INT; cdecl;
function X509_STORE_get0_param(xs: PX509_STORE): PX509_VERIFY_PARAM; cdecl;
function X509_STORE_set_verify(xs: PX509_STORE; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl;
function X509_STORE_CTX_set_verify(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl;
function X509_STORE_get_verify(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_set_verify_cb(xs: PX509_STORE; verify_cb: TX509_STORE_CTX_verify_cb): void; cdecl;
function X509_STORE_get_verify_cb(xs: PX509_STORE): TX509_STORE_CTX_verify_cb; cdecl;
function X509_STORE_set_get_issuer(xs: PX509_STORE; get_issuer: TX509_STORE_CTX_get_issuer_fn): void; cdecl;
function X509_STORE_get_get_issuer(xs: PX509_STORE): TX509_STORE_CTX_get_issuer_fn; cdecl;
function X509_STORE_set_check_issued(xs: PX509_STORE; check_issued: TX509_STORE_CTX_check_issued_fn): void; cdecl;
function X509_STORE_get_check_issued(s: PX509_STORE): TX509_STORE_CTX_check_issued_fn; cdecl;
function X509_STORE_set_check_revocation(xs: PX509_STORE; check_revocation: TX509_STORE_CTX_cleanup_fn): void; cdecl;
function X509_STORE_get_check_revocation(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_set_get_crl(xs: PX509_STORE; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl;
function X509_STORE_get_get_crl(xs: PX509_STORE): TX509_STORE_CTX_get_crl_fn; cdecl;
function X509_STORE_set_check_crl(xs: PX509_STORE; check_crl: TX509_STORE_CTX_check_crl_fn): void; cdecl;
function X509_STORE_get_check_crl(xs: PX509_STORE): TX509_STORE_CTX_check_crl_fn; cdecl;
function X509_STORE_set_cert_crl(xs: PX509_STORE; cert_crl: TX509_STORE_CTX_cert_crl_fn): void; cdecl;
function X509_STORE_get_cert_crl(xs: PX509_STORE): TX509_STORE_CTX_cert_crl_fn; cdecl;
function X509_STORE_set_check_policy(xs: PX509_STORE; check_policy: TX509_STORE_CTX_cleanup_fn): void; cdecl;
function X509_STORE_get_check_policy(s: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_set_lookup_certs(xs: PX509_STORE; lookup_certs: TX509_STORE_CTX_lookup_certs_fn): void; cdecl;
function X509_STORE_get_lookup_certs(s: PX509_STORE): TX509_STORE_CTX_lookup_certs_fn; cdecl;
function X509_STORE_set_lookup_crls(xs: PX509_STORE; lookup_crls: TX509_STORE_CTX_lookup_crls_fn): void; cdecl;
function X509_STORE_get_lookup_crls(xs: PX509_STORE): TX509_STORE_CTX_lookup_crls_fn; cdecl;
function X509_STORE_set_cleanup(xs: PX509_STORE; cleanup: TX509_STORE_CTX_cleanup_fn): void; cdecl;
function X509_STORE_get_cleanup(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_set_ex_data(xs: PX509_STORE; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl;
function X509_STORE_get_ex_data(xs: PX509_STORE; idx: TIdC_INT): Pointer; cdecl;
function X509_STORE_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_STORE_CTX; cdecl;
function X509_STORE_CTX_new: PX509_STORE_CTX; cdecl;
function X509_STORE_CTX_get1_issuer(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT; cdecl;
function X509_STORE_CTX_free(ctx: PX509_STORE_CTX): void; cdecl;
function X509_STORE_CTX_init(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; target: PX509; untrusted: Pstack_st_X509): TIdC_INT; cdecl;
function X509_STORE_CTX_init_rpk(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; rpk: PEVP_PKEY): TIdC_INT; cdecl;
function X509_STORE_CTX_set0_trusted_stack(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl;
function X509_STORE_CTX_cleanup(ctx: PX509_STORE_CTX): void; cdecl;
function X509_STORE_CTX_get0_store(ctx: PX509_STORE_CTX): PX509_STORE; cdecl;
function X509_STORE_CTX_get0_cert(ctx: PX509_STORE_CTX): PX509; cdecl;
function X509_STORE_CTX_get0_rpk(ctx: PX509_STORE_CTX): PEVP_PKEY; cdecl;
function X509_STORE_CTX_get0_untrusted(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl;
function X509_STORE_CTX_set0_untrusted(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl;
function X509_STORE_CTX_set_verify_cb(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_verify_cb): void; cdecl;
function X509_STORE_CTX_get_verify_cb(ctx: PX509_STORE_CTX): TX509_STORE_CTX_verify_cb; cdecl;
function X509_STORE_CTX_get_verify(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_CTX_get_get_issuer(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_issuer_fn; cdecl;
function X509_STORE_CTX_get_check_issued(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_issued_fn; cdecl;
function X509_STORE_CTX_get_check_revocation(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_CTX_set_get_crl(ctx: PX509_STORE_CTX; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl;
function X509_STORE_CTX_get_get_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_crl_fn; cdecl;
function X509_STORE_CTX_get_check_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_crl_fn; cdecl;
function X509_STORE_CTX_get_cert_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cert_crl_fn; cdecl;
function X509_STORE_CTX_get_check_policy(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_CTX_get_lookup_certs(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_certs_fn; cdecl;
function X509_STORE_CTX_get_lookup_crls(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_crls_fn; cdecl;
function X509_STORE_CTX_get_cleanup(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl;
function X509_STORE_add_lookup(xs: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl;
function X509_LOOKUP_hash_dir: PX509_LOOKUP_METHOD; cdecl;
function X509_LOOKUP_file: PX509_LOOKUP_METHOD; cdecl;
function X509_LOOKUP_store: PX509_LOOKUP_METHOD; cdecl;
function X509_LOOKUP_meth_new(name: PIdAnsiChar): PX509_LOOKUP_METHOD; cdecl;
function X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD): void; cdecl;
function X509_LOOKUP_meth_set_new_item(method: PX509_LOOKUP_METHOD; new_item: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_new_item(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl;
function X509_LOOKUP_meth_set_free(method: PX509_LOOKUP_METHOD; free_fn: Tsk_X509_LOOKUP_freefunc): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_free(method: PX509_LOOKUP_METHOD): Tsk_X509_LOOKUP_freefunc; cdecl;
function X509_LOOKUP_meth_set_init(method: PX509_LOOKUP_METHOD; init: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_init(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl;
function X509_LOOKUP_meth_set_shutdown(method: PX509_LOOKUP_METHOD; shutdown: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_shutdown(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl;
function X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: TX509_LOOKUP_ctrl_fn): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_ctrl(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_ctrl_fn; cdecl;
function X509_LOOKUP_meth_set_get_by_subject(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_subject_fn): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_get_by_subject(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_subject_fn; cdecl;
function X509_LOOKUP_meth_set_get_by_issuer_serial(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_issuer_serial_fn): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_get_by_issuer_serial(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_issuer_serial_fn; cdecl;
function X509_LOOKUP_meth_set_get_by_fingerprint(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_fingerprint_fn): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_get_by_fingerprint(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_fingerprint_fn; cdecl;
function X509_LOOKUP_meth_set_get_by_alias(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_alias_fn): TIdC_INT; cdecl;
function X509_LOOKUP_meth_get_get_by_alias(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_alias_fn; cdecl;
function X509_STORE_add_cert(xs: PX509_STORE; x: PX509): TIdC_INT; cdecl;
function X509_STORE_add_crl(xs: PX509_STORE; x: PX509_CRL): TIdC_INT; cdecl;
function X509_STORE_CTX_get_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl;
function X509_STORE_CTX_get_obj_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl;
function X509_LOOKUP_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_LOOKUP_ctrl_ex(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_load_cert_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl;
function X509_load_cert_file_ex(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_load_crl_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl;
function X509_load_cert_crl_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl;
function X509_load_cert_crl_file_ex(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_LOOKUP_new(method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl;
function X509_LOOKUP_free(ctx: PX509_LOOKUP): void; cdecl;
function X509_LOOKUP_init(ctx: PX509_LOOKUP): TIdC_INT; cdecl;
function X509_LOOKUP_by_subject(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl;
function X509_LOOKUP_by_subject_ex(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_LOOKUP_by_issuer_serial(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; cdecl;
function X509_LOOKUP_by_fingerprint(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; bytes: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl;
function X509_LOOKUP_by_alias(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl;
function X509_LOOKUP_set_method_data(ctx: PX509_LOOKUP; data: Pointer): TIdC_INT; cdecl;
function X509_LOOKUP_get_method_data(ctx: PX509_LOOKUP): Pointer; cdecl;
function X509_LOOKUP_get_store(ctx: PX509_LOOKUP): PX509_STORE; cdecl;
function X509_LOOKUP_shutdown(ctx: PX509_LOOKUP): TIdC_INT; cdecl;
function X509_STORE_load_file(xs: PX509_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_load_path(xs: PX509_STORE; path: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_load_store(xs: PX509_STORE; store: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_load_locations(s: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_set_default_paths(xs: PX509_STORE): TIdC_INT; cdecl;
function X509_STORE_load_file_ex(xs: PX509_STORE; _file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_load_store_ex(xs: PX509_STORE; store: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_load_locations_ex(xs: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_set_default_paths_ex(xs: PX509_STORE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_CTX_set_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl;
function X509_STORE_CTX_get_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT): Pointer; cdecl;
function X509_STORE_CTX_get_error(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509_STORE_CTX_set_error(ctx: PX509_STORE_CTX; s: TIdC_INT): void; cdecl;
function X509_STORE_CTX_get_error_depth(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509_STORE_CTX_set_error_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl;
function X509_STORE_CTX_get_current_cert(ctx: PX509_STORE_CTX): PX509; cdecl;
function X509_STORE_CTX_set_current_cert(ctx: PX509_STORE_CTX; x: PX509): void; cdecl;
function X509_STORE_CTX_get0_current_issuer(ctx: PX509_STORE_CTX): PX509; cdecl;
function X509_STORE_CTX_get0_current_crl(ctx: PX509_STORE_CTX): PX509_CRL; cdecl;
function X509_STORE_CTX_get0_parent_ctx(ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl;
function X509_STORE_CTX_get0_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl;
function X509_STORE_CTX_get1_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl;
function X509_STORE_CTX_set_cert(ctx: PX509_STORE_CTX; target: PX509): void; cdecl;
function X509_STORE_CTX_set0_rpk(ctx: PX509_STORE_CTX; target: PEVP_PKEY): void; cdecl;
function X509_STORE_CTX_set0_verified_chain(c: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl;
function X509_STORE_CTX_set0_crls(ctx: PX509_STORE_CTX; sk: Pstack_st_X509_CRL): void; cdecl;
function X509_STORE_CTX_set_ocsp_resp(ctx: PX509_STORE_CTX; sk: Pstack_st_OCSP_RESPONSE): void; cdecl;
function X509_STORE_CTX_set_purpose(ctx: PX509_STORE_CTX; purpose: TIdC_INT): TIdC_INT; cdecl;
function X509_STORE_CTX_set_trust(ctx: PX509_STORE_CTX; trust: TIdC_INT): TIdC_INT; cdecl;
function X509_STORE_CTX_purpose_inherit(ctx: PX509_STORE_CTX; def_purpose: TIdC_INT; purpose: TIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl;
function X509_STORE_CTX_set_flags(ctx: PX509_STORE_CTX; flags: TIdC_ULONG): void; cdecl;
function X509_STORE_CTX_set_time(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET): void; cdecl;
function X509_STORE_CTX_set_current_reasons(ctx: PX509_STORE_CTX; current_reasons: TIdC_UINT): void; cdecl;
function X509_STORE_CTX_get0_policy_tree(ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl;
function X509_STORE_CTX_get_explicit_policy(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509_STORE_CTX_get_num_untrusted(ctx: PX509_STORE_CTX): TIdC_INT; cdecl;
function X509_STORE_CTX_get0_param(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl;
function X509_STORE_CTX_set0_param(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM): void; cdecl;
function X509_STORE_CTX_set_default(ctx: PX509_STORE_CTX; name: PIdAnsiChar): TIdC_INT; cdecl;
function X509_STORE_CTX_set0_dane(ctx: PX509_STORE_CTX; dane: PSSL_DANE): void; cdecl;
function X509_VERIFY_PARAM_new: PX509_VERIFY_PARAM; cdecl;
function X509_VERIFY_PARAM_free(param: PX509_VERIFY_PARAM): void; cdecl;
function X509_VERIFY_PARAM_inherit(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set1(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set1_name(param: PX509_VERIFY_PARAM; name: PIdAnsiChar): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_clear_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get_flags(param: PX509_VERIFY_PARAM): TIdC_ULONG; cdecl;
function X509_VERIFY_PARAM_set_purpose(param: PX509_VERIFY_PARAM; purpose: TIdC_INT): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get_purpose(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set_trust(param: PX509_VERIFY_PARAM; trust: TIdC_INT): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set_depth(param: PX509_VERIFY_PARAM; depth: TIdC_INT): void; cdecl;
function X509_VERIFY_PARAM_set_auth_level(param: PX509_VERIFY_PARAM; auth_level: TIdC_INT): void; cdecl;
function X509_VERIFY_PARAM_get_time(param: PX509_VERIFY_PARAM): TIdC_TIMET; cdecl;
function X509_VERIFY_PARAM_set_time(param: PX509_VERIFY_PARAM; t: TIdC_TIMET): void; cdecl;
function X509_VERIFY_PARAM_add0_policy(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set1_policies(param: PX509_VERIFY_PARAM; policies: Pstack_st_ASN1_OBJECT): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set_inh_flags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT32): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get_inh_flags(param: PX509_VERIFY_PARAM): TIdC_UINT32; cdecl;
function X509_VERIFY_PARAM_get0_host(param: PX509_VERIFY_PARAM; idx: TIdC_INT): PIdAnsiChar; cdecl;
function X509_VERIFY_PARAM_set1_host(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_add1_host(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set_hostflags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT): void; cdecl;
function X509_VERIFY_PARAM_get_hostflags(param: PX509_VERIFY_PARAM): TIdC_UINT; cdecl;
function X509_VERIFY_PARAM_get0_peername(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl;
function X509_VERIFY_PARAM_move_peername(arg1: PX509_VERIFY_PARAM; arg2: PX509_VERIFY_PARAM): void; cdecl;
function X509_VERIFY_PARAM_get0_email(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl;
function X509_VERIFY_PARAM_set1_email(param: PX509_VERIFY_PARAM; email: PIdAnsiChar; emaillen: TIdC_SIZET): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get1_ip_asc(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl;
function X509_VERIFY_PARAM_set1_ip(param: PX509_VERIFY_PARAM; ip: PIdAnsiChar; iplen: TIdC_SIZET): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_set1_ip_asc(param: PX509_VERIFY_PARAM; ipasc: PIdAnsiChar): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get_depth(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get_auth_level(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get0_name(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl;
function X509_VERIFY_PARAM_add0_table(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get_count: TIdC_INT; cdecl;
function X509_VERIFY_PARAM_get0(id: TIdC_INT): PX509_VERIFY_PARAM; cdecl;
function X509_VERIFY_PARAM_lookup(name: PIdAnsiChar): PX509_VERIFY_PARAM; cdecl;
function X509_VERIFY_PARAM_table_cleanup: void; cdecl;
function X509_policy_check(ptree: PPX509_POLICY_TREE; pexplicit_policy: PIdC_INT; certs: Pstack_st_X509; policy_oids: Pstack_st_ASN1_OBJECT; flags: TIdC_UINT): TIdC_INT; cdecl;
function X509_policy_tree_free(tree: PX509_POLICY_TREE): void; cdecl;
function X509_policy_tree_level_count(tree: PX509_POLICY_TREE): TIdC_INT; cdecl;
function X509_policy_tree_get0_level(tree: PX509_POLICY_TREE; i: TIdC_INT): PX509_POLICY_LEVEL; cdecl;
function X509_policy_tree_get0_policies(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl;
function X509_policy_tree_get0_user_policies(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl;
function X509_policy_level_node_count(level: PX509_POLICY_LEVEL): TIdC_INT; cdecl;
function X509_policy_level_get0_node(level: PX509_POLICY_LEVEL; i: TIdC_INT): PX509_POLICY_NODE; cdecl;
function X509_policy_node_get0_policy(node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl;
function X509_policy_node_get0_qualifiers(node: PX509_POLICY_NODE): Pstack_st_POLICYQUALINFO; cdecl;
function X509_policy_node_get0_parent(node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_LOOKUP_load_file(x: Pointer; name: Pointer; _type: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_LOOKUP_add_dir(x: Pointer; name: Pointer; _type: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_LOOKUP_add_store(x: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_LOOKUP_load_store(x: Pointer; name: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_LOOKUP_load_file_ex(x: Pointer; name: Pointer; _type: Pointer; libctx: Pointer; propq: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_LOOKUP_load_store_ex(x: Pointer; name: Pointer; libctx: Pointer; propq: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_LOOKUP_add_store_ex(x: Pointer; name: Pointer; libctx: Pointer; propq: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_set_verify_func(ctx: Pointer; func: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_set_verify_cb_func(ctx: Pointer; func: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_set_lookup_crls_cb(ctx: Pointer; func: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_CTX_get_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_CTX_set_chain(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_CTX_trusted_stack(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_get_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_get1_certs(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_get1_crls(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_get1_cert(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_STORE_get1_crl(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl;


// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack OCSP_RESPONSE definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OCSP_RESPONSE = Pointer;
  {$EXTERNALSYM PSTACK_OF_OCSP_RESPONSE}

  { Original Stack Macros for OCSP_RESPONSE:
    DEFINE_STACK_OF(OCSP_RESPONSE)
  }

  { TODO 1 -copenssl stack X509_LOOKUP definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_LOOKUP = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_LOOKUP}

  { Original Stack Macros for X509_LOOKUP:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_LOOKUP, X509_LOOKUP, X509_LOOKUP)
    sk_X509_LOOKUP_num(sk) OPENSSL_sk_num(ossl_check_const_X509_LOOKUP_sk_type(sk))
    sk_X509_LOOKUP_value(sk, idx) ((X509_LOOKUP *)OPENSSL_sk_value(ossl_check_const_X509_LOOKUP_sk_type(sk), (idx)))
    sk_X509_LOOKUP_new(cmp) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_new(ossl_check_X509_LOOKUP_compfunc_type(cmp)))
    sk_X509_LOOKUP_new_null() ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_new_null())
    sk_X509_LOOKUP_new_reserve(cmp, n) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_new_reserve(ossl_check_X509_LOOKUP_compfunc_type(cmp), (n)))
    sk_X509_LOOKUP_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_LOOKUP_sk_type(sk), (n))
    sk_X509_LOOKUP_free(sk) OPENSSL_sk_free(ossl_check_X509_LOOKUP_sk_type(sk))
    sk_X509_LOOKUP_zero(sk) OPENSSL_sk_zero(ossl_check_X509_LOOKUP_sk_type(sk))
    sk_X509_LOOKUP_delete(sk, i) ((X509_LOOKUP *)OPENSSL_sk_delete(ossl_check_X509_LOOKUP_sk_type(sk), (i)))
    sk_X509_LOOKUP_delete_ptr(sk, ptr) ((X509_LOOKUP *)OPENSSL_sk_delete_ptr(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr)))
    sk_X509_LOOKUP_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
    sk_X509_LOOKUP_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
    sk_X509_LOOKUP_pop(sk) ((X509_LOOKUP *)OPENSSL_sk_pop(ossl_check_X509_LOOKUP_sk_type(sk)))
    sk_X509_LOOKUP_shift(sk) ((X509_LOOKUP *)OPENSSL_sk_shift(ossl_check_X509_LOOKUP_sk_type(sk)))
    sk_X509_LOOKUP_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_freefunc_type(freefunc))
    sk_X509_LOOKUP_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr), (idx))
    sk_X509_LOOKUP_set(sk, idx, ptr) ((X509_LOOKUP *)OPENSSL_sk_set(ossl_check_X509_LOOKUP_sk_type(sk), (idx), ossl_check_X509_LOOKUP_type(ptr)))
    sk_X509_LOOKUP_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
    sk_X509_LOOKUP_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
    sk_X509_LOOKUP_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr), pnum)
    sk_X509_LOOKUP_sort(sk) OPENSSL_sk_sort(ossl_check_X509_LOOKUP_sk_type(sk))
    sk_X509_LOOKUP_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_LOOKUP_sk_type(sk))
    sk_X509_LOOKUP_dup(sk) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_dup(ossl_check_const_X509_LOOKUP_sk_type(sk)))
    sk_X509_LOOKUP_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_copyfunc_type(copyfunc), ossl_check_X509_LOOKUP_freefunc_type(freefunc)))
    sk_X509_LOOKUP_set_cmp_func(sk, cmp) ((sk_X509_LOOKUP_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack X509_OBJECT definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_OBJECT = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_OBJECT}

  { Original Stack Macros for X509_OBJECT:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_OBJECT, X509_OBJECT, X509_OBJECT)
    sk_X509_OBJECT_num(sk) OPENSSL_sk_num(ossl_check_const_X509_OBJECT_sk_type(sk))
    sk_X509_OBJECT_value(sk, idx) ((X509_OBJECT *)OPENSSL_sk_value(ossl_check_const_X509_OBJECT_sk_type(sk), (idx)))
    sk_X509_OBJECT_new(cmp) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_new(ossl_check_X509_OBJECT_compfunc_type(cmp)))
    sk_X509_OBJECT_new_null() ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_new_null())
    sk_X509_OBJECT_new_reserve(cmp, n) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_new_reserve(ossl_check_X509_OBJECT_compfunc_type(cmp), (n)))
    sk_X509_OBJECT_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_OBJECT_sk_type(sk), (n))
    sk_X509_OBJECT_free(sk) OPENSSL_sk_free(ossl_check_X509_OBJECT_sk_type(sk))
    sk_X509_OBJECT_zero(sk) OPENSSL_sk_zero(ossl_check_X509_OBJECT_sk_type(sk))
    sk_X509_OBJECT_delete(sk, i) ((X509_OBJECT *)OPENSSL_sk_delete(ossl_check_X509_OBJECT_sk_type(sk), (i)))
    sk_X509_OBJECT_delete_ptr(sk, ptr) ((X509_OBJECT *)OPENSSL_sk_delete_ptr(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr)))
    sk_X509_OBJECT_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
    sk_X509_OBJECT_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
    sk_X509_OBJECT_pop(sk) ((X509_OBJECT *)OPENSSL_sk_pop(ossl_check_X509_OBJECT_sk_type(sk)))
    sk_X509_OBJECT_shift(sk) ((X509_OBJECT *)OPENSSL_sk_shift(ossl_check_X509_OBJECT_sk_type(sk)))
    sk_X509_OBJECT_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_freefunc_type(freefunc))
    sk_X509_OBJECT_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr), (idx))
    sk_X509_OBJECT_set(sk, idx, ptr) ((X509_OBJECT *)OPENSSL_sk_set(ossl_check_X509_OBJECT_sk_type(sk), (idx), ossl_check_X509_OBJECT_type(ptr)))
    sk_X509_OBJECT_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
    sk_X509_OBJECT_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
    sk_X509_OBJECT_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr), pnum)
    sk_X509_OBJECT_sort(sk) OPENSSL_sk_sort(ossl_check_X509_OBJECT_sk_type(sk))
    sk_X509_OBJECT_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_OBJECT_sk_type(sk))
    sk_X509_OBJECT_dup(sk) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_dup(ossl_check_const_X509_OBJECT_sk_type(sk)))
    sk_X509_OBJECT_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_copyfunc_type(copyfunc), ossl_check_X509_OBJECT_freefunc_type(freefunc)))
    sk_X509_OBJECT_set_cmp_func(sk, cmp) ((sk_X509_OBJECT_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack X509_VERIFY_PARAM definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_VERIFY_PARAM = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_VERIFY_PARAM}

  { Original Stack Macros for X509_VERIFY_PARAM:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_VERIFY_PARAM, X509_VERIFY_PARAM, X509_VERIFY_PARAM)
    sk_X509_VERIFY_PARAM_num(sk) OPENSSL_sk_num(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk))
    sk_X509_VERIFY_PARAM_value(sk, idx) ((X509_VERIFY_PARAM *)OPENSSL_sk_value(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk), (idx)))
    sk_X509_VERIFY_PARAM_new(cmp) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_new(ossl_check_X509_VERIFY_PARAM_compfunc_type(cmp)))
    sk_X509_VERIFY_PARAM_new_null() ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_new_null())
    sk_X509_VERIFY_PARAM_new_reserve(cmp, n) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_new_reserve(ossl_check_X509_VERIFY_PARAM_compfunc_type(cmp), (n)))
    sk_X509_VERIFY_PARAM_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_VERIFY_PARAM_sk_type(sk), (n))
    sk_X509_VERIFY_PARAM_free(sk) OPENSSL_sk_free(ossl_check_X509_VERIFY_PARAM_sk_type(sk))
    sk_X509_VERIFY_PARAM_zero(sk) OPENSSL_sk_zero(ossl_check_X509_VERIFY_PARAM_sk_type(sk))
    sk_X509_VERIFY_PARAM_delete(sk, i) ((X509_VERIFY_PARAM *)OPENSSL_sk_delete(ossl_check_X509_VERIFY_PARAM_sk_type(sk), (i)))
    sk_X509_VERIFY_PARAM_delete_ptr(sk, ptr) ((X509_VERIFY_PARAM *)OPENSSL_sk_delete_ptr(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr)))
    sk_X509_VERIFY_PARAM_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
    sk_X509_VERIFY_PARAM_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
    sk_X509_VERIFY_PARAM_pop(sk) ((X509_VERIFY_PARAM *)OPENSSL_sk_pop(ossl_check_X509_VERIFY_PARAM_sk_type(sk)))
    sk_X509_VERIFY_PARAM_shift(sk) ((X509_VERIFY_PARAM *)OPENSSL_sk_shift(ossl_check_X509_VERIFY_PARAM_sk_type(sk)))
    sk_X509_VERIFY_PARAM_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_freefunc_type(freefunc))
    sk_X509_VERIFY_PARAM_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr), (idx))
    sk_X509_VERIFY_PARAM_set(sk, idx, ptr) ((X509_VERIFY_PARAM *)OPENSSL_sk_set(ossl_check_X509_VERIFY_PARAM_sk_type(sk), (idx), ossl_check_X509_VERIFY_PARAM_type(ptr)))
    sk_X509_VERIFY_PARAM_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
    sk_X509_VERIFY_PARAM_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
    sk_X509_VERIFY_PARAM_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr), pnum)
    sk_X509_VERIFY_PARAM_sort(sk) OPENSSL_sk_sort(ossl_check_X509_VERIFY_PARAM_sk_type(sk))
    sk_X509_VERIFY_PARAM_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk))
    sk_X509_VERIFY_PARAM_dup(sk) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_dup(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk)))
    sk_X509_VERIFY_PARAM_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_copyfunc_type(copyfunc), ossl_check_X509_VERIFY_PARAM_freefunc_type(freefunc)))
    sk_X509_VERIFY_PARAM_set_cmp_func(sk, cmp) ((sk_X509_VERIFY_PARAM_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack X509_TRUST definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_TRUST = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_TRUST}

  { Original Stack Macros for X509_TRUST:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_TRUST, X509_TRUST, X509_TRUST)
    sk_X509_TRUST_num(sk) OPENSSL_sk_num(ossl_check_const_X509_TRUST_sk_type(sk))
    sk_X509_TRUST_value(sk, idx) ((X509_TRUST *)OPENSSL_sk_value(ossl_check_const_X509_TRUST_sk_type(sk), (idx)))
    sk_X509_TRUST_new(cmp) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_new(ossl_check_X509_TRUST_compfunc_type(cmp)))
    sk_X509_TRUST_new_null() ((STACK_OF(X509_TRUST) *)OPENSSL_sk_new_null())
    sk_X509_TRUST_new_reserve(cmp, n) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_new_reserve(ossl_check_X509_TRUST_compfunc_type(cmp), (n)))
    sk_X509_TRUST_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_TRUST_sk_type(sk), (n))
    sk_X509_TRUST_free(sk) OPENSSL_sk_free(ossl_check_X509_TRUST_sk_type(sk))
    sk_X509_TRUST_zero(sk) OPENSSL_sk_zero(ossl_check_X509_TRUST_sk_type(sk))
    sk_X509_TRUST_delete(sk, i) ((X509_TRUST *)OPENSSL_sk_delete(ossl_check_X509_TRUST_sk_type(sk), (i)))
    sk_X509_TRUST_delete_ptr(sk, ptr) ((X509_TRUST *)OPENSSL_sk_delete_ptr(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr)))
    sk_X509_TRUST_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
    sk_X509_TRUST_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
    sk_X509_TRUST_pop(sk) ((X509_TRUST *)OPENSSL_sk_pop(ossl_check_X509_TRUST_sk_type(sk)))
    sk_X509_TRUST_shift(sk) ((X509_TRUST *)OPENSSL_sk_shift(ossl_check_X509_TRUST_sk_type(sk)))
    sk_X509_TRUST_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_freefunc_type(freefunc))
    sk_X509_TRUST_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr), (idx))
    sk_X509_TRUST_set(sk, idx, ptr) ((X509_TRUST *)OPENSSL_sk_set(ossl_check_X509_TRUST_sk_type(sk), (idx), ossl_check_X509_TRUST_type(ptr)))
    sk_X509_TRUST_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
    sk_X509_TRUST_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
    sk_X509_TRUST_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr), pnum)
    sk_X509_TRUST_sort(sk) OPENSSL_sk_sort(ossl_check_X509_TRUST_sk_type(sk))
    sk_X509_TRUST_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_TRUST_sk_type(sk))
    sk_X509_TRUST_dup(sk) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_dup(ossl_check_const_X509_TRUST_sk_type(sk)))
    sk_X509_TRUST_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_copyfunc_type(copyfunc), ossl_check_X509_TRUST_freefunc_type(freefunc)))
    sk_X509_TRUST_set_cmp_func(sk, cmp) ((sk_X509_TRUST_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_compfunc_type(cmp)))
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

function X509_TRUST_set(t: PIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_TRUST_set';
function X509_TRUST_get_count: TIdC_INT; cdecl external CLibCrypto name 'X509_TRUST_get_count';
function X509_TRUST_get0(idx: TIdC_INT): PX509_TRUST; cdecl external CLibCrypto name 'X509_TRUST_get0';
function X509_TRUST_get_by_id(id: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_TRUST_get_by_id';
function X509_TRUST_add(id: TIdC_INT; flags: TIdC_INT; ck: Tsk_X509_VERIFY_PARAM_copyfunc_func_cb; name: PIdAnsiChar; arg1: TIdC_INT; arg2: Pointer): TIdC_INT; cdecl external CLibCrypto name 'X509_TRUST_add';
function X509_TRUST_cleanup: void; cdecl external CLibCrypto name 'X509_TRUST_cleanup';
function X509_TRUST_get_flags(xp: PX509_TRUST): TIdC_INT; cdecl external CLibCrypto name 'X509_TRUST_get_flags';
function X509_TRUST_get0_name(xp: PX509_TRUST): PIdAnsiChar; cdecl external CLibCrypto name 'X509_TRUST_get0_name';
function X509_TRUST_get_trust(xp: PX509_TRUST): TIdC_INT; cdecl external CLibCrypto name 'X509_TRUST_get_trust';
function X509_trusted(x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_trusted';
function X509_add1_trust_object(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_add1_trust_object';
function X509_add1_reject_object(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_add1_reject_object';
function X509_trust_clear(x: PX509): void; cdecl external CLibCrypto name 'X509_trust_clear';
function X509_reject_clear(x: PX509): void; cdecl external CLibCrypto name 'X509_reject_clear';
function X509_get0_trust_objects(x: PX509): Pstack_st_ASN1_OBJECT; cdecl external CLibCrypto name 'X509_get0_trust_objects';
function X509_get0_reject_objects(x: PX509): Pstack_st_ASN1_OBJECT; cdecl external CLibCrypto name 'X509_get0_reject_objects';
function X509_TRUST_set_default(trust: TX509_TRUST_set_default_trust_cb): TX509_TRUST_set_default_trust_cb; cdecl external CLibCrypto name 'X509_TRUST_set_default';
function X509_check_trust(x: PX509; id: TIdC_INT; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_check_trust';
function X509_verify_cert(ctx: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_verify_cert';
function X509_STORE_CTX_verify(ctx: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_verify';
function X509_build_chain(target: PX509; certs: Pstack_st_X509; store: PX509_STORE; with_self_signed: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509; cdecl external CLibCrypto name 'X509_build_chain';
function X509_STORE_set_depth(store: PX509_STORE; depth: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set_depth';
function X509_STORE_CTX_print_verify_cb(ok: TIdC_INT; ctx: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_print_verify_cb';
function X509_STORE_CTX_set_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_depth';
function X509_OBJECT_idx_by_subject(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_OBJECT_idx_by_subject';
function X509_OBJECT_retrieve_by_subject(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl external CLibCrypto name 'X509_OBJECT_retrieve_by_subject';
function X509_OBJECT_retrieve_match(h: Pstack_st_X509_OBJECT; x: PX509_OBJECT): PX509_OBJECT; cdecl external CLibCrypto name 'X509_OBJECT_retrieve_match';
function X509_OBJECT_up_ref_count(a: PX509_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_OBJECT_up_ref_count';
function X509_OBJECT_new: PX509_OBJECT; cdecl external CLibCrypto name 'X509_OBJECT_new';
function X509_OBJECT_free(a: PX509_OBJECT): void; cdecl external CLibCrypto name 'X509_OBJECT_free';
function X509_OBJECT_get_type(a: PX509_OBJECT): TX509_LOOKUP_TYPE; cdecl external CLibCrypto name 'X509_OBJECT_get_type';
function X509_OBJECT_get0_X509(a: PX509_OBJECT): PX509; cdecl external CLibCrypto name 'X509_OBJECT_get0_X509';
function X509_OBJECT_set1_X509(a: PX509_OBJECT; obj: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_OBJECT_set1_X509';
function X509_OBJECT_get0_X509_CRL(a: PX509_OBJECT): PX509_CRL; cdecl external CLibCrypto name 'X509_OBJECT_get0_X509_CRL';
function X509_OBJECT_set1_X509_CRL(a: PX509_OBJECT; obj: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_OBJECT_set1_X509_CRL';
function X509_STORE_new: PX509_STORE; cdecl external CLibCrypto name 'X509_STORE_new';
function X509_STORE_free(xs: PX509_STORE): void; cdecl external CLibCrypto name 'X509_STORE_free';
function X509_STORE_lock(xs: PX509_STORE): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_lock';
function X509_STORE_unlock(xs: PX509_STORE): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_unlock';
function X509_STORE_up_ref(xs: PX509_STORE): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_up_ref';
function X509_STORE_get0_objects(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl external CLibCrypto name 'X509_STORE_get0_objects';
function X509_STORE_get1_objects(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl external CLibCrypto name 'X509_STORE_get1_objects';
function X509_STORE_get1_all_certs(xs: PX509_STORE): Pstack_st_X509; cdecl external CLibCrypto name 'X509_STORE_get1_all_certs';
function X509_STORE_CTX_get1_certs(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl external CLibCrypto name 'X509_STORE_CTX_get1_certs';
function X509_STORE_CTX_get1_crls(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl external CLibCrypto name 'X509_STORE_CTX_get1_crls';
function X509_STORE_set_flags(xs: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set_flags';
function X509_STORE_set_purpose(xs: PX509_STORE; purpose: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set_purpose';
function X509_STORE_set_trust(xs: PX509_STORE; trust: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set_trust';
function X509_STORE_set1_param(xs: PX509_STORE; pm: PX509_VERIFY_PARAM): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set1_param';
function X509_STORE_get0_param(xs: PX509_STORE): PX509_VERIFY_PARAM; cdecl external CLibCrypto name 'X509_STORE_get0_param';
function X509_STORE_set_verify(xs: PX509_STORE; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_verify';
function X509_STORE_CTX_set_verify(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_verify';
function X509_STORE_get_verify(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_get_verify';
function X509_STORE_set_verify_cb(xs: PX509_STORE; verify_cb: TX509_STORE_CTX_verify_cb): void; cdecl external CLibCrypto name 'X509_STORE_set_verify_cb';
function X509_STORE_get_verify_cb(xs: PX509_STORE): TX509_STORE_CTX_verify_cb; cdecl external CLibCrypto name 'X509_STORE_get_verify_cb';
function X509_STORE_set_get_issuer(xs: PX509_STORE; get_issuer: TX509_STORE_CTX_get_issuer_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_get_issuer';
function X509_STORE_get_get_issuer(xs: PX509_STORE): TX509_STORE_CTX_get_issuer_fn; cdecl external CLibCrypto name 'X509_STORE_get_get_issuer';
function X509_STORE_set_check_issued(xs: PX509_STORE; check_issued: TX509_STORE_CTX_check_issued_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_check_issued';
function X509_STORE_get_check_issued(s: PX509_STORE): TX509_STORE_CTX_check_issued_fn; cdecl external CLibCrypto name 'X509_STORE_get_check_issued';
function X509_STORE_set_check_revocation(xs: PX509_STORE; check_revocation: TX509_STORE_CTX_cleanup_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_check_revocation';
function X509_STORE_get_check_revocation(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_get_check_revocation';
function X509_STORE_set_get_crl(xs: PX509_STORE; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_get_crl';
function X509_STORE_get_get_crl(xs: PX509_STORE): TX509_STORE_CTX_get_crl_fn; cdecl external CLibCrypto name 'X509_STORE_get_get_crl';
function X509_STORE_set_check_crl(xs: PX509_STORE; check_crl: TX509_STORE_CTX_check_crl_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_check_crl';
function X509_STORE_get_check_crl(xs: PX509_STORE): TX509_STORE_CTX_check_crl_fn; cdecl external CLibCrypto name 'X509_STORE_get_check_crl';
function X509_STORE_set_cert_crl(xs: PX509_STORE; cert_crl: TX509_STORE_CTX_cert_crl_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_cert_crl';
function X509_STORE_get_cert_crl(xs: PX509_STORE): TX509_STORE_CTX_cert_crl_fn; cdecl external CLibCrypto name 'X509_STORE_get_cert_crl';
function X509_STORE_set_check_policy(xs: PX509_STORE; check_policy: TX509_STORE_CTX_cleanup_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_check_policy';
function X509_STORE_get_check_policy(s: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_get_check_policy';
function X509_STORE_set_lookup_certs(xs: PX509_STORE; lookup_certs: TX509_STORE_CTX_lookup_certs_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_lookup_certs';
function X509_STORE_get_lookup_certs(s: PX509_STORE): TX509_STORE_CTX_lookup_certs_fn; cdecl external CLibCrypto name 'X509_STORE_get_lookup_certs';
function X509_STORE_set_lookup_crls(xs: PX509_STORE; lookup_crls: TX509_STORE_CTX_lookup_crls_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_lookup_crls';
function X509_STORE_get_lookup_crls(xs: PX509_STORE): TX509_STORE_CTX_lookup_crls_fn; cdecl external CLibCrypto name 'X509_STORE_get_lookup_crls';
function X509_STORE_set_cleanup(xs: PX509_STORE; cleanup: TX509_STORE_CTX_cleanup_fn): void; cdecl external CLibCrypto name 'X509_STORE_set_cleanup';
function X509_STORE_get_cleanup(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_get_cleanup';
function X509_STORE_set_ex_data(xs: PX509_STORE; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set_ex_data';
function X509_STORE_get_ex_data(xs: PX509_STORE; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'X509_STORE_get_ex_data';
function X509_STORE_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_STORE_CTX; cdecl external CLibCrypto name 'X509_STORE_CTX_new_ex';
function X509_STORE_CTX_new: PX509_STORE_CTX; cdecl external CLibCrypto name 'X509_STORE_CTX_new';
function X509_STORE_CTX_get1_issuer(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_get1_issuer';
function X509_STORE_CTX_free(ctx: PX509_STORE_CTX): void; cdecl external CLibCrypto name 'X509_STORE_CTX_free';
function X509_STORE_CTX_init(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; target: PX509; untrusted: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_init';
function X509_STORE_CTX_init_rpk(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; rpk: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_init_rpk';
function X509_STORE_CTX_set0_trusted_stack(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set0_trusted_stack';
function X509_STORE_CTX_cleanup(ctx: PX509_STORE_CTX): void; cdecl external CLibCrypto name 'X509_STORE_CTX_cleanup';
function X509_STORE_CTX_get0_store(ctx: PX509_STORE_CTX): PX509_STORE; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_store';
function X509_STORE_CTX_get0_cert(ctx: PX509_STORE_CTX): PX509; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_cert';
function X509_STORE_CTX_get0_rpk(ctx: PX509_STORE_CTX): PEVP_PKEY; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_rpk';
function X509_STORE_CTX_get0_untrusted(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_untrusted';
function X509_STORE_CTX_set0_untrusted(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set0_untrusted';
function X509_STORE_CTX_set_verify_cb(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_verify_cb): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_verify_cb';
function X509_STORE_CTX_get_verify_cb(ctx: PX509_STORE_CTX): TX509_STORE_CTX_verify_cb; cdecl external CLibCrypto name 'X509_STORE_CTX_get_verify_cb';
function X509_STORE_CTX_get_verify(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_verify';
function X509_STORE_CTX_get_get_issuer(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_issuer_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_get_issuer';
function X509_STORE_CTX_get_check_issued(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_issued_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_check_issued';
function X509_STORE_CTX_get_check_revocation(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_check_revocation';
function X509_STORE_CTX_set_get_crl(ctx: PX509_STORE_CTX; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_get_crl';
function X509_STORE_CTX_get_get_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_crl_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_get_crl';
function X509_STORE_CTX_get_check_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_crl_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_check_crl';
function X509_STORE_CTX_get_cert_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cert_crl_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_cert_crl';
function X509_STORE_CTX_get_check_policy(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_check_policy';
function X509_STORE_CTX_get_lookup_certs(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_certs_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_lookup_certs';
function X509_STORE_CTX_get_lookup_crls(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_crls_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_lookup_crls';
function X509_STORE_CTX_get_cleanup(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl external CLibCrypto name 'X509_STORE_CTX_get_cleanup';
function X509_STORE_add_lookup(xs: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl external CLibCrypto name 'X509_STORE_add_lookup';
function X509_LOOKUP_hash_dir: PX509_LOOKUP_METHOD; cdecl external CLibCrypto name 'X509_LOOKUP_hash_dir';
function X509_LOOKUP_file: PX509_LOOKUP_METHOD; cdecl external CLibCrypto name 'X509_LOOKUP_file';
function X509_LOOKUP_store: PX509_LOOKUP_METHOD; cdecl external CLibCrypto name 'X509_LOOKUP_store';
function X509_LOOKUP_meth_new(name: PIdAnsiChar): PX509_LOOKUP_METHOD; cdecl external CLibCrypto name 'X509_LOOKUP_meth_new';
function X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD): void; cdecl external CLibCrypto name 'X509_LOOKUP_meth_free';
function X509_LOOKUP_meth_set_new_item(method: PX509_LOOKUP_METHOD; new_item: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_new_item';
function X509_LOOKUP_meth_get_new_item(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_new_item';
function X509_LOOKUP_meth_set_free(method: PX509_LOOKUP_METHOD; free_fn: Tsk_X509_LOOKUP_freefunc): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_free';
function X509_LOOKUP_meth_get_free(method: PX509_LOOKUP_METHOD): Tsk_X509_LOOKUP_freefunc; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_free';
function X509_LOOKUP_meth_set_init(method: PX509_LOOKUP_METHOD; init: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_init';
function X509_LOOKUP_meth_get_init(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_init';
function X509_LOOKUP_meth_set_shutdown(method: PX509_LOOKUP_METHOD; shutdown: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_shutdown';
function X509_LOOKUP_meth_get_shutdown(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_shutdown';
function X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: TX509_LOOKUP_ctrl_fn): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_ctrl';
function X509_LOOKUP_meth_get_ctrl(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_ctrl_fn; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_ctrl';
function X509_LOOKUP_meth_set_get_by_subject(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_subject_fn): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_get_by_subject';
function X509_LOOKUP_meth_get_get_by_subject(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_subject_fn; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_get_by_subject';
function X509_LOOKUP_meth_set_get_by_issuer_serial(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_issuer_serial_fn): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_get_by_issuer_serial';
function X509_LOOKUP_meth_get_get_by_issuer_serial(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_issuer_serial_fn; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_get_by_issuer_serial';
function X509_LOOKUP_meth_set_get_by_fingerprint(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_fingerprint_fn): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_get_by_fingerprint';
function X509_LOOKUP_meth_get_get_by_fingerprint(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_fingerprint_fn; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_get_by_fingerprint';
function X509_LOOKUP_meth_set_get_by_alias(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_alias_fn): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_meth_set_get_by_alias';
function X509_LOOKUP_meth_get_get_by_alias(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_alias_fn; cdecl external CLibCrypto name 'X509_LOOKUP_meth_get_get_by_alias';
function X509_STORE_add_cert(xs: PX509_STORE; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_add_cert';
function X509_STORE_add_crl(xs: PX509_STORE; x: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_add_crl';
function X509_STORE_CTX_get_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_get_by_subject';
function X509_STORE_CTX_get_obj_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl external CLibCrypto name 'X509_STORE_CTX_get_obj_by_subject';
function X509_LOOKUP_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_ctrl';
function X509_LOOKUP_ctrl_ex(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_ctrl_ex';
function X509_load_cert_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_load_cert_file';
function X509_load_cert_file_ex(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_load_cert_file_ex';
function X509_load_crl_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_load_crl_file';
function X509_load_cert_crl_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_load_cert_crl_file';
function X509_load_cert_crl_file_ex(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_load_cert_crl_file_ex';
function X509_LOOKUP_new(method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl external CLibCrypto name 'X509_LOOKUP_new';
function X509_LOOKUP_free(ctx: PX509_LOOKUP): void; cdecl external CLibCrypto name 'X509_LOOKUP_free';
function X509_LOOKUP_init(ctx: PX509_LOOKUP): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_init';
function X509_LOOKUP_by_subject(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_by_subject';
function X509_LOOKUP_by_subject_ex(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_by_subject_ex';
function X509_LOOKUP_by_issuer_serial(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_by_issuer_serial';
function X509_LOOKUP_by_fingerprint(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; bytes: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_by_fingerprint';
function X509_LOOKUP_by_alias(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_by_alias';
function X509_LOOKUP_set_method_data(ctx: PX509_LOOKUP; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_set_method_data';
function X509_LOOKUP_get_method_data(ctx: PX509_LOOKUP): Pointer; cdecl external CLibCrypto name 'X509_LOOKUP_get_method_data';
function X509_LOOKUP_get_store(ctx: PX509_LOOKUP): PX509_STORE; cdecl external CLibCrypto name 'X509_LOOKUP_get_store';
function X509_LOOKUP_shutdown(ctx: PX509_LOOKUP): TIdC_INT; cdecl external CLibCrypto name 'X509_LOOKUP_shutdown';
function X509_STORE_load_file(xs: PX509_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_load_file';
function X509_STORE_load_path(xs: PX509_STORE; path: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_load_path';
function X509_STORE_load_store(xs: PX509_STORE; store: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_load_store';
function X509_STORE_load_locations(s: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_load_locations';
function X509_STORE_set_default_paths(xs: PX509_STORE): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set_default_paths';
function X509_STORE_load_file_ex(xs: PX509_STORE; _file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_load_file_ex';
function X509_STORE_load_store_ex(xs: PX509_STORE; store: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_load_store_ex';
function X509_STORE_load_locations_ex(xs: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_load_locations_ex';
function X509_STORE_set_default_paths_ex(xs: PX509_STORE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_set_default_paths_ex';
function X509_STORE_CTX_set_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_set_ex_data';
function X509_STORE_CTX_get_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'X509_STORE_CTX_get_ex_data';
function X509_STORE_CTX_get_error(ctx: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_get_error';
function X509_STORE_CTX_set_error(ctx: PX509_STORE_CTX; s: TIdC_INT): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_error';
function X509_STORE_CTX_get_error_depth(ctx: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_get_error_depth';
function X509_STORE_CTX_set_error_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_error_depth';
function X509_STORE_CTX_get_current_cert(ctx: PX509_STORE_CTX): PX509; cdecl external CLibCrypto name 'X509_STORE_CTX_get_current_cert';
function X509_STORE_CTX_set_current_cert(ctx: PX509_STORE_CTX; x: PX509): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_current_cert';
function X509_STORE_CTX_get0_current_issuer(ctx: PX509_STORE_CTX): PX509; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_current_issuer';
function X509_STORE_CTX_get0_current_crl(ctx: PX509_STORE_CTX): PX509_CRL; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_current_crl';
function X509_STORE_CTX_get0_parent_ctx(ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_parent_ctx';
function X509_STORE_CTX_get0_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_chain';
function X509_STORE_CTX_get1_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl external CLibCrypto name 'X509_STORE_CTX_get1_chain';
function X509_STORE_CTX_set_cert(ctx: PX509_STORE_CTX; target: PX509): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_cert';
function X509_STORE_CTX_set0_rpk(ctx: PX509_STORE_CTX; target: PEVP_PKEY): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set0_rpk';
function X509_STORE_CTX_set0_verified_chain(c: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set0_verified_chain';
function X509_STORE_CTX_set0_crls(ctx: PX509_STORE_CTX; sk: Pstack_st_X509_CRL): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set0_crls';
function X509_STORE_CTX_set_ocsp_resp(ctx: PX509_STORE_CTX; sk: Pstack_st_OCSP_RESPONSE): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_ocsp_resp';
function X509_STORE_CTX_set_purpose(ctx: PX509_STORE_CTX; purpose: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_set_purpose';
function X509_STORE_CTX_set_trust(ctx: PX509_STORE_CTX; trust: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_set_trust';
function X509_STORE_CTX_purpose_inherit(ctx: PX509_STORE_CTX; def_purpose: TIdC_INT; purpose: TIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_purpose_inherit';
function X509_STORE_CTX_set_flags(ctx: PX509_STORE_CTX; flags: TIdC_ULONG): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_flags';
function X509_STORE_CTX_set_time(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_time';
function X509_STORE_CTX_set_current_reasons(ctx: PX509_STORE_CTX; current_reasons: TIdC_UINT): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set_current_reasons';
function X509_STORE_CTX_get0_policy_tree(ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_policy_tree';
function X509_STORE_CTX_get_explicit_policy(ctx: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_get_explicit_policy';
function X509_STORE_CTX_get_num_untrusted(ctx: PX509_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_get_num_untrusted';
function X509_STORE_CTX_get0_param(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl external CLibCrypto name 'X509_STORE_CTX_get0_param';
function X509_STORE_CTX_set0_param(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set0_param';
function X509_STORE_CTX_set_default(ctx: PX509_STORE_CTX; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_STORE_CTX_set_default';
function X509_STORE_CTX_set0_dane(ctx: PX509_STORE_CTX; dane: PSSL_DANE): void; cdecl external CLibCrypto name 'X509_STORE_CTX_set0_dane';
function X509_VERIFY_PARAM_new: PX509_VERIFY_PARAM; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_new';
function X509_VERIFY_PARAM_free(param: PX509_VERIFY_PARAM): void; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_free';
function X509_VERIFY_PARAM_inherit(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_inherit';
function X509_VERIFY_PARAM_set1(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set1';
function X509_VERIFY_PARAM_set1_name(param: PX509_VERIFY_PARAM; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set1_name';
function X509_VERIFY_PARAM_set_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_flags';
function X509_VERIFY_PARAM_clear_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_clear_flags';
function X509_VERIFY_PARAM_get_flags(param: PX509_VERIFY_PARAM): TIdC_ULONG; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_flags';
function X509_VERIFY_PARAM_set_purpose(param: PX509_VERIFY_PARAM; purpose: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_purpose';
function X509_VERIFY_PARAM_get_purpose(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_purpose';
function X509_VERIFY_PARAM_set_trust(param: PX509_VERIFY_PARAM; trust: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_trust';
function X509_VERIFY_PARAM_set_depth(param: PX509_VERIFY_PARAM; depth: TIdC_INT): void; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_depth';
function X509_VERIFY_PARAM_set_auth_level(param: PX509_VERIFY_PARAM; auth_level: TIdC_INT): void; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_auth_level';
function X509_VERIFY_PARAM_get_time(param: PX509_VERIFY_PARAM): TIdC_TIMET; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_time';
function X509_VERIFY_PARAM_set_time(param: PX509_VERIFY_PARAM; t: TIdC_TIMET): void; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_time';
function X509_VERIFY_PARAM_add0_policy(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_add0_policy';
function X509_VERIFY_PARAM_set1_policies(param: PX509_VERIFY_PARAM; policies: Pstack_st_ASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set1_policies';
function X509_VERIFY_PARAM_set_inh_flags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT32): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_inh_flags';
function X509_VERIFY_PARAM_get_inh_flags(param: PX509_VERIFY_PARAM): TIdC_UINT32; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_inh_flags';
function X509_VERIFY_PARAM_get0_host(param: PX509_VERIFY_PARAM; idx: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get0_host';
function X509_VERIFY_PARAM_set1_host(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set1_host';
function X509_VERIFY_PARAM_add1_host(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_add1_host';
function X509_VERIFY_PARAM_set_hostflags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT): void; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set_hostflags';
function X509_VERIFY_PARAM_get_hostflags(param: PX509_VERIFY_PARAM): TIdC_UINT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_hostflags';
function X509_VERIFY_PARAM_get0_peername(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get0_peername';
function X509_VERIFY_PARAM_move_peername(arg1: PX509_VERIFY_PARAM; arg2: PX509_VERIFY_PARAM): void; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_move_peername';
function X509_VERIFY_PARAM_get0_email(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get0_email';
function X509_VERIFY_PARAM_set1_email(param: PX509_VERIFY_PARAM; email: PIdAnsiChar; emaillen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set1_email';
function X509_VERIFY_PARAM_get1_ip_asc(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get1_ip_asc';
function X509_VERIFY_PARAM_set1_ip(param: PX509_VERIFY_PARAM; ip: PIdAnsiChar; iplen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set1_ip';
function X509_VERIFY_PARAM_set1_ip_asc(param: PX509_VERIFY_PARAM; ipasc: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_set1_ip_asc';
function X509_VERIFY_PARAM_get_depth(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_depth';
function X509_VERIFY_PARAM_get_auth_level(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_auth_level';
function X509_VERIFY_PARAM_get0_name(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get0_name';
function X509_VERIFY_PARAM_add0_table(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_add0_table';
function X509_VERIFY_PARAM_get_count: TIdC_INT; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get_count';
function X509_VERIFY_PARAM_get0(id: TIdC_INT): PX509_VERIFY_PARAM; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_get0';
function X509_VERIFY_PARAM_lookup(name: PIdAnsiChar): PX509_VERIFY_PARAM; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_lookup';
function X509_VERIFY_PARAM_table_cleanup: void; cdecl external CLibCrypto name 'X509_VERIFY_PARAM_table_cleanup';
function X509_policy_check(ptree: PPX509_POLICY_TREE; pexplicit_policy: PIdC_INT; certs: Pstack_st_X509; policy_oids: Pstack_st_ASN1_OBJECT; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_policy_check';
function X509_policy_tree_free(tree: PX509_POLICY_TREE): void; cdecl external CLibCrypto name 'X509_policy_tree_free';
function X509_policy_tree_level_count(tree: PX509_POLICY_TREE): TIdC_INT; cdecl external CLibCrypto name 'X509_policy_tree_level_count';
function X509_policy_tree_get0_level(tree: PX509_POLICY_TREE; i: TIdC_INT): PX509_POLICY_LEVEL; cdecl external CLibCrypto name 'X509_policy_tree_get0_level';
function X509_policy_tree_get0_policies(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl external CLibCrypto name 'X509_policy_tree_get0_policies';
function X509_policy_tree_get0_user_policies(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl external CLibCrypto name 'X509_policy_tree_get0_user_policies';
function X509_policy_level_node_count(level: PX509_POLICY_LEVEL): TIdC_INT; cdecl external CLibCrypto name 'X509_policy_level_node_count';
function X509_policy_level_get0_node(level: PX509_POLICY_LEVEL; i: TIdC_INT): PX509_POLICY_NODE; cdecl external CLibCrypto name 'X509_policy_level_get0_node';
function X509_policy_node_get0_policy(node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl external CLibCrypto name 'X509_policy_node_get0_policy';
function X509_policy_node_get0_qualifiers(node: PX509_POLICY_NODE): Pstack_st_POLICYQUALINFO; cdecl external CLibCrypto name 'X509_policy_node_get0_qualifiers';
function X509_policy_node_get0_parent(node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl external CLibCrypto name 'X509_policy_node_get0_parent';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  X509_TRUST_set_procname = 'X509_TRUST_set';
  X509_TRUST_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_get_count_procname = 'X509_TRUST_get_count';
  X509_TRUST_get_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_get0_procname = 'X509_TRUST_get0';
  X509_TRUST_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_get_by_id_procname = 'X509_TRUST_get_by_id';
  X509_TRUST_get_by_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_add_procname = 'X509_TRUST_add';
  X509_TRUST_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_cleanup_procname = 'X509_TRUST_cleanup';
  X509_TRUST_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_get_flags_procname = 'X509_TRUST_get_flags';
  X509_TRUST_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_get0_name_procname = 'X509_TRUST_get0_name';
  X509_TRUST_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_get_trust_procname = 'X509_TRUST_get_trust';
  X509_TRUST_get_trust_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_trusted_procname = 'X509_trusted';
  X509_trusted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_add1_trust_object_procname = 'X509_add1_trust_object';
  X509_add1_trust_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_add1_reject_object_procname = 'X509_add1_reject_object';
  X509_add1_reject_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_trust_clear_procname = 'X509_trust_clear';
  X509_trust_clear_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_reject_clear_procname = 'X509_reject_clear';
  X509_reject_clear_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_trust_objects_procname = 'X509_get0_trust_objects';
  X509_get0_trust_objects_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_reject_objects_procname = 'X509_get0_reject_objects';
  X509_get0_reject_objects_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_TRUST_set_default_procname = 'X509_TRUST_set_default';
  X509_TRUST_set_default_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_trust_procname = 'X509_check_trust';
  X509_check_trust_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_verify_cert_procname = 'X509_verify_cert';
  X509_verify_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_verify_procname = 'X509_STORE_CTX_verify';
  X509_STORE_CTX_verify_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_build_chain_procname = 'X509_build_chain';
  X509_build_chain_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_set_depth_procname = 'X509_STORE_set_depth';
  X509_STORE_set_depth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_print_verify_cb_procname = 'X509_STORE_CTX_print_verify_cb';
  X509_STORE_CTX_print_verify_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_CTX_set_depth_procname = 'X509_STORE_CTX_set_depth';
  X509_STORE_CTX_set_depth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_idx_by_subject_procname = 'X509_OBJECT_idx_by_subject';
  X509_OBJECT_idx_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_retrieve_by_subject_procname = 'X509_OBJECT_retrieve_by_subject';
  X509_OBJECT_retrieve_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_retrieve_match_procname = 'X509_OBJECT_retrieve_match';
  X509_OBJECT_retrieve_match_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_up_ref_count_procname = 'X509_OBJECT_up_ref_count';
  X509_OBJECT_up_ref_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_new_procname = 'X509_OBJECT_new';
  X509_OBJECT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_free_procname = 'X509_OBJECT_free';
  X509_OBJECT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_get_type_procname = 'X509_OBJECT_get_type';
  X509_OBJECT_get_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_get0_X509_procname = 'X509_OBJECT_get0_X509';
  X509_OBJECT_get0_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_set1_X509_procname = 'X509_OBJECT_set1_X509';
  X509_OBJECT_set1_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_OBJECT_get0_X509_CRL_procname = 'X509_OBJECT_get0_X509_CRL';
  X509_OBJECT_get0_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_OBJECT_set1_X509_CRL_procname = 'X509_OBJECT_set1_X509_CRL';
  X509_OBJECT_set1_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_STORE_new_procname = 'X509_STORE_new';
  X509_STORE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_free_procname = 'X509_STORE_free';
  X509_STORE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_lock_procname = 'X509_STORE_lock';
  X509_STORE_lock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_unlock_procname = 'X509_STORE_unlock';
  X509_STORE_unlock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_up_ref_procname = 'X509_STORE_up_ref';
  X509_STORE_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get0_objects_procname = 'X509_STORE_get0_objects';
  X509_STORE_get0_objects_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get1_objects_procname = 'X509_STORE_get1_objects';
  X509_STORE_get1_objects_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  X509_STORE_get1_all_certs_procname = 'X509_STORE_get1_all_certs';
  X509_STORE_get1_all_certs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_CTX_get1_certs_procname = 'X509_STORE_CTX_get1_certs';
  X509_STORE_CTX_get1_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get1_crls_procname = 'X509_STORE_CTX_get1_crls';
  X509_STORE_CTX_get1_crls_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_flags_procname = 'X509_STORE_set_flags';
  X509_STORE_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_purpose_procname = 'X509_STORE_set_purpose';
  X509_STORE_set_purpose_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_trust_procname = 'X509_STORE_set_trust';
  X509_STORE_set_trust_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set1_param_procname = 'X509_STORE_set1_param';
  X509_STORE_set1_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get0_param_procname = 'X509_STORE_get0_param';
  X509_STORE_get0_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_verify_procname = 'X509_STORE_set_verify';
  X509_STORE_set_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_verify_procname = 'X509_STORE_CTX_set_verify';
  X509_STORE_CTX_set_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_verify_procname = 'X509_STORE_get_verify';
  X509_STORE_get_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_verify_cb_procname = 'X509_STORE_set_verify_cb';
  X509_STORE_set_verify_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_verify_cb_procname = 'X509_STORE_get_verify_cb';
  X509_STORE_get_verify_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_get_issuer_procname = 'X509_STORE_set_get_issuer';
  X509_STORE_set_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_get_issuer_procname = 'X509_STORE_get_get_issuer';
  X509_STORE_get_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_check_issued_procname = 'X509_STORE_set_check_issued';
  X509_STORE_set_check_issued_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_check_issued_procname = 'X509_STORE_get_check_issued';
  X509_STORE_get_check_issued_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_check_revocation_procname = 'X509_STORE_set_check_revocation';
  X509_STORE_set_check_revocation_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_check_revocation_procname = 'X509_STORE_get_check_revocation';
  X509_STORE_get_check_revocation_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_get_crl_procname = 'X509_STORE_set_get_crl';
  X509_STORE_set_get_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_get_crl_procname = 'X509_STORE_get_get_crl';
  X509_STORE_get_get_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_check_crl_procname = 'X509_STORE_set_check_crl';
  X509_STORE_set_check_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_check_crl_procname = 'X509_STORE_get_check_crl';
  X509_STORE_get_check_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_cert_crl_procname = 'X509_STORE_set_cert_crl';
  X509_STORE_set_cert_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_cert_crl_procname = 'X509_STORE_get_cert_crl';
  X509_STORE_get_cert_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_check_policy_procname = 'X509_STORE_set_check_policy';
  X509_STORE_set_check_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_check_policy_procname = 'X509_STORE_get_check_policy';
  X509_STORE_get_check_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_lookup_certs_procname = 'X509_STORE_set_lookup_certs';
  X509_STORE_set_lookup_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_lookup_certs_procname = 'X509_STORE_get_lookup_certs';
  X509_STORE_get_lookup_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_lookup_crls_procname = 'X509_STORE_set_lookup_crls';
  X509_STORE_set_lookup_crls_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_lookup_crls_procname = 'X509_STORE_get_lookup_crls';
  X509_STORE_get_lookup_crls_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_cleanup_procname = 'X509_STORE_set_cleanup';
  X509_STORE_set_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_cleanup_procname = 'X509_STORE_get_cleanup';
  X509_STORE_get_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_ex_data_procname = 'X509_STORE_set_ex_data';
  X509_STORE_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_get_ex_data_procname = 'X509_STORE_get_ex_data';
  X509_STORE_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_new_ex_procname = 'X509_STORE_CTX_new_ex';
  X509_STORE_CTX_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_CTX_new_procname = 'X509_STORE_CTX_new';
  X509_STORE_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get1_issuer_procname = 'X509_STORE_CTX_get1_issuer';
  X509_STORE_CTX_get1_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_free_procname = 'X509_STORE_CTX_free';
  X509_STORE_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_init_procname = 'X509_STORE_CTX_init';
  X509_STORE_CTX_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_init_rpk_procname = 'X509_STORE_CTX_init_rpk';
  X509_STORE_CTX_init_rpk_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  X509_STORE_CTX_set0_trusted_stack_procname = 'X509_STORE_CTX_set0_trusted_stack';
  X509_STORE_CTX_set0_trusted_stack_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_cleanup_procname = 'X509_STORE_CTX_cleanup';
  X509_STORE_CTX_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_store_procname = 'X509_STORE_CTX_get0_store';
  X509_STORE_CTX_get0_store_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_cert_procname = 'X509_STORE_CTX_get0_cert';
  X509_STORE_CTX_get0_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_rpk_procname = 'X509_STORE_CTX_get0_rpk';
  X509_STORE_CTX_get0_rpk_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  X509_STORE_CTX_get0_untrusted_procname = 'X509_STORE_CTX_get0_untrusted';
  X509_STORE_CTX_get0_untrusted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set0_untrusted_procname = 'X509_STORE_CTX_set0_untrusted';
  X509_STORE_CTX_set0_untrusted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_verify_cb_procname = 'X509_STORE_CTX_set_verify_cb';
  X509_STORE_CTX_set_verify_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_verify_cb_procname = 'X509_STORE_CTX_get_verify_cb';
  X509_STORE_CTX_get_verify_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_verify_procname = 'X509_STORE_CTX_get_verify';
  X509_STORE_CTX_get_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_get_issuer_procname = 'X509_STORE_CTX_get_get_issuer';
  X509_STORE_CTX_get_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_check_issued_procname = 'X509_STORE_CTX_get_check_issued';
  X509_STORE_CTX_get_check_issued_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_check_revocation_procname = 'X509_STORE_CTX_get_check_revocation';
  X509_STORE_CTX_get_check_revocation_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_get_crl_procname = 'X509_STORE_CTX_set_get_crl';
  X509_STORE_CTX_set_get_crl_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  X509_STORE_CTX_get_get_crl_procname = 'X509_STORE_CTX_get_get_crl';
  X509_STORE_CTX_get_get_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_check_crl_procname = 'X509_STORE_CTX_get_check_crl';
  X509_STORE_CTX_get_check_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_cert_crl_procname = 'X509_STORE_CTX_get_cert_crl';
  X509_STORE_CTX_get_cert_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_check_policy_procname = 'X509_STORE_CTX_get_check_policy';
  X509_STORE_CTX_get_check_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_lookup_certs_procname = 'X509_STORE_CTX_get_lookup_certs';
  X509_STORE_CTX_get_lookup_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_lookup_crls_procname = 'X509_STORE_CTX_get_lookup_crls';
  X509_STORE_CTX_get_lookup_crls_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_cleanup_procname = 'X509_STORE_CTX_get_cleanup';
  X509_STORE_CTX_get_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_add_lookup_procname = 'X509_STORE_add_lookup';
  X509_STORE_add_lookup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_hash_dir_procname = 'X509_LOOKUP_hash_dir';
  X509_LOOKUP_hash_dir_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_file_procname = 'X509_LOOKUP_file';
  X509_LOOKUP_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_store_procname = 'X509_LOOKUP_store';
  X509_LOOKUP_store_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_LOOKUP_meth_new_procname = 'X509_LOOKUP_meth_new';
  X509_LOOKUP_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_free_procname = 'X509_LOOKUP_meth_free';
  X509_LOOKUP_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_new_item_procname = 'X509_LOOKUP_meth_set_new_item';
  X509_LOOKUP_meth_set_new_item_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_new_item_procname = 'X509_LOOKUP_meth_get_new_item';
  X509_LOOKUP_meth_get_new_item_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_free_procname = 'X509_LOOKUP_meth_set_free';
  X509_LOOKUP_meth_set_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_free_procname = 'X509_LOOKUP_meth_get_free';
  X509_LOOKUP_meth_get_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_init_procname = 'X509_LOOKUP_meth_set_init';
  X509_LOOKUP_meth_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_init_procname = 'X509_LOOKUP_meth_get_init';
  X509_LOOKUP_meth_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_shutdown_procname = 'X509_LOOKUP_meth_set_shutdown';
  X509_LOOKUP_meth_set_shutdown_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_shutdown_procname = 'X509_LOOKUP_meth_get_shutdown';
  X509_LOOKUP_meth_get_shutdown_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_ctrl_procname = 'X509_LOOKUP_meth_set_ctrl';
  X509_LOOKUP_meth_set_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_ctrl_procname = 'X509_LOOKUP_meth_get_ctrl';
  X509_LOOKUP_meth_get_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_get_by_subject_procname = 'X509_LOOKUP_meth_set_get_by_subject';
  X509_LOOKUP_meth_set_get_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_get_by_subject_procname = 'X509_LOOKUP_meth_get_get_by_subject';
  X509_LOOKUP_meth_get_get_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_get_by_issuer_serial_procname = 'X509_LOOKUP_meth_set_get_by_issuer_serial';
  X509_LOOKUP_meth_set_get_by_issuer_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_get_by_issuer_serial_procname = 'X509_LOOKUP_meth_get_get_by_issuer_serial';
  X509_LOOKUP_meth_get_get_by_issuer_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_get_by_fingerprint_procname = 'X509_LOOKUP_meth_set_get_by_fingerprint';
  X509_LOOKUP_meth_set_get_by_fingerprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_get_by_fingerprint_procname = 'X509_LOOKUP_meth_get_get_by_fingerprint';
  X509_LOOKUP_meth_get_get_by_fingerprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_set_get_by_alias_procname = 'X509_LOOKUP_meth_set_get_by_alias';
  X509_LOOKUP_meth_set_get_by_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_meth_get_get_by_alias_procname = 'X509_LOOKUP_meth_get_get_by_alias';
  X509_LOOKUP_meth_get_get_by_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_STORE_add_cert_procname = 'X509_STORE_add_cert';
  X509_STORE_add_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_add_crl_procname = 'X509_STORE_add_crl';
  X509_STORE_add_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_by_subject_procname = 'X509_STORE_CTX_get_by_subject';
  X509_STORE_CTX_get_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_obj_by_subject_procname = 'X509_STORE_CTX_get_obj_by_subject';
  X509_STORE_CTX_get_obj_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_ctrl_procname = 'X509_LOOKUP_ctrl';
  X509_LOOKUP_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_ctrl_ex_procname = 'X509_LOOKUP_ctrl_ex';
  X509_LOOKUP_ctrl_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_load_cert_file_procname = 'X509_load_cert_file';
  X509_load_cert_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_load_cert_file_ex_procname = 'X509_load_cert_file_ex';
  X509_load_cert_file_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_load_crl_file_procname = 'X509_load_crl_file';
  X509_load_crl_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_load_cert_crl_file_procname = 'X509_load_cert_crl_file';
  X509_load_cert_crl_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_load_cert_crl_file_ex_procname = 'X509_load_cert_crl_file_ex';
  X509_load_cert_crl_file_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_LOOKUP_new_procname = 'X509_LOOKUP_new';
  X509_LOOKUP_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_free_procname = 'X509_LOOKUP_free';
  X509_LOOKUP_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_init_procname = 'X509_LOOKUP_init';
  X509_LOOKUP_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_by_subject_procname = 'X509_LOOKUP_by_subject';
  X509_LOOKUP_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_by_subject_ex_procname = 'X509_LOOKUP_by_subject_ex';
  X509_LOOKUP_by_subject_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_LOOKUP_by_issuer_serial_procname = 'X509_LOOKUP_by_issuer_serial';
  X509_LOOKUP_by_issuer_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_by_fingerprint_procname = 'X509_LOOKUP_by_fingerprint';
  X509_LOOKUP_by_fingerprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_by_alias_procname = 'X509_LOOKUP_by_alias';
  X509_LOOKUP_by_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_LOOKUP_set_method_data_procname = 'X509_LOOKUP_set_method_data';
  X509_LOOKUP_set_method_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_get_method_data_procname = 'X509_LOOKUP_get_method_data';
  X509_LOOKUP_get_method_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_get_store_procname = 'X509_LOOKUP_get_store';
  X509_LOOKUP_get_store_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_LOOKUP_shutdown_procname = 'X509_LOOKUP_shutdown';
  X509_LOOKUP_shutdown_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_load_file_procname = 'X509_STORE_load_file';
  X509_STORE_load_file_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_load_path_procname = 'X509_STORE_load_path';
  X509_STORE_load_path_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_load_store_procname = 'X509_STORE_load_store';
  X509_STORE_load_store_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_load_locations_procname = 'X509_STORE_load_locations';
  X509_STORE_load_locations_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_set_default_paths_procname = 'X509_STORE_set_default_paths';
  X509_STORE_set_default_paths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_load_file_ex_procname = 'X509_STORE_load_file_ex';
  X509_STORE_load_file_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_load_store_ex_procname = 'X509_STORE_load_store_ex';
  X509_STORE_load_store_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_load_locations_ex_procname = 'X509_STORE_load_locations_ex';
  X509_STORE_load_locations_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_set_default_paths_ex_procname = 'X509_STORE_set_default_paths_ex';
  X509_STORE_set_default_paths_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_STORE_CTX_set_ex_data_procname = 'X509_STORE_CTX_set_ex_data';
  X509_STORE_CTX_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_ex_data_procname = 'X509_STORE_CTX_get_ex_data';
  X509_STORE_CTX_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_error_procname = 'X509_STORE_CTX_get_error';
  X509_STORE_CTX_get_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_error_procname = 'X509_STORE_CTX_set_error';
  X509_STORE_CTX_set_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_error_depth_procname = 'X509_STORE_CTX_get_error_depth';
  X509_STORE_CTX_get_error_depth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_error_depth_procname = 'X509_STORE_CTX_set_error_depth';
  X509_STORE_CTX_set_error_depth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_current_cert_procname = 'X509_STORE_CTX_get_current_cert';
  X509_STORE_CTX_get_current_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_current_cert_procname = 'X509_STORE_CTX_set_current_cert';
  X509_STORE_CTX_set_current_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_current_issuer_procname = 'X509_STORE_CTX_get0_current_issuer';
  X509_STORE_CTX_get0_current_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_current_crl_procname = 'X509_STORE_CTX_get0_current_crl';
  X509_STORE_CTX_get0_current_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_parent_ctx_procname = 'X509_STORE_CTX_get0_parent_ctx';
  X509_STORE_CTX_get0_parent_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_chain_procname = 'X509_STORE_CTX_get0_chain';
  X509_STORE_CTX_get0_chain_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get1_chain_procname = 'X509_STORE_CTX_get1_chain';
  X509_STORE_CTX_get1_chain_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_cert_procname = 'X509_STORE_CTX_set_cert';
  X509_STORE_CTX_set_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set0_rpk_procname = 'X509_STORE_CTX_set0_rpk';
  X509_STORE_CTX_set0_rpk_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  X509_STORE_CTX_set0_verified_chain_procname = 'X509_STORE_CTX_set0_verified_chain';
  X509_STORE_CTX_set0_verified_chain_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set0_crls_procname = 'X509_STORE_CTX_set0_crls';
  X509_STORE_CTX_set0_crls_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_ocsp_resp_procname = 'X509_STORE_CTX_set_ocsp_resp';
  X509_STORE_CTX_set_ocsp_resp_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  X509_STORE_CTX_set_purpose_procname = 'X509_STORE_CTX_set_purpose';
  X509_STORE_CTX_set_purpose_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_trust_procname = 'X509_STORE_CTX_set_trust';
  X509_STORE_CTX_set_trust_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_purpose_inherit_procname = 'X509_STORE_CTX_purpose_inherit';
  X509_STORE_CTX_purpose_inherit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_flags_procname = 'X509_STORE_CTX_set_flags';
  X509_STORE_CTX_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_time_procname = 'X509_STORE_CTX_set_time';
  X509_STORE_CTX_set_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_current_reasons_procname = 'X509_STORE_CTX_set_current_reasons';
  X509_STORE_CTX_set_current_reasons_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  X509_STORE_CTX_get0_policy_tree_procname = 'X509_STORE_CTX_get0_policy_tree';
  X509_STORE_CTX_get0_policy_tree_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_explicit_policy_procname = 'X509_STORE_CTX_get_explicit_policy';
  X509_STORE_CTX_get_explicit_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get_num_untrusted_procname = 'X509_STORE_CTX_get_num_untrusted';
  X509_STORE_CTX_get_num_untrusted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_get0_param_procname = 'X509_STORE_CTX_get0_param';
  X509_STORE_CTX_get0_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set0_param_procname = 'X509_STORE_CTX_set0_param';
  X509_STORE_CTX_set0_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set_default_procname = 'X509_STORE_CTX_set_default';
  X509_STORE_CTX_set_default_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_STORE_CTX_set0_dane_procname = 'X509_STORE_CTX_set0_dane';
  X509_STORE_CTX_set0_dane_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_new_procname = 'X509_VERIFY_PARAM_new';
  X509_VERIFY_PARAM_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_free_procname = 'X509_VERIFY_PARAM_free';
  X509_VERIFY_PARAM_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_inherit_procname = 'X509_VERIFY_PARAM_inherit';
  X509_VERIFY_PARAM_inherit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set1_procname = 'X509_VERIFY_PARAM_set1';
  X509_VERIFY_PARAM_set1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set1_name_procname = 'X509_VERIFY_PARAM_set1_name';
  X509_VERIFY_PARAM_set1_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set_flags_procname = 'X509_VERIFY_PARAM_set_flags';
  X509_VERIFY_PARAM_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_clear_flags_procname = 'X509_VERIFY_PARAM_clear_flags';
  X509_VERIFY_PARAM_clear_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get_flags_procname = 'X509_VERIFY_PARAM_get_flags';
  X509_VERIFY_PARAM_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set_purpose_procname = 'X509_VERIFY_PARAM_set_purpose';
  X509_VERIFY_PARAM_set_purpose_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get_purpose_procname = 'X509_VERIFY_PARAM_get_purpose';
  X509_VERIFY_PARAM_get_purpose_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set_trust_procname = 'X509_VERIFY_PARAM_set_trust';
  X509_VERIFY_PARAM_set_trust_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set_depth_procname = 'X509_VERIFY_PARAM_set_depth';
  X509_VERIFY_PARAM_set_depth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set_auth_level_procname = 'X509_VERIFY_PARAM_set_auth_level';
  X509_VERIFY_PARAM_set_auth_level_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get_time_procname = 'X509_VERIFY_PARAM_get_time';
  X509_VERIFY_PARAM_get_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0d);

  X509_VERIFY_PARAM_set_time_procname = 'X509_VERIFY_PARAM_set_time';
  X509_VERIFY_PARAM_set_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_add0_policy_procname = 'X509_VERIFY_PARAM_add0_policy';
  X509_VERIFY_PARAM_add0_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set1_policies_procname = 'X509_VERIFY_PARAM_set1_policies';
  X509_VERIFY_PARAM_set1_policies_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set_inh_flags_procname = 'X509_VERIFY_PARAM_set_inh_flags';
  X509_VERIFY_PARAM_set_inh_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0d);

  X509_VERIFY_PARAM_get_inh_flags_procname = 'X509_VERIFY_PARAM_get_inh_flags';
  X509_VERIFY_PARAM_get_inh_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0d);

  X509_VERIFY_PARAM_get0_host_procname = 'X509_VERIFY_PARAM_get0_host';
  X509_VERIFY_PARAM_get0_host_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set1_host_procname = 'X509_VERIFY_PARAM_set1_host';
  X509_VERIFY_PARAM_set1_host_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_add1_host_procname = 'X509_VERIFY_PARAM_add1_host';
  X509_VERIFY_PARAM_add1_host_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set_hostflags_procname = 'X509_VERIFY_PARAM_set_hostflags';
  X509_VERIFY_PARAM_set_hostflags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get_hostflags_procname = 'X509_VERIFY_PARAM_get_hostflags';
  X509_VERIFY_PARAM_get_hostflags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0i);

  X509_VERIFY_PARAM_get0_peername_procname = 'X509_VERIFY_PARAM_get0_peername';
  X509_VERIFY_PARAM_get0_peername_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_move_peername_procname = 'X509_VERIFY_PARAM_move_peername';
  X509_VERIFY_PARAM_move_peername_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get0_email_procname = 'X509_VERIFY_PARAM_get0_email';
  X509_VERIFY_PARAM_get0_email_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set1_email_procname = 'X509_VERIFY_PARAM_set1_email';
  X509_VERIFY_PARAM_set1_email_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get1_ip_asc_procname = 'X509_VERIFY_PARAM_get1_ip_asc';
  X509_VERIFY_PARAM_get1_ip_asc_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set1_ip_procname = 'X509_VERIFY_PARAM_set1_ip';
  X509_VERIFY_PARAM_set1_ip_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_set1_ip_asc_procname = 'X509_VERIFY_PARAM_set1_ip_asc';
  X509_VERIFY_PARAM_set1_ip_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get_depth_procname = 'X509_VERIFY_PARAM_get_depth';
  X509_VERIFY_PARAM_get_depth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get_auth_level_procname = 'X509_VERIFY_PARAM_get_auth_level';
  X509_VERIFY_PARAM_get_auth_level_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get0_name_procname = 'X509_VERIFY_PARAM_get0_name';
  X509_VERIFY_PARAM_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_add0_table_procname = 'X509_VERIFY_PARAM_add0_table';
  X509_VERIFY_PARAM_add0_table_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get_count_procname = 'X509_VERIFY_PARAM_get_count';
  X509_VERIFY_PARAM_get_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_get0_procname = 'X509_VERIFY_PARAM_get0';
  X509_VERIFY_PARAM_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_lookup_procname = 'X509_VERIFY_PARAM_lookup';
  X509_VERIFY_PARAM_lookup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VERIFY_PARAM_table_cleanup_procname = 'X509_VERIFY_PARAM_table_cleanup';
  X509_VERIFY_PARAM_table_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_check_procname = 'X509_policy_check';
  X509_policy_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_tree_free_procname = 'X509_policy_tree_free';
  X509_policy_tree_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_tree_level_count_procname = 'X509_policy_tree_level_count';
  X509_policy_tree_level_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_tree_get0_level_procname = 'X509_policy_tree_get0_level';
  X509_policy_tree_get0_level_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_tree_get0_policies_procname = 'X509_policy_tree_get0_policies';
  X509_policy_tree_get0_policies_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_tree_get0_user_policies_procname = 'X509_policy_tree_get0_user_policies';
  X509_policy_tree_get0_user_policies_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_level_node_count_procname = 'X509_policy_level_node_count';
  X509_policy_level_node_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_level_get0_node_procname = 'X509_policy_level_get0_node';
  X509_policy_level_get0_node_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_node_get0_policy_procname = 'X509_policy_node_get0_policy';
  X509_policy_node_get0_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_node_get0_qualifiers_procname = 'X509_policy_node_get0_qualifiers';
  X509_policy_node_get0_qualifiers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_policy_node_get0_parent_procname = 'X509_policy_node_get0_parent';
  X509_policy_node_get0_parent_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function X509_LOOKUP_load_file(x: Pointer; name: Pointer; _type: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_LOOKUP_load_file(x, name, type) \
    X509_LOOKUP_ctrl((x), X509_L_FILE_LOAD, (name), (long)(type), NULL)
  }
end;

function X509_LOOKUP_add_dir(x: Pointer; name: Pointer; _type: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_LOOKUP_add_dir(x, name, type) \
    X509_LOOKUP_ctrl((x), X509_L_ADD_DIR, (name), (long)(type), NULL)
  }
end;

function X509_LOOKUP_add_store(x: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_LOOKUP_add_store(x, name) \
    X509_LOOKUP_ctrl((x), X509_L_ADD_STORE, (name), 0, NULL)
  }
end;

function X509_LOOKUP_load_store(x: Pointer; name: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_LOOKUP_load_store(x, name) \
    X509_LOOKUP_ctrl((x), X509_L_LOAD_STORE, (name), 0, NULL)
  }
end;

function X509_LOOKUP_load_file_ex(x: Pointer; name: Pointer; _type: Pointer; libctx: Pointer; propq: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_LOOKUP_load_file_ex(x, name, type, libctx, propq)             \
    X509_LOOKUP_ctrl_ex((x), X509_L_FILE_LOAD, (name), (long)(type), NULL, \
        (libctx), (propq))
  }
end;

function X509_LOOKUP_load_store_ex(x: Pointer; name: Pointer; libctx: Pointer; propq: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_LOOKUP_load_store_ex(x, name, libctx, propq)        \
    X509_LOOKUP_ctrl_ex((x), X509_L_LOAD_STORE, (name), 0, NULL, \
        (libctx), (propq))
  }
end;

function X509_LOOKUP_add_store_ex(x: Pointer; name: Pointer; libctx: Pointer; propq: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_LOOKUP_add_store_ex(x, name, libctx, propq)        \
    X509_LOOKUP_ctrl_ex((x), X509_L_ADD_STORE, (name), 0, NULL, \
        (libctx), (propq))
  }
end;

function X509_STORE_set_verify_func(ctx: Pointer; func: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_set_verify_func(ctx, func) \
    X509_STORE_set_verify((ctx), (func))
  }
end;

function X509_STORE_set_verify_cb_func(ctx: Pointer; func: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_set_verify_cb_func(ctx, func) \
    X509_STORE_set_verify_cb((ctx), (func))
  }
end;

function X509_STORE_set_lookup_crls_cb(ctx: Pointer; func: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_set_lookup_crls_cb(ctx, func) \
    X509_STORE_set_lookup_crls((ctx), (func))
  }
end;

function X509_STORE_CTX_get_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_CTX_get_chain X509_STORE_CTX_get0_chain
  }
end;

function X509_STORE_CTX_set_chain(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_CTX_set_chain X509_STORE_CTX_set0_untrusted
  }
end;

function X509_STORE_CTX_trusted_stack(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_CTX_trusted_stack X509_STORE_CTX_set0_trusted_stack
  }
end;

function X509_STORE_get_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_get_by_subject X509_STORE_CTX_get_by_subject
  }
end;

function X509_STORE_get1_certs(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_get1_certs X509_STORE_CTX_get1_certs
  }
end;

function X509_STORE_get1_crls(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_get1_crls X509_STORE_CTX_get1_crls
  }
end;

function X509_STORE_get1_cert(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_get1_cert X509_STORE_CTX_get1_certs
  }
end;

function X509_STORE_get1_crl(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_STORE_get1_crl X509_STORE_CTX_get1_crls
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_X509_TRUST_set(t: PIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_set_procname);
end;

function ERR_X509_TRUST_get_count: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_count_procname);
end;

function ERR_X509_TRUST_get0(idx: TIdC_INT): PX509_TRUST; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get0_procname);
end;

function ERR_X509_TRUST_get_by_id(id: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_by_id_procname);
end;

function ERR_X509_TRUST_add(id: TIdC_INT; flags: TIdC_INT; ck: Tsk_X509_VERIFY_PARAM_copyfunc_func_cb; name: PIdAnsiChar; arg1: TIdC_INT; arg2: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_add_procname);
end;

function ERR_X509_TRUST_cleanup: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_cleanup_procname);
end;

function ERR_X509_TRUST_get_flags(xp: PX509_TRUST): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_flags_procname);
end;

function ERR_X509_TRUST_get0_name(xp: PX509_TRUST): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get0_name_procname);
end;

function ERR_X509_TRUST_get_trust(xp: PX509_TRUST): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_get_trust_procname);
end;

function ERR_X509_trusted(x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_trusted_procname);
end;

function ERR_X509_add1_trust_object(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add1_trust_object_procname);
end;

function ERR_X509_add1_reject_object(x: PX509; obj: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add1_reject_object_procname);
end;

function ERR_X509_trust_clear(x: PX509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_trust_clear_procname);
end;

function ERR_X509_reject_clear(x: PX509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_reject_clear_procname);
end;

function ERR_X509_get0_trust_objects(x: PX509): Pstack_st_ASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_trust_objects_procname);
end;

function ERR_X509_get0_reject_objects(x: PX509): Pstack_st_ASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_reject_objects_procname);
end;

function ERR_X509_TRUST_set_default(trust: TX509_TRUST_set_default_trust_cb): TX509_TRUST_set_default_trust_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_TRUST_set_default_procname);
end;

function ERR_X509_check_trust(x: PX509; id: TIdC_INT; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_trust_procname);
end;

function ERR_X509_verify_cert(ctx: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_verify_cert_procname);
end;

function ERR_X509_STORE_CTX_verify(ctx: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_verify_procname);
end;

function ERR_X509_build_chain(target: PX509; certs: Pstack_st_X509; store: PX509_STORE; with_self_signed: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_build_chain_procname);
end;

function ERR_X509_STORE_set_depth(store: PX509_STORE; depth: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_depth_procname);
end;

function ERR_X509_STORE_CTX_print_verify_cb(ok: TIdC_INT; ctx: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_print_verify_cb_procname);
end;

function ERR_X509_STORE_CTX_set_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_depth_procname);
end;

function ERR_X509_OBJECT_idx_by_subject(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_idx_by_subject_procname);
end;

function ERR_X509_OBJECT_retrieve_by_subject(h: Pstack_st_X509_OBJECT; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_retrieve_by_subject_procname);
end;

function ERR_X509_OBJECT_retrieve_match(h: Pstack_st_X509_OBJECT; x: PX509_OBJECT): PX509_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_retrieve_match_procname);
end;

function ERR_X509_OBJECT_up_ref_count(a: PX509_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_up_ref_count_procname);
end;

function ERR_X509_OBJECT_new: PX509_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_new_procname);
end;

function ERR_X509_OBJECT_free(a: PX509_OBJECT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_free_procname);
end;

function ERR_X509_OBJECT_get_type(a: PX509_OBJECT): TX509_LOOKUP_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_get_type_procname);
end;

function ERR_X509_OBJECT_get0_X509(a: PX509_OBJECT): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_get0_X509_procname);
end;

function ERR_X509_OBJECT_set1_X509(a: PX509_OBJECT; obj: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_set1_X509_procname);
end;

function ERR_X509_OBJECT_get0_X509_CRL(a: PX509_OBJECT): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_get0_X509_CRL_procname);
end;

function ERR_X509_OBJECT_set1_X509_CRL(a: PX509_OBJECT; obj: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_OBJECT_set1_X509_CRL_procname);
end;

function ERR_X509_STORE_new: PX509_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_new_procname);
end;

function ERR_X509_STORE_free(xs: PX509_STORE): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_free_procname);
end;

function ERR_X509_STORE_lock(xs: PX509_STORE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_lock_procname);
end;

function ERR_X509_STORE_unlock(xs: PX509_STORE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_unlock_procname);
end;

function ERR_X509_STORE_up_ref(xs: PX509_STORE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_up_ref_procname);
end;

function ERR_X509_STORE_get0_objects(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get0_objects_procname);
end;

function ERR_X509_STORE_get1_objects(xs: PX509_STORE): Pstack_st_X509_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get1_objects_procname);
end;

function ERR_X509_STORE_get1_all_certs(xs: PX509_STORE): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get1_all_certs_procname);
end;

function ERR_X509_STORE_CTX_get1_certs(xs: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get1_certs_procname);
end;

function ERR_X509_STORE_CTX_get1_crls(st: PX509_STORE_CTX; nm: PX509_NAME): Pstack_st_X509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get1_crls_procname);
end;

function ERR_X509_STORE_set_flags(xs: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_flags_procname);
end;

function ERR_X509_STORE_set_purpose(xs: PX509_STORE; purpose: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_purpose_procname);
end;

function ERR_X509_STORE_set_trust(xs: PX509_STORE; trust: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_trust_procname);
end;

function ERR_X509_STORE_set1_param(xs: PX509_STORE; pm: PX509_VERIFY_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set1_param_procname);
end;

function ERR_X509_STORE_get0_param(xs: PX509_STORE): PX509_VERIFY_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get0_param_procname);
end;

function ERR_X509_STORE_set_verify(xs: PX509_STORE; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_verify_procname);
end;

function ERR_X509_STORE_CTX_set_verify(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_cleanup_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_verify_procname);
end;

function ERR_X509_STORE_get_verify(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_verify_procname);
end;

function ERR_X509_STORE_set_verify_cb(xs: PX509_STORE; verify_cb: TX509_STORE_CTX_verify_cb): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_verify_cb_procname);
end;

function ERR_X509_STORE_get_verify_cb(xs: PX509_STORE): TX509_STORE_CTX_verify_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_verify_cb_procname);
end;

function ERR_X509_STORE_set_get_issuer(xs: PX509_STORE; get_issuer: TX509_STORE_CTX_get_issuer_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_get_issuer_procname);
end;

function ERR_X509_STORE_get_get_issuer(xs: PX509_STORE): TX509_STORE_CTX_get_issuer_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_get_issuer_procname);
end;

function ERR_X509_STORE_set_check_issued(xs: PX509_STORE; check_issued: TX509_STORE_CTX_check_issued_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_issued_procname);
end;

function ERR_X509_STORE_get_check_issued(s: PX509_STORE): TX509_STORE_CTX_check_issued_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_issued_procname);
end;

function ERR_X509_STORE_set_check_revocation(xs: PX509_STORE; check_revocation: TX509_STORE_CTX_cleanup_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_revocation_procname);
end;

function ERR_X509_STORE_get_check_revocation(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_revocation_procname);
end;

function ERR_X509_STORE_set_get_crl(xs: PX509_STORE; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_get_crl_procname);
end;

function ERR_X509_STORE_get_get_crl(xs: PX509_STORE): TX509_STORE_CTX_get_crl_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_get_crl_procname);
end;

function ERR_X509_STORE_set_check_crl(xs: PX509_STORE; check_crl: TX509_STORE_CTX_check_crl_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_crl_procname);
end;

function ERR_X509_STORE_get_check_crl(xs: PX509_STORE): TX509_STORE_CTX_check_crl_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_crl_procname);
end;

function ERR_X509_STORE_set_cert_crl(xs: PX509_STORE; cert_crl: TX509_STORE_CTX_cert_crl_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_cert_crl_procname);
end;

function ERR_X509_STORE_get_cert_crl(xs: PX509_STORE): TX509_STORE_CTX_cert_crl_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_cert_crl_procname);
end;

function ERR_X509_STORE_set_check_policy(xs: PX509_STORE; check_policy: TX509_STORE_CTX_cleanup_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_check_policy_procname);
end;

function ERR_X509_STORE_get_check_policy(s: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_check_policy_procname);
end;

function ERR_X509_STORE_set_lookup_certs(xs: PX509_STORE; lookup_certs: TX509_STORE_CTX_lookup_certs_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_lookup_certs_procname);
end;

function ERR_X509_STORE_get_lookup_certs(s: PX509_STORE): TX509_STORE_CTX_lookup_certs_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_lookup_certs_procname);
end;

function ERR_X509_STORE_set_lookup_crls(xs: PX509_STORE; lookup_crls: TX509_STORE_CTX_lookup_crls_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_lookup_crls_procname);
end;

function ERR_X509_STORE_get_lookup_crls(xs: PX509_STORE): TX509_STORE_CTX_lookup_crls_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_lookup_crls_procname);
end;

function ERR_X509_STORE_set_cleanup(xs: PX509_STORE; cleanup: TX509_STORE_CTX_cleanup_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_cleanup_procname);
end;

function ERR_X509_STORE_get_cleanup(xs: PX509_STORE): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_cleanup_procname);
end;

function ERR_X509_STORE_set_ex_data(xs: PX509_STORE; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_ex_data_procname);
end;

function ERR_X509_STORE_get_ex_data(xs: PX509_STORE; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_get_ex_data_procname);
end;

function ERR_X509_STORE_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_STORE_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_new_ex_procname);
end;

function ERR_X509_STORE_CTX_new: PX509_STORE_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_new_procname);
end;

function ERR_X509_STORE_CTX_get1_issuer(issuer: PPX509; ctx: PX509_STORE_CTX; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get1_issuer_procname);
end;

function ERR_X509_STORE_CTX_free(ctx: PX509_STORE_CTX): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_free_procname);
end;

function ERR_X509_STORE_CTX_init(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; target: PX509; untrusted: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_init_procname);
end;

function ERR_X509_STORE_CTX_init_rpk(ctx: PX509_STORE_CTX; trust_store: PX509_STORE; rpk: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_init_rpk_procname);
end;

function ERR_X509_STORE_CTX_set0_trusted_stack(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_trusted_stack_procname);
end;

function ERR_X509_STORE_CTX_cleanup(ctx: PX509_STORE_CTX): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_cleanup_procname);
end;

function ERR_X509_STORE_CTX_get0_store(ctx: PX509_STORE_CTX): PX509_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_store_procname);
end;

function ERR_X509_STORE_CTX_get0_cert(ctx: PX509_STORE_CTX): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_cert_procname);
end;

function ERR_X509_STORE_CTX_get0_rpk(ctx: PX509_STORE_CTX): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_rpk_procname);
end;

function ERR_X509_STORE_CTX_get0_untrusted(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_untrusted_procname);
end;

function ERR_X509_STORE_CTX_set0_untrusted(ctx: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_untrusted_procname);
end;

function ERR_X509_STORE_CTX_set_verify_cb(ctx: PX509_STORE_CTX; verify: TX509_STORE_CTX_verify_cb): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_verify_cb_procname);
end;

function ERR_X509_STORE_CTX_get_verify_cb(ctx: PX509_STORE_CTX): TX509_STORE_CTX_verify_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_verify_cb_procname);
end;

function ERR_X509_STORE_CTX_get_verify(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_verify_procname);
end;

function ERR_X509_STORE_CTX_get_get_issuer(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_issuer_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_get_issuer_procname);
end;

function ERR_X509_STORE_CTX_get_check_issued(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_issued_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_issued_procname);
end;

function ERR_X509_STORE_CTX_get_check_revocation(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_revocation_procname);
end;

function ERR_X509_STORE_CTX_set_get_crl(ctx: PX509_STORE_CTX; get_crl: TX509_STORE_CTX_get_crl_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_get_crl_procname);
end;

function ERR_X509_STORE_CTX_get_get_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_get_crl_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_get_crl_procname);
end;

function ERR_X509_STORE_CTX_get_check_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_check_crl_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_crl_procname);
end;

function ERR_X509_STORE_CTX_get_cert_crl(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cert_crl_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_cert_crl_procname);
end;

function ERR_X509_STORE_CTX_get_check_policy(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_check_policy_procname);
end;

function ERR_X509_STORE_CTX_get_lookup_certs(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_certs_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_lookup_certs_procname);
end;

function ERR_X509_STORE_CTX_get_lookup_crls(ctx: PX509_STORE_CTX): TX509_STORE_CTX_lookup_crls_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_lookup_crls_procname);
end;

function ERR_X509_STORE_CTX_get_cleanup(ctx: PX509_STORE_CTX): TX509_STORE_CTX_cleanup_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_cleanup_procname);
end;

function ERR_X509_STORE_add_lookup(xs: PX509_STORE; m: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_add_lookup_procname);
end;

function ERR_X509_LOOKUP_hash_dir: PX509_LOOKUP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_hash_dir_procname);
end;

function ERR_X509_LOOKUP_file: PX509_LOOKUP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_file_procname);
end;

function ERR_X509_LOOKUP_store: PX509_LOOKUP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_store_procname);
end;

function ERR_X509_LOOKUP_meth_new(name: PIdAnsiChar): PX509_LOOKUP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_new_procname);
end;

function ERR_X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_free_procname);
end;

function ERR_X509_LOOKUP_meth_set_new_item(method: PX509_LOOKUP_METHOD; new_item: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_new_item_procname);
end;

function ERR_X509_LOOKUP_meth_get_new_item(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_new_item_procname);
end;

function ERR_X509_LOOKUP_meth_set_free(method: PX509_LOOKUP_METHOD; free_fn: Tsk_X509_LOOKUP_freefunc): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_free_procname);
end;

function ERR_X509_LOOKUP_meth_get_free(method: PX509_LOOKUP_METHOD): Tsk_X509_LOOKUP_freefunc; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_free_procname);
end;

function ERR_X509_LOOKUP_meth_set_init(method: PX509_LOOKUP_METHOD; init: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_init_procname);
end;

function ERR_X509_LOOKUP_meth_get_init(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_init_procname);
end;

function ERR_X509_LOOKUP_meth_set_shutdown(method: PX509_LOOKUP_METHOD; shutdown: TX509_LOOKUP_meth_set_new_item_new_item_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_shutdown_procname);
end;

function ERR_X509_LOOKUP_meth_get_shutdown(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_meth_set_new_item_new_item_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_shutdown_procname);
end;

function ERR_X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: TX509_LOOKUP_ctrl_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_ctrl_procname);
end;

function ERR_X509_LOOKUP_meth_get_ctrl(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_ctrl_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_ctrl_procname);
end;

function ERR_X509_LOOKUP_meth_set_get_by_subject(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_subject_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_subject_procname);
end;

function ERR_X509_LOOKUP_meth_get_get_by_subject(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_subject_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_subject_procname);
end;

function ERR_X509_LOOKUP_meth_set_get_by_issuer_serial(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_issuer_serial_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_issuer_serial_procname);
end;

function ERR_X509_LOOKUP_meth_get_get_by_issuer_serial(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_issuer_serial_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_issuer_serial_procname);
end;

function ERR_X509_LOOKUP_meth_set_get_by_fingerprint(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_fingerprint_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_fingerprint_procname);
end;

function ERR_X509_LOOKUP_meth_get_get_by_fingerprint(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_fingerprint_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_fingerprint_procname);
end;

function ERR_X509_LOOKUP_meth_set_get_by_alias(method: PX509_LOOKUP_METHOD; fn: TX509_LOOKUP_get_by_alias_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_set_get_by_alias_procname);
end;

function ERR_X509_LOOKUP_meth_get_get_by_alias(method: PX509_LOOKUP_METHOD): TX509_LOOKUP_get_by_alias_fn; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_meth_get_get_by_alias_procname);
end;

function ERR_X509_STORE_add_cert(xs: PX509_STORE; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_add_cert_procname);
end;

function ERR_X509_STORE_add_crl(xs: PX509_STORE; x: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_add_crl_procname);
end;

function ERR_X509_STORE_CTX_get_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_by_subject_procname);
end;

function ERR_X509_STORE_CTX_get_obj_by_subject(vs: PX509_STORE_CTX; _type: TX509_LOOKUP_TYPE; name: PX509_NAME): PX509_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_obj_by_subject_procname);
end;

function ERR_X509_LOOKUP_ctrl(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_ctrl_procname);
end;

function ERR_X509_LOOKUP_ctrl_ex(ctx: PX509_LOOKUP; cmd: TIdC_INT; argc: PIdAnsiChar; argl: TIdC_LONG; ret: PPIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_ctrl_ex_procname);
end;

function ERR_X509_load_cert_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_load_cert_file_procname);
end;

function ERR_X509_load_cert_file_ex(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_load_cert_file_ex_procname);
end;

function ERR_X509_load_crl_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_load_crl_file_procname);
end;

function ERR_X509_load_cert_crl_file(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_load_cert_crl_file_procname);
end;

function ERR_X509_load_cert_crl_file_ex(ctx: PX509_LOOKUP; _file: PIdAnsiChar; _type: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_load_cert_crl_file_ex_procname);
end;

function ERR_X509_LOOKUP_new(method: PX509_LOOKUP_METHOD): PX509_LOOKUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_new_procname);
end;

function ERR_X509_LOOKUP_free(ctx: PX509_LOOKUP): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_free_procname);
end;

function ERR_X509_LOOKUP_init(ctx: PX509_LOOKUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_init_procname);
end;

function ERR_X509_LOOKUP_by_subject(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_subject_procname);
end;

function ERR_X509_LOOKUP_by_subject_ex(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; ret: PX509_OBJECT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_subject_ex_procname);
end;

function ERR_X509_LOOKUP_by_issuer_serial(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; name: PX509_NAME; serial: PASN1_INTEGER; ret: PX509_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_issuer_serial_procname);
end;

function ERR_X509_LOOKUP_by_fingerprint(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; bytes: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_fingerprint_procname);
end;

function ERR_X509_LOOKUP_by_alias(ctx: PX509_LOOKUP; _type: TX509_LOOKUP_TYPE; str: PIdAnsiChar; len: TIdC_INT; ret: PX509_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_by_alias_procname);
end;

function ERR_X509_LOOKUP_set_method_data(ctx: PX509_LOOKUP; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_set_method_data_procname);
end;

function ERR_X509_LOOKUP_get_method_data(ctx: PX509_LOOKUP): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_get_method_data_procname);
end;

function ERR_X509_LOOKUP_get_store(ctx: PX509_LOOKUP): PX509_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_get_store_procname);
end;

function ERR_X509_LOOKUP_shutdown(ctx: PX509_LOOKUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_LOOKUP_shutdown_procname);
end;

function ERR_X509_STORE_load_file(xs: PX509_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_load_file_procname);
end;

function ERR_X509_STORE_load_path(xs: PX509_STORE; path: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_load_path_procname);
end;

function ERR_X509_STORE_load_store(xs: PX509_STORE; store: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_load_store_procname);
end;

function ERR_X509_STORE_load_locations(s: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_load_locations_procname);
end;

function ERR_X509_STORE_set_default_paths(xs: PX509_STORE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_default_paths_procname);
end;

function ERR_X509_STORE_load_file_ex(xs: PX509_STORE; _file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_load_file_ex_procname);
end;

function ERR_X509_STORE_load_store_ex(xs: PX509_STORE; store: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_load_store_ex_procname);
end;

function ERR_X509_STORE_load_locations_ex(xs: PX509_STORE; _file: PIdAnsiChar; dir: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_load_locations_ex_procname);
end;

function ERR_X509_STORE_set_default_paths_ex(xs: PX509_STORE; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_set_default_paths_ex_procname);
end;

function ERR_X509_STORE_CTX_set_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_ex_data_procname);
end;

function ERR_X509_STORE_CTX_get_ex_data(ctx: PX509_STORE_CTX; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_ex_data_procname);
end;

function ERR_X509_STORE_CTX_get_error(ctx: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_error_procname);
end;

function ERR_X509_STORE_CTX_set_error(ctx: PX509_STORE_CTX; s: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_error_procname);
end;

function ERR_X509_STORE_CTX_get_error_depth(ctx: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_error_depth_procname);
end;

function ERR_X509_STORE_CTX_set_error_depth(ctx: PX509_STORE_CTX; depth: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_error_depth_procname);
end;

function ERR_X509_STORE_CTX_get_current_cert(ctx: PX509_STORE_CTX): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_current_cert_procname);
end;

function ERR_X509_STORE_CTX_set_current_cert(ctx: PX509_STORE_CTX; x: PX509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_current_cert_procname);
end;

function ERR_X509_STORE_CTX_get0_current_issuer(ctx: PX509_STORE_CTX): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_current_issuer_procname);
end;

function ERR_X509_STORE_CTX_get0_current_crl(ctx: PX509_STORE_CTX): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_current_crl_procname);
end;

function ERR_X509_STORE_CTX_get0_parent_ctx(ctx: PX509_STORE_CTX): PX509_STORE_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_parent_ctx_procname);
end;

function ERR_X509_STORE_CTX_get0_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_chain_procname);
end;

function ERR_X509_STORE_CTX_get1_chain(ctx: PX509_STORE_CTX): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get1_chain_procname);
end;

function ERR_X509_STORE_CTX_set_cert(ctx: PX509_STORE_CTX; target: PX509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_cert_procname);
end;

function ERR_X509_STORE_CTX_set0_rpk(ctx: PX509_STORE_CTX; target: PEVP_PKEY): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_rpk_procname);
end;

function ERR_X509_STORE_CTX_set0_verified_chain(c: PX509_STORE_CTX; sk: Pstack_st_X509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_verified_chain_procname);
end;

function ERR_X509_STORE_CTX_set0_crls(ctx: PX509_STORE_CTX; sk: Pstack_st_X509_CRL): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_crls_procname);
end;

function ERR_X509_STORE_CTX_set_ocsp_resp(ctx: PX509_STORE_CTX; sk: Pstack_st_OCSP_RESPONSE): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_ocsp_resp_procname);
end;

function ERR_X509_STORE_CTX_set_purpose(ctx: PX509_STORE_CTX; purpose: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_purpose_procname);
end;

function ERR_X509_STORE_CTX_set_trust(ctx: PX509_STORE_CTX; trust: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_trust_procname);
end;

function ERR_X509_STORE_CTX_purpose_inherit(ctx: PX509_STORE_CTX; def_purpose: TIdC_INT; purpose: TIdC_INT; trust: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_purpose_inherit_procname);
end;

function ERR_X509_STORE_CTX_set_flags(ctx: PX509_STORE_CTX; flags: TIdC_ULONG): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_flags_procname);
end;

function ERR_X509_STORE_CTX_set_time(ctx: PX509_STORE_CTX; flags: TIdC_ULONG; t: TIdC_TIMET): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_time_procname);
end;

function ERR_X509_STORE_CTX_set_current_reasons(ctx: PX509_STORE_CTX; current_reasons: TIdC_UINT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_current_reasons_procname);
end;

function ERR_X509_STORE_CTX_get0_policy_tree(ctx: PX509_STORE_CTX): PX509_POLICY_TREE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_policy_tree_procname);
end;

function ERR_X509_STORE_CTX_get_explicit_policy(ctx: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_explicit_policy_procname);
end;

function ERR_X509_STORE_CTX_get_num_untrusted(ctx: PX509_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get_num_untrusted_procname);
end;

function ERR_X509_STORE_CTX_get0_param(ctx: PX509_STORE_CTX): PX509_VERIFY_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_get0_param_procname);
end;

function ERR_X509_STORE_CTX_set0_param(ctx: PX509_STORE_CTX; param: PX509_VERIFY_PARAM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_param_procname);
end;

function ERR_X509_STORE_CTX_set_default(ctx: PX509_STORE_CTX; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set_default_procname);
end;

function ERR_X509_STORE_CTX_set0_dane(ctx: PX509_STORE_CTX; dane: PSSL_DANE): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_STORE_CTX_set0_dane_procname);
end;

function ERR_X509_VERIFY_PARAM_new: PX509_VERIFY_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_new_procname);
end;

function ERR_X509_VERIFY_PARAM_free(param: PX509_VERIFY_PARAM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_free_procname);
end;

function ERR_X509_VERIFY_PARAM_inherit(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_inherit_procname);
end;

function ERR_X509_VERIFY_PARAM_set1(_to: PX509_VERIFY_PARAM; from: PX509_VERIFY_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_procname);
end;

function ERR_X509_VERIFY_PARAM_set1_name(param: PX509_VERIFY_PARAM; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_name_procname);
end;

function ERR_X509_VERIFY_PARAM_set_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_flags_procname);
end;

function ERR_X509_VERIFY_PARAM_clear_flags(param: PX509_VERIFY_PARAM; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_clear_flags_procname);
end;

function ERR_X509_VERIFY_PARAM_get_flags(param: PX509_VERIFY_PARAM): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_flags_procname);
end;

function ERR_X509_VERIFY_PARAM_set_purpose(param: PX509_VERIFY_PARAM; purpose: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_purpose_procname);
end;

function ERR_X509_VERIFY_PARAM_get_purpose(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_purpose_procname);
end;

function ERR_X509_VERIFY_PARAM_set_trust(param: PX509_VERIFY_PARAM; trust: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_trust_procname);
end;

function ERR_X509_VERIFY_PARAM_set_depth(param: PX509_VERIFY_PARAM; depth: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_depth_procname);
end;

function ERR_X509_VERIFY_PARAM_set_auth_level(param: PX509_VERIFY_PARAM; auth_level: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_auth_level_procname);
end;

function ERR_X509_VERIFY_PARAM_get_time(param: PX509_VERIFY_PARAM): TIdC_TIMET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_time_procname);
end;

function ERR_X509_VERIFY_PARAM_set_time(param: PX509_VERIFY_PARAM; t: TIdC_TIMET): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_time_procname);
end;

function ERR_X509_VERIFY_PARAM_add0_policy(param: PX509_VERIFY_PARAM; policy: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_add0_policy_procname);
end;

function ERR_X509_VERIFY_PARAM_set1_policies(param: PX509_VERIFY_PARAM; policies: Pstack_st_ASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_policies_procname);
end;

function ERR_X509_VERIFY_PARAM_set_inh_flags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_inh_flags_procname);
end;

function ERR_X509_VERIFY_PARAM_get_inh_flags(param: PX509_VERIFY_PARAM): TIdC_UINT32; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_inh_flags_procname);
end;

function ERR_X509_VERIFY_PARAM_get0_host(param: PX509_VERIFY_PARAM; idx: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_host_procname);
end;

function ERR_X509_VERIFY_PARAM_set1_host(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_host_procname);
end;

function ERR_X509_VERIFY_PARAM_add1_host(param: PX509_VERIFY_PARAM; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_add1_host_procname);
end;

function ERR_X509_VERIFY_PARAM_set_hostflags(param: PX509_VERIFY_PARAM; flags: TIdC_UINT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set_hostflags_procname);
end;

function ERR_X509_VERIFY_PARAM_get_hostflags(param: PX509_VERIFY_PARAM): TIdC_UINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_hostflags_procname);
end;

function ERR_X509_VERIFY_PARAM_get0_peername(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_peername_procname);
end;

function ERR_X509_VERIFY_PARAM_move_peername(arg1: PX509_VERIFY_PARAM; arg2: PX509_VERIFY_PARAM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_move_peername_procname);
end;

function ERR_X509_VERIFY_PARAM_get0_email(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_email_procname);
end;

function ERR_X509_VERIFY_PARAM_set1_email(param: PX509_VERIFY_PARAM; email: PIdAnsiChar; emaillen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_email_procname);
end;

function ERR_X509_VERIFY_PARAM_get1_ip_asc(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get1_ip_asc_procname);
end;

function ERR_X509_VERIFY_PARAM_set1_ip(param: PX509_VERIFY_PARAM; ip: PIdAnsiChar; iplen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_ip_procname);
end;

function ERR_X509_VERIFY_PARAM_set1_ip_asc(param: PX509_VERIFY_PARAM; ipasc: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_set1_ip_asc_procname);
end;

function ERR_X509_VERIFY_PARAM_get_depth(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_depth_procname);
end;

function ERR_X509_VERIFY_PARAM_get_auth_level(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_auth_level_procname);
end;

function ERR_X509_VERIFY_PARAM_get0_name(param: PX509_VERIFY_PARAM): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_name_procname);
end;

function ERR_X509_VERIFY_PARAM_add0_table(param: PX509_VERIFY_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_add0_table_procname);
end;

function ERR_X509_VERIFY_PARAM_get_count: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get_count_procname);
end;

function ERR_X509_VERIFY_PARAM_get0(id: TIdC_INT): PX509_VERIFY_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_get0_procname);
end;

function ERR_X509_VERIFY_PARAM_lookup(name: PIdAnsiChar): PX509_VERIFY_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_lookup_procname);
end;

function ERR_X509_VERIFY_PARAM_table_cleanup: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VERIFY_PARAM_table_cleanup_procname);
end;

function ERR_X509_policy_check(ptree: PPX509_POLICY_TREE; pexplicit_policy: PIdC_INT; certs: Pstack_st_X509; policy_oids: Pstack_st_ASN1_OBJECT; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_check_procname);
end;

function ERR_X509_policy_tree_free(tree: PX509_POLICY_TREE): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_tree_free_procname);
end;

function ERR_X509_policy_tree_level_count(tree: PX509_POLICY_TREE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_tree_level_count_procname);
end;

function ERR_X509_policy_tree_get0_level(tree: PX509_POLICY_TREE; i: TIdC_INT): PX509_POLICY_LEVEL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_tree_get0_level_procname);
end;

function ERR_X509_policy_tree_get0_policies(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_tree_get0_policies_procname);
end;

function ERR_X509_policy_tree_get0_user_policies(tree: PX509_POLICY_TREE): Pstack_st_X509_POLICY_NODE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_tree_get0_user_policies_procname);
end;

function ERR_X509_policy_level_node_count(level: PX509_POLICY_LEVEL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_level_node_count_procname);
end;

function ERR_X509_policy_level_get0_node(level: PX509_POLICY_LEVEL; i: TIdC_INT): PX509_POLICY_NODE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_level_get0_node_procname);
end;

function ERR_X509_policy_node_get0_policy(node: PX509_POLICY_NODE): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_node_get0_policy_procname);
end;

function ERR_X509_policy_node_get0_qualifiers(node: PX509_POLICY_NODE): Pstack_st_POLICYQUALINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_node_get0_qualifiers_procname);
end;

function ERR_X509_policy_node_get0_parent(node: PX509_POLICY_NODE): PX509_POLICY_NODE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_policy_node_get0_parent_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
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
  
  X509_TRUST_add := LoadLibFunction(ADllHandle, X509_TRUST_add_procname);
  FuncLoadError := not assigned(X509_TRUST_add);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_add_allownil)}
    X509_TRUST_add := ERR_X509_TRUST_add;
    {$ifend}
    {$if declared(X509_TRUST_add_introduced)}
    if LibVersion < X509_TRUST_add_introduced then
    begin
      {$if declared(FC_X509_TRUST_add)}
      X509_TRUST_add := FC_X509_TRUST_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_add_removed)}
    if X509_TRUST_add_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_add)}
      X509_TRUST_add := _X509_TRUST_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_add_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_add');
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
  
  X509_get0_trust_objects := LoadLibFunction(ADllHandle, X509_get0_trust_objects_procname);
  FuncLoadError := not assigned(X509_get0_trust_objects);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_trust_objects_allownil)}
    X509_get0_trust_objects := ERR_X509_get0_trust_objects;
    {$ifend}
    {$if declared(X509_get0_trust_objects_introduced)}
    if LibVersion < X509_get0_trust_objects_introduced then
    begin
      {$if declared(FC_X509_get0_trust_objects)}
      X509_get0_trust_objects := FC_X509_get0_trust_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_trust_objects_removed)}
    if X509_get0_trust_objects_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_trust_objects)}
      X509_get0_trust_objects := _X509_get0_trust_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_trust_objects_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_trust_objects');
    {$ifend}
  end;
  
  X509_get0_reject_objects := LoadLibFunction(ADllHandle, X509_get0_reject_objects_procname);
  FuncLoadError := not assigned(X509_get0_reject_objects);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_reject_objects_allownil)}
    X509_get0_reject_objects := ERR_X509_get0_reject_objects;
    {$ifend}
    {$if declared(X509_get0_reject_objects_introduced)}
    if LibVersion < X509_get0_reject_objects_introduced then
    begin
      {$if declared(FC_X509_get0_reject_objects)}
      X509_get0_reject_objects := FC_X509_get0_reject_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_reject_objects_removed)}
    if X509_get0_reject_objects_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_reject_objects)}
      X509_get0_reject_objects := _X509_get0_reject_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_reject_objects_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_reject_objects');
    {$ifend}
  end;
  
  X509_TRUST_set_default := LoadLibFunction(ADllHandle, X509_TRUST_set_default_procname);
  FuncLoadError := not assigned(X509_TRUST_set_default);
  if FuncLoadError then
  begin
    {$if not defined(X509_TRUST_set_default_allownil)}
    X509_TRUST_set_default := ERR_X509_TRUST_set_default;
    {$ifend}
    {$if declared(X509_TRUST_set_default_introduced)}
    if LibVersion < X509_TRUST_set_default_introduced then
    begin
      {$if declared(FC_X509_TRUST_set_default)}
      X509_TRUST_set_default := FC_X509_TRUST_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_TRUST_set_default_removed)}
    if X509_TRUST_set_default_removed <= LibVersion then
    begin
      {$if declared(_X509_TRUST_set_default)}
      X509_TRUST_set_default := _X509_TRUST_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_TRUST_set_default_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_TRUST_set_default');
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
  
  X509_STORE_CTX_verify := LoadLibFunction(ADllHandle, X509_STORE_CTX_verify_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_verify_allownil)}
    X509_STORE_CTX_verify := ERR_X509_STORE_CTX_verify;
    {$ifend}
    {$if declared(X509_STORE_CTX_verify_introduced)}
    if LibVersion < X509_STORE_CTX_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_verify)}
      X509_STORE_CTX_verify := FC_X509_STORE_CTX_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_verify_removed)}
    if X509_STORE_CTX_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_verify)}
      X509_STORE_CTX_verify := _X509_STORE_CTX_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_verify');
    {$ifend}
  end;
  
  X509_build_chain := LoadLibFunction(ADllHandle, X509_build_chain_procname);
  FuncLoadError := not assigned(X509_build_chain);
  if FuncLoadError then
  begin
    {$if not defined(X509_build_chain_allownil)}
    X509_build_chain := ERR_X509_build_chain;
    {$ifend}
    {$if declared(X509_build_chain_introduced)}
    if LibVersion < X509_build_chain_introduced then
    begin
      {$if declared(FC_X509_build_chain)}
      X509_build_chain := FC_X509_build_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_build_chain_removed)}
    if X509_build_chain_removed <= LibVersion then
    begin
      {$if declared(_X509_build_chain)}
      X509_build_chain := _X509_build_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_build_chain_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_build_chain');
    {$ifend}
  end;
  
  X509_STORE_set_depth := LoadLibFunction(ADllHandle, X509_STORE_set_depth_procname);
  FuncLoadError := not assigned(X509_STORE_set_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_depth_allownil)}
    X509_STORE_set_depth := ERR_X509_STORE_set_depth;
    {$ifend}
    {$if declared(X509_STORE_set_depth_introduced)}
    if LibVersion < X509_STORE_set_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_set_depth)}
      X509_STORE_set_depth := FC_X509_STORE_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_depth_removed)}
    if X509_STORE_set_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_depth)}
      X509_STORE_set_depth := _X509_STORE_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_depth');
    {$ifend}
  end;
  
  X509_STORE_CTX_print_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_CTX_print_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_print_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_print_verify_cb_allownil)}
    X509_STORE_CTX_print_verify_cb := ERR_X509_STORE_CTX_print_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_CTX_print_verify_cb_introduced)}
    if LibVersion < X509_STORE_CTX_print_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_print_verify_cb)}
      X509_STORE_CTX_print_verify_cb := FC_X509_STORE_CTX_print_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_print_verify_cb_removed)}
    if X509_STORE_CTX_print_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_print_verify_cb)}
      X509_STORE_CTX_print_verify_cb := _X509_STORE_CTX_print_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_print_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_print_verify_cb');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_depth := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_depth_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_depth_allownil)}
    X509_STORE_CTX_set_depth := ERR_X509_STORE_CTX_set_depth;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_depth_introduced)}
    if LibVersion < X509_STORE_CTX_set_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_depth)}
      X509_STORE_CTX_set_depth := FC_X509_STORE_CTX_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_depth_removed)}
    if X509_STORE_CTX_set_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_depth)}
      X509_STORE_CTX_set_depth := _X509_STORE_CTX_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_depth');
    {$ifend}
  end;
  
  X509_OBJECT_idx_by_subject := LoadLibFunction(ADllHandle, X509_OBJECT_idx_by_subject_procname);
  FuncLoadError := not assigned(X509_OBJECT_idx_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_idx_by_subject_allownil)}
    X509_OBJECT_idx_by_subject := ERR_X509_OBJECT_idx_by_subject;
    {$ifend}
    {$if declared(X509_OBJECT_idx_by_subject_introduced)}
    if LibVersion < X509_OBJECT_idx_by_subject_introduced then
    begin
      {$if declared(FC_X509_OBJECT_idx_by_subject)}
      X509_OBJECT_idx_by_subject := FC_X509_OBJECT_idx_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_idx_by_subject_removed)}
    if X509_OBJECT_idx_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_idx_by_subject)}
      X509_OBJECT_idx_by_subject := _X509_OBJECT_idx_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_idx_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_idx_by_subject');
    {$ifend}
  end;
  
  X509_OBJECT_retrieve_by_subject := LoadLibFunction(ADllHandle, X509_OBJECT_retrieve_by_subject_procname);
  FuncLoadError := not assigned(X509_OBJECT_retrieve_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_retrieve_by_subject_allownil)}
    X509_OBJECT_retrieve_by_subject := ERR_X509_OBJECT_retrieve_by_subject;
    {$ifend}
    {$if declared(X509_OBJECT_retrieve_by_subject_introduced)}
    if LibVersion < X509_OBJECT_retrieve_by_subject_introduced then
    begin
      {$if declared(FC_X509_OBJECT_retrieve_by_subject)}
      X509_OBJECT_retrieve_by_subject := FC_X509_OBJECT_retrieve_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_retrieve_by_subject_removed)}
    if X509_OBJECT_retrieve_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_retrieve_by_subject)}
      X509_OBJECT_retrieve_by_subject := _X509_OBJECT_retrieve_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_retrieve_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_retrieve_by_subject');
    {$ifend}
  end;
  
  X509_OBJECT_retrieve_match := LoadLibFunction(ADllHandle, X509_OBJECT_retrieve_match_procname);
  FuncLoadError := not assigned(X509_OBJECT_retrieve_match);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_retrieve_match_allownil)}
    X509_OBJECT_retrieve_match := ERR_X509_OBJECT_retrieve_match;
    {$ifend}
    {$if declared(X509_OBJECT_retrieve_match_introduced)}
    if LibVersion < X509_OBJECT_retrieve_match_introduced then
    begin
      {$if declared(FC_X509_OBJECT_retrieve_match)}
      X509_OBJECT_retrieve_match := FC_X509_OBJECT_retrieve_match;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_retrieve_match_removed)}
    if X509_OBJECT_retrieve_match_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_retrieve_match)}
      X509_OBJECT_retrieve_match := _X509_OBJECT_retrieve_match;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_retrieve_match_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_retrieve_match');
    {$ifend}
  end;
  
  X509_OBJECT_up_ref_count := LoadLibFunction(ADllHandle, X509_OBJECT_up_ref_count_procname);
  FuncLoadError := not assigned(X509_OBJECT_up_ref_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_up_ref_count_allownil)}
    X509_OBJECT_up_ref_count := ERR_X509_OBJECT_up_ref_count;
    {$ifend}
    {$if declared(X509_OBJECT_up_ref_count_introduced)}
    if LibVersion < X509_OBJECT_up_ref_count_introduced then
    begin
      {$if declared(FC_X509_OBJECT_up_ref_count)}
      X509_OBJECT_up_ref_count := FC_X509_OBJECT_up_ref_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_up_ref_count_removed)}
    if X509_OBJECT_up_ref_count_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_up_ref_count)}
      X509_OBJECT_up_ref_count := _X509_OBJECT_up_ref_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_up_ref_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_up_ref_count');
    {$ifend}
  end;
  
  X509_OBJECT_new := LoadLibFunction(ADllHandle, X509_OBJECT_new_procname);
  FuncLoadError := not assigned(X509_OBJECT_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_new_allownil)}
    X509_OBJECT_new := ERR_X509_OBJECT_new;
    {$ifend}
    {$if declared(X509_OBJECT_new_introduced)}
    if LibVersion < X509_OBJECT_new_introduced then
    begin
      {$if declared(FC_X509_OBJECT_new)}
      X509_OBJECT_new := FC_X509_OBJECT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_new_removed)}
    if X509_OBJECT_new_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_new)}
      X509_OBJECT_new := _X509_OBJECT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_new');
    {$ifend}
  end;
  
  X509_OBJECT_free := LoadLibFunction(ADllHandle, X509_OBJECT_free_procname);
  FuncLoadError := not assigned(X509_OBJECT_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_free_allownil)}
    X509_OBJECT_free := ERR_X509_OBJECT_free;
    {$ifend}
    {$if declared(X509_OBJECT_free_introduced)}
    if LibVersion < X509_OBJECT_free_introduced then
    begin
      {$if declared(FC_X509_OBJECT_free)}
      X509_OBJECT_free := FC_X509_OBJECT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_free_removed)}
    if X509_OBJECT_free_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_free)}
      X509_OBJECT_free := _X509_OBJECT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_free');
    {$ifend}
  end;
  
  X509_OBJECT_get_type := LoadLibFunction(ADllHandle, X509_OBJECT_get_type_procname);
  FuncLoadError := not assigned(X509_OBJECT_get_type);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_get_type_allownil)}
    X509_OBJECT_get_type := ERR_X509_OBJECT_get_type;
    {$ifend}
    {$if declared(X509_OBJECT_get_type_introduced)}
    if LibVersion < X509_OBJECT_get_type_introduced then
    begin
      {$if declared(FC_X509_OBJECT_get_type)}
      X509_OBJECT_get_type := FC_X509_OBJECT_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_get_type_removed)}
    if X509_OBJECT_get_type_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_get_type)}
      X509_OBJECT_get_type := _X509_OBJECT_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_get_type');
    {$ifend}
  end;
  
  X509_OBJECT_get0_X509 := LoadLibFunction(ADllHandle, X509_OBJECT_get0_X509_procname);
  FuncLoadError := not assigned(X509_OBJECT_get0_X509);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_get0_X509_allownil)}
    X509_OBJECT_get0_X509 := ERR_X509_OBJECT_get0_X509;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_introduced)}
    if LibVersion < X509_OBJECT_get0_X509_introduced then
    begin
      {$if declared(FC_X509_OBJECT_get0_X509)}
      X509_OBJECT_get0_X509 := FC_X509_OBJECT_get0_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_removed)}
    if X509_OBJECT_get0_X509_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_get0_X509)}
      X509_OBJECT_get0_X509 := _X509_OBJECT_get0_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_get0_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_get0_X509');
    {$ifend}
  end;
  
  X509_OBJECT_set1_X509 := LoadLibFunction(ADllHandle, X509_OBJECT_set1_X509_procname);
  FuncLoadError := not assigned(X509_OBJECT_set1_X509);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_set1_X509_allownil)}
    X509_OBJECT_set1_X509 := ERR_X509_OBJECT_set1_X509;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_introduced)}
    if LibVersion < X509_OBJECT_set1_X509_introduced then
    begin
      {$if declared(FC_X509_OBJECT_set1_X509)}
      X509_OBJECT_set1_X509 := FC_X509_OBJECT_set1_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_removed)}
    if X509_OBJECT_set1_X509_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_set1_X509)}
      X509_OBJECT_set1_X509 := _X509_OBJECT_set1_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_set1_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_set1_X509');
    {$ifend}
  end;
  
  X509_OBJECT_get0_X509_CRL := LoadLibFunction(ADllHandle, X509_OBJECT_get0_X509_CRL_procname);
  FuncLoadError := not assigned(X509_OBJECT_get0_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_get0_X509_CRL_allownil)}
    X509_OBJECT_get0_X509_CRL := ERR_X509_OBJECT_get0_X509_CRL;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_CRL_introduced)}
    if LibVersion < X509_OBJECT_get0_X509_CRL_introduced then
    begin
      {$if declared(FC_X509_OBJECT_get0_X509_CRL)}
      X509_OBJECT_get0_X509_CRL := FC_X509_OBJECT_get0_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_get0_X509_CRL_removed)}
    if X509_OBJECT_get0_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_get0_X509_CRL)}
      X509_OBJECT_get0_X509_CRL := _X509_OBJECT_get0_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_get0_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_get0_X509_CRL');
    {$ifend}
  end;
  
  X509_OBJECT_set1_X509_CRL := LoadLibFunction(ADllHandle, X509_OBJECT_set1_X509_CRL_procname);
  FuncLoadError := not assigned(X509_OBJECT_set1_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(X509_OBJECT_set1_X509_CRL_allownil)}
    X509_OBJECT_set1_X509_CRL := ERR_X509_OBJECT_set1_X509_CRL;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_CRL_introduced)}
    if LibVersion < X509_OBJECT_set1_X509_CRL_introduced then
    begin
      {$if declared(FC_X509_OBJECT_set1_X509_CRL)}
      X509_OBJECT_set1_X509_CRL := FC_X509_OBJECT_set1_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_OBJECT_set1_X509_CRL_removed)}
    if X509_OBJECT_set1_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_X509_OBJECT_set1_X509_CRL)}
      X509_OBJECT_set1_X509_CRL := _X509_OBJECT_set1_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_OBJECT_set1_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_OBJECT_set1_X509_CRL');
    {$ifend}
  end;
  
  X509_STORE_new := LoadLibFunction(ADllHandle, X509_STORE_new_procname);
  FuncLoadError := not assigned(X509_STORE_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_new_allownil)}
    X509_STORE_new := ERR_X509_STORE_new;
    {$ifend}
    {$if declared(X509_STORE_new_introduced)}
    if LibVersion < X509_STORE_new_introduced then
    begin
      {$if declared(FC_X509_STORE_new)}
      X509_STORE_new := FC_X509_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_new_removed)}
    if X509_STORE_new_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_new)}
      X509_STORE_new := _X509_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_new');
    {$ifend}
  end;
  
  X509_STORE_free := LoadLibFunction(ADllHandle, X509_STORE_free_procname);
  FuncLoadError := not assigned(X509_STORE_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_free_allownil)}
    X509_STORE_free := ERR_X509_STORE_free;
    {$ifend}
    {$if declared(X509_STORE_free_introduced)}
    if LibVersion < X509_STORE_free_introduced then
    begin
      {$if declared(FC_X509_STORE_free)}
      X509_STORE_free := FC_X509_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_free_removed)}
    if X509_STORE_free_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_free)}
      X509_STORE_free := _X509_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_free');
    {$ifend}
  end;
  
  X509_STORE_lock := LoadLibFunction(ADllHandle, X509_STORE_lock_procname);
  FuncLoadError := not assigned(X509_STORE_lock);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_lock_allownil)}
    X509_STORE_lock := ERR_X509_STORE_lock;
    {$ifend}
    {$if declared(X509_STORE_lock_introduced)}
    if LibVersion < X509_STORE_lock_introduced then
    begin
      {$if declared(FC_X509_STORE_lock)}
      X509_STORE_lock := FC_X509_STORE_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_lock_removed)}
    if X509_STORE_lock_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_lock)}
      X509_STORE_lock := _X509_STORE_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_lock_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_lock');
    {$ifend}
  end;
  
  X509_STORE_unlock := LoadLibFunction(ADllHandle, X509_STORE_unlock_procname);
  FuncLoadError := not assigned(X509_STORE_unlock);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_unlock_allownil)}
    X509_STORE_unlock := ERR_X509_STORE_unlock;
    {$ifend}
    {$if declared(X509_STORE_unlock_introduced)}
    if LibVersion < X509_STORE_unlock_introduced then
    begin
      {$if declared(FC_X509_STORE_unlock)}
      X509_STORE_unlock := FC_X509_STORE_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_unlock_removed)}
    if X509_STORE_unlock_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_unlock)}
      X509_STORE_unlock := _X509_STORE_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_unlock_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_unlock');
    {$ifend}
  end;
  
  X509_STORE_up_ref := LoadLibFunction(ADllHandle, X509_STORE_up_ref_procname);
  FuncLoadError := not assigned(X509_STORE_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_up_ref_allownil)}
    X509_STORE_up_ref := ERR_X509_STORE_up_ref;
    {$ifend}
    {$if declared(X509_STORE_up_ref_introduced)}
    if LibVersion < X509_STORE_up_ref_introduced then
    begin
      {$if declared(FC_X509_STORE_up_ref)}
      X509_STORE_up_ref := FC_X509_STORE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_up_ref_removed)}
    if X509_STORE_up_ref_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_up_ref)}
      X509_STORE_up_ref := _X509_STORE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_up_ref');
    {$ifend}
  end;
  
  X509_STORE_get0_objects := LoadLibFunction(ADllHandle, X509_STORE_get0_objects_procname);
  FuncLoadError := not assigned(X509_STORE_get0_objects);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get0_objects_allownil)}
    X509_STORE_get0_objects := ERR_X509_STORE_get0_objects;
    {$ifend}
    {$if declared(X509_STORE_get0_objects_introduced)}
    if LibVersion < X509_STORE_get0_objects_introduced then
    begin
      {$if declared(FC_X509_STORE_get0_objects)}
      X509_STORE_get0_objects := FC_X509_STORE_get0_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get0_objects_removed)}
    if X509_STORE_get0_objects_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get0_objects)}
      X509_STORE_get0_objects := _X509_STORE_get0_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get0_objects_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get0_objects');
    {$ifend}
  end;
  
  X509_STORE_get1_objects := LoadLibFunction(ADllHandle, X509_STORE_get1_objects_procname);
  FuncLoadError := not assigned(X509_STORE_get1_objects);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get1_objects_allownil)}
    X509_STORE_get1_objects := ERR_X509_STORE_get1_objects;
    {$ifend}
    {$if declared(X509_STORE_get1_objects_introduced)}
    if LibVersion < X509_STORE_get1_objects_introduced then
    begin
      {$if declared(FC_X509_STORE_get1_objects)}
      X509_STORE_get1_objects := FC_X509_STORE_get1_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get1_objects_removed)}
    if X509_STORE_get1_objects_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get1_objects)}
      X509_STORE_get1_objects := _X509_STORE_get1_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get1_objects_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get1_objects');
    {$ifend}
  end;
  
  X509_STORE_get1_all_certs := LoadLibFunction(ADllHandle, X509_STORE_get1_all_certs_procname);
  FuncLoadError := not assigned(X509_STORE_get1_all_certs);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get1_all_certs_allownil)}
    X509_STORE_get1_all_certs := ERR_X509_STORE_get1_all_certs;
    {$ifend}
    {$if declared(X509_STORE_get1_all_certs_introduced)}
    if LibVersion < X509_STORE_get1_all_certs_introduced then
    begin
      {$if declared(FC_X509_STORE_get1_all_certs)}
      X509_STORE_get1_all_certs := FC_X509_STORE_get1_all_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get1_all_certs_removed)}
    if X509_STORE_get1_all_certs_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get1_all_certs)}
      X509_STORE_get1_all_certs := _X509_STORE_get1_all_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get1_all_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get1_all_certs');
    {$ifend}
  end;
  
  X509_STORE_CTX_get1_certs := LoadLibFunction(ADllHandle, X509_STORE_CTX_get1_certs_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get1_certs);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get1_certs_allownil)}
    X509_STORE_CTX_get1_certs := ERR_X509_STORE_CTX_get1_certs;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_certs_introduced)}
    if LibVersion < X509_STORE_CTX_get1_certs_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get1_certs)}
      X509_STORE_CTX_get1_certs := FC_X509_STORE_CTX_get1_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_certs_removed)}
    if X509_STORE_CTX_get1_certs_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get1_certs)}
      X509_STORE_CTX_get1_certs := _X509_STORE_CTX_get1_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get1_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get1_certs');
    {$ifend}
  end;
  
  X509_STORE_CTX_get1_crls := LoadLibFunction(ADllHandle, X509_STORE_CTX_get1_crls_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get1_crls);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get1_crls_allownil)}
    X509_STORE_CTX_get1_crls := ERR_X509_STORE_CTX_get1_crls;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_crls_introduced)}
    if LibVersion < X509_STORE_CTX_get1_crls_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get1_crls)}
      X509_STORE_CTX_get1_crls := FC_X509_STORE_CTX_get1_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_crls_removed)}
    if X509_STORE_CTX_get1_crls_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get1_crls)}
      X509_STORE_CTX_get1_crls := _X509_STORE_CTX_get1_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get1_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get1_crls');
    {$ifend}
  end;
  
  X509_STORE_set_flags := LoadLibFunction(ADllHandle, X509_STORE_set_flags_procname);
  FuncLoadError := not assigned(X509_STORE_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_flags_allownil)}
    X509_STORE_set_flags := ERR_X509_STORE_set_flags;
    {$ifend}
    {$if declared(X509_STORE_set_flags_introduced)}
    if LibVersion < X509_STORE_set_flags_introduced then
    begin
      {$if declared(FC_X509_STORE_set_flags)}
      X509_STORE_set_flags := FC_X509_STORE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_flags_removed)}
    if X509_STORE_set_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_flags)}
      X509_STORE_set_flags := _X509_STORE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_flags');
    {$ifend}
  end;
  
  X509_STORE_set_purpose := LoadLibFunction(ADllHandle, X509_STORE_set_purpose_procname);
  FuncLoadError := not assigned(X509_STORE_set_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_purpose_allownil)}
    X509_STORE_set_purpose := ERR_X509_STORE_set_purpose;
    {$ifend}
    {$if declared(X509_STORE_set_purpose_introduced)}
    if LibVersion < X509_STORE_set_purpose_introduced then
    begin
      {$if declared(FC_X509_STORE_set_purpose)}
      X509_STORE_set_purpose := FC_X509_STORE_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_purpose_removed)}
    if X509_STORE_set_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_purpose)}
      X509_STORE_set_purpose := _X509_STORE_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_purpose');
    {$ifend}
  end;
  
  X509_STORE_set_trust := LoadLibFunction(ADllHandle, X509_STORE_set_trust_procname);
  FuncLoadError := not assigned(X509_STORE_set_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_trust_allownil)}
    X509_STORE_set_trust := ERR_X509_STORE_set_trust;
    {$ifend}
    {$if declared(X509_STORE_set_trust_introduced)}
    if LibVersion < X509_STORE_set_trust_introduced then
    begin
      {$if declared(FC_X509_STORE_set_trust)}
      X509_STORE_set_trust := FC_X509_STORE_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_trust_removed)}
    if X509_STORE_set_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_trust)}
      X509_STORE_set_trust := _X509_STORE_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_trust');
    {$ifend}
  end;
  
  X509_STORE_set1_param := LoadLibFunction(ADllHandle, X509_STORE_set1_param_procname);
  FuncLoadError := not assigned(X509_STORE_set1_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set1_param_allownil)}
    X509_STORE_set1_param := ERR_X509_STORE_set1_param;
    {$ifend}
    {$if declared(X509_STORE_set1_param_introduced)}
    if LibVersion < X509_STORE_set1_param_introduced then
    begin
      {$if declared(FC_X509_STORE_set1_param)}
      X509_STORE_set1_param := FC_X509_STORE_set1_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set1_param_removed)}
    if X509_STORE_set1_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set1_param)}
      X509_STORE_set1_param := _X509_STORE_set1_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set1_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set1_param');
    {$ifend}
  end;
  
  X509_STORE_get0_param := LoadLibFunction(ADllHandle, X509_STORE_get0_param_procname);
  FuncLoadError := not assigned(X509_STORE_get0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get0_param_allownil)}
    X509_STORE_get0_param := ERR_X509_STORE_get0_param;
    {$ifend}
    {$if declared(X509_STORE_get0_param_introduced)}
    if LibVersion < X509_STORE_get0_param_introduced then
    begin
      {$if declared(FC_X509_STORE_get0_param)}
      X509_STORE_get0_param := FC_X509_STORE_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get0_param_removed)}
    if X509_STORE_get0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get0_param)}
      X509_STORE_get0_param := _X509_STORE_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get0_param');
    {$ifend}
  end;
  
  X509_STORE_set_verify := LoadLibFunction(ADllHandle, X509_STORE_set_verify_procname);
  FuncLoadError := not assigned(X509_STORE_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_verify_allownil)}
    X509_STORE_set_verify := ERR_X509_STORE_set_verify;
    {$ifend}
    {$if declared(X509_STORE_set_verify_introduced)}
    if LibVersion < X509_STORE_set_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_set_verify)}
      X509_STORE_set_verify := FC_X509_STORE_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_verify_removed)}
    if X509_STORE_set_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_verify)}
      X509_STORE_set_verify := _X509_STORE_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_verify');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_verify := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_verify_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_verify_allownil)}
    X509_STORE_CTX_set_verify := ERR_X509_STORE_CTX_set_verify;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_introduced)}
    if LibVersion < X509_STORE_CTX_set_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_verify)}
      X509_STORE_CTX_set_verify := FC_X509_STORE_CTX_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_removed)}
    if X509_STORE_CTX_set_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_verify)}
      X509_STORE_CTX_set_verify := _X509_STORE_CTX_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_verify');
    {$ifend}
  end;
  
  X509_STORE_get_verify := LoadLibFunction(ADllHandle, X509_STORE_get_verify_procname);
  FuncLoadError := not assigned(X509_STORE_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_verify_allownil)}
    X509_STORE_get_verify := ERR_X509_STORE_get_verify;
    {$ifend}
    {$if declared(X509_STORE_get_verify_introduced)}
    if LibVersion < X509_STORE_get_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_get_verify)}
      X509_STORE_get_verify := FC_X509_STORE_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_verify_removed)}
    if X509_STORE_get_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_verify)}
      X509_STORE_get_verify := _X509_STORE_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_verify');
    {$ifend}
  end;
  
  X509_STORE_set_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_set_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_set_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_verify_cb_allownil)}
    X509_STORE_set_verify_cb := ERR_X509_STORE_set_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_set_verify_cb_introduced)}
    if LibVersion < X509_STORE_set_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_set_verify_cb)}
      X509_STORE_set_verify_cb := FC_X509_STORE_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_verify_cb_removed)}
    if X509_STORE_set_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_verify_cb)}
      X509_STORE_set_verify_cb := _X509_STORE_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_verify_cb');
    {$ifend}
  end;
  
  X509_STORE_get_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_get_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_get_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_verify_cb_allownil)}
    X509_STORE_get_verify_cb := ERR_X509_STORE_get_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_get_verify_cb_introduced)}
    if LibVersion < X509_STORE_get_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_get_verify_cb)}
      X509_STORE_get_verify_cb := FC_X509_STORE_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_verify_cb_removed)}
    if X509_STORE_get_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_verify_cb)}
      X509_STORE_get_verify_cb := _X509_STORE_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_verify_cb');
    {$ifend}
  end;
  
  X509_STORE_set_get_issuer := LoadLibFunction(ADllHandle, X509_STORE_set_get_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_set_get_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_get_issuer_allownil)}
    X509_STORE_set_get_issuer := ERR_X509_STORE_set_get_issuer;
    {$ifend}
    {$if declared(X509_STORE_set_get_issuer_introduced)}
    if LibVersion < X509_STORE_set_get_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_set_get_issuer)}
      X509_STORE_set_get_issuer := FC_X509_STORE_set_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_get_issuer_removed)}
    if X509_STORE_set_get_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_get_issuer)}
      X509_STORE_set_get_issuer := _X509_STORE_set_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_get_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_get_issuer');
    {$ifend}
  end;
  
  X509_STORE_get_get_issuer := LoadLibFunction(ADllHandle, X509_STORE_get_get_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_get_get_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_get_issuer_allownil)}
    X509_STORE_get_get_issuer := ERR_X509_STORE_get_get_issuer;
    {$ifend}
    {$if declared(X509_STORE_get_get_issuer_introduced)}
    if LibVersion < X509_STORE_get_get_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_get_get_issuer)}
      X509_STORE_get_get_issuer := FC_X509_STORE_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_get_issuer_removed)}
    if X509_STORE_get_get_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_get_issuer)}
      X509_STORE_get_get_issuer := _X509_STORE_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_get_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_get_issuer');
    {$ifend}
  end;
  
  X509_STORE_set_check_issued := LoadLibFunction(ADllHandle, X509_STORE_set_check_issued_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_issued_allownil)}
    X509_STORE_set_check_issued := ERR_X509_STORE_set_check_issued;
    {$ifend}
    {$if declared(X509_STORE_set_check_issued_introduced)}
    if LibVersion < X509_STORE_set_check_issued_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_issued)}
      X509_STORE_set_check_issued := FC_X509_STORE_set_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_issued_removed)}
    if X509_STORE_set_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_issued)}
      X509_STORE_set_check_issued := _X509_STORE_set_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_issued');
    {$ifend}
  end;
  
  X509_STORE_get_check_issued := LoadLibFunction(ADllHandle, X509_STORE_get_check_issued_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_issued_allownil)}
    X509_STORE_get_check_issued := ERR_X509_STORE_get_check_issued;
    {$ifend}
    {$if declared(X509_STORE_get_check_issued_introduced)}
    if LibVersion < X509_STORE_get_check_issued_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_issued)}
      X509_STORE_get_check_issued := FC_X509_STORE_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_issued_removed)}
    if X509_STORE_get_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_issued)}
      X509_STORE_get_check_issued := _X509_STORE_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_issued');
    {$ifend}
  end;
  
  X509_STORE_set_check_revocation := LoadLibFunction(ADllHandle, X509_STORE_set_check_revocation_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_revocation);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_revocation_allownil)}
    X509_STORE_set_check_revocation := ERR_X509_STORE_set_check_revocation;
    {$ifend}
    {$if declared(X509_STORE_set_check_revocation_introduced)}
    if LibVersion < X509_STORE_set_check_revocation_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_revocation)}
      X509_STORE_set_check_revocation := FC_X509_STORE_set_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_revocation_removed)}
    if X509_STORE_set_check_revocation_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_revocation)}
      X509_STORE_set_check_revocation := _X509_STORE_set_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_revocation_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_revocation');
    {$ifend}
  end;
  
  X509_STORE_get_check_revocation := LoadLibFunction(ADllHandle, X509_STORE_get_check_revocation_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_revocation);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_revocation_allownil)}
    X509_STORE_get_check_revocation := ERR_X509_STORE_get_check_revocation;
    {$ifend}
    {$if declared(X509_STORE_get_check_revocation_introduced)}
    if LibVersion < X509_STORE_get_check_revocation_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_revocation)}
      X509_STORE_get_check_revocation := FC_X509_STORE_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_revocation_removed)}
    if X509_STORE_get_check_revocation_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_revocation)}
      X509_STORE_get_check_revocation := _X509_STORE_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_revocation_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_revocation');
    {$ifend}
  end;
  
  X509_STORE_set_get_crl := LoadLibFunction(ADllHandle, X509_STORE_set_get_crl_procname);
  FuncLoadError := not assigned(X509_STORE_set_get_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_get_crl_allownil)}
    X509_STORE_set_get_crl := ERR_X509_STORE_set_get_crl;
    {$ifend}
    {$if declared(X509_STORE_set_get_crl_introduced)}
    if LibVersion < X509_STORE_set_get_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_set_get_crl)}
      X509_STORE_set_get_crl := FC_X509_STORE_set_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_get_crl_removed)}
    if X509_STORE_set_get_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_get_crl)}
      X509_STORE_set_get_crl := _X509_STORE_set_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_get_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_get_crl');
    {$ifend}
  end;
  
  X509_STORE_get_get_crl := LoadLibFunction(ADllHandle, X509_STORE_get_get_crl_procname);
  FuncLoadError := not assigned(X509_STORE_get_get_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_get_crl_allownil)}
    X509_STORE_get_get_crl := ERR_X509_STORE_get_get_crl;
    {$ifend}
    {$if declared(X509_STORE_get_get_crl_introduced)}
    if LibVersion < X509_STORE_get_get_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_get_get_crl)}
      X509_STORE_get_get_crl := FC_X509_STORE_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_get_crl_removed)}
    if X509_STORE_get_get_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_get_crl)}
      X509_STORE_get_get_crl := _X509_STORE_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_get_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_get_crl');
    {$ifend}
  end;
  
  X509_STORE_set_check_crl := LoadLibFunction(ADllHandle, X509_STORE_set_check_crl_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_crl_allownil)}
    X509_STORE_set_check_crl := ERR_X509_STORE_set_check_crl;
    {$ifend}
    {$if declared(X509_STORE_set_check_crl_introduced)}
    if LibVersion < X509_STORE_set_check_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_crl)}
      X509_STORE_set_check_crl := FC_X509_STORE_set_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_crl_removed)}
    if X509_STORE_set_check_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_crl)}
      X509_STORE_set_check_crl := _X509_STORE_set_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_crl');
    {$ifend}
  end;
  
  X509_STORE_get_check_crl := LoadLibFunction(ADllHandle, X509_STORE_get_check_crl_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_crl_allownil)}
    X509_STORE_get_check_crl := ERR_X509_STORE_get_check_crl;
    {$ifend}
    {$if declared(X509_STORE_get_check_crl_introduced)}
    if LibVersion < X509_STORE_get_check_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_crl)}
      X509_STORE_get_check_crl := FC_X509_STORE_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_crl_removed)}
    if X509_STORE_get_check_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_crl)}
      X509_STORE_get_check_crl := _X509_STORE_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_crl');
    {$ifend}
  end;
  
  X509_STORE_set_cert_crl := LoadLibFunction(ADllHandle, X509_STORE_set_cert_crl_procname);
  FuncLoadError := not assigned(X509_STORE_set_cert_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_cert_crl_allownil)}
    X509_STORE_set_cert_crl := ERR_X509_STORE_set_cert_crl;
    {$ifend}
    {$if declared(X509_STORE_set_cert_crl_introduced)}
    if LibVersion < X509_STORE_set_cert_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_set_cert_crl)}
      X509_STORE_set_cert_crl := FC_X509_STORE_set_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_cert_crl_removed)}
    if X509_STORE_set_cert_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_cert_crl)}
      X509_STORE_set_cert_crl := _X509_STORE_set_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_cert_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_cert_crl');
    {$ifend}
  end;
  
  X509_STORE_get_cert_crl := LoadLibFunction(ADllHandle, X509_STORE_get_cert_crl_procname);
  FuncLoadError := not assigned(X509_STORE_get_cert_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_cert_crl_allownil)}
    X509_STORE_get_cert_crl := ERR_X509_STORE_get_cert_crl;
    {$ifend}
    {$if declared(X509_STORE_get_cert_crl_introduced)}
    if LibVersion < X509_STORE_get_cert_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_get_cert_crl)}
      X509_STORE_get_cert_crl := FC_X509_STORE_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_cert_crl_removed)}
    if X509_STORE_get_cert_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_cert_crl)}
      X509_STORE_get_cert_crl := _X509_STORE_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_cert_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_cert_crl');
    {$ifend}
  end;
  
  X509_STORE_set_check_policy := LoadLibFunction(ADllHandle, X509_STORE_set_check_policy_procname);
  FuncLoadError := not assigned(X509_STORE_set_check_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_check_policy_allownil)}
    X509_STORE_set_check_policy := ERR_X509_STORE_set_check_policy;
    {$ifend}
    {$if declared(X509_STORE_set_check_policy_introduced)}
    if LibVersion < X509_STORE_set_check_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_set_check_policy)}
      X509_STORE_set_check_policy := FC_X509_STORE_set_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_check_policy_removed)}
    if X509_STORE_set_check_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_check_policy)}
      X509_STORE_set_check_policy := _X509_STORE_set_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_check_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_check_policy');
    {$ifend}
  end;
  
  X509_STORE_get_check_policy := LoadLibFunction(ADllHandle, X509_STORE_get_check_policy_procname);
  FuncLoadError := not assigned(X509_STORE_get_check_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_check_policy_allownil)}
    X509_STORE_get_check_policy := ERR_X509_STORE_get_check_policy;
    {$ifend}
    {$if declared(X509_STORE_get_check_policy_introduced)}
    if LibVersion < X509_STORE_get_check_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_get_check_policy)}
      X509_STORE_get_check_policy := FC_X509_STORE_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_check_policy_removed)}
    if X509_STORE_get_check_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_check_policy)}
      X509_STORE_get_check_policy := _X509_STORE_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_check_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_check_policy');
    {$ifend}
  end;
  
  X509_STORE_set_lookup_certs := LoadLibFunction(ADllHandle, X509_STORE_set_lookup_certs_procname);
  FuncLoadError := not assigned(X509_STORE_set_lookup_certs);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_lookup_certs_allownil)}
    X509_STORE_set_lookup_certs := ERR_X509_STORE_set_lookup_certs;
    {$ifend}
    {$if declared(X509_STORE_set_lookup_certs_introduced)}
    if LibVersion < X509_STORE_set_lookup_certs_introduced then
    begin
      {$if declared(FC_X509_STORE_set_lookup_certs)}
      X509_STORE_set_lookup_certs := FC_X509_STORE_set_lookup_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_lookup_certs_removed)}
    if X509_STORE_set_lookup_certs_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_lookup_certs)}
      X509_STORE_set_lookup_certs := _X509_STORE_set_lookup_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_lookup_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_lookup_certs');
    {$ifend}
  end;
  
  X509_STORE_get_lookup_certs := LoadLibFunction(ADllHandle, X509_STORE_get_lookup_certs_procname);
  FuncLoadError := not assigned(X509_STORE_get_lookup_certs);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_lookup_certs_allownil)}
    X509_STORE_get_lookup_certs := ERR_X509_STORE_get_lookup_certs;
    {$ifend}
    {$if declared(X509_STORE_get_lookup_certs_introduced)}
    if LibVersion < X509_STORE_get_lookup_certs_introduced then
    begin
      {$if declared(FC_X509_STORE_get_lookup_certs)}
      X509_STORE_get_lookup_certs := FC_X509_STORE_get_lookup_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_lookup_certs_removed)}
    if X509_STORE_get_lookup_certs_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_lookup_certs)}
      X509_STORE_get_lookup_certs := _X509_STORE_get_lookup_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_lookup_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_lookup_certs');
    {$ifend}
  end;
  
  X509_STORE_set_lookup_crls := LoadLibFunction(ADllHandle, X509_STORE_set_lookup_crls_procname);
  FuncLoadError := not assigned(X509_STORE_set_lookup_crls);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_lookup_crls_allownil)}
    X509_STORE_set_lookup_crls := ERR_X509_STORE_set_lookup_crls;
    {$ifend}
    {$if declared(X509_STORE_set_lookup_crls_introduced)}
    if LibVersion < X509_STORE_set_lookup_crls_introduced then
    begin
      {$if declared(FC_X509_STORE_set_lookup_crls)}
      X509_STORE_set_lookup_crls := FC_X509_STORE_set_lookup_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_lookup_crls_removed)}
    if X509_STORE_set_lookup_crls_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_lookup_crls)}
      X509_STORE_set_lookup_crls := _X509_STORE_set_lookup_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_lookup_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_lookup_crls');
    {$ifend}
  end;
  
  X509_STORE_get_lookup_crls := LoadLibFunction(ADllHandle, X509_STORE_get_lookup_crls_procname);
  FuncLoadError := not assigned(X509_STORE_get_lookup_crls);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_lookup_crls_allownil)}
    X509_STORE_get_lookup_crls := ERR_X509_STORE_get_lookup_crls;
    {$ifend}
    {$if declared(X509_STORE_get_lookup_crls_introduced)}
    if LibVersion < X509_STORE_get_lookup_crls_introduced then
    begin
      {$if declared(FC_X509_STORE_get_lookup_crls)}
      X509_STORE_get_lookup_crls := FC_X509_STORE_get_lookup_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_lookup_crls_removed)}
    if X509_STORE_get_lookup_crls_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_lookup_crls)}
      X509_STORE_get_lookup_crls := _X509_STORE_get_lookup_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_lookup_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_lookup_crls');
    {$ifend}
  end;
  
  X509_STORE_set_cleanup := LoadLibFunction(ADllHandle, X509_STORE_set_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_set_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_cleanup_allownil)}
    X509_STORE_set_cleanup := ERR_X509_STORE_set_cleanup;
    {$ifend}
    {$if declared(X509_STORE_set_cleanup_introduced)}
    if LibVersion < X509_STORE_set_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_set_cleanup)}
      X509_STORE_set_cleanup := FC_X509_STORE_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_cleanup_removed)}
    if X509_STORE_set_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_cleanup)}
      X509_STORE_set_cleanup := _X509_STORE_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_cleanup');
    {$ifend}
  end;
  
  X509_STORE_get_cleanup := LoadLibFunction(ADllHandle, X509_STORE_get_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_cleanup_allownil)}
    X509_STORE_get_cleanup := ERR_X509_STORE_get_cleanup;
    {$ifend}
    {$if declared(X509_STORE_get_cleanup_introduced)}
    if LibVersion < X509_STORE_get_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_get_cleanup)}
      X509_STORE_get_cleanup := FC_X509_STORE_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_cleanup_removed)}
    if X509_STORE_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_cleanup)}
      X509_STORE_get_cleanup := _X509_STORE_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_cleanup');
    {$ifend}
  end;
  
  X509_STORE_set_ex_data := LoadLibFunction(ADllHandle, X509_STORE_set_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_ex_data_allownil)}
    X509_STORE_set_ex_data := ERR_X509_STORE_set_ex_data;
    {$ifend}
    {$if declared(X509_STORE_set_ex_data_introduced)}
    if LibVersion < X509_STORE_set_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_set_ex_data)}
      X509_STORE_set_ex_data := FC_X509_STORE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_ex_data_removed)}
    if X509_STORE_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_ex_data)}
      X509_STORE_set_ex_data := _X509_STORE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_ex_data');
    {$ifend}
  end;
  
  X509_STORE_get_ex_data := LoadLibFunction(ADllHandle, X509_STORE_get_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_get_ex_data_allownil)}
    X509_STORE_get_ex_data := ERR_X509_STORE_get_ex_data;
    {$ifend}
    {$if declared(X509_STORE_get_ex_data_introduced)}
    if LibVersion < X509_STORE_get_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_get_ex_data)}
      X509_STORE_get_ex_data := FC_X509_STORE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_get_ex_data_removed)}
    if X509_STORE_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_get_ex_data)}
      X509_STORE_get_ex_data := _X509_STORE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_get_ex_data');
    {$ifend}
  end;
  
  X509_STORE_CTX_new_ex := LoadLibFunction(ADllHandle, X509_STORE_CTX_new_ex_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_new_ex_allownil)}
    X509_STORE_CTX_new_ex := ERR_X509_STORE_CTX_new_ex;
    {$ifend}
    {$if declared(X509_STORE_CTX_new_ex_introduced)}
    if LibVersion < X509_STORE_CTX_new_ex_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_new_ex)}
      X509_STORE_CTX_new_ex := FC_X509_STORE_CTX_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_new_ex_removed)}
    if X509_STORE_CTX_new_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_new_ex)}
      X509_STORE_CTX_new_ex := _X509_STORE_CTX_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_new_ex');
    {$ifend}
  end;
  
  X509_STORE_CTX_new := LoadLibFunction(ADllHandle, X509_STORE_CTX_new_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_new_allownil)}
    X509_STORE_CTX_new := ERR_X509_STORE_CTX_new;
    {$ifend}
    {$if declared(X509_STORE_CTX_new_introduced)}
    if LibVersion < X509_STORE_CTX_new_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_new)}
      X509_STORE_CTX_new := FC_X509_STORE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_new_removed)}
    if X509_STORE_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_new)}
      X509_STORE_CTX_new := _X509_STORE_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_new');
    {$ifend}
  end;
  
  X509_STORE_CTX_get1_issuer := LoadLibFunction(ADllHandle, X509_STORE_CTX_get1_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get1_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get1_issuer_allownil)}
    X509_STORE_CTX_get1_issuer := ERR_X509_STORE_CTX_get1_issuer;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_issuer_introduced)}
    if LibVersion < X509_STORE_CTX_get1_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get1_issuer)}
      X509_STORE_CTX_get1_issuer := FC_X509_STORE_CTX_get1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_issuer_removed)}
    if X509_STORE_CTX_get1_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get1_issuer)}
      X509_STORE_CTX_get1_issuer := _X509_STORE_CTX_get1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get1_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get1_issuer');
    {$ifend}
  end;
  
  X509_STORE_CTX_free := LoadLibFunction(ADllHandle, X509_STORE_CTX_free_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_free_allownil)}
    X509_STORE_CTX_free := ERR_X509_STORE_CTX_free;
    {$ifend}
    {$if declared(X509_STORE_CTX_free_introduced)}
    if LibVersion < X509_STORE_CTX_free_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_free)}
      X509_STORE_CTX_free := FC_X509_STORE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_free_removed)}
    if X509_STORE_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_free)}
      X509_STORE_CTX_free := _X509_STORE_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_free');
    {$ifend}
  end;
  
  X509_STORE_CTX_init := LoadLibFunction(ADllHandle, X509_STORE_CTX_init_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_init);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_init_allownil)}
    X509_STORE_CTX_init := ERR_X509_STORE_CTX_init;
    {$ifend}
    {$if declared(X509_STORE_CTX_init_introduced)}
    if LibVersion < X509_STORE_CTX_init_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_init)}
      X509_STORE_CTX_init := FC_X509_STORE_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_init_removed)}
    if X509_STORE_CTX_init_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_init)}
      X509_STORE_CTX_init := _X509_STORE_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_init_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_init');
    {$ifend}
  end;
  
  X509_STORE_CTX_init_rpk := LoadLibFunction(ADllHandle, X509_STORE_CTX_init_rpk_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_init_rpk);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_init_rpk_allownil)}
    X509_STORE_CTX_init_rpk := ERR_X509_STORE_CTX_init_rpk;
    {$ifend}
    {$if declared(X509_STORE_CTX_init_rpk_introduced)}
    if LibVersion < X509_STORE_CTX_init_rpk_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_init_rpk)}
      X509_STORE_CTX_init_rpk := FC_X509_STORE_CTX_init_rpk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_init_rpk_removed)}
    if X509_STORE_CTX_init_rpk_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_init_rpk)}
      X509_STORE_CTX_init_rpk := _X509_STORE_CTX_init_rpk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_init_rpk_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_init_rpk');
    {$ifend}
  end;
  
  X509_STORE_CTX_set0_trusted_stack := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_trusted_stack_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_trusted_stack);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_trusted_stack_allownil)}
    X509_STORE_CTX_set0_trusted_stack := ERR_X509_STORE_CTX_set0_trusted_stack;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_trusted_stack_introduced)}
    if LibVersion < X509_STORE_CTX_set0_trusted_stack_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_trusted_stack)}
      X509_STORE_CTX_set0_trusted_stack := FC_X509_STORE_CTX_set0_trusted_stack;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_trusted_stack_removed)}
    if X509_STORE_CTX_set0_trusted_stack_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_trusted_stack)}
      X509_STORE_CTX_set0_trusted_stack := _X509_STORE_CTX_set0_trusted_stack;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_trusted_stack_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_trusted_stack');
    {$ifend}
  end;
  
  X509_STORE_CTX_cleanup := LoadLibFunction(ADllHandle, X509_STORE_CTX_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_cleanup_allownil)}
    X509_STORE_CTX_cleanup := ERR_X509_STORE_CTX_cleanup;
    {$ifend}
    {$if declared(X509_STORE_CTX_cleanup_introduced)}
    if LibVersion < X509_STORE_CTX_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_cleanup)}
      X509_STORE_CTX_cleanup := FC_X509_STORE_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_cleanup_removed)}
    if X509_STORE_CTX_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_cleanup)}
      X509_STORE_CTX_cleanup := _X509_STORE_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_cleanup');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_store := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_store_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_store);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_store_allownil)}
    X509_STORE_CTX_get0_store := ERR_X509_STORE_CTX_get0_store;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_store_introduced)}
    if LibVersion < X509_STORE_CTX_get0_store_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_store)}
      X509_STORE_CTX_get0_store := FC_X509_STORE_CTX_get0_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_store_removed)}
    if X509_STORE_CTX_get0_store_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_store)}
      X509_STORE_CTX_get0_store := _X509_STORE_CTX_get0_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_store_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_store');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_cert_allownil)}
    X509_STORE_CTX_get0_cert := ERR_X509_STORE_CTX_get0_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_cert_introduced)}
    if LibVersion < X509_STORE_CTX_get0_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_cert)}
      X509_STORE_CTX_get0_cert := FC_X509_STORE_CTX_get0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_cert_removed)}
    if X509_STORE_CTX_get0_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_cert)}
      X509_STORE_CTX_get0_cert := _X509_STORE_CTX_get0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_cert');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_rpk := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_rpk_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_rpk);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_rpk_allownil)}
    X509_STORE_CTX_get0_rpk := ERR_X509_STORE_CTX_get0_rpk;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_rpk_introduced)}
    if LibVersion < X509_STORE_CTX_get0_rpk_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_rpk)}
      X509_STORE_CTX_get0_rpk := FC_X509_STORE_CTX_get0_rpk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_rpk_removed)}
    if X509_STORE_CTX_get0_rpk_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_rpk)}
      X509_STORE_CTX_get0_rpk := _X509_STORE_CTX_get0_rpk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_rpk_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_rpk');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_untrusted := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_untrusted_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_untrusted);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_untrusted_allownil)}
    X509_STORE_CTX_get0_untrusted := ERR_X509_STORE_CTX_get0_untrusted;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_untrusted_introduced)}
    if LibVersion < X509_STORE_CTX_get0_untrusted_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_untrusted)}
      X509_STORE_CTX_get0_untrusted := FC_X509_STORE_CTX_get0_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_untrusted_removed)}
    if X509_STORE_CTX_get0_untrusted_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_untrusted)}
      X509_STORE_CTX_get0_untrusted := _X509_STORE_CTX_get0_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_untrusted_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_untrusted');
    {$ifend}
  end;
  
  X509_STORE_CTX_set0_untrusted := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_untrusted_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_untrusted);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_untrusted_allownil)}
    X509_STORE_CTX_set0_untrusted := ERR_X509_STORE_CTX_set0_untrusted;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_untrusted_introduced)}
    if LibVersion < X509_STORE_CTX_set0_untrusted_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_untrusted)}
      X509_STORE_CTX_set0_untrusted := FC_X509_STORE_CTX_set0_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_untrusted_removed)}
    if X509_STORE_CTX_set0_untrusted_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_untrusted)}
      X509_STORE_CTX_set0_untrusted := _X509_STORE_CTX_set0_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_untrusted_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_untrusted');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_verify_cb_allownil)}
    X509_STORE_CTX_set_verify_cb := ERR_X509_STORE_CTX_set_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_cb_introduced)}
    if LibVersion < X509_STORE_CTX_set_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_verify_cb)}
      X509_STORE_CTX_set_verify_cb := FC_X509_STORE_CTX_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_verify_cb_removed)}
    if X509_STORE_CTX_set_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_verify_cb)}
      X509_STORE_CTX_set_verify_cb := _X509_STORE_CTX_set_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_verify_cb');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_verify_cb := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_verify_cb_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_verify_cb);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_verify_cb_allownil)}
    X509_STORE_CTX_get_verify_cb := ERR_X509_STORE_CTX_get_verify_cb;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_cb_introduced)}
    if LibVersion < X509_STORE_CTX_get_verify_cb_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_verify_cb)}
      X509_STORE_CTX_get_verify_cb := FC_X509_STORE_CTX_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_cb_removed)}
    if X509_STORE_CTX_get_verify_cb_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_verify_cb)}
      X509_STORE_CTX_get_verify_cb := _X509_STORE_CTX_get_verify_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_verify_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_verify_cb');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_verify := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_verify_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_verify_allownil)}
    X509_STORE_CTX_get_verify := ERR_X509_STORE_CTX_get_verify;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_introduced)}
    if LibVersion < X509_STORE_CTX_get_verify_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_verify)}
      X509_STORE_CTX_get_verify := FC_X509_STORE_CTX_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_verify_removed)}
    if X509_STORE_CTX_get_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_verify)}
      X509_STORE_CTX_get_verify := _X509_STORE_CTX_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_verify');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_get_issuer := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_get_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_get_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_get_issuer_allownil)}
    X509_STORE_CTX_get_get_issuer := ERR_X509_STORE_CTX_get_get_issuer;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_issuer_introduced)}
    if LibVersion < X509_STORE_CTX_get_get_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_get_issuer)}
      X509_STORE_CTX_get_get_issuer := FC_X509_STORE_CTX_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_issuer_removed)}
    if X509_STORE_CTX_get_get_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_get_issuer)}
      X509_STORE_CTX_get_get_issuer := _X509_STORE_CTX_get_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_get_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_get_issuer');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_check_issued := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_issued_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_issued_allownil)}
    X509_STORE_CTX_get_check_issued := ERR_X509_STORE_CTX_get_check_issued;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_issued_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_issued_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_issued)}
      X509_STORE_CTX_get_check_issued := FC_X509_STORE_CTX_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_issued_removed)}
    if X509_STORE_CTX_get_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_issued)}
      X509_STORE_CTX_get_check_issued := _X509_STORE_CTX_get_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_issued');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_check_revocation := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_revocation_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_revocation);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_revocation_allownil)}
    X509_STORE_CTX_get_check_revocation := ERR_X509_STORE_CTX_get_check_revocation;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_revocation_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_revocation_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_revocation)}
      X509_STORE_CTX_get_check_revocation := FC_X509_STORE_CTX_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_revocation_removed)}
    if X509_STORE_CTX_get_check_revocation_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_revocation)}
      X509_STORE_CTX_get_check_revocation := _X509_STORE_CTX_get_check_revocation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_revocation_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_revocation');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_get_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_get_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_get_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_get_crl_allownil)}
    X509_STORE_CTX_set_get_crl := ERR_X509_STORE_CTX_set_get_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_get_crl_introduced)}
    if LibVersion < X509_STORE_CTX_set_get_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_get_crl)}
      X509_STORE_CTX_set_get_crl := FC_X509_STORE_CTX_set_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_get_crl_removed)}
    if X509_STORE_CTX_set_get_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_get_crl)}
      X509_STORE_CTX_set_get_crl := _X509_STORE_CTX_set_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_get_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_get_crl');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_get_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_get_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_get_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_get_crl_allownil)}
    X509_STORE_CTX_get_get_crl := ERR_X509_STORE_CTX_get_get_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get_get_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_get_crl)}
      X509_STORE_CTX_get_get_crl := FC_X509_STORE_CTX_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_get_crl_removed)}
    if X509_STORE_CTX_get_get_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_get_crl)}
      X509_STORE_CTX_get_get_crl := _X509_STORE_CTX_get_get_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_get_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_get_crl');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_check_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_crl_allownil)}
    X509_STORE_CTX_get_check_crl := ERR_X509_STORE_CTX_get_check_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_crl)}
      X509_STORE_CTX_get_check_crl := FC_X509_STORE_CTX_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_crl_removed)}
    if X509_STORE_CTX_get_check_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_crl)}
      X509_STORE_CTX_get_check_crl := _X509_STORE_CTX_get_check_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_crl');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_cert_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_cert_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_cert_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_cert_crl_allownil)}
    X509_STORE_CTX_get_cert_crl := ERR_X509_STORE_CTX_get_cert_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cert_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get_cert_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_cert_crl)}
      X509_STORE_CTX_get_cert_crl := FC_X509_STORE_CTX_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cert_crl_removed)}
    if X509_STORE_CTX_get_cert_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_cert_crl)}
      X509_STORE_CTX_get_cert_crl := _X509_STORE_CTX_get_cert_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_cert_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_cert_crl');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_check_policy := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_check_policy_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_check_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_check_policy_allownil)}
    X509_STORE_CTX_get_check_policy := ERR_X509_STORE_CTX_get_check_policy;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_policy_introduced)}
    if LibVersion < X509_STORE_CTX_get_check_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_check_policy)}
      X509_STORE_CTX_get_check_policy := FC_X509_STORE_CTX_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_check_policy_removed)}
    if X509_STORE_CTX_get_check_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_check_policy)}
      X509_STORE_CTX_get_check_policy := _X509_STORE_CTX_get_check_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_check_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_check_policy');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_lookup_certs := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_lookup_certs_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_lookup_certs);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_lookup_certs_allownil)}
    X509_STORE_CTX_get_lookup_certs := ERR_X509_STORE_CTX_get_lookup_certs;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_lookup_certs_introduced)}
    if LibVersion < X509_STORE_CTX_get_lookup_certs_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_lookup_certs)}
      X509_STORE_CTX_get_lookup_certs := FC_X509_STORE_CTX_get_lookup_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_lookup_certs_removed)}
    if X509_STORE_CTX_get_lookup_certs_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_lookup_certs)}
      X509_STORE_CTX_get_lookup_certs := _X509_STORE_CTX_get_lookup_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_lookup_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_lookup_certs');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_lookup_crls := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_lookup_crls_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_lookup_crls);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_lookup_crls_allownil)}
    X509_STORE_CTX_get_lookup_crls := ERR_X509_STORE_CTX_get_lookup_crls;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_lookup_crls_introduced)}
    if LibVersion < X509_STORE_CTX_get_lookup_crls_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_lookup_crls)}
      X509_STORE_CTX_get_lookup_crls := FC_X509_STORE_CTX_get_lookup_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_lookup_crls_removed)}
    if X509_STORE_CTX_get_lookup_crls_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_lookup_crls)}
      X509_STORE_CTX_get_lookup_crls := _X509_STORE_CTX_get_lookup_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_lookup_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_lookup_crls');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_cleanup := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_cleanup_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_cleanup_allownil)}
    X509_STORE_CTX_get_cleanup := ERR_X509_STORE_CTX_get_cleanup;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cleanup_introduced)}
    if LibVersion < X509_STORE_CTX_get_cleanup_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_cleanup)}
      X509_STORE_CTX_get_cleanup := FC_X509_STORE_CTX_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_cleanup_removed)}
    if X509_STORE_CTX_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_cleanup)}
      X509_STORE_CTX_get_cleanup := _X509_STORE_CTX_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_cleanup');
    {$ifend}
  end;
  
  X509_STORE_add_lookup := LoadLibFunction(ADllHandle, X509_STORE_add_lookup_procname);
  FuncLoadError := not assigned(X509_STORE_add_lookup);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_add_lookup_allownil)}
    X509_STORE_add_lookup := ERR_X509_STORE_add_lookup;
    {$ifend}
    {$if declared(X509_STORE_add_lookup_introduced)}
    if LibVersion < X509_STORE_add_lookup_introduced then
    begin
      {$if declared(FC_X509_STORE_add_lookup)}
      X509_STORE_add_lookup := FC_X509_STORE_add_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_add_lookup_removed)}
    if X509_STORE_add_lookup_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_add_lookup)}
      X509_STORE_add_lookup := _X509_STORE_add_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_add_lookup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_add_lookup');
    {$ifend}
  end;
  
  X509_LOOKUP_hash_dir := LoadLibFunction(ADllHandle, X509_LOOKUP_hash_dir_procname);
  FuncLoadError := not assigned(X509_LOOKUP_hash_dir);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_hash_dir_allownil)}
    X509_LOOKUP_hash_dir := ERR_X509_LOOKUP_hash_dir;
    {$ifend}
    {$if declared(X509_LOOKUP_hash_dir_introduced)}
    if LibVersion < X509_LOOKUP_hash_dir_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_hash_dir)}
      X509_LOOKUP_hash_dir := FC_X509_LOOKUP_hash_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_hash_dir_removed)}
    if X509_LOOKUP_hash_dir_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_hash_dir)}
      X509_LOOKUP_hash_dir := _X509_LOOKUP_hash_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_hash_dir_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_hash_dir');
    {$ifend}
  end;
  
  X509_LOOKUP_file := LoadLibFunction(ADllHandle, X509_LOOKUP_file_procname);
  FuncLoadError := not assigned(X509_LOOKUP_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_file_allownil)}
    X509_LOOKUP_file := ERR_X509_LOOKUP_file;
    {$ifend}
    {$if declared(X509_LOOKUP_file_introduced)}
    if LibVersion < X509_LOOKUP_file_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_file)}
      X509_LOOKUP_file := FC_X509_LOOKUP_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_file_removed)}
    if X509_LOOKUP_file_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_file)}
      X509_LOOKUP_file := _X509_LOOKUP_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_file');
    {$ifend}
  end;
  
  X509_LOOKUP_store := LoadLibFunction(ADllHandle, X509_LOOKUP_store_procname);
  FuncLoadError := not assigned(X509_LOOKUP_store);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_store_allownil)}
    X509_LOOKUP_store := ERR_X509_LOOKUP_store;
    {$ifend}
    {$if declared(X509_LOOKUP_store_introduced)}
    if LibVersion < X509_LOOKUP_store_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_store)}
      X509_LOOKUP_store := FC_X509_LOOKUP_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_store_removed)}
    if X509_LOOKUP_store_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_store)}
      X509_LOOKUP_store := _X509_LOOKUP_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_store_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_store');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_new := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_new_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_new_allownil)}
    X509_LOOKUP_meth_new := ERR_X509_LOOKUP_meth_new;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_new_introduced)}
    if LibVersion < X509_LOOKUP_meth_new_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_new)}
      X509_LOOKUP_meth_new := FC_X509_LOOKUP_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_new_removed)}
    if X509_LOOKUP_meth_new_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_new)}
      X509_LOOKUP_meth_new := _X509_LOOKUP_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_new');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_free := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_free_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_free_allownil)}
    X509_LOOKUP_meth_free := ERR_X509_LOOKUP_meth_free;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_free_introduced)}
    if LibVersion < X509_LOOKUP_meth_free_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_free)}
      X509_LOOKUP_meth_free := FC_X509_LOOKUP_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_free_removed)}
    if X509_LOOKUP_meth_free_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_free)}
      X509_LOOKUP_meth_free := _X509_LOOKUP_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_free');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_new_item := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_new_item_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_new_item);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_new_item_allownil)}
    X509_LOOKUP_meth_set_new_item := ERR_X509_LOOKUP_meth_set_new_item;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_new_item_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_new_item_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_new_item)}
      X509_LOOKUP_meth_set_new_item := FC_X509_LOOKUP_meth_set_new_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_new_item_removed)}
    if X509_LOOKUP_meth_set_new_item_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_new_item)}
      X509_LOOKUP_meth_set_new_item := _X509_LOOKUP_meth_set_new_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_new_item_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_new_item');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_new_item := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_new_item_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_new_item);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_new_item_allownil)}
    X509_LOOKUP_meth_get_new_item := ERR_X509_LOOKUP_meth_get_new_item;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_new_item_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_new_item_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_new_item)}
      X509_LOOKUP_meth_get_new_item := FC_X509_LOOKUP_meth_get_new_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_new_item_removed)}
    if X509_LOOKUP_meth_get_new_item_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_new_item)}
      X509_LOOKUP_meth_get_new_item := _X509_LOOKUP_meth_get_new_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_new_item_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_new_item');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_free := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_free_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_free_allownil)}
    X509_LOOKUP_meth_set_free := ERR_X509_LOOKUP_meth_set_free;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_free_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_free_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_free)}
      X509_LOOKUP_meth_set_free := FC_X509_LOOKUP_meth_set_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_free_removed)}
    if X509_LOOKUP_meth_set_free_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_free)}
      X509_LOOKUP_meth_set_free := _X509_LOOKUP_meth_set_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_free');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_free := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_free_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_free_allownil)}
    X509_LOOKUP_meth_get_free := ERR_X509_LOOKUP_meth_get_free;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_free_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_free_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_free)}
      X509_LOOKUP_meth_get_free := FC_X509_LOOKUP_meth_get_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_free_removed)}
    if X509_LOOKUP_meth_get_free_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_free)}
      X509_LOOKUP_meth_get_free := _X509_LOOKUP_meth_get_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_free');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_init := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_init_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_init);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_init_allownil)}
    X509_LOOKUP_meth_set_init := ERR_X509_LOOKUP_meth_set_init;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_init_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_init_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_init)}
      X509_LOOKUP_meth_set_init := FC_X509_LOOKUP_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_init_removed)}
    if X509_LOOKUP_meth_set_init_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_init)}
      X509_LOOKUP_meth_set_init := _X509_LOOKUP_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_init');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_init := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_init_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_init);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_init_allownil)}
    X509_LOOKUP_meth_get_init := ERR_X509_LOOKUP_meth_get_init;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_init_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_init_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_init)}
      X509_LOOKUP_meth_get_init := FC_X509_LOOKUP_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_init_removed)}
    if X509_LOOKUP_meth_get_init_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_init)}
      X509_LOOKUP_meth_get_init := _X509_LOOKUP_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_init');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_shutdown := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_shutdown_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_shutdown);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_shutdown_allownil)}
    X509_LOOKUP_meth_set_shutdown := ERR_X509_LOOKUP_meth_set_shutdown;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_shutdown_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_shutdown_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_shutdown)}
      X509_LOOKUP_meth_set_shutdown := FC_X509_LOOKUP_meth_set_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_shutdown_removed)}
    if X509_LOOKUP_meth_set_shutdown_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_shutdown)}
      X509_LOOKUP_meth_set_shutdown := _X509_LOOKUP_meth_set_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_shutdown_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_shutdown');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_shutdown := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_shutdown_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_shutdown);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_shutdown_allownil)}
    X509_LOOKUP_meth_get_shutdown := ERR_X509_LOOKUP_meth_get_shutdown;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_shutdown_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_shutdown_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_shutdown)}
      X509_LOOKUP_meth_get_shutdown := FC_X509_LOOKUP_meth_get_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_shutdown_removed)}
    if X509_LOOKUP_meth_get_shutdown_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_shutdown)}
      X509_LOOKUP_meth_get_shutdown := _X509_LOOKUP_meth_get_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_shutdown_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_shutdown');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_ctrl := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_ctrl_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_ctrl_allownil)}
    X509_LOOKUP_meth_set_ctrl := ERR_X509_LOOKUP_meth_set_ctrl;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_ctrl_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_ctrl_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_ctrl)}
      X509_LOOKUP_meth_set_ctrl := FC_X509_LOOKUP_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_ctrl_removed)}
    if X509_LOOKUP_meth_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_ctrl)}
      X509_LOOKUP_meth_set_ctrl := _X509_LOOKUP_meth_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_ctrl');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_ctrl := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_ctrl_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_ctrl_allownil)}
    X509_LOOKUP_meth_get_ctrl := ERR_X509_LOOKUP_meth_get_ctrl;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_ctrl_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_ctrl_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_ctrl)}
      X509_LOOKUP_meth_get_ctrl := FC_X509_LOOKUP_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_ctrl_removed)}
    if X509_LOOKUP_meth_get_ctrl_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_ctrl)}
      X509_LOOKUP_meth_get_ctrl := _X509_LOOKUP_meth_get_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_ctrl');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_get_by_subject := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_subject_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_subject_allownil)}
    X509_LOOKUP_meth_set_get_by_subject := ERR_X509_LOOKUP_meth_set_get_by_subject;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_subject_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_subject_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_subject)}
      X509_LOOKUP_meth_set_get_by_subject := FC_X509_LOOKUP_meth_set_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_subject_removed)}
    if X509_LOOKUP_meth_set_get_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_subject)}
      X509_LOOKUP_meth_set_get_by_subject := _X509_LOOKUP_meth_set_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_subject');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_get_by_subject := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_subject_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_subject_allownil)}
    X509_LOOKUP_meth_get_get_by_subject := ERR_X509_LOOKUP_meth_get_get_by_subject;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_subject_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_subject_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_subject)}
      X509_LOOKUP_meth_get_get_by_subject := FC_X509_LOOKUP_meth_get_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_subject_removed)}
    if X509_LOOKUP_meth_get_get_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_subject)}
      X509_LOOKUP_meth_get_get_by_subject := _X509_LOOKUP_meth_get_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_subject');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_get_by_issuer_serial := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_issuer_serial_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_issuer_serial_allownil)}
    X509_LOOKUP_meth_set_get_by_issuer_serial := ERR_X509_LOOKUP_meth_set_get_by_issuer_serial;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_issuer_serial_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_issuer_serial_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_issuer_serial)}
      X509_LOOKUP_meth_set_get_by_issuer_serial := FC_X509_LOOKUP_meth_set_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_issuer_serial_removed)}
    if X509_LOOKUP_meth_set_get_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_issuer_serial)}
      X509_LOOKUP_meth_set_get_by_issuer_serial := _X509_LOOKUP_meth_set_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_issuer_serial');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_get_by_issuer_serial := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_issuer_serial_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_issuer_serial_allownil)}
    X509_LOOKUP_meth_get_get_by_issuer_serial := ERR_X509_LOOKUP_meth_get_get_by_issuer_serial;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_issuer_serial_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_issuer_serial_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_issuer_serial)}
      X509_LOOKUP_meth_get_get_by_issuer_serial := FC_X509_LOOKUP_meth_get_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_issuer_serial_removed)}
    if X509_LOOKUP_meth_get_get_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_issuer_serial)}
      X509_LOOKUP_meth_get_get_by_issuer_serial := _X509_LOOKUP_meth_get_get_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_issuer_serial');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_get_by_fingerprint := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_fingerprint_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_fingerprint_allownil)}
    X509_LOOKUP_meth_set_get_by_fingerprint := ERR_X509_LOOKUP_meth_set_get_by_fingerprint;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_fingerprint_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_fingerprint_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_fingerprint)}
      X509_LOOKUP_meth_set_get_by_fingerprint := FC_X509_LOOKUP_meth_set_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_fingerprint_removed)}
    if X509_LOOKUP_meth_set_get_by_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_fingerprint)}
      X509_LOOKUP_meth_set_get_by_fingerprint := _X509_LOOKUP_meth_set_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_fingerprint');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_get_by_fingerprint := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_fingerprint_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_fingerprint_allownil)}
    X509_LOOKUP_meth_get_get_by_fingerprint := ERR_X509_LOOKUP_meth_get_get_by_fingerprint;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_fingerprint_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_fingerprint_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_fingerprint)}
      X509_LOOKUP_meth_get_get_by_fingerprint := FC_X509_LOOKUP_meth_get_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_fingerprint_removed)}
    if X509_LOOKUP_meth_get_get_by_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_fingerprint)}
      X509_LOOKUP_meth_get_get_by_fingerprint := _X509_LOOKUP_meth_get_get_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_fingerprint');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_set_get_by_alias := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_set_get_by_alias_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_set_get_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_set_get_by_alias_allownil)}
    X509_LOOKUP_meth_set_get_by_alias := ERR_X509_LOOKUP_meth_set_get_by_alias;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_alias_introduced)}
    if LibVersion < X509_LOOKUP_meth_set_get_by_alias_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_set_get_by_alias)}
      X509_LOOKUP_meth_set_get_by_alias := FC_X509_LOOKUP_meth_set_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_set_get_by_alias_removed)}
    if X509_LOOKUP_meth_set_get_by_alias_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_set_get_by_alias)}
      X509_LOOKUP_meth_set_get_by_alias := _X509_LOOKUP_meth_set_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_set_get_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_set_get_by_alias');
    {$ifend}
  end;
  
  X509_LOOKUP_meth_get_get_by_alias := LoadLibFunction(ADllHandle, X509_LOOKUP_meth_get_get_by_alias_procname);
  FuncLoadError := not assigned(X509_LOOKUP_meth_get_get_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_meth_get_get_by_alias_allownil)}
    X509_LOOKUP_meth_get_get_by_alias := ERR_X509_LOOKUP_meth_get_get_by_alias;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_alias_introduced)}
    if LibVersion < X509_LOOKUP_meth_get_get_by_alias_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_meth_get_get_by_alias)}
      X509_LOOKUP_meth_get_get_by_alias := FC_X509_LOOKUP_meth_get_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_meth_get_get_by_alias_removed)}
    if X509_LOOKUP_meth_get_get_by_alias_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_meth_get_get_by_alias)}
      X509_LOOKUP_meth_get_get_by_alias := _X509_LOOKUP_meth_get_get_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_meth_get_get_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_meth_get_get_by_alias');
    {$ifend}
  end;
  
  X509_STORE_add_cert := LoadLibFunction(ADllHandle, X509_STORE_add_cert_procname);
  FuncLoadError := not assigned(X509_STORE_add_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_add_cert_allownil)}
    X509_STORE_add_cert := ERR_X509_STORE_add_cert;
    {$ifend}
    {$if declared(X509_STORE_add_cert_introduced)}
    if LibVersion < X509_STORE_add_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_add_cert)}
      X509_STORE_add_cert := FC_X509_STORE_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_add_cert_removed)}
    if X509_STORE_add_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_add_cert)}
      X509_STORE_add_cert := _X509_STORE_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_add_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_add_cert');
    {$ifend}
  end;
  
  X509_STORE_add_crl := LoadLibFunction(ADllHandle, X509_STORE_add_crl_procname);
  FuncLoadError := not assigned(X509_STORE_add_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_add_crl_allownil)}
    X509_STORE_add_crl := ERR_X509_STORE_add_crl;
    {$ifend}
    {$if declared(X509_STORE_add_crl_introduced)}
    if LibVersion < X509_STORE_add_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_add_crl)}
      X509_STORE_add_crl := FC_X509_STORE_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_add_crl_removed)}
    if X509_STORE_add_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_add_crl)}
      X509_STORE_add_crl := _X509_STORE_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_add_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_add_crl');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_by_subject := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_by_subject_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_by_subject_allownil)}
    X509_STORE_CTX_get_by_subject := ERR_X509_STORE_CTX_get_by_subject;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_by_subject_introduced)}
    if LibVersion < X509_STORE_CTX_get_by_subject_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_by_subject)}
      X509_STORE_CTX_get_by_subject := FC_X509_STORE_CTX_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_by_subject_removed)}
    if X509_STORE_CTX_get_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_by_subject)}
      X509_STORE_CTX_get_by_subject := _X509_STORE_CTX_get_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_by_subject');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_obj_by_subject := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_obj_by_subject_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_obj_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_obj_by_subject_allownil)}
    X509_STORE_CTX_get_obj_by_subject := ERR_X509_STORE_CTX_get_obj_by_subject;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_obj_by_subject_introduced)}
    if LibVersion < X509_STORE_CTX_get_obj_by_subject_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_obj_by_subject)}
      X509_STORE_CTX_get_obj_by_subject := FC_X509_STORE_CTX_get_obj_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_obj_by_subject_removed)}
    if X509_STORE_CTX_get_obj_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_obj_by_subject)}
      X509_STORE_CTX_get_obj_by_subject := _X509_STORE_CTX_get_obj_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_obj_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_obj_by_subject');
    {$ifend}
  end;
  
  X509_LOOKUP_ctrl := LoadLibFunction(ADllHandle, X509_LOOKUP_ctrl_procname);
  FuncLoadError := not assigned(X509_LOOKUP_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_ctrl_allownil)}
    X509_LOOKUP_ctrl := ERR_X509_LOOKUP_ctrl;
    {$ifend}
    {$if declared(X509_LOOKUP_ctrl_introduced)}
    if LibVersion < X509_LOOKUP_ctrl_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_ctrl)}
      X509_LOOKUP_ctrl := FC_X509_LOOKUP_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_ctrl_removed)}
    if X509_LOOKUP_ctrl_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_ctrl)}
      X509_LOOKUP_ctrl := _X509_LOOKUP_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_ctrl');
    {$ifend}
  end;
  
  X509_LOOKUP_ctrl_ex := LoadLibFunction(ADllHandle, X509_LOOKUP_ctrl_ex_procname);
  FuncLoadError := not assigned(X509_LOOKUP_ctrl_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_ctrl_ex_allownil)}
    X509_LOOKUP_ctrl_ex := ERR_X509_LOOKUP_ctrl_ex;
    {$ifend}
    {$if declared(X509_LOOKUP_ctrl_ex_introduced)}
    if LibVersion < X509_LOOKUP_ctrl_ex_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_ctrl_ex)}
      X509_LOOKUP_ctrl_ex := FC_X509_LOOKUP_ctrl_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_ctrl_ex_removed)}
    if X509_LOOKUP_ctrl_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_ctrl_ex)}
      X509_LOOKUP_ctrl_ex := _X509_LOOKUP_ctrl_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_ctrl_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_ctrl_ex');
    {$ifend}
  end;
  
  X509_load_cert_file := LoadLibFunction(ADllHandle, X509_load_cert_file_procname);
  FuncLoadError := not assigned(X509_load_cert_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_cert_file_allownil)}
    X509_load_cert_file := ERR_X509_load_cert_file;
    {$ifend}
    {$if declared(X509_load_cert_file_introduced)}
    if LibVersion < X509_load_cert_file_introduced then
    begin
      {$if declared(FC_X509_load_cert_file)}
      X509_load_cert_file := FC_X509_load_cert_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_cert_file_removed)}
    if X509_load_cert_file_removed <= LibVersion then
    begin
      {$if declared(_X509_load_cert_file)}
      X509_load_cert_file := _X509_load_cert_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_cert_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_cert_file');
    {$ifend}
  end;
  
  X509_load_cert_file_ex := LoadLibFunction(ADllHandle, X509_load_cert_file_ex_procname);
  FuncLoadError := not assigned(X509_load_cert_file_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_cert_file_ex_allownil)}
    X509_load_cert_file_ex := ERR_X509_load_cert_file_ex;
    {$ifend}
    {$if declared(X509_load_cert_file_ex_introduced)}
    if LibVersion < X509_load_cert_file_ex_introduced then
    begin
      {$if declared(FC_X509_load_cert_file_ex)}
      X509_load_cert_file_ex := FC_X509_load_cert_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_cert_file_ex_removed)}
    if X509_load_cert_file_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_load_cert_file_ex)}
      X509_load_cert_file_ex := _X509_load_cert_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_cert_file_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_cert_file_ex');
    {$ifend}
  end;
  
  X509_load_crl_file := LoadLibFunction(ADllHandle, X509_load_crl_file_procname);
  FuncLoadError := not assigned(X509_load_crl_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_crl_file_allownil)}
    X509_load_crl_file := ERR_X509_load_crl_file;
    {$ifend}
    {$if declared(X509_load_crl_file_introduced)}
    if LibVersion < X509_load_crl_file_introduced then
    begin
      {$if declared(FC_X509_load_crl_file)}
      X509_load_crl_file := FC_X509_load_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_crl_file_removed)}
    if X509_load_crl_file_removed <= LibVersion then
    begin
      {$if declared(_X509_load_crl_file)}
      X509_load_crl_file := _X509_load_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_crl_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_crl_file');
    {$ifend}
  end;
  
  X509_load_cert_crl_file := LoadLibFunction(ADllHandle, X509_load_cert_crl_file_procname);
  FuncLoadError := not assigned(X509_load_cert_crl_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_cert_crl_file_allownil)}
    X509_load_cert_crl_file := ERR_X509_load_cert_crl_file;
    {$ifend}
    {$if declared(X509_load_cert_crl_file_introduced)}
    if LibVersion < X509_load_cert_crl_file_introduced then
    begin
      {$if declared(FC_X509_load_cert_crl_file)}
      X509_load_cert_crl_file := FC_X509_load_cert_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_cert_crl_file_removed)}
    if X509_load_cert_crl_file_removed <= LibVersion then
    begin
      {$if declared(_X509_load_cert_crl_file)}
      X509_load_cert_crl_file := _X509_load_cert_crl_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_cert_crl_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_cert_crl_file');
    {$ifend}
  end;
  
  X509_load_cert_crl_file_ex := LoadLibFunction(ADllHandle, X509_load_cert_crl_file_ex_procname);
  FuncLoadError := not assigned(X509_load_cert_crl_file_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_cert_crl_file_ex_allownil)}
    X509_load_cert_crl_file_ex := ERR_X509_load_cert_crl_file_ex;
    {$ifend}
    {$if declared(X509_load_cert_crl_file_ex_introduced)}
    if LibVersion < X509_load_cert_crl_file_ex_introduced then
    begin
      {$if declared(FC_X509_load_cert_crl_file_ex)}
      X509_load_cert_crl_file_ex := FC_X509_load_cert_crl_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_cert_crl_file_ex_removed)}
    if X509_load_cert_crl_file_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_load_cert_crl_file_ex)}
      X509_load_cert_crl_file_ex := _X509_load_cert_crl_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_cert_crl_file_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_cert_crl_file_ex');
    {$ifend}
  end;
  
  X509_LOOKUP_new := LoadLibFunction(ADllHandle, X509_LOOKUP_new_procname);
  FuncLoadError := not assigned(X509_LOOKUP_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_new_allownil)}
    X509_LOOKUP_new := ERR_X509_LOOKUP_new;
    {$ifend}
    {$if declared(X509_LOOKUP_new_introduced)}
    if LibVersion < X509_LOOKUP_new_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_new)}
      X509_LOOKUP_new := FC_X509_LOOKUP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_new_removed)}
    if X509_LOOKUP_new_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_new)}
      X509_LOOKUP_new := _X509_LOOKUP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_new');
    {$ifend}
  end;
  
  X509_LOOKUP_free := LoadLibFunction(ADllHandle, X509_LOOKUP_free_procname);
  FuncLoadError := not assigned(X509_LOOKUP_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_free_allownil)}
    X509_LOOKUP_free := ERR_X509_LOOKUP_free;
    {$ifend}
    {$if declared(X509_LOOKUP_free_introduced)}
    if LibVersion < X509_LOOKUP_free_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_free)}
      X509_LOOKUP_free := FC_X509_LOOKUP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_free_removed)}
    if X509_LOOKUP_free_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_free)}
      X509_LOOKUP_free := _X509_LOOKUP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_free');
    {$ifend}
  end;
  
  X509_LOOKUP_init := LoadLibFunction(ADllHandle, X509_LOOKUP_init_procname);
  FuncLoadError := not assigned(X509_LOOKUP_init);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_init_allownil)}
    X509_LOOKUP_init := ERR_X509_LOOKUP_init;
    {$ifend}
    {$if declared(X509_LOOKUP_init_introduced)}
    if LibVersion < X509_LOOKUP_init_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_init)}
      X509_LOOKUP_init := FC_X509_LOOKUP_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_init_removed)}
    if X509_LOOKUP_init_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_init)}
      X509_LOOKUP_init := _X509_LOOKUP_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_init_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_init');
    {$ifend}
  end;
  
  X509_LOOKUP_by_subject := LoadLibFunction(ADllHandle, X509_LOOKUP_by_subject_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_subject_allownil)}
    X509_LOOKUP_by_subject := ERR_X509_LOOKUP_by_subject;
    {$ifend}
    {$if declared(X509_LOOKUP_by_subject_introduced)}
    if LibVersion < X509_LOOKUP_by_subject_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_subject)}
      X509_LOOKUP_by_subject := FC_X509_LOOKUP_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_subject_removed)}
    if X509_LOOKUP_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_subject)}
      X509_LOOKUP_by_subject := _X509_LOOKUP_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_subject');
    {$ifend}
  end;
  
  X509_LOOKUP_by_subject_ex := LoadLibFunction(ADllHandle, X509_LOOKUP_by_subject_ex_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_subject_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_subject_ex_allownil)}
    X509_LOOKUP_by_subject_ex := ERR_X509_LOOKUP_by_subject_ex;
    {$ifend}
    {$if declared(X509_LOOKUP_by_subject_ex_introduced)}
    if LibVersion < X509_LOOKUP_by_subject_ex_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_subject_ex)}
      X509_LOOKUP_by_subject_ex := FC_X509_LOOKUP_by_subject_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_subject_ex_removed)}
    if X509_LOOKUP_by_subject_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_subject_ex)}
      X509_LOOKUP_by_subject_ex := _X509_LOOKUP_by_subject_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_subject_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_subject_ex');
    {$ifend}
  end;
  
  X509_LOOKUP_by_issuer_serial := LoadLibFunction(ADllHandle, X509_LOOKUP_by_issuer_serial_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_issuer_serial_allownil)}
    X509_LOOKUP_by_issuer_serial := ERR_X509_LOOKUP_by_issuer_serial;
    {$ifend}
    {$if declared(X509_LOOKUP_by_issuer_serial_introduced)}
    if LibVersion < X509_LOOKUP_by_issuer_serial_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_issuer_serial)}
      X509_LOOKUP_by_issuer_serial := FC_X509_LOOKUP_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_issuer_serial_removed)}
    if X509_LOOKUP_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_issuer_serial)}
      X509_LOOKUP_by_issuer_serial := _X509_LOOKUP_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_issuer_serial');
    {$ifend}
  end;
  
  X509_LOOKUP_by_fingerprint := LoadLibFunction(ADllHandle, X509_LOOKUP_by_fingerprint_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_fingerprint_allownil)}
    X509_LOOKUP_by_fingerprint := ERR_X509_LOOKUP_by_fingerprint;
    {$ifend}
    {$if declared(X509_LOOKUP_by_fingerprint_introduced)}
    if LibVersion < X509_LOOKUP_by_fingerprint_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_fingerprint)}
      X509_LOOKUP_by_fingerprint := FC_X509_LOOKUP_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_fingerprint_removed)}
    if X509_LOOKUP_by_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_fingerprint)}
      X509_LOOKUP_by_fingerprint := _X509_LOOKUP_by_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_fingerprint');
    {$ifend}
  end;
  
  X509_LOOKUP_by_alias := LoadLibFunction(ADllHandle, X509_LOOKUP_by_alias_procname);
  FuncLoadError := not assigned(X509_LOOKUP_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_by_alias_allownil)}
    X509_LOOKUP_by_alias := ERR_X509_LOOKUP_by_alias;
    {$ifend}
    {$if declared(X509_LOOKUP_by_alias_introduced)}
    if LibVersion < X509_LOOKUP_by_alias_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_by_alias)}
      X509_LOOKUP_by_alias := FC_X509_LOOKUP_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_by_alias_removed)}
    if X509_LOOKUP_by_alias_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_by_alias)}
      X509_LOOKUP_by_alias := _X509_LOOKUP_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_by_alias');
    {$ifend}
  end;
  
  X509_LOOKUP_set_method_data := LoadLibFunction(ADllHandle, X509_LOOKUP_set_method_data_procname);
  FuncLoadError := not assigned(X509_LOOKUP_set_method_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_set_method_data_allownil)}
    X509_LOOKUP_set_method_data := ERR_X509_LOOKUP_set_method_data;
    {$ifend}
    {$if declared(X509_LOOKUP_set_method_data_introduced)}
    if LibVersion < X509_LOOKUP_set_method_data_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_set_method_data)}
      X509_LOOKUP_set_method_data := FC_X509_LOOKUP_set_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_set_method_data_removed)}
    if X509_LOOKUP_set_method_data_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_set_method_data)}
      X509_LOOKUP_set_method_data := _X509_LOOKUP_set_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_set_method_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_set_method_data');
    {$ifend}
  end;
  
  X509_LOOKUP_get_method_data := LoadLibFunction(ADllHandle, X509_LOOKUP_get_method_data_procname);
  FuncLoadError := not assigned(X509_LOOKUP_get_method_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_get_method_data_allownil)}
    X509_LOOKUP_get_method_data := ERR_X509_LOOKUP_get_method_data;
    {$ifend}
    {$if declared(X509_LOOKUP_get_method_data_introduced)}
    if LibVersion < X509_LOOKUP_get_method_data_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_get_method_data)}
      X509_LOOKUP_get_method_data := FC_X509_LOOKUP_get_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_get_method_data_removed)}
    if X509_LOOKUP_get_method_data_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_get_method_data)}
      X509_LOOKUP_get_method_data := _X509_LOOKUP_get_method_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_get_method_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_get_method_data');
    {$ifend}
  end;
  
  X509_LOOKUP_get_store := LoadLibFunction(ADllHandle, X509_LOOKUP_get_store_procname);
  FuncLoadError := not assigned(X509_LOOKUP_get_store);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_get_store_allownil)}
    X509_LOOKUP_get_store := ERR_X509_LOOKUP_get_store;
    {$ifend}
    {$if declared(X509_LOOKUP_get_store_introduced)}
    if LibVersion < X509_LOOKUP_get_store_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_get_store)}
      X509_LOOKUP_get_store := FC_X509_LOOKUP_get_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_get_store_removed)}
    if X509_LOOKUP_get_store_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_get_store)}
      X509_LOOKUP_get_store := _X509_LOOKUP_get_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_get_store_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_get_store');
    {$ifend}
  end;
  
  X509_LOOKUP_shutdown := LoadLibFunction(ADllHandle, X509_LOOKUP_shutdown_procname);
  FuncLoadError := not assigned(X509_LOOKUP_shutdown);
  if FuncLoadError then
  begin
    {$if not defined(X509_LOOKUP_shutdown_allownil)}
    X509_LOOKUP_shutdown := ERR_X509_LOOKUP_shutdown;
    {$ifend}
    {$if declared(X509_LOOKUP_shutdown_introduced)}
    if LibVersion < X509_LOOKUP_shutdown_introduced then
    begin
      {$if declared(FC_X509_LOOKUP_shutdown)}
      X509_LOOKUP_shutdown := FC_X509_LOOKUP_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_LOOKUP_shutdown_removed)}
    if X509_LOOKUP_shutdown_removed <= LibVersion then
    begin
      {$if declared(_X509_LOOKUP_shutdown)}
      X509_LOOKUP_shutdown := _X509_LOOKUP_shutdown;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_LOOKUP_shutdown_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_LOOKUP_shutdown');
    {$ifend}
  end;
  
  X509_STORE_load_file := LoadLibFunction(ADllHandle, X509_STORE_load_file_procname);
  FuncLoadError := not assigned(X509_STORE_load_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_file_allownil)}
    X509_STORE_load_file := ERR_X509_STORE_load_file;
    {$ifend}
    {$if declared(X509_STORE_load_file_introduced)}
    if LibVersion < X509_STORE_load_file_introduced then
    begin
      {$if declared(FC_X509_STORE_load_file)}
      X509_STORE_load_file := FC_X509_STORE_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_file_removed)}
    if X509_STORE_load_file_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_file)}
      X509_STORE_load_file := _X509_STORE_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_file');
    {$ifend}
  end;
  
  X509_STORE_load_path := LoadLibFunction(ADllHandle, X509_STORE_load_path_procname);
  FuncLoadError := not assigned(X509_STORE_load_path);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_path_allownil)}
    X509_STORE_load_path := ERR_X509_STORE_load_path;
    {$ifend}
    {$if declared(X509_STORE_load_path_introduced)}
    if LibVersion < X509_STORE_load_path_introduced then
    begin
      {$if declared(FC_X509_STORE_load_path)}
      X509_STORE_load_path := FC_X509_STORE_load_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_path_removed)}
    if X509_STORE_load_path_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_path)}
      X509_STORE_load_path := _X509_STORE_load_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_path_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_path');
    {$ifend}
  end;
  
  X509_STORE_load_store := LoadLibFunction(ADllHandle, X509_STORE_load_store_procname);
  FuncLoadError := not assigned(X509_STORE_load_store);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_store_allownil)}
    X509_STORE_load_store := ERR_X509_STORE_load_store;
    {$ifend}
    {$if declared(X509_STORE_load_store_introduced)}
    if LibVersion < X509_STORE_load_store_introduced then
    begin
      {$if declared(FC_X509_STORE_load_store)}
      X509_STORE_load_store := FC_X509_STORE_load_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_store_removed)}
    if X509_STORE_load_store_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_store)}
      X509_STORE_load_store := _X509_STORE_load_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_store_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_store');
    {$ifend}
  end;
  
  X509_STORE_load_locations := LoadLibFunction(ADllHandle, X509_STORE_load_locations_procname);
  FuncLoadError := not assigned(X509_STORE_load_locations);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_locations_allownil)}
    X509_STORE_load_locations := ERR_X509_STORE_load_locations;
    {$ifend}
    {$if declared(X509_STORE_load_locations_introduced)}
    if LibVersion < X509_STORE_load_locations_introduced then
    begin
      {$if declared(FC_X509_STORE_load_locations)}
      X509_STORE_load_locations := FC_X509_STORE_load_locations;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_locations_removed)}
    if X509_STORE_load_locations_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_locations)}
      X509_STORE_load_locations := _X509_STORE_load_locations;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_locations_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_locations');
    {$ifend}
  end;
  
  X509_STORE_set_default_paths := LoadLibFunction(ADllHandle, X509_STORE_set_default_paths_procname);
  FuncLoadError := not assigned(X509_STORE_set_default_paths);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_default_paths_allownil)}
    X509_STORE_set_default_paths := ERR_X509_STORE_set_default_paths;
    {$ifend}
    {$if declared(X509_STORE_set_default_paths_introduced)}
    if LibVersion < X509_STORE_set_default_paths_introduced then
    begin
      {$if declared(FC_X509_STORE_set_default_paths)}
      X509_STORE_set_default_paths := FC_X509_STORE_set_default_paths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_default_paths_removed)}
    if X509_STORE_set_default_paths_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_default_paths)}
      X509_STORE_set_default_paths := _X509_STORE_set_default_paths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_default_paths_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_default_paths');
    {$ifend}
  end;
  
  X509_STORE_load_file_ex := LoadLibFunction(ADllHandle, X509_STORE_load_file_ex_procname);
  FuncLoadError := not assigned(X509_STORE_load_file_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_file_ex_allownil)}
    X509_STORE_load_file_ex := ERR_X509_STORE_load_file_ex;
    {$ifend}
    {$if declared(X509_STORE_load_file_ex_introduced)}
    if LibVersion < X509_STORE_load_file_ex_introduced then
    begin
      {$if declared(FC_X509_STORE_load_file_ex)}
      X509_STORE_load_file_ex := FC_X509_STORE_load_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_file_ex_removed)}
    if X509_STORE_load_file_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_file_ex)}
      X509_STORE_load_file_ex := _X509_STORE_load_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_file_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_file_ex');
    {$ifend}
  end;
  
  X509_STORE_load_store_ex := LoadLibFunction(ADllHandle, X509_STORE_load_store_ex_procname);
  FuncLoadError := not assigned(X509_STORE_load_store_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_store_ex_allownil)}
    X509_STORE_load_store_ex := ERR_X509_STORE_load_store_ex;
    {$ifend}
    {$if declared(X509_STORE_load_store_ex_introduced)}
    if LibVersion < X509_STORE_load_store_ex_introduced then
    begin
      {$if declared(FC_X509_STORE_load_store_ex)}
      X509_STORE_load_store_ex := FC_X509_STORE_load_store_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_store_ex_removed)}
    if X509_STORE_load_store_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_store_ex)}
      X509_STORE_load_store_ex := _X509_STORE_load_store_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_store_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_store_ex');
    {$ifend}
  end;
  
  X509_STORE_load_locations_ex := LoadLibFunction(ADllHandle, X509_STORE_load_locations_ex_procname);
  FuncLoadError := not assigned(X509_STORE_load_locations_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_load_locations_ex_allownil)}
    X509_STORE_load_locations_ex := ERR_X509_STORE_load_locations_ex;
    {$ifend}
    {$if declared(X509_STORE_load_locations_ex_introduced)}
    if LibVersion < X509_STORE_load_locations_ex_introduced then
    begin
      {$if declared(FC_X509_STORE_load_locations_ex)}
      X509_STORE_load_locations_ex := FC_X509_STORE_load_locations_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_load_locations_ex_removed)}
    if X509_STORE_load_locations_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_load_locations_ex)}
      X509_STORE_load_locations_ex := _X509_STORE_load_locations_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_load_locations_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_load_locations_ex');
    {$ifend}
  end;
  
  X509_STORE_set_default_paths_ex := LoadLibFunction(ADllHandle, X509_STORE_set_default_paths_ex_procname);
  FuncLoadError := not assigned(X509_STORE_set_default_paths_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_set_default_paths_ex_allownil)}
    X509_STORE_set_default_paths_ex := ERR_X509_STORE_set_default_paths_ex;
    {$ifend}
    {$if declared(X509_STORE_set_default_paths_ex_introduced)}
    if LibVersion < X509_STORE_set_default_paths_ex_introduced then
    begin
      {$if declared(FC_X509_STORE_set_default_paths_ex)}
      X509_STORE_set_default_paths_ex := FC_X509_STORE_set_default_paths_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_set_default_paths_ex_removed)}
    if X509_STORE_set_default_paths_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_set_default_paths_ex)}
      X509_STORE_set_default_paths_ex := _X509_STORE_set_default_paths_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_set_default_paths_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_set_default_paths_ex');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_ex_data := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_ex_data_allownil)}
    X509_STORE_CTX_set_ex_data := ERR_X509_STORE_CTX_set_ex_data;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_ex_data_introduced)}
    if LibVersion < X509_STORE_CTX_set_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_ex_data)}
      X509_STORE_CTX_set_ex_data := FC_X509_STORE_CTX_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_ex_data_removed)}
    if X509_STORE_CTX_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_ex_data)}
      X509_STORE_CTX_set_ex_data := _X509_STORE_CTX_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_ex_data');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_ex_data := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_ex_data_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_ex_data_allownil)}
    X509_STORE_CTX_get_ex_data := ERR_X509_STORE_CTX_get_ex_data;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_ex_data_introduced)}
    if LibVersion < X509_STORE_CTX_get_ex_data_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_ex_data)}
      X509_STORE_CTX_get_ex_data := FC_X509_STORE_CTX_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_ex_data_removed)}
    if X509_STORE_CTX_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_ex_data)}
      X509_STORE_CTX_get_ex_data := _X509_STORE_CTX_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_ex_data');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_error := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_error_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_error);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_error_allownil)}
    X509_STORE_CTX_get_error := ERR_X509_STORE_CTX_get_error;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_introduced)}
    if LibVersion < X509_STORE_CTX_get_error_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_error)}
      X509_STORE_CTX_get_error := FC_X509_STORE_CTX_get_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_removed)}
    if X509_STORE_CTX_get_error_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_error)}
      X509_STORE_CTX_get_error := _X509_STORE_CTX_get_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_error_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_error');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_error := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_error_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_error);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_error_allownil)}
    X509_STORE_CTX_set_error := ERR_X509_STORE_CTX_set_error;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_introduced)}
    if LibVersion < X509_STORE_CTX_set_error_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_error)}
      X509_STORE_CTX_set_error := FC_X509_STORE_CTX_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_removed)}
    if X509_STORE_CTX_set_error_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_error)}
      X509_STORE_CTX_set_error := _X509_STORE_CTX_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_error_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_error');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_error_depth := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_error_depth_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_error_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_error_depth_allownil)}
    X509_STORE_CTX_get_error_depth := ERR_X509_STORE_CTX_get_error_depth;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_depth_introduced)}
    if LibVersion < X509_STORE_CTX_get_error_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_error_depth)}
      X509_STORE_CTX_get_error_depth := FC_X509_STORE_CTX_get_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_error_depth_removed)}
    if X509_STORE_CTX_get_error_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_error_depth)}
      X509_STORE_CTX_get_error_depth := _X509_STORE_CTX_get_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_error_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_error_depth');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_error_depth := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_error_depth_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_error_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_error_depth_allownil)}
    X509_STORE_CTX_set_error_depth := ERR_X509_STORE_CTX_set_error_depth;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_depth_introduced)}
    if LibVersion < X509_STORE_CTX_set_error_depth_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_error_depth)}
      X509_STORE_CTX_set_error_depth := FC_X509_STORE_CTX_set_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_error_depth_removed)}
    if X509_STORE_CTX_set_error_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_error_depth)}
      X509_STORE_CTX_set_error_depth := _X509_STORE_CTX_set_error_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_error_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_error_depth');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_current_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_current_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_current_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_current_cert_allownil)}
    X509_STORE_CTX_get_current_cert := ERR_X509_STORE_CTX_get_current_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_current_cert_introduced)}
    if LibVersion < X509_STORE_CTX_get_current_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_current_cert)}
      X509_STORE_CTX_get_current_cert := FC_X509_STORE_CTX_get_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_current_cert_removed)}
    if X509_STORE_CTX_get_current_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_current_cert)}
      X509_STORE_CTX_get_current_cert := _X509_STORE_CTX_get_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_current_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_current_cert');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_current_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_current_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_current_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_current_cert_allownil)}
    X509_STORE_CTX_set_current_cert := ERR_X509_STORE_CTX_set_current_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_current_cert_introduced)}
    if LibVersion < X509_STORE_CTX_set_current_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_current_cert)}
      X509_STORE_CTX_set_current_cert := FC_X509_STORE_CTX_set_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_current_cert_removed)}
    if X509_STORE_CTX_set_current_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_current_cert)}
      X509_STORE_CTX_set_current_cert := _X509_STORE_CTX_set_current_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_current_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_current_cert');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_current_issuer := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_current_issuer_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_current_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_current_issuer_allownil)}
    X509_STORE_CTX_get0_current_issuer := ERR_X509_STORE_CTX_get0_current_issuer;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_issuer_introduced)}
    if LibVersion < X509_STORE_CTX_get0_current_issuer_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_current_issuer)}
      X509_STORE_CTX_get0_current_issuer := FC_X509_STORE_CTX_get0_current_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_issuer_removed)}
    if X509_STORE_CTX_get0_current_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_current_issuer)}
      X509_STORE_CTX_get0_current_issuer := _X509_STORE_CTX_get0_current_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_current_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_current_issuer');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_current_crl := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_current_crl_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_current_crl);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_current_crl_allownil)}
    X509_STORE_CTX_get0_current_crl := ERR_X509_STORE_CTX_get0_current_crl;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_crl_introduced)}
    if LibVersion < X509_STORE_CTX_get0_current_crl_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_current_crl)}
      X509_STORE_CTX_get0_current_crl := FC_X509_STORE_CTX_get0_current_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_current_crl_removed)}
    if X509_STORE_CTX_get0_current_crl_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_current_crl)}
      X509_STORE_CTX_get0_current_crl := _X509_STORE_CTX_get0_current_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_current_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_current_crl');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_parent_ctx := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_parent_ctx_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_parent_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_parent_ctx_allownil)}
    X509_STORE_CTX_get0_parent_ctx := ERR_X509_STORE_CTX_get0_parent_ctx;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_parent_ctx_introduced)}
    if LibVersion < X509_STORE_CTX_get0_parent_ctx_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_parent_ctx)}
      X509_STORE_CTX_get0_parent_ctx := FC_X509_STORE_CTX_get0_parent_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_parent_ctx_removed)}
    if X509_STORE_CTX_get0_parent_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_parent_ctx)}
      X509_STORE_CTX_get0_parent_ctx := _X509_STORE_CTX_get0_parent_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_parent_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_parent_ctx');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_chain := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_chain_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_chain);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_chain_allownil)}
    X509_STORE_CTX_get0_chain := ERR_X509_STORE_CTX_get0_chain;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_chain_introduced)}
    if LibVersion < X509_STORE_CTX_get0_chain_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_chain)}
      X509_STORE_CTX_get0_chain := FC_X509_STORE_CTX_get0_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_chain_removed)}
    if X509_STORE_CTX_get0_chain_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_chain)}
      X509_STORE_CTX_get0_chain := _X509_STORE_CTX_get0_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_chain_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_chain');
    {$ifend}
  end;
  
  X509_STORE_CTX_get1_chain := LoadLibFunction(ADllHandle, X509_STORE_CTX_get1_chain_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get1_chain);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get1_chain_allownil)}
    X509_STORE_CTX_get1_chain := ERR_X509_STORE_CTX_get1_chain;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_chain_introduced)}
    if LibVersion < X509_STORE_CTX_get1_chain_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get1_chain)}
      X509_STORE_CTX_get1_chain := FC_X509_STORE_CTX_get1_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get1_chain_removed)}
    if X509_STORE_CTX_get1_chain_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get1_chain)}
      X509_STORE_CTX_get1_chain := _X509_STORE_CTX_get1_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get1_chain_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get1_chain');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_cert := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_cert_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_cert_allownil)}
    X509_STORE_CTX_set_cert := ERR_X509_STORE_CTX_set_cert;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_cert_introduced)}
    if LibVersion < X509_STORE_CTX_set_cert_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_cert)}
      X509_STORE_CTX_set_cert := FC_X509_STORE_CTX_set_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_cert_removed)}
    if X509_STORE_CTX_set_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_cert)}
      X509_STORE_CTX_set_cert := _X509_STORE_CTX_set_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_cert');
    {$ifend}
  end;
  
  X509_STORE_CTX_set0_rpk := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_rpk_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_rpk);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_rpk_allownil)}
    X509_STORE_CTX_set0_rpk := ERR_X509_STORE_CTX_set0_rpk;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_rpk_introduced)}
    if LibVersion < X509_STORE_CTX_set0_rpk_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_rpk)}
      X509_STORE_CTX_set0_rpk := FC_X509_STORE_CTX_set0_rpk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_rpk_removed)}
    if X509_STORE_CTX_set0_rpk_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_rpk)}
      X509_STORE_CTX_set0_rpk := _X509_STORE_CTX_set0_rpk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_rpk_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_rpk');
    {$ifend}
  end;
  
  X509_STORE_CTX_set0_verified_chain := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_verified_chain_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_verified_chain);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_verified_chain_allownil)}
    X509_STORE_CTX_set0_verified_chain := ERR_X509_STORE_CTX_set0_verified_chain;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_verified_chain_introduced)}
    if LibVersion < X509_STORE_CTX_set0_verified_chain_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_verified_chain)}
      X509_STORE_CTX_set0_verified_chain := FC_X509_STORE_CTX_set0_verified_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_verified_chain_removed)}
    if X509_STORE_CTX_set0_verified_chain_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_verified_chain)}
      X509_STORE_CTX_set0_verified_chain := _X509_STORE_CTX_set0_verified_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_verified_chain_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_verified_chain');
    {$ifend}
  end;
  
  X509_STORE_CTX_set0_crls := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_crls_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_crls);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_crls_allownil)}
    X509_STORE_CTX_set0_crls := ERR_X509_STORE_CTX_set0_crls;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_crls_introduced)}
    if LibVersion < X509_STORE_CTX_set0_crls_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_crls)}
      X509_STORE_CTX_set0_crls := FC_X509_STORE_CTX_set0_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_crls_removed)}
    if X509_STORE_CTX_set0_crls_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_crls)}
      X509_STORE_CTX_set0_crls := _X509_STORE_CTX_set0_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_crls');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_ocsp_resp := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_ocsp_resp_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_ocsp_resp);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_ocsp_resp_allownil)}
    X509_STORE_CTX_set_ocsp_resp := ERR_X509_STORE_CTX_set_ocsp_resp;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_ocsp_resp_introduced)}
    if LibVersion < X509_STORE_CTX_set_ocsp_resp_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_ocsp_resp)}
      X509_STORE_CTX_set_ocsp_resp := FC_X509_STORE_CTX_set_ocsp_resp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_ocsp_resp_removed)}
    if X509_STORE_CTX_set_ocsp_resp_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_ocsp_resp)}
      X509_STORE_CTX_set_ocsp_resp := _X509_STORE_CTX_set_ocsp_resp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_ocsp_resp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_ocsp_resp');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_purpose := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_purpose_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_purpose_allownil)}
    X509_STORE_CTX_set_purpose := ERR_X509_STORE_CTX_set_purpose;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_purpose_introduced)}
    if LibVersion < X509_STORE_CTX_set_purpose_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_purpose)}
      X509_STORE_CTX_set_purpose := FC_X509_STORE_CTX_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_purpose_removed)}
    if X509_STORE_CTX_set_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_purpose)}
      X509_STORE_CTX_set_purpose := _X509_STORE_CTX_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_purpose');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_trust := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_trust_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_trust_allownil)}
    X509_STORE_CTX_set_trust := ERR_X509_STORE_CTX_set_trust;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_trust_introduced)}
    if LibVersion < X509_STORE_CTX_set_trust_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_trust)}
      X509_STORE_CTX_set_trust := FC_X509_STORE_CTX_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_trust_removed)}
    if X509_STORE_CTX_set_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_trust)}
      X509_STORE_CTX_set_trust := _X509_STORE_CTX_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_trust');
    {$ifend}
  end;
  
  X509_STORE_CTX_purpose_inherit := LoadLibFunction(ADllHandle, X509_STORE_CTX_purpose_inherit_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_purpose_inherit);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_purpose_inherit_allownil)}
    X509_STORE_CTX_purpose_inherit := ERR_X509_STORE_CTX_purpose_inherit;
    {$ifend}
    {$if declared(X509_STORE_CTX_purpose_inherit_introduced)}
    if LibVersion < X509_STORE_CTX_purpose_inherit_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_purpose_inherit)}
      X509_STORE_CTX_purpose_inherit := FC_X509_STORE_CTX_purpose_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_purpose_inherit_removed)}
    if X509_STORE_CTX_purpose_inherit_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_purpose_inherit)}
      X509_STORE_CTX_purpose_inherit := _X509_STORE_CTX_purpose_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_purpose_inherit_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_purpose_inherit');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_flags := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_flags_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_flags_allownil)}
    X509_STORE_CTX_set_flags := ERR_X509_STORE_CTX_set_flags;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_flags_introduced)}
    if LibVersion < X509_STORE_CTX_set_flags_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_flags)}
      X509_STORE_CTX_set_flags := FC_X509_STORE_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_flags_removed)}
    if X509_STORE_CTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_flags)}
      X509_STORE_CTX_set_flags := _X509_STORE_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_flags');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_time := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_time_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_time);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_time_allownil)}
    X509_STORE_CTX_set_time := ERR_X509_STORE_CTX_set_time;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_time_introduced)}
    if LibVersion < X509_STORE_CTX_set_time_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_time)}
      X509_STORE_CTX_set_time := FC_X509_STORE_CTX_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_time_removed)}
    if X509_STORE_CTX_set_time_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_time)}
      X509_STORE_CTX_set_time := _X509_STORE_CTX_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_time_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_time');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_current_reasons := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_current_reasons_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_current_reasons);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_current_reasons_allownil)}
    X509_STORE_CTX_set_current_reasons := ERR_X509_STORE_CTX_set_current_reasons;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_current_reasons_introduced)}
    if LibVersion < X509_STORE_CTX_set_current_reasons_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_current_reasons)}
      X509_STORE_CTX_set_current_reasons := FC_X509_STORE_CTX_set_current_reasons;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_current_reasons_removed)}
    if X509_STORE_CTX_set_current_reasons_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_current_reasons)}
      X509_STORE_CTX_set_current_reasons := _X509_STORE_CTX_set_current_reasons;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_current_reasons_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_current_reasons');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_policy_tree := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_policy_tree_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_policy_tree);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_policy_tree_allownil)}
    X509_STORE_CTX_get0_policy_tree := ERR_X509_STORE_CTX_get0_policy_tree;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_policy_tree_introduced)}
    if LibVersion < X509_STORE_CTX_get0_policy_tree_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_policy_tree)}
      X509_STORE_CTX_get0_policy_tree := FC_X509_STORE_CTX_get0_policy_tree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_policy_tree_removed)}
    if X509_STORE_CTX_get0_policy_tree_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_policy_tree)}
      X509_STORE_CTX_get0_policy_tree := _X509_STORE_CTX_get0_policy_tree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_policy_tree_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_policy_tree');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_explicit_policy := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_explicit_policy_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_explicit_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_explicit_policy_allownil)}
    X509_STORE_CTX_get_explicit_policy := ERR_X509_STORE_CTX_get_explicit_policy;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_explicit_policy_introduced)}
    if LibVersion < X509_STORE_CTX_get_explicit_policy_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_explicit_policy)}
      X509_STORE_CTX_get_explicit_policy := FC_X509_STORE_CTX_get_explicit_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_explicit_policy_removed)}
    if X509_STORE_CTX_get_explicit_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_explicit_policy)}
      X509_STORE_CTX_get_explicit_policy := _X509_STORE_CTX_get_explicit_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_explicit_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_explicit_policy');
    {$ifend}
  end;
  
  X509_STORE_CTX_get_num_untrusted := LoadLibFunction(ADllHandle, X509_STORE_CTX_get_num_untrusted_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get_num_untrusted);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get_num_untrusted_allownil)}
    X509_STORE_CTX_get_num_untrusted := ERR_X509_STORE_CTX_get_num_untrusted;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_num_untrusted_introduced)}
    if LibVersion < X509_STORE_CTX_get_num_untrusted_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get_num_untrusted)}
      X509_STORE_CTX_get_num_untrusted := FC_X509_STORE_CTX_get_num_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get_num_untrusted_removed)}
    if X509_STORE_CTX_get_num_untrusted_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get_num_untrusted)}
      X509_STORE_CTX_get_num_untrusted := _X509_STORE_CTX_get_num_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get_num_untrusted_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get_num_untrusted');
    {$ifend}
  end;
  
  X509_STORE_CTX_get0_param := LoadLibFunction(ADllHandle, X509_STORE_CTX_get0_param_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_get0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_get0_param_allownil)}
    X509_STORE_CTX_get0_param := ERR_X509_STORE_CTX_get0_param;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_param_introduced)}
    if LibVersion < X509_STORE_CTX_get0_param_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_get0_param)}
      X509_STORE_CTX_get0_param := FC_X509_STORE_CTX_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_get0_param_removed)}
    if X509_STORE_CTX_get0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_get0_param)}
      X509_STORE_CTX_get0_param := _X509_STORE_CTX_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_get0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_get0_param');
    {$ifend}
  end;
  
  X509_STORE_CTX_set0_param := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_param_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_param_allownil)}
    X509_STORE_CTX_set0_param := ERR_X509_STORE_CTX_set0_param;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_param_introduced)}
    if LibVersion < X509_STORE_CTX_set0_param_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_param)}
      X509_STORE_CTX_set0_param := FC_X509_STORE_CTX_set0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_param_removed)}
    if X509_STORE_CTX_set0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_param)}
      X509_STORE_CTX_set0_param := _X509_STORE_CTX_set0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_param');
    {$ifend}
  end;
  
  X509_STORE_CTX_set_default := LoadLibFunction(ADllHandle, X509_STORE_CTX_set_default_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set_default);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set_default_allownil)}
    X509_STORE_CTX_set_default := ERR_X509_STORE_CTX_set_default;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_default_introduced)}
    if LibVersion < X509_STORE_CTX_set_default_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set_default)}
      X509_STORE_CTX_set_default := FC_X509_STORE_CTX_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set_default_removed)}
    if X509_STORE_CTX_set_default_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set_default)}
      X509_STORE_CTX_set_default := _X509_STORE_CTX_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set_default_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set_default');
    {$ifend}
  end;
  
  X509_STORE_CTX_set0_dane := LoadLibFunction(ADllHandle, X509_STORE_CTX_set0_dane_procname);
  FuncLoadError := not assigned(X509_STORE_CTX_set0_dane);
  if FuncLoadError then
  begin
    {$if not defined(X509_STORE_CTX_set0_dane_allownil)}
    X509_STORE_CTX_set0_dane := ERR_X509_STORE_CTX_set0_dane;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_dane_introduced)}
    if LibVersion < X509_STORE_CTX_set0_dane_introduced then
    begin
      {$if declared(FC_X509_STORE_CTX_set0_dane)}
      X509_STORE_CTX_set0_dane := FC_X509_STORE_CTX_set0_dane;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_STORE_CTX_set0_dane_removed)}
    if X509_STORE_CTX_set0_dane_removed <= LibVersion then
    begin
      {$if declared(_X509_STORE_CTX_set0_dane)}
      X509_STORE_CTX_set0_dane := _X509_STORE_CTX_set0_dane;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_STORE_CTX_set0_dane_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_STORE_CTX_set0_dane');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_new := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_new_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_new_allownil)}
    X509_VERIFY_PARAM_new := ERR_X509_VERIFY_PARAM_new;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_new_introduced)}
    if LibVersion < X509_VERIFY_PARAM_new_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_new)}
      X509_VERIFY_PARAM_new := FC_X509_VERIFY_PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_new_removed)}
    if X509_VERIFY_PARAM_new_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_new)}
      X509_VERIFY_PARAM_new := _X509_VERIFY_PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_new');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_free := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_free_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_free_allownil)}
    X509_VERIFY_PARAM_free := ERR_X509_VERIFY_PARAM_free;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_free_introduced)}
    if LibVersion < X509_VERIFY_PARAM_free_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_free)}
      X509_VERIFY_PARAM_free := FC_X509_VERIFY_PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_free_removed)}
    if X509_VERIFY_PARAM_free_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_free)}
      X509_VERIFY_PARAM_free := _X509_VERIFY_PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_free');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_inherit := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_inherit_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_inherit);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_inherit_allownil)}
    X509_VERIFY_PARAM_inherit := ERR_X509_VERIFY_PARAM_inherit;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_inherit_introduced)}
    if LibVersion < X509_VERIFY_PARAM_inherit_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_inherit)}
      X509_VERIFY_PARAM_inherit := FC_X509_VERIFY_PARAM_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_inherit_removed)}
    if X509_VERIFY_PARAM_inherit_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_inherit)}
      X509_VERIFY_PARAM_inherit := _X509_VERIFY_PARAM_inherit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_inherit_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_inherit');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set1 := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_allownil)}
    X509_VERIFY_PARAM_set1 := ERR_X509_VERIFY_PARAM_set1;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1)}
      X509_VERIFY_PARAM_set1 := FC_X509_VERIFY_PARAM_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_removed)}
    if X509_VERIFY_PARAM_set1_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1)}
      X509_VERIFY_PARAM_set1 := _X509_VERIFY_PARAM_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set1_name := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_name_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_name_allownil)}
    X509_VERIFY_PARAM_set1_name := ERR_X509_VERIFY_PARAM_set1_name;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_name_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_name_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_name)}
      X509_VERIFY_PARAM_set1_name := FC_X509_VERIFY_PARAM_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_name_removed)}
    if X509_VERIFY_PARAM_set1_name_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_name)}
      X509_VERIFY_PARAM_set1_name := _X509_VERIFY_PARAM_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_name');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_flags_allownil)}
    X509_VERIFY_PARAM_set_flags := ERR_X509_VERIFY_PARAM_set_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_flags)}
      X509_VERIFY_PARAM_set_flags := FC_X509_VERIFY_PARAM_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_flags_removed)}
    if X509_VERIFY_PARAM_set_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_flags)}
      X509_VERIFY_PARAM_set_flags := _X509_VERIFY_PARAM_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_flags');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_clear_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_clear_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_clear_flags_allownil)}
    X509_VERIFY_PARAM_clear_flags := ERR_X509_VERIFY_PARAM_clear_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_clear_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_clear_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_clear_flags)}
      X509_VERIFY_PARAM_clear_flags := FC_X509_VERIFY_PARAM_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_clear_flags_removed)}
    if X509_VERIFY_PARAM_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_clear_flags)}
      X509_VERIFY_PARAM_clear_flags := _X509_VERIFY_PARAM_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_clear_flags');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_flags_allownil)}
    X509_VERIFY_PARAM_get_flags := ERR_X509_VERIFY_PARAM_get_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_flags)}
      X509_VERIFY_PARAM_get_flags := FC_X509_VERIFY_PARAM_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_flags_removed)}
    if X509_VERIFY_PARAM_get_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_flags)}
      X509_VERIFY_PARAM_get_flags := _X509_VERIFY_PARAM_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_flags');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_purpose := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_purpose_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_purpose_allownil)}
    X509_VERIFY_PARAM_set_purpose := ERR_X509_VERIFY_PARAM_set_purpose;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_purpose_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_purpose_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_purpose)}
      X509_VERIFY_PARAM_set_purpose := FC_X509_VERIFY_PARAM_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_purpose_removed)}
    if X509_VERIFY_PARAM_set_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_purpose)}
      X509_VERIFY_PARAM_set_purpose := _X509_VERIFY_PARAM_set_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_purpose');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_purpose := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_purpose_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_purpose_allownil)}
    X509_VERIFY_PARAM_get_purpose := ERR_X509_VERIFY_PARAM_get_purpose;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_purpose_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_purpose_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_purpose)}
      X509_VERIFY_PARAM_get_purpose := FC_X509_VERIFY_PARAM_get_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_purpose_removed)}
    if X509_VERIFY_PARAM_get_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_purpose)}
      X509_VERIFY_PARAM_get_purpose := _X509_VERIFY_PARAM_get_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_purpose');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_trust := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_trust_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_trust_allownil)}
    X509_VERIFY_PARAM_set_trust := ERR_X509_VERIFY_PARAM_set_trust;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_trust_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_trust_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_trust)}
      X509_VERIFY_PARAM_set_trust := FC_X509_VERIFY_PARAM_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_trust_removed)}
    if X509_VERIFY_PARAM_set_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_trust)}
      X509_VERIFY_PARAM_set_trust := _X509_VERIFY_PARAM_set_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_trust');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_depth := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_depth_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_depth_allownil)}
    X509_VERIFY_PARAM_set_depth := ERR_X509_VERIFY_PARAM_set_depth;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_depth_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_depth_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_depth)}
      X509_VERIFY_PARAM_set_depth := FC_X509_VERIFY_PARAM_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_depth_removed)}
    if X509_VERIFY_PARAM_set_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_depth)}
      X509_VERIFY_PARAM_set_depth := _X509_VERIFY_PARAM_set_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_depth');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_auth_level := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_auth_level_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_auth_level);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_auth_level_allownil)}
    X509_VERIFY_PARAM_set_auth_level := ERR_X509_VERIFY_PARAM_set_auth_level;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_auth_level_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_auth_level_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_auth_level)}
      X509_VERIFY_PARAM_set_auth_level := FC_X509_VERIFY_PARAM_set_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_auth_level_removed)}
    if X509_VERIFY_PARAM_set_auth_level_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_auth_level)}
      X509_VERIFY_PARAM_set_auth_level := _X509_VERIFY_PARAM_set_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_auth_level_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_auth_level');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_time := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_time_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_time);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_time_allownil)}
    X509_VERIFY_PARAM_get_time := ERR_X509_VERIFY_PARAM_get_time;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_time_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_time_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_time)}
      X509_VERIFY_PARAM_get_time := FC_X509_VERIFY_PARAM_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_time_removed)}
    if X509_VERIFY_PARAM_get_time_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_time)}
      X509_VERIFY_PARAM_get_time := _X509_VERIFY_PARAM_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_time_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_time');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_time := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_time_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_time);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_time_allownil)}
    X509_VERIFY_PARAM_set_time := ERR_X509_VERIFY_PARAM_set_time;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_time_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_time_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_time)}
      X509_VERIFY_PARAM_set_time := FC_X509_VERIFY_PARAM_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_time_removed)}
    if X509_VERIFY_PARAM_set_time_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_time)}
      X509_VERIFY_PARAM_set_time := _X509_VERIFY_PARAM_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_time_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_time');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_add0_policy := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_add0_policy_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add0_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_add0_policy_allownil)}
    X509_VERIFY_PARAM_add0_policy := ERR_X509_VERIFY_PARAM_add0_policy;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_policy_introduced)}
    if LibVersion < X509_VERIFY_PARAM_add0_policy_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_add0_policy)}
      X509_VERIFY_PARAM_add0_policy := FC_X509_VERIFY_PARAM_add0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_policy_removed)}
    if X509_VERIFY_PARAM_add0_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_add0_policy)}
      X509_VERIFY_PARAM_add0_policy := _X509_VERIFY_PARAM_add0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_add0_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_add0_policy');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set1_policies := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_policies_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_policies);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_policies_allownil)}
    X509_VERIFY_PARAM_set1_policies := ERR_X509_VERIFY_PARAM_set1_policies;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_policies_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_policies_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_policies)}
      X509_VERIFY_PARAM_set1_policies := FC_X509_VERIFY_PARAM_set1_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_policies_removed)}
    if X509_VERIFY_PARAM_set1_policies_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_policies)}
      X509_VERIFY_PARAM_set1_policies := _X509_VERIFY_PARAM_set1_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_policies_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_policies');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_inh_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_inh_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_inh_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_inh_flags_allownil)}
    X509_VERIFY_PARAM_set_inh_flags := ERR_X509_VERIFY_PARAM_set_inh_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_inh_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_inh_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_inh_flags)}
      X509_VERIFY_PARAM_set_inh_flags := FC_X509_VERIFY_PARAM_set_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_inh_flags_removed)}
    if X509_VERIFY_PARAM_set_inh_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_inh_flags)}
      X509_VERIFY_PARAM_set_inh_flags := _X509_VERIFY_PARAM_set_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_inh_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_inh_flags');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_inh_flags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_inh_flags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_inh_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_inh_flags_allownil)}
    X509_VERIFY_PARAM_get_inh_flags := ERR_X509_VERIFY_PARAM_get_inh_flags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_inh_flags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_inh_flags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_inh_flags)}
      X509_VERIFY_PARAM_get_inh_flags := FC_X509_VERIFY_PARAM_get_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_inh_flags_removed)}
    if X509_VERIFY_PARAM_get_inh_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_inh_flags)}
      X509_VERIFY_PARAM_get_inh_flags := _X509_VERIFY_PARAM_get_inh_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_inh_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_inh_flags');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get0_host := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_host_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_host_allownil)}
    X509_VERIFY_PARAM_get0_host := ERR_X509_VERIFY_PARAM_get0_host;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_host_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_host_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0_host)}
      X509_VERIFY_PARAM_get0_host := FC_X509_VERIFY_PARAM_get0_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_host_removed)}
    if X509_VERIFY_PARAM_get0_host_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0_host)}
      X509_VERIFY_PARAM_get0_host := _X509_VERIFY_PARAM_get0_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0_host');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set1_host := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_host_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_host_allownil)}
    X509_VERIFY_PARAM_set1_host := ERR_X509_VERIFY_PARAM_set1_host;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_host_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_host_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_host)}
      X509_VERIFY_PARAM_set1_host := FC_X509_VERIFY_PARAM_set1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_host_removed)}
    if X509_VERIFY_PARAM_set1_host_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_host)}
      X509_VERIFY_PARAM_set1_host := _X509_VERIFY_PARAM_set1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_host');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_add1_host := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_add1_host_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add1_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_add1_host_allownil)}
    X509_VERIFY_PARAM_add1_host := ERR_X509_VERIFY_PARAM_add1_host;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add1_host_introduced)}
    if LibVersion < X509_VERIFY_PARAM_add1_host_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_add1_host)}
      X509_VERIFY_PARAM_add1_host := FC_X509_VERIFY_PARAM_add1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add1_host_removed)}
    if X509_VERIFY_PARAM_add1_host_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_add1_host)}
      X509_VERIFY_PARAM_add1_host := _X509_VERIFY_PARAM_add1_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_add1_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_add1_host');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set_hostflags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set_hostflags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set_hostflags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set_hostflags_allownil)}
    X509_VERIFY_PARAM_set_hostflags := ERR_X509_VERIFY_PARAM_set_hostflags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_hostflags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set_hostflags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set_hostflags)}
      X509_VERIFY_PARAM_set_hostflags := FC_X509_VERIFY_PARAM_set_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set_hostflags_removed)}
    if X509_VERIFY_PARAM_set_hostflags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set_hostflags)}
      X509_VERIFY_PARAM_set_hostflags := _X509_VERIFY_PARAM_set_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set_hostflags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set_hostflags');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_hostflags := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_hostflags_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_hostflags);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_hostflags_allownil)}
    X509_VERIFY_PARAM_get_hostflags := ERR_X509_VERIFY_PARAM_get_hostflags;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_hostflags_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_hostflags_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_hostflags)}
      X509_VERIFY_PARAM_get_hostflags := FC_X509_VERIFY_PARAM_get_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_hostflags_removed)}
    if X509_VERIFY_PARAM_get_hostflags_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_hostflags)}
      X509_VERIFY_PARAM_get_hostflags := _X509_VERIFY_PARAM_get_hostflags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_hostflags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_hostflags');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get0_peername := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_peername_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_peername);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_peername_allownil)}
    X509_VERIFY_PARAM_get0_peername := ERR_X509_VERIFY_PARAM_get0_peername;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_peername_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_peername_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0_peername)}
      X509_VERIFY_PARAM_get0_peername := FC_X509_VERIFY_PARAM_get0_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_peername_removed)}
    if X509_VERIFY_PARAM_get0_peername_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0_peername)}
      X509_VERIFY_PARAM_get0_peername := _X509_VERIFY_PARAM_get0_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_peername_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0_peername');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_move_peername := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_move_peername_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_move_peername);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_move_peername_allownil)}
    X509_VERIFY_PARAM_move_peername := ERR_X509_VERIFY_PARAM_move_peername;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_move_peername_introduced)}
    if LibVersion < X509_VERIFY_PARAM_move_peername_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_move_peername)}
      X509_VERIFY_PARAM_move_peername := FC_X509_VERIFY_PARAM_move_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_move_peername_removed)}
    if X509_VERIFY_PARAM_move_peername_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_move_peername)}
      X509_VERIFY_PARAM_move_peername := _X509_VERIFY_PARAM_move_peername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_move_peername_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_move_peername');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get0_email := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_email_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_email_allownil)}
    X509_VERIFY_PARAM_get0_email := ERR_X509_VERIFY_PARAM_get0_email;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_email_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_email_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0_email)}
      X509_VERIFY_PARAM_get0_email := FC_X509_VERIFY_PARAM_get0_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_email_removed)}
    if X509_VERIFY_PARAM_get0_email_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0_email)}
      X509_VERIFY_PARAM_get0_email := _X509_VERIFY_PARAM_get0_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0_email');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set1_email := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_email_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_email_allownil)}
    X509_VERIFY_PARAM_set1_email := ERR_X509_VERIFY_PARAM_set1_email;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_email_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_email_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_email)}
      X509_VERIFY_PARAM_set1_email := FC_X509_VERIFY_PARAM_set1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_email_removed)}
    if X509_VERIFY_PARAM_set1_email_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_email)}
      X509_VERIFY_PARAM_set1_email := _X509_VERIFY_PARAM_set1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_email');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get1_ip_asc := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get1_ip_asc_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get1_ip_asc);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get1_ip_asc_allownil)}
    X509_VERIFY_PARAM_get1_ip_asc := ERR_X509_VERIFY_PARAM_get1_ip_asc;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get1_ip_asc_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get1_ip_asc_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get1_ip_asc)}
      X509_VERIFY_PARAM_get1_ip_asc := FC_X509_VERIFY_PARAM_get1_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get1_ip_asc_removed)}
    if X509_VERIFY_PARAM_get1_ip_asc_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get1_ip_asc)}
      X509_VERIFY_PARAM_get1_ip_asc := _X509_VERIFY_PARAM_get1_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get1_ip_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get1_ip_asc');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set1_ip := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_ip_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_ip);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_ip_allownil)}
    X509_VERIFY_PARAM_set1_ip := ERR_X509_VERIFY_PARAM_set1_ip;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_ip_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_ip)}
      X509_VERIFY_PARAM_set1_ip := FC_X509_VERIFY_PARAM_set1_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_removed)}
    if X509_VERIFY_PARAM_set1_ip_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_ip)}
      X509_VERIFY_PARAM_set1_ip := _X509_VERIFY_PARAM_set1_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_ip_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_ip');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_set1_ip_asc := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_set1_ip_asc_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_set1_ip_asc);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_set1_ip_asc_allownil)}
    X509_VERIFY_PARAM_set1_ip_asc := ERR_X509_VERIFY_PARAM_set1_ip_asc;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_asc_introduced)}
    if LibVersion < X509_VERIFY_PARAM_set1_ip_asc_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_set1_ip_asc)}
      X509_VERIFY_PARAM_set1_ip_asc := FC_X509_VERIFY_PARAM_set1_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_set1_ip_asc_removed)}
    if X509_VERIFY_PARAM_set1_ip_asc_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_set1_ip_asc)}
      X509_VERIFY_PARAM_set1_ip_asc := _X509_VERIFY_PARAM_set1_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_set1_ip_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_set1_ip_asc');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_depth := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_depth_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_depth);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_depth_allownil)}
    X509_VERIFY_PARAM_get_depth := ERR_X509_VERIFY_PARAM_get_depth;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_depth_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_depth_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_depth)}
      X509_VERIFY_PARAM_get_depth := FC_X509_VERIFY_PARAM_get_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_depth_removed)}
    if X509_VERIFY_PARAM_get_depth_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_depth)}
      X509_VERIFY_PARAM_get_depth := _X509_VERIFY_PARAM_get_depth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_depth_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_depth');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_auth_level := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_auth_level_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_auth_level);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_auth_level_allownil)}
    X509_VERIFY_PARAM_get_auth_level := ERR_X509_VERIFY_PARAM_get_auth_level;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_auth_level_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_auth_level_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_auth_level)}
      X509_VERIFY_PARAM_get_auth_level := FC_X509_VERIFY_PARAM_get_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_auth_level_removed)}
    if X509_VERIFY_PARAM_get_auth_level_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_auth_level)}
      X509_VERIFY_PARAM_get_auth_level := _X509_VERIFY_PARAM_get_auth_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_auth_level_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_auth_level');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get0_name := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_name_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_name_allownil)}
    X509_VERIFY_PARAM_get0_name := ERR_X509_VERIFY_PARAM_get0_name;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_name_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_name_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0_name)}
      X509_VERIFY_PARAM_get0_name := FC_X509_VERIFY_PARAM_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_name_removed)}
    if X509_VERIFY_PARAM_get0_name_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0_name)}
      X509_VERIFY_PARAM_get0_name := _X509_VERIFY_PARAM_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0_name');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_add0_table := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_add0_table_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_add0_table);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_add0_table_allownil)}
    X509_VERIFY_PARAM_add0_table := ERR_X509_VERIFY_PARAM_add0_table;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_table_introduced)}
    if LibVersion < X509_VERIFY_PARAM_add0_table_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_add0_table)}
      X509_VERIFY_PARAM_add0_table := FC_X509_VERIFY_PARAM_add0_table;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_add0_table_removed)}
    if X509_VERIFY_PARAM_add0_table_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_add0_table)}
      X509_VERIFY_PARAM_add0_table := _X509_VERIFY_PARAM_add0_table;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_add0_table_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_add0_table');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get_count := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get_count_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get_count_allownil)}
    X509_VERIFY_PARAM_get_count := ERR_X509_VERIFY_PARAM_get_count;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_count_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get_count_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get_count)}
      X509_VERIFY_PARAM_get_count := FC_X509_VERIFY_PARAM_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get_count_removed)}
    if X509_VERIFY_PARAM_get_count_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get_count)}
      X509_VERIFY_PARAM_get_count := _X509_VERIFY_PARAM_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get_count');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_get0 := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_get0_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_get0_allownil)}
    X509_VERIFY_PARAM_get0 := ERR_X509_VERIFY_PARAM_get0;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_introduced)}
    if LibVersion < X509_VERIFY_PARAM_get0_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_get0)}
      X509_VERIFY_PARAM_get0 := FC_X509_VERIFY_PARAM_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_get0_removed)}
    if X509_VERIFY_PARAM_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_get0)}
      X509_VERIFY_PARAM_get0 := _X509_VERIFY_PARAM_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_get0');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_lookup := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_lookup_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_lookup);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_lookup_allownil)}
    X509_VERIFY_PARAM_lookup := ERR_X509_VERIFY_PARAM_lookup;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_lookup_introduced)}
    if LibVersion < X509_VERIFY_PARAM_lookup_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_lookup)}
      X509_VERIFY_PARAM_lookup := FC_X509_VERIFY_PARAM_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_lookup_removed)}
    if X509_VERIFY_PARAM_lookup_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_lookup)}
      X509_VERIFY_PARAM_lookup := _X509_VERIFY_PARAM_lookup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_lookup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_lookup');
    {$ifend}
  end;
  
  X509_VERIFY_PARAM_table_cleanup := LoadLibFunction(ADllHandle, X509_VERIFY_PARAM_table_cleanup_procname);
  FuncLoadError := not assigned(X509_VERIFY_PARAM_table_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_VERIFY_PARAM_table_cleanup_allownil)}
    X509_VERIFY_PARAM_table_cleanup := ERR_X509_VERIFY_PARAM_table_cleanup;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_table_cleanup_introduced)}
    if LibVersion < X509_VERIFY_PARAM_table_cleanup_introduced then
    begin
      {$if declared(FC_X509_VERIFY_PARAM_table_cleanup)}
      X509_VERIFY_PARAM_table_cleanup := FC_X509_VERIFY_PARAM_table_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VERIFY_PARAM_table_cleanup_removed)}
    if X509_VERIFY_PARAM_table_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_VERIFY_PARAM_table_cleanup)}
      X509_VERIFY_PARAM_table_cleanup := _X509_VERIFY_PARAM_table_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VERIFY_PARAM_table_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VERIFY_PARAM_table_cleanup');
    {$ifend}
  end;
  
  X509_policy_check := LoadLibFunction(ADllHandle, X509_policy_check_procname);
  FuncLoadError := not assigned(X509_policy_check);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_check_allownil)}
    X509_policy_check := ERR_X509_policy_check;
    {$ifend}
    {$if declared(X509_policy_check_introduced)}
    if LibVersion < X509_policy_check_introduced then
    begin
      {$if declared(FC_X509_policy_check)}
      X509_policy_check := FC_X509_policy_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_check_removed)}
    if X509_policy_check_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_check)}
      X509_policy_check := _X509_policy_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_check_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_check');
    {$ifend}
  end;
  
  X509_policy_tree_free := LoadLibFunction(ADllHandle, X509_policy_tree_free_procname);
  FuncLoadError := not assigned(X509_policy_tree_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_free_allownil)}
    X509_policy_tree_free := ERR_X509_policy_tree_free;
    {$ifend}
    {$if declared(X509_policy_tree_free_introduced)}
    if LibVersion < X509_policy_tree_free_introduced then
    begin
      {$if declared(FC_X509_policy_tree_free)}
      X509_policy_tree_free := FC_X509_policy_tree_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_free_removed)}
    if X509_policy_tree_free_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_free)}
      X509_policy_tree_free := _X509_policy_tree_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_free');
    {$ifend}
  end;
  
  X509_policy_tree_level_count := LoadLibFunction(ADllHandle, X509_policy_tree_level_count_procname);
  FuncLoadError := not assigned(X509_policy_tree_level_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_level_count_allownil)}
    X509_policy_tree_level_count := ERR_X509_policy_tree_level_count;
    {$ifend}
    {$if declared(X509_policy_tree_level_count_introduced)}
    if LibVersion < X509_policy_tree_level_count_introduced then
    begin
      {$if declared(FC_X509_policy_tree_level_count)}
      X509_policy_tree_level_count := FC_X509_policy_tree_level_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_level_count_removed)}
    if X509_policy_tree_level_count_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_level_count)}
      X509_policy_tree_level_count := _X509_policy_tree_level_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_level_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_level_count');
    {$ifend}
  end;
  
  X509_policy_tree_get0_level := LoadLibFunction(ADllHandle, X509_policy_tree_get0_level_procname);
  FuncLoadError := not assigned(X509_policy_tree_get0_level);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_get0_level_allownil)}
    X509_policy_tree_get0_level := ERR_X509_policy_tree_get0_level;
    {$ifend}
    {$if declared(X509_policy_tree_get0_level_introduced)}
    if LibVersion < X509_policy_tree_get0_level_introduced then
    begin
      {$if declared(FC_X509_policy_tree_get0_level)}
      X509_policy_tree_get0_level := FC_X509_policy_tree_get0_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_get0_level_removed)}
    if X509_policy_tree_get0_level_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_get0_level)}
      X509_policy_tree_get0_level := _X509_policy_tree_get0_level;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_get0_level_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_get0_level');
    {$ifend}
  end;
  
  X509_policy_tree_get0_policies := LoadLibFunction(ADllHandle, X509_policy_tree_get0_policies_procname);
  FuncLoadError := not assigned(X509_policy_tree_get0_policies);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_get0_policies_allownil)}
    X509_policy_tree_get0_policies := ERR_X509_policy_tree_get0_policies;
    {$ifend}
    {$if declared(X509_policy_tree_get0_policies_introduced)}
    if LibVersion < X509_policy_tree_get0_policies_introduced then
    begin
      {$if declared(FC_X509_policy_tree_get0_policies)}
      X509_policy_tree_get0_policies := FC_X509_policy_tree_get0_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_get0_policies_removed)}
    if X509_policy_tree_get0_policies_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_get0_policies)}
      X509_policy_tree_get0_policies := _X509_policy_tree_get0_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_get0_policies_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_get0_policies');
    {$ifend}
  end;
  
  X509_policy_tree_get0_user_policies := LoadLibFunction(ADllHandle, X509_policy_tree_get0_user_policies_procname);
  FuncLoadError := not assigned(X509_policy_tree_get0_user_policies);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_tree_get0_user_policies_allownil)}
    X509_policy_tree_get0_user_policies := ERR_X509_policy_tree_get0_user_policies;
    {$ifend}
    {$if declared(X509_policy_tree_get0_user_policies_introduced)}
    if LibVersion < X509_policy_tree_get0_user_policies_introduced then
    begin
      {$if declared(FC_X509_policy_tree_get0_user_policies)}
      X509_policy_tree_get0_user_policies := FC_X509_policy_tree_get0_user_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_tree_get0_user_policies_removed)}
    if X509_policy_tree_get0_user_policies_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_tree_get0_user_policies)}
      X509_policy_tree_get0_user_policies := _X509_policy_tree_get0_user_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_tree_get0_user_policies_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_tree_get0_user_policies');
    {$ifend}
  end;
  
  X509_policy_level_node_count := LoadLibFunction(ADllHandle, X509_policy_level_node_count_procname);
  FuncLoadError := not assigned(X509_policy_level_node_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_level_node_count_allownil)}
    X509_policy_level_node_count := ERR_X509_policy_level_node_count;
    {$ifend}
    {$if declared(X509_policy_level_node_count_introduced)}
    if LibVersion < X509_policy_level_node_count_introduced then
    begin
      {$if declared(FC_X509_policy_level_node_count)}
      X509_policy_level_node_count := FC_X509_policy_level_node_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_level_node_count_removed)}
    if X509_policy_level_node_count_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_level_node_count)}
      X509_policy_level_node_count := _X509_policy_level_node_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_level_node_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_level_node_count');
    {$ifend}
  end;
  
  X509_policy_level_get0_node := LoadLibFunction(ADllHandle, X509_policy_level_get0_node_procname);
  FuncLoadError := not assigned(X509_policy_level_get0_node);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_level_get0_node_allownil)}
    X509_policy_level_get0_node := ERR_X509_policy_level_get0_node;
    {$ifend}
    {$if declared(X509_policy_level_get0_node_introduced)}
    if LibVersion < X509_policy_level_get0_node_introduced then
    begin
      {$if declared(FC_X509_policy_level_get0_node)}
      X509_policy_level_get0_node := FC_X509_policy_level_get0_node;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_level_get0_node_removed)}
    if X509_policy_level_get0_node_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_level_get0_node)}
      X509_policy_level_get0_node := _X509_policy_level_get0_node;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_level_get0_node_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_level_get0_node');
    {$ifend}
  end;
  
  X509_policy_node_get0_policy := LoadLibFunction(ADllHandle, X509_policy_node_get0_policy_procname);
  FuncLoadError := not assigned(X509_policy_node_get0_policy);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_node_get0_policy_allownil)}
    X509_policy_node_get0_policy := ERR_X509_policy_node_get0_policy;
    {$ifend}
    {$if declared(X509_policy_node_get0_policy_introduced)}
    if LibVersion < X509_policy_node_get0_policy_introduced then
    begin
      {$if declared(FC_X509_policy_node_get0_policy)}
      X509_policy_node_get0_policy := FC_X509_policy_node_get0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_node_get0_policy_removed)}
    if X509_policy_node_get0_policy_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_node_get0_policy)}
      X509_policy_node_get0_policy := _X509_policy_node_get0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_node_get0_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_node_get0_policy');
    {$ifend}
  end;
  
  X509_policy_node_get0_qualifiers := LoadLibFunction(ADllHandle, X509_policy_node_get0_qualifiers_procname);
  FuncLoadError := not assigned(X509_policy_node_get0_qualifiers);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_node_get0_qualifiers_allownil)}
    X509_policy_node_get0_qualifiers := ERR_X509_policy_node_get0_qualifiers;
    {$ifend}
    {$if declared(X509_policy_node_get0_qualifiers_introduced)}
    if LibVersion < X509_policy_node_get0_qualifiers_introduced then
    begin
      {$if declared(FC_X509_policy_node_get0_qualifiers)}
      X509_policy_node_get0_qualifiers := FC_X509_policy_node_get0_qualifiers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_node_get0_qualifiers_removed)}
    if X509_policy_node_get0_qualifiers_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_node_get0_qualifiers)}
      X509_policy_node_get0_qualifiers := _X509_policy_node_get0_qualifiers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_node_get0_qualifiers_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_node_get0_qualifiers');
    {$ifend}
  end;
  
  X509_policy_node_get0_parent := LoadLibFunction(ADllHandle, X509_policy_node_get0_parent_procname);
  FuncLoadError := not assigned(X509_policy_node_get0_parent);
  if FuncLoadError then
  begin
    {$if not defined(X509_policy_node_get0_parent_allownil)}
    X509_policy_node_get0_parent := ERR_X509_policy_node_get0_parent;
    {$ifend}
    {$if declared(X509_policy_node_get0_parent_introduced)}
    if LibVersion < X509_policy_node_get0_parent_introduced then
    begin
      {$if declared(FC_X509_policy_node_get0_parent)}
      X509_policy_node_get0_parent := FC_X509_policy_node_get0_parent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_policy_node_get0_parent_removed)}
    if X509_policy_node_get0_parent_removed <= LibVersion then
    begin
      {$if declared(_X509_policy_node_get0_parent)}
      X509_policy_node_get0_parent := _X509_policy_node_get0_parent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_policy_node_get0_parent_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_policy_node_get0_parent');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  X509_TRUST_set := nil;
  X509_TRUST_get_count := nil;
  X509_TRUST_get0 := nil;
  X509_TRUST_get_by_id := nil;
  X509_TRUST_add := nil;
  X509_TRUST_cleanup := nil;
  X509_TRUST_get_flags := nil;
  X509_TRUST_get0_name := nil;
  X509_TRUST_get_trust := nil;
  X509_trusted := nil;
  X509_add1_trust_object := nil;
  X509_add1_reject_object := nil;
  X509_trust_clear := nil;
  X509_reject_clear := nil;
  X509_get0_trust_objects := nil;
  X509_get0_reject_objects := nil;
  X509_TRUST_set_default := nil;
  X509_check_trust := nil;
  X509_verify_cert := nil;
  X509_STORE_CTX_verify := nil;
  X509_build_chain := nil;
  X509_STORE_set_depth := nil;
  X509_STORE_CTX_print_verify_cb := nil;
  X509_STORE_CTX_set_depth := nil;
  X509_OBJECT_idx_by_subject := nil;
  X509_OBJECT_retrieve_by_subject := nil;
  X509_OBJECT_retrieve_match := nil;
  X509_OBJECT_up_ref_count := nil;
  X509_OBJECT_new := nil;
  X509_OBJECT_free := nil;
  X509_OBJECT_get_type := nil;
  X509_OBJECT_get0_X509 := nil;
  X509_OBJECT_set1_X509 := nil;
  X509_OBJECT_get0_X509_CRL := nil;
  X509_OBJECT_set1_X509_CRL := nil;
  X509_STORE_new := nil;
  X509_STORE_free := nil;
  X509_STORE_lock := nil;
  X509_STORE_unlock := nil;
  X509_STORE_up_ref := nil;
  X509_STORE_get0_objects := nil;
  X509_STORE_get1_objects := nil;
  X509_STORE_get1_all_certs := nil;
  X509_STORE_CTX_get1_certs := nil;
  X509_STORE_CTX_get1_crls := nil;
  X509_STORE_set_flags := nil;
  X509_STORE_set_purpose := nil;
  X509_STORE_set_trust := nil;
  X509_STORE_set1_param := nil;
  X509_STORE_get0_param := nil;
  X509_STORE_set_verify := nil;
  X509_STORE_CTX_set_verify := nil;
  X509_STORE_get_verify := nil;
  X509_STORE_set_verify_cb := nil;
  X509_STORE_get_verify_cb := nil;
  X509_STORE_set_get_issuer := nil;
  X509_STORE_get_get_issuer := nil;
  X509_STORE_set_check_issued := nil;
  X509_STORE_get_check_issued := nil;
  X509_STORE_set_check_revocation := nil;
  X509_STORE_get_check_revocation := nil;
  X509_STORE_set_get_crl := nil;
  X509_STORE_get_get_crl := nil;
  X509_STORE_set_check_crl := nil;
  X509_STORE_get_check_crl := nil;
  X509_STORE_set_cert_crl := nil;
  X509_STORE_get_cert_crl := nil;
  X509_STORE_set_check_policy := nil;
  X509_STORE_get_check_policy := nil;
  X509_STORE_set_lookup_certs := nil;
  X509_STORE_get_lookup_certs := nil;
  X509_STORE_set_lookup_crls := nil;
  X509_STORE_get_lookup_crls := nil;
  X509_STORE_set_cleanup := nil;
  X509_STORE_get_cleanup := nil;
  X509_STORE_set_ex_data := nil;
  X509_STORE_get_ex_data := nil;
  X509_STORE_CTX_new_ex := nil;
  X509_STORE_CTX_new := nil;
  X509_STORE_CTX_get1_issuer := nil;
  X509_STORE_CTX_free := nil;
  X509_STORE_CTX_init := nil;
  X509_STORE_CTX_init_rpk := nil;
  X509_STORE_CTX_set0_trusted_stack := nil;
  X509_STORE_CTX_cleanup := nil;
  X509_STORE_CTX_get0_store := nil;
  X509_STORE_CTX_get0_cert := nil;
  X509_STORE_CTX_get0_rpk := nil;
  X509_STORE_CTX_get0_untrusted := nil;
  X509_STORE_CTX_set0_untrusted := nil;
  X509_STORE_CTX_set_verify_cb := nil;
  X509_STORE_CTX_get_verify_cb := nil;
  X509_STORE_CTX_get_verify := nil;
  X509_STORE_CTX_get_get_issuer := nil;
  X509_STORE_CTX_get_check_issued := nil;
  X509_STORE_CTX_get_check_revocation := nil;
  X509_STORE_CTX_set_get_crl := nil;
  X509_STORE_CTX_get_get_crl := nil;
  X509_STORE_CTX_get_check_crl := nil;
  X509_STORE_CTX_get_cert_crl := nil;
  X509_STORE_CTX_get_check_policy := nil;
  X509_STORE_CTX_get_lookup_certs := nil;
  X509_STORE_CTX_get_lookup_crls := nil;
  X509_STORE_CTX_get_cleanup := nil;
  X509_STORE_add_lookup := nil;
  X509_LOOKUP_hash_dir := nil;
  X509_LOOKUP_file := nil;
  X509_LOOKUP_store := nil;
  X509_LOOKUP_meth_new := nil;
  X509_LOOKUP_meth_free := nil;
  X509_LOOKUP_meth_set_new_item := nil;
  X509_LOOKUP_meth_get_new_item := nil;
  X509_LOOKUP_meth_set_free := nil;
  X509_LOOKUP_meth_get_free := nil;
  X509_LOOKUP_meth_set_init := nil;
  X509_LOOKUP_meth_get_init := nil;
  X509_LOOKUP_meth_set_shutdown := nil;
  X509_LOOKUP_meth_get_shutdown := nil;
  X509_LOOKUP_meth_set_ctrl := nil;
  X509_LOOKUP_meth_get_ctrl := nil;
  X509_LOOKUP_meth_set_get_by_subject := nil;
  X509_LOOKUP_meth_get_get_by_subject := nil;
  X509_LOOKUP_meth_set_get_by_issuer_serial := nil;
  X509_LOOKUP_meth_get_get_by_issuer_serial := nil;
  X509_LOOKUP_meth_set_get_by_fingerprint := nil;
  X509_LOOKUP_meth_get_get_by_fingerprint := nil;
  X509_LOOKUP_meth_set_get_by_alias := nil;
  X509_LOOKUP_meth_get_get_by_alias := nil;
  X509_STORE_add_cert := nil;
  X509_STORE_add_crl := nil;
  X509_STORE_CTX_get_by_subject := nil;
  X509_STORE_CTX_get_obj_by_subject := nil;
  X509_LOOKUP_ctrl := nil;
  X509_LOOKUP_ctrl_ex := nil;
  X509_load_cert_file := nil;
  X509_load_cert_file_ex := nil;
  X509_load_crl_file := nil;
  X509_load_cert_crl_file := nil;
  X509_load_cert_crl_file_ex := nil;
  X509_LOOKUP_new := nil;
  X509_LOOKUP_free := nil;
  X509_LOOKUP_init := nil;
  X509_LOOKUP_by_subject := nil;
  X509_LOOKUP_by_subject_ex := nil;
  X509_LOOKUP_by_issuer_serial := nil;
  X509_LOOKUP_by_fingerprint := nil;
  X509_LOOKUP_by_alias := nil;
  X509_LOOKUP_set_method_data := nil;
  X509_LOOKUP_get_method_data := nil;
  X509_LOOKUP_get_store := nil;
  X509_LOOKUP_shutdown := nil;
  X509_STORE_load_file := nil;
  X509_STORE_load_path := nil;
  X509_STORE_load_store := nil;
  X509_STORE_load_locations := nil;
  X509_STORE_set_default_paths := nil;
  X509_STORE_load_file_ex := nil;
  X509_STORE_load_store_ex := nil;
  X509_STORE_load_locations_ex := nil;
  X509_STORE_set_default_paths_ex := nil;
  X509_STORE_CTX_set_ex_data := nil;
  X509_STORE_CTX_get_ex_data := nil;
  X509_STORE_CTX_get_error := nil;
  X509_STORE_CTX_set_error := nil;
  X509_STORE_CTX_get_error_depth := nil;
  X509_STORE_CTX_set_error_depth := nil;
  X509_STORE_CTX_get_current_cert := nil;
  X509_STORE_CTX_set_current_cert := nil;
  X509_STORE_CTX_get0_current_issuer := nil;
  X509_STORE_CTX_get0_current_crl := nil;
  X509_STORE_CTX_get0_parent_ctx := nil;
  X509_STORE_CTX_get0_chain := nil;
  X509_STORE_CTX_get1_chain := nil;
  X509_STORE_CTX_set_cert := nil;
  X509_STORE_CTX_set0_rpk := nil;
  X509_STORE_CTX_set0_verified_chain := nil;
  X509_STORE_CTX_set0_crls := nil;
  X509_STORE_CTX_set_ocsp_resp := nil;
  X509_STORE_CTX_set_purpose := nil;
  X509_STORE_CTX_set_trust := nil;
  X509_STORE_CTX_purpose_inherit := nil;
  X509_STORE_CTX_set_flags := nil;
  X509_STORE_CTX_set_time := nil;
  X509_STORE_CTX_set_current_reasons := nil;
  X509_STORE_CTX_get0_policy_tree := nil;
  X509_STORE_CTX_get_explicit_policy := nil;
  X509_STORE_CTX_get_num_untrusted := nil;
  X509_STORE_CTX_get0_param := nil;
  X509_STORE_CTX_set0_param := nil;
  X509_STORE_CTX_set_default := nil;
  X509_STORE_CTX_set0_dane := nil;
  X509_VERIFY_PARAM_new := nil;
  X509_VERIFY_PARAM_free := nil;
  X509_VERIFY_PARAM_inherit := nil;
  X509_VERIFY_PARAM_set1 := nil;
  X509_VERIFY_PARAM_set1_name := nil;
  X509_VERIFY_PARAM_set_flags := nil;
  X509_VERIFY_PARAM_clear_flags := nil;
  X509_VERIFY_PARAM_get_flags := nil;
  X509_VERIFY_PARAM_set_purpose := nil;
  X509_VERIFY_PARAM_get_purpose := nil;
  X509_VERIFY_PARAM_set_trust := nil;
  X509_VERIFY_PARAM_set_depth := nil;
  X509_VERIFY_PARAM_set_auth_level := nil;
  X509_VERIFY_PARAM_get_time := nil;
  X509_VERIFY_PARAM_set_time := nil;
  X509_VERIFY_PARAM_add0_policy := nil;
  X509_VERIFY_PARAM_set1_policies := nil;
  X509_VERIFY_PARAM_set_inh_flags := nil;
  X509_VERIFY_PARAM_get_inh_flags := nil;
  X509_VERIFY_PARAM_get0_host := nil;
  X509_VERIFY_PARAM_set1_host := nil;
  X509_VERIFY_PARAM_add1_host := nil;
  X509_VERIFY_PARAM_set_hostflags := nil;
  X509_VERIFY_PARAM_get_hostflags := nil;
  X509_VERIFY_PARAM_get0_peername := nil;
  X509_VERIFY_PARAM_move_peername := nil;
  X509_VERIFY_PARAM_get0_email := nil;
  X509_VERIFY_PARAM_set1_email := nil;
  X509_VERIFY_PARAM_get1_ip_asc := nil;
  X509_VERIFY_PARAM_set1_ip := nil;
  X509_VERIFY_PARAM_set1_ip_asc := nil;
  X509_VERIFY_PARAM_get_depth := nil;
  X509_VERIFY_PARAM_get_auth_level := nil;
  X509_VERIFY_PARAM_get0_name := nil;
  X509_VERIFY_PARAM_add0_table := nil;
  X509_VERIFY_PARAM_get_count := nil;
  X509_VERIFY_PARAM_get0 := nil;
  X509_VERIFY_PARAM_lookup := nil;
  X509_VERIFY_PARAM_table_cleanup := nil;
  X509_policy_check := nil;
  X509_policy_tree_free := nil;
  X509_policy_tree_level_count := nil;
  X509_policy_tree_get0_level := nil;
  X509_policy_tree_get0_policies := nil;
  X509_policy_tree_get0_user_policies := nil;
  X509_policy_level_node_count := nil;
  X509_policy_level_get0_node := nil;
  X509_policy_node_get0_policy := nil;
  X509_policy_node_get0_qualifiers := nil;
  X509_policy_node_get0_parent := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.