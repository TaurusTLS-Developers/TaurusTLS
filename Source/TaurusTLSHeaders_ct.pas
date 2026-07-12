/// <exclude />
{$I TaurusTLSCompilerDefines.inc}
unit TaurusTLSHeaders_ct;

{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_sha,
  TaurusTLSHeaders_stack,
  TaurusTLSHeaders_x509;

const
//* Minimum RSA key size, from RFC6962 */
  {$EXTERNALSYM SCT_MIN_RSA_BITS}
   SCT_MIN_RSA_BITS = 2048;

//* All hashes are SHA256 in v1 of Certificate Transparency */
  {$EXTERNALSYM CT_V1_HASHLEN}
   CT_V1_HASHLEN = SHA256_DIGEST_LENGTH;

  {$EXTERNALSYM CT_F_CTLOG_NEW}
  CT_F_CTLOG_NEW                                  = 117;
  {$EXTERNALSYM CT_F_CTLOG_NEW_FROM_BASE64}
  CT_F_CTLOG_NEW_FROM_BASE64                      = 118;
  {$EXTERNALSYM CT_F_CTLOG_NEW_FROM_CONF}
  CT_F_CTLOG_NEW_FROM_CONF                        = 119;
  {$EXTERNALSYM CT_F_CTLOG_STORE_LOAD_CTX_NEW}
  CT_F_CTLOG_STORE_LOAD_CTX_NEW                   = 122;
  {$EXTERNALSYM CT_F_CTLOG_STORE_LOAD_FILE}
  CT_F_CTLOG_STORE_LOAD_FILE                      = 123;
  {$EXTERNALSYM CT_F_CTLOG_STORE_LOAD_LOG}
  CT_F_CTLOG_STORE_LOAD_LOG                       = 130;
  {$EXTERNALSYM CT_F_CTLOG_STORE_NEW}
  CT_F_CTLOG_STORE_NEW                            = 131;
  {$EXTERNALSYM CT_F_CT_BASE64_DECODE}
  CT_F_CT_BASE64_DECODE                           = 124;
  {$EXTERNALSYM CT_F_CT_POLICY_EVAL_CTX_NEW}
  CT_F_CT_POLICY_EVAL_CTX_NEW                     = 133;
  {$EXTERNALSYM CT_F_CT_V1_LOG_ID_FROM_PKEY}
  CT_F_CT_V1_LOG_ID_FROM_PKEY                     = 125;
  {$EXTERNALSYM CT_F_I2O_SCT}
  CT_F_I2O_SCT                                    = 107;
  {$EXTERNALSYM CT_F_I2O_SCT_LIST}
  CT_F_I2O_SCT_LIST                               = 108;
  {$EXTERNALSYM CT_F_I2O_SCT_SIGNATURE}
  CT_F_I2O_SCT_SIGNATURE                          = 109;
  {$EXTERNALSYM CT_F_O2I_SCT}
  CT_F_O2I_SCT                                    = 110;
  {$EXTERNALSYM CT_F_O2I_SCT_LIST}
  CT_F_O2I_SCT_LIST                               = 111;
  {$EXTERNALSYM CT_F_O2I_SCT_SIGNATURE}
  CT_F_O2I_SCT_SIGNATURE                          = 112;
  {$EXTERNALSYM CT_F_SCT_CTX_NEW}
  CT_F_SCT_CTX_NEW                                = 126;
  {$EXTERNALSYM CT_F_SCT_CTX_VERIFY}
  CT_F_SCT_CTX_VERIFY                             = 128;
  {$EXTERNALSYM CT_F_SCT_NEW}
  CT_F_SCT_NEW                                    = 100;
  {$EXTERNALSYM CT_F_SCT_NEW_FROM_BASE64}
  CT_F_SCT_NEW_FROM_BASE64                        = 127;
  {$EXTERNALSYM CT_F_SCT_SET0_LOG_ID}
  CT_F_SCT_SET0_LOG_ID                            = 101;
  {$EXTERNALSYM CT_F_SCT_SET1_EXTENSIONS}
  CT_F_SCT_SET1_EXTENSIONS                        = 114;
  {$EXTERNALSYM CT_F_SCT_SET1_LOG_ID}
  CT_F_SCT_SET1_LOG_ID                            = 115;
  {$EXTERNALSYM CT_F_SCT_SET1_SIGNATURE}
  CT_F_SCT_SET1_SIGNATURE                         = 116;
  {$EXTERNALSYM CT_F_SCT_SET_LOG_ENTRY_TYPE}
  CT_F_SCT_SET_LOG_ENTRY_TYPE                     = 102;
  {$EXTERNALSYM CT_F_SCT_SET_SIGNATURE_NID}
  CT_F_SCT_SET_SIGNATURE_NID                      = 103;
  {$EXTERNALSYM CT_F_SCT_SET_VERSION}
  CT_F_SCT_SET_VERSION                            = 104;

//* Reason codes. */
  {$EXTERNALSYM CT_R_BASE64_DECODE_ERROR}
  CT_R_BASE64_DECODE_ERROR                        = 108;
  {$EXTERNALSYM CT_R_INVALID_LOG_ID_LENGTH}
  CT_R_INVALID_LOG_ID_LENGTH                      = 100;
  {$EXTERNALSYM CT_R_LOG_CONF_INVALID}
  CT_R_LOG_CONF_INVALID                           = 109;
  {$EXTERNALSYM CT_R_LOG_CONF_INVALID_KEY}
  CT_R_LOG_CONF_INVALID_KEY                       = 110;
  {$EXTERNALSYM CT_R_LOG_CONF_MISSING_DESCRIPTION}
  CT_R_LOG_CONF_MISSING_DESCRIPTION               = 111;
  {$EXTERNALSYM CT_R_LOG_CONF_MISSING_KEY}
  CT_R_LOG_CONF_MISSING_KEY                       = 112;
  {$EXTERNALSYM CT_R_LOG_KEY_INVALID}
  CT_R_LOG_KEY_INVALID                            = 113;
  {$EXTERNALSYM CT_R_SCT_FUTURE_TIMESTAMP}
  CT_R_SCT_FUTURE_TIMESTAMP                       = 116;
  {$EXTERNALSYM CT_R_SCT_INVALID}
  CT_R_SCT_INVALID                                = 104;
  {$EXTERNALSYM CT_R_SCT_INVALID_SIGNATURE}
  CT_R_SCT_INVALID_SIGNATURE                      = 107;
  {$EXTERNALSYM CT_R_SCT_LIST_INVALID}
  CT_R_SCT_LIST_INVALID                           = 105;
  {$EXTERNALSYM CT_R_SCT_LOG_ID_MISMATCH}
  CT_R_SCT_LOG_ID_MISMATCH                        = 114;
  {$EXTERNALSYM CT_R_SCT_NOT_SET}
  CT_R_SCT_NOT_SET                                = 106;
  {$EXTERNALSYM CT_R_SCT_UNSUPPORTED_VERSION}
  CT_R_SCT_UNSUPPORTED_VERSION                    = 115;
  {$EXTERNALSYM CT_R_UNRECOGNIZED_SIGNATURE_NID}
  CT_R_UNRECOGNIZED_SIGNATURE_NID                 = 101;
  {$EXTERNALSYM CT_R_UNSUPPORTED_ENTRY_TYPE}
  CT_R_UNSUPPORTED_ENTRY_TYPE                     = 102;
  {$EXTERNALSYM CT_R_UNSUPPORTED_VERSION}
  CT_R_UNSUPPORTED_VERSION                        = 103;

type
  {$EXTERNALSYM STACK_OF_SCT}
  STACK_OF_SCT = record end;
  {$EXTERNALSYM PSTACK_OF_SCT}
  PSTACK_OF_SCT = ^STACK_OF_SCT;
  {$EXTERNALSYM PPSTACK_OF_SCT}
  PPSTACK_OF_SCT = ^PSTACK_OF_SCT;
  {$EXTERNALSYM STACK_OF_CTLOG}
  STACK_OF_CTLOG = record end;
  {$EXTERNALSYM PSTACK_OF_CTLOG}
  PSTACK_OF_CTLOG = ^STACK_OF_CTLOG;
  {$EXTERNALSYM ct_log_entry_type_t}
  ct_log_entry_type_t = (CT_LOG_ENTRY_TYPE_NOT_SET = -1,
  {$EXTERNALSYM CT_LOG_ENTRY_TYPE_X509}
    CT_LOG_ENTRY_TYPE_X509 = 0, CT_LOG_ENTRY_TYPE_PRECERT = 1);
  {$EXTERNALSYM sct_version_t}
  sct_version_t = (SCT_VERSION_NOT_SET = -1, SCT_VERSION_V1 = 0);
  {$EXTERNALSYM sct_source_t}
  sct_source_t = (SCT_SOURCE_UNKNOWN, SCT_SOURCE_TLS_EXTENSION,
    SCT_SOURCE_X509V3_EXTENSION, SCT_SOURCE_OCSP_STAPLED_RESPONSE);
  {$EXTERNALSYM sct_validation_status_t}
  sct_validation_status_t = (SCT_VALIDATION_STATUS_NOT_SET,
    SCT_VALIDATION_STATUS_UNKNOWN_LOG, SCT_VALIDATION_STATUS_VALID,
    SCT_VALIDATION_STATUS_INVALID, SCT_VALIDATION_STATUS_UNVERIFIED,
    SCT_VALIDATION_STATUS_UNKNOWN_VERSION);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

var
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_new}
  CT_POLICY_EVAL_CTX_new: function(): PCT_POLICY_EVAL_CTX; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_free}
  CT_POLICY_EVAL_CTX_free: procedure(ctx: PCT_POLICY_EVAL_CTX); cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_cert}
  CT_POLICY_EVAL_CTX_get0_cert: function(const ctx : PCT_POLICY_EVAL_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set1_cert}
  CT_POLICY_EVAL_CTX_set1_cert: function(ctx : PCT_POLICY_EVAL_CTX; cert : PX509) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_issuer}
  CT_POLICY_EVAL_CTX_get0_issuer: function(const ctx : PCT_POLICY_EVAL_CTX) : PX509; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set1_issuer}
  CT_POLICY_EVAL_CTX_set1_issuer: function(ctx : PCT_POLICY_EVAL_CTX; issuer : PX509) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_log_store}
  CT_POLICY_EVAL_CTX_get0_log_store: function(const ctx : PCT_POLICY_EVAL_CTX) : PCTLOG_STORE; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE}
  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE : procedure(ctx : PCT_POLICY_EVAL_CTX;
                                                        log_store : PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get_time}
  CT_POLICY_EVAL_CTX_get_time : function(const ctx : PCT_POLICY_EVAL_CTX) : TIdC_UINT64; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set_time}
  CT_POLICY_EVAL_CTX_set_time : procedure(ctx : PCT_POLICY_EVAL_CTX; time_in_ms : TIdC_UINT64); cdecl = nil;

  {$EXTERNALSYM SCT_new}
  SCT_new : function : PSCT; cdecl = nil;
  {$EXTERNALSYM SCT_new_from_base64}
  SCT_new_from_base64 : function(version : TIdAnsiChar;
                                 logid_base64 : PIdAnsiChar;
                                 entry_type : ct_log_entry_type_t;
                                 timestamp : TIdC_UINT64;
                                 extensions_base64,
                                 signature_base64 : PIdAnsiChar) : PSCT; cdecl = nil;
  {$EXTERNALSYM SCT_free}
  SCT_free : procedure(sct : PSCT); cdecl = nil;
  {$EXTERNALSYM SCT_LIST_free}
  SCT_LIST_free : procedure(a : PSTACK_OF_SCT); cdecl = nil;
  {$EXTERNALSYM SCT_get_version}
  SCT_get_version : function(const sct : PSCT) : sct_version_t; cdecl = nil;
  {$EXTERNALSYM SCT_set_version}
  SCT_set_version : function(sct : PSCT;  version : sct_version_t) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_get_log_entry_type}
  SCT_get_log_entry_type : function(const sct : PSCT) : ct_log_entry_type_t; cdecl = nil;
  {$EXTERNALSYM SCT_set_log_entry_type}
  SCT_set_log_entry_type : function(sct : PSCT; entry_type : ct_log_entry_type_t) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_get0_log_id}
  SCT_get0_log_id : function(const sct : PSCT; log_id : PPIdAnsiChar) : TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM SCT_set0_log_id}
  SCT_set0_log_id : function(sct : PSCT; log_id : PIdAnsiChar; log_id_len : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set1_log_id}
  SCT_set1_log_id : function(sct : PSCT; const log_id : PIdAnsiChar;
                             log_id_len : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_get_timestamp}
  SCT_get_timestamp : function(const sct : PSCT) : TIdC_UINT64; cdecl = nil;
  {$EXTERNALSYM SCT_set_timestamp}
  SCT_set_timestamp : procedure(sct : PSCT; timestamp : TIdC_UINT64); cdecl = nil;
  {$EXTERNALSYM SCT_get_signature_nid}
  SCT_get_signature_nid : function(const sct : PSCT) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set_signature_nid}
  SCT_set_signature_nid : function(sct : PSCT; nid : TIdC_INT) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_get0_extensions}
  SCT_get0_extensions : function(const sct : PSCT; ext : PPIdAnsiChar) : TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM SCT_set0_extensions}
  SCT_set0_extensions : procedure(sct : PSCT; ext : PIdAnsiChar; ext_len : TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM SCT_set1_extensions}
  SCT_set1_extensions : function(sct : PSCT; const ext : PIdAnsiChar; ext_len : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_get0_signature}
  SCT_get0_signature : function(const sct : PSCT; sig : PPIdAnsiChar) : TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM SCT_set0_signature}
  SCT_set0_signature : procedure(sct : PSCT; sig : PIdAnsiChar; sig_len : TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM SCT_set1_signature}
  SCT_set1_signature : function(sct : PSCT; const sig : PIdAnsiChar; sig_len : TIdC_SIZET) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_get_source}
  SCT_get_source : function(const sct : PSCT) : sct_source_t; cdecl = nil;
  {$EXTERNALSYM SCT_set_source}
  SCT_set_source : function(sct : PSCT; source : sct_source_t) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_validation_status_string}
  SCT_validation_status_string : function(const sct : PSCT) : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM SCT_print}
  SCT_print : procedure(const sct : PSCT; _out : PBIO; indent : TIdC_INT; const logs : PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM SCT_LIST_print}
  SCT_LIST_print : procedure(const sct_list : PSTACK_OF_SCT; _out : PBIO; indent : TIdC_INT;
                    const separator : PIdAnsiChar; const logs : PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM SCT_get_validation_status}
   SCT_get_validation_status : function(const sct : PSCT) : sct_validation_status_t; cdecl = nil;
  {$EXTERNALSYM SCT_validate}
   SCT_validate : function(sct : PSCT; const ctx : PCT_POLICY_EVAL_CTX) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_LIST_validate}
   SCT_LIST_validate : function(const scts : PSTACK_OF_SCT; ctx : PCT_POLICY_EVAL_CTX) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM i2o_SCT_LIST}
   i2o_SCT_LIST : function(const a : PSTACK_OF_SCT; pp : PPIdAnsiChar) : TIdC_INT; cdecl = nil;
   {$EXTERNALSYM o2i_SCT_LIST}
   o2i_SCT_LIST : function(a : PSTACK_OF_SCT; const pp : PIdAnsiChar;
                            len : TIdC_SIZET) : PSTACK_OF_SCT; cdecl = nil;
  {$EXTERNALSYM i2d_SCT_LIST}
   i2d_SCT_LIST : function(const a : PSTACK_OF_SCT; pp : PPIdAnsiChar) : TIdC_INT; cdecl = nil;
   {$EXTERNALSYM d2i_SCT_LIST}
   d2i_SCT_LIST : function(a : PPSTACK_OF_SCT; const pp : PPIdAnsiChar;
                      len : TIdC_LONG) : PSTACK_OF_SCT; cdecl = nil;
  {$EXTERNALSYM i2o_SCT}
   i2o_SCT : function(const sct : PSCT; _out : PPIdAnsiChar) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM o2i_SCT}
   o2i_SCT : function(psct : PPSCT; const _in : PPIdAnsiChar; len : TIdC_SIZET) : PSCT; cdecl = nil;
  {$EXTERNALSYM CTLOG_new}
   CTLOG_new : function(public_key : PEVP_PKEY; const name : PIdAnsiChar) : PCTLOG; cdecl = nil;
   {$EXTERNALSYM CTLOG_new_from_base64}
   CTLOG_new_from_base64 : function(ct_log : PPCTLOG;
                          const pkey_base64, name : PIdAnsiChar) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CTLOG_free}
   CTLOG_free : procedure(log : PCTLOG); cdecl = nil;
  {$EXTERNALSYM CTLOG_get0_name}
   CTLOG_get0_name : function(const log : PCTLOG) : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CTLOG_get0_log_id}
   CTLOG_get0_log_id : procedure(const log : PCTLOG; const log_id : PPIdAnsiChar;
                                 log_id_len : TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM CTLOG_get0_public_key}
   CTLOG_get0_public_key : function(const log : PCTLOG) : PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_new}
   CTLOG_STORE_new : function : PCTLOG_STORE; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_free}
   CTLOG_STORE_free : procedure(store : PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_get0_log_by_id}
   CTLOG_STORE_get0_log_by_id : function(const store : PCTLOG_STORE;
                                         const log_id : PIdAnsiChar;
                                         log_id_len : TIdC_SIZET) : PCTLOG; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_load_file}
   CTLOG_STORE_load_file : function(store : PCTLOG_STORE; const _file : PIdAnsiChar) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_load_default_file}
   CTLOG_STORE_load_default_file : function(store : PCTLOG_STORE) : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ERR_load_CT_strings}
   ERR_load_CT_strings : function : TIdC_INT; cdecl = nil;
{$ELSE}
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_new}
function CT_POLICY_EVAL_CTX_new(): PCT_POLICY_EVAL_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_free}
procedure CT_POLICY_EVAL_CTX_free(ctx: PCT_POLICY_EVAL_CTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_cert}
function CT_POLICY_EVAL_CTX_get0_cert(const ctx : PCT_POLICY_EVAL_CTX) : PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set1_cert}
function CT_POLICY_EVAL_CTX_set1_cert(ctx : PCT_POLICY_EVAL_CTX; cert : PX509) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_issuer}
function CT_POLICY_EVAL_CTX_get0_issuer(const ctx : PCT_POLICY_EVAL_CTX) : PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set1_issuer}
function CT_POLICY_EVAL_CTX_set1_issuer(ctx : PCT_POLICY_EVAL_CTX; issuer : PX509) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_log_store}
function CT_POLICY_EVAL_CTX_get0_log_store(const ctx : PCT_POLICY_EVAL_CTX) : PCTLOG_STORE cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE}
procedure CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx : PCT_POLICY_EVAL_CTX;
                                                    log_store : PCTLOG_STORE) cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get_time}
function CT_POLICY_EVAL_CTX_get_time(const ctx : PCT_POLICY_EVAL_CTX) : TIdC_UINT64 cdecl; external CLibCrypto;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set_time}
procedure CT_POLICY_EVAL_CTX_set_time(ctx : PCT_POLICY_EVAL_CTX; time_in_ms : TIdC_UINT64) cdecl; external CLibCrypto;

  {$EXTERNALSYM SCT_new}
function SCT_new : PSCT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_new_from_base64}
function SCT_new_from_base64(version : TIdAnsiChar;
                             logid_base64 : PIdAnsiChar;
                             entry_type : ct_log_entry_type_t;
                             timestamp : TIdC_UINT64;
                             extensions_base64,
                             signature_base64 : PIdAnsiChar) : PSCT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_free}
procedure SCT_free(sct : PSCT) cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_LIST_free}
procedure SCT_LIST_free(a : PSTACK_OF_SCT) cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get_version}
function SCT_get_version(const sct : PSCT) : sct_version_t cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set_version}
function SCT_set_version(sct : PSCT; version : sct_version_t) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get_log_entry_type}
function SCT_get_log_entry_type(const sct : PSCT) : ct_log_entry_type_t cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set_log_entry_type}
function SCT_set_log_entry_type(sct : PSCT; entry_type : ct_log_entry_type_t) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get0_log_id}
function SCT_get0_log_id(const sct : PSCT; log_id : PPIdAnsiChar) : TIdC_SIZET cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set0_log_id}
function SCT_set0_log_id(sct : PSCT; log_id : PIdAnsiChar; log_id_len : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set1_log_id}
function SCT_set1_log_id(sct : PSCT; const log_id : PIdAnsiChar;
                         log_id_len : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get_timestamp}
function SCT_get_timestamp(const sct : PSCT) : TIdC_UINT64 cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set_timestamp}
procedure SCT_set_timestamp(sct : PSCT; timestamp : TIdC_UINT64) cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get_signature_nid}
function SCT_get_signature_nid(const sct : PSCT) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set_signature_nid}
function SCT_set_signature_nid(sct : PSCT; nid : TIdC_INT) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get0_extensions}
function SCT_get0_extensions(const sct : PSCT; ext : PPIdAnsiChar) : TIdC_SIZET cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set0_extensions}
procedure SCT_set0_extensions(sct : PSCT; ext : PIdAnsiChar; ext_len : TIdC_SIZET) cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set1_extensions}
function SCT_set1_extensions(sct : PSCT; const ext : PIdAnsiChar;  ext_len : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get0_signature}
function SCT_get0_signature(const sct : PSCT; sig : PPIdAnsiChar) : TIdC_SIZET cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set0_signature}
procedure SCT_set0_signature(sct : PSCT; sig : PIdAnsiChar; sig_len : TIdC_SIZET) cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set1_signature}
function SCT_set1_signature(sct : PSCT; const sig : PIdAnsiChar; sig_len : TIdC_SIZET) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get_source}
function SCT_get_source(const sct : PSCT) : sct_source_t cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_set_source}
function SCT_set_source(sct : PSCT;  source : sct_source_t) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_validation_status_string}
function SCT_validation_status_string(const sct : PSCT) : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_print}
procedure SCT_print(const sct : PSCT; _out : PBIO; indent : TIdC_INT; const logs : PCTLOG_STORE)  cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_LIST_print}
procedure SCT_LIST_print(const sct_list : PSTACK_OF_SCT; _out : PBIO; indent : TIdC_INT;
                         separator : PIdAnsiChar; const logs : PCTLOG_STORE) cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_get_validation_status}
function SCT_get_validation_status(const sct : PSCT) : sct_validation_status_t cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_validate}
function SCT_validate(sct : PSCT; const ctx : PCT_POLICY_EVAL_CTX) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SCT_LIST_validate}
function SCT_LIST_validate(const scts : PSTACK_OF_SCT; ctx : PCT_POLICY_EVAL_CTX) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2o_SCT_LIST}
function i2o_SCT_LIST(const a : PSTACK_OF_SCT; pp : PPIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM o2i_SCT_LIST}
function o2i_SCT_LIST(a : PSTACK_OF_SCT; const pp : PIdAnsiChar;
                            len : TIdC_SIZET) : PSTACK_OF_SCT  cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_SCT_LIST}
function i2d_SCT_LIST(const a : PSTACK_OF_SCT; pp : PPIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_SCT_LIST}
function d2i_SCT_LIST(a : PPSTACK_OF_SCT; const pp : PPIdAnsiChar;
                      len : TIdC_LONG) : PSTACK_OF_SCT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2o_SCT}
function i2o_SCT(const sct : PSCT; _out : PPIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM o2i_SCT}
function o2i_SCT(psct : PPSCT; const _in : PPIdAnsiChar; len : TIdC_SIZET) : PSCT cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_new}
function CTLOG_new(public_key : PEVP_PKEY; const name : PIdAnsiChar) : PCTLOG cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_new_from_base64}
function CTLOG_new_from_base64(ct_log : PPCTLOG;
                          const pkey_base64, name : PIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_free}
procedure CTLOG_free(log : PCTLOG) cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_get0_name}
function CTLOG_get0_name(const log : PCTLOG) : PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_get0_log_id}
procedure CTLOG_get0_log_id(const log : PCTLOG; const log_id : PIdAnsiChar;
                            log_id_len : TIdC_SIZET)  cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_get0_public_key}
function CTLOG_get0_public_key(const log : PCTLOG) : PEVP_PKEY cdecl; external CLibCrypto;

  {$EXTERNALSYM CTLOG_STORE_new}
function CTLOG_STORE_new : PCTLOG_STORE cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_STORE_free}
procedure CTLOG_STORE_free(store : PCTLOG_STORE) cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_STORE_get0_log_by_id}
function CTLOG_STORE_get0_log_by_id(const store : PCTLOG_STORE;
                                    const log_id : PIdAnsiChar;
                                    log_id_len : TIdC_SIZET) : PCTLOG  cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_STORE_load_file}
function CTLOG_STORE_load_file(store : PCTLOG_STORE; const _file : PIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM CTLOG_STORE_load_default_file}
function CTLOG_STORE_load_default_file(store : PCTLOG_STORE) : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ERR_load_CT_strings}
function ERR_load_CT_strings : TIdC_INT cdecl; external CLibCrypto;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
type
  {$EXTERNALSYM Tsk_SCT_new}
  Tsk_SCT_new = function(cmp: TOPENSSL_sk_compfunc): PSTACK_OF_SCT cdecl;
  {$EXTERNALSYM Tsk_SCT_new_null}
  Tsk_SCT_new_null = function: PSTACK_OF_SCT cdecl;
  {$EXTERNALSYM Tsk_SCT_free}
  Tsk_SCT_free = procedure(st: PSTACK_OF_SCT) cdecl;
  {$EXTERNALSYM Tsk_SCT_num}
  Tsk_SCT_num = function(const sk: PSTACK_OF_SCT): TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_SCT_value}
  Tsk_SCT_value = function(const sk: PSTACK_OF_SCT; i: TIdC_INT): PSCT cdecl;
  {$EXTERNALSYM Tsk_SCT_push}
  Tsk_SCT_push = function(sk: PSTACK_OF_SCT; st: PSCT): TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_SCT_dup}
  Tsk_SCT_dup = function(sk: PSTACK_OF_SCT): PSTACK_OF_SCT cdecl;
  {$EXTERNALSYM Tsk_SCT_find}
  Tsk_SCT_find = function(sk: PSTACK_OF_SCT; _val: PSCT): TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_SCT_pop_free}
  Tsk_SCT_pop_free = procedure(sk: PSTACK_OF_SCT; func: TOPENSSL_sk_freefunc)cdecl;

  {$EXTERNALSYM Tsk_CTLOG_new}
  Tsk_CTLOG_new = function(cmp: TOPENSSL_sk_compfunc): PSTACK_OF_CTLOG cdecl;
  {$EXTERNALSYM Tsk_CTLOG_new_null}
  Tsk_CTLOG_new_null = function: PSTACK_OF_CTLOG cdecl;
  {$EXTERNALSYM Tsk_CTLOG_free}
  Tsk_CTLOG_free = procedure(st: PSTACK_OF_CTLOG) cdecl;
  {$EXTERNALSYM Tsk_CTLOG_num}
  Tsk_CTLOG_num = function(const sk: PSTACK_OF_CTLOG): TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_CTLOG_value}
  Tsk_CTLOG_value = function(const sk: PSTACK_OF_CTLOG; i: TIdC_INT): PCTLOG cdecl;
  {$EXTERNALSYM Tsk_CTLOG_push}
  Tsk_CTLOG_push = function(sk: PSTACK_OF_CTLOG; st: PCTLOG): TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_CTLOG_dup}
  Tsk_CTLOG_dup = function(sk: PSTACK_OF_CTLOG): PSTACK_OF_CTLOG cdecl;
  {$EXTERNALSYM Tsk_CTLOG_find}
  Tsk_CTLOG_find = function(sk: PSTACK_OF_CTLOG; _val: PCTLOG): TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_CTLOG_pop_free}
  Tsk_CTLOG_pop_free = procedure(sk: PSTACK_OF_CTLOG; func: TOPENSSL_sk_freefunc)cdecl;

var
  {$EXTERNALSYM sk_SCT_new}
  sk_SCT_new: Tsk_SCT_new = nil;
  {$EXTERNALSYM sk_SCT_new_null}
  sk_SCT_new_null: Tsk_SCT_new_null = nil;
  {$EXTERNALSYM sk_SCT_free}
  sk_SCT_free: Tsk_SCT_free = nil;
  {$EXTERNALSYM sk_SCT_num}
  sk_SCT_num: Tsk_SCT_num = nil;
  {$EXTERNALSYM sk_SCT_value}
  sk_SCT_value: Tsk_SCT_value = nil;
  {$EXTERNALSYM sk_SCT_push}
  sk_SCT_push: Tsk_SCT_push = nil;
  {$EXTERNALSYM sk_SCT_dup}
  sk_SCT_dup: Tsk_SCT_dup = nil;
  {$EXTERNALSYM sk_SCT_find}
  sk_SCT_find: Tsk_SCT_find = nil;
  {$EXTERNALSYM sk_SCT_pop_free}
  sk_SCT_pop_free: Tsk_SCT_pop_free = nil;

  {$EXTERNALSYM sk_CTLOG_new}
  sk_CTLOG_new: Tsk_CTLOG_new = nil;
  {$EXTERNALSYM sk_CTLOG_new_null}
  sk_CTLOG_new_null: Tsk_CTLOG_new_null = nil;
  {$EXTERNALSYM sk_CTLOG_free}
  sk_CTLOG_free: Tsk_CTLOG_free = nil;
  {$EXTERNALSYM sk_CTLOG_num}
  sk_CTLOG_num: Tsk_CTLOG_num = nil;
  {$EXTERNALSYM sk_CTLOG_value}
  sk_CTLOG_value: Tsk_CTLOG_value = nil;
  {$EXTERNALSYM sk_CTLOG_push}
  sk_CTLOG_push: Tsk_CTLOG_push = nil;
  {$EXTERNALSYM sk_CTLOG_dup}
  sk_CTLOG_dup: Tsk_CTLOG_dup = nil;
  {$EXTERNALSYM sk_CTLOG_find}
  sk_CTLOG_find: Tsk_CTLOG_find = nil;
  {$EXTERNALSYM sk_CTLOG_pop_free}
  sk_CTLOG_pop_free: Tsk_CTLOG_pop_free = nil;

{$ELSE}
  {$EXTERNALSYM sk_SCT_new}
function sk_SCT_new(cmp: TOPENSSL_sk_compfunc): PSTACK_OF_SCT cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_SCT_new_null}
function sk_SCT_new_null: PSTACK_OF_SCT cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_SCT_free}
procedure sk_SCT_free(st: PSTACK_OF_SCT)cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_SCT_num}
function sk_SCT_num(const sk: PSTACK_OF_SCT): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_SCT_value}
function sk_SCT_value(const sk: PSTACK_OF_SCT; i: TIdC_INT): PSCT cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_SCT_push}
function sk_SCT_push(sk: PSTACK_OF_SCT; st: PSCT): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_SCT_dup}
function sk_SCT_dup(sk: PSTACK_OF_SCT): PSTACK_OF_SCT cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_SCT_find}
function sk_SCT_find(sk: PSTACK_OF_SCT; _val: PSCT): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_SCT_pop_free}
procedure sk_SCT_pop_free(sk: PSTACK_OF_SCT; func: TOPENSSL_sk_freefunc)cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

  {$EXTERNALSYM sk_CTLOG_new}
function sk_CTLOG_new(cmp: TOPENSSL_sk_compfunc): PSTACK_OF_CTLOG cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_CTLOG_new_null}
function sk_CTLOG_new_null: PSTACK_OF_CTLOG cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_CTLOG_free}
procedure sk_CTLOG_free(st: PSTACK_OF_CTLOG) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_CTLOG_num}
function sk_CTLOG_num(const sk: PSTACK_OF_CTLOG): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_CTLOG_value}
function sk_CTLOG_value(const sk: PSTACK_OF_CTLOG; i: TIdC_INT): PCTLOG cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_CTLOG_push}
function sk_CTLOG_push(sk: PSTACK_OF_CTLOG; st: PCTLOG): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_CTLOG_dup}
function sk_CTLOG_dup(sk: PSTACK_OF_CTLOG): PSTACK_OF_CTLOG cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_CTLOG_find}
function sk_CTLOG_find(sk: PSTACK_OF_CTLOG; _val: PCTLOG): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_CTLOG_pop_free}
procedure sk_CTLOG_pop_free(sk: PSTACK_OF_CTLOG; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
{$ENDIF}

implementation

uses
  classes,
  TaurusTLSExceptionHandlers
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    , TaurusTLSLoader
{$ENDIF};

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

const
  CT_POLICY_EVAL_CTX_new_procname = 'CT_POLICY_EVAL_CTX_new';
  CT_POLICY_EVAL_CTX_free_procname = 'CT_POLICY_EVAL_CTX_free';
  CT_POLICY_EVAL_CTX_get0_cert_procname = 'CT_POLICY_EVAL_CTX_get0_cert';
  CT_POLICY_EVAL_CTX_set1_cert_procname = 'CT_POLICY_EVAL_CTX_set1_cert';
  CT_POLICY_EVAL_CTX_get0_issuer_procname = 'CT_POLICY_EVAL_CTX_get0_issuer';
  CT_POLICY_EVAL_CTX_set1_issuer_procname = 'CT_POLICY_EVAL_CTX_set1_issuer';
  CT_POLICY_EVAL_CTX_get0_log_store_procname = 'CT_POLICY_EVAL_CTX_get0_log_store';
  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_procname = 'CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE';
  CT_POLICY_EVAL_CTX_get_time_procname = 'CT_POLICY_EVAL_CTX_get_time';
  CT_POLICY_EVAL_CTX_set_time_procname = 'CT_POLICY_EVAL_CTX_set_time';

  SCT_new_procname = 'SCT_new';
  SCT_new_from_base64_procname = 'SCT_new_from_base64';
  SCT_free_procname = 'SCT_free';
  SCT_LIST_free_procname = 'SCT_LIST_free';
  SCT_get_version_procname = 'SCT_get_version';
  SCT_set_version_procname = 'SCT_set_version';
  SCT_get_log_entry_type_procname = 'SCT_get_log_entry_type';
  SCT_set_log_entry_type_procname = 'SCT_set_log_entry_type';
  SCT_get0_log_id_procname = 'SCT_get0_log_id';
  SCT_set0_log_id_procname = 'SCT_set0_log_id';
  SCT_set1_log_id_procname = 'SCT_set1_log_id';
  SCT_get_timestamp_procname = 'SCT_get_timestamp';
  SCT_set_timestamp_procname = 'SCT_set_timestamp';
  SCT_get_signature_nid_procname = 'SCT_get_signature_nid';
  SCT_set_signature_nid_procname = 'SCT_set_signature_nid';
  SCT_get0_extensions_procname = 'SCT_get0_extensions';
  SCT_set0_extensions_procname = 'SCT_set0_extensions';
  SCT_set1_extensions_procname = 'SCT_set1_extensions';
  SCT_get0_signature_procname = 'SCT_get0_signature';
  SCT_set0_signature_procname = 'SCT_set0_signature';
  SCT_set1_signature_procname = 'SCT_set1_signature';
  SCT_get_source_procname = 'SCT_get_source';
  SCT_set_source_procname = 'SCT_set_source';
  SCT_validation_status_string_procname = 'SCT_validation_status_string';
  SCT_print_procname = 'SCT_print';
  SCT_LIST_print_procname = 'SCT_LIST_print';
  SCT_get_validation_status_procname = 'SCT_get_validation_status';
  SCT_validate_procname = 'SCT_validate';
  SCT_LIST_validate_procname = 'SCT_LIST_validate';

  i2o_SCT_LIST_procname = 'i2o_SCT_LIST';
  o2i_SCT_LIST_procname = 'o2i_SCT_LIST';
  i2d_SCT_LIST_procname = 'i2d_SCT_LIST';
  d2i_SCT_LIST_procname = 'd2i_SCT_LIST';
  i2o_SCT_procname = 'i2o_SCT';
  o2i_SCT_procname = 'o2i_SCT';

  CTLOG_new_procname = 'CTLOG_new';
  CTLOG_new_from_base64_procname = 'CTLOG_new_from_base64';
  CTLOG_free_procname = 'CTLOG_free';
  CTLOG_get0_name_procname = 'CTLOG_get0_name';
  CTLOG_get0_log_id_procname = 'CTLOG_get0_log_id';
  CTLOG_get0_public_key_procname = 'CTLOG_get0_public_key';

  CTLOG_STORE_new_procname = 'CTLOG_STORE_new';
  CTLOG_STORE_free_procname = 'CTLOG_STORE_free';
  CTLOG_STORE_get0_log_by_id_procname = 'CTLOG_STORE_get0_log_by_id';
  CTLOG_STORE_load_file_procname = 'CTLOG_STORE_load_file';
  CTLOG_STORE_load_default_file_procname = 'CTLOG_STORE_load_default_file';

  ERR_load_CT_strings_procname = 'ERR_load_CT_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}

function ERR_CT_POLICY_EVAL_CTX_new(): PCT_POLICY_EVAL_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (CT_POLICY_EVAL_CTX_new_procname);
end;

procedure ERR_CT_POLICY_EVAL_CTX_free(ctx: PCT_POLICY_EVAL_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (CT_POLICY_EVAL_CTX_free_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get0_cert(const ctx : PCT_POLICY_EVAL_CTX): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get0_cert_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_set1_cert(ctx : PCT_POLICY_EVAL_CTX; cert : PX509) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set1_cert_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get0_issuer(const ctx : PCT_POLICY_EVAL_CTX) : PX509; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get0_issuer_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_set1_issuer(ctx : PCT_POLICY_EVAL_CTX; issuer : PX509) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set1_issuer_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get0_log_store(const ctx : PCT_POLICY_EVAL_CTX) : PCTLOG_STORE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get0_log_store_procname);
end;

procedure ERR_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx : PCT_POLICY_EVAL_CTX;
                                                    log_store : PCTLOG_STORE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get_time(const ctx : PCT_POLICY_EVAL_CTX) : TIdC_UINT64; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get_time_procname);
end;

procedure ERR_CT_POLICY_EVAL_CTX_set_time(ctx : PCT_POLICY_EVAL_CTX; time_in_ms : TIdC_UINT64); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set_time_procname);
end;

function ERR_SCT_new : PSCT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_new_procname);
end;

function ERR_SCT_new_from_base64(version : TIdAnsiChar;
                             logid_base64 : PIdAnsiChar;
                             entry_type : ct_log_entry_type_t;
                             timestamp : TIdC_UINT64;
                             extensions_base64,
                             signature_base64 : PIdAnsiChar) : PSCT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_new_from_base64_procname);
end;

procedure ERR_SCT_free(sct : PSCT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_free_procname);
end;

procedure ERR_SCT_LIST_free(a : PSTACK_OF_SCT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_LIST_free_procname );
end;

function ERR_SCT_get_version(const sct : PSCT) : sct_version_t; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_version_procname);
end;

function ERR_SCT_set_version(sct : PSCT; version : sct_version_t) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_version_procname);
end;

function ERR_SCT_get_log_entry_type(const sct : PSCT) : ct_log_entry_type_t; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_log_entry_type_procname);
end;

function ERR_SCT_set_log_entry_type(sct : PSCT; entry_type : ct_log_entry_type_t) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_log_entry_type_procname);
end;

function ERR_SCT_get0_log_id(const sct : PSCT; log_id : PPIdAnsiChar) : TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get0_log_id_procname);
end;

function ERR_SCT_set0_log_id(sct : PSCT; log_id : PIdAnsiChar; log_id_len : TIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set0_log_id_procname);
end;

function ERR_SCT_set1_log_id(sct : PSCT; const log_id : PIdAnsiChar;
                         log_id_len : TIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set1_log_id_procname);
end;

function ERR_SCT_get_timestamp(const sct : PSCT) : TIdC_UINT64; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_get_timestamp_procname);
end;

procedure ERR_SCT_set_timestamp(sct : PSCT; timestamp : TIdC_UINT64); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_set_timestamp_procname);
end;

function ERR_SCT_get_signature_nid(const sct : PSCT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_get_signature_nid_procname);
end;

function ERR_SCT_set_signature_nid(sct : PSCT; nid : TIdC_INT) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_signature_nid_procname);
end;

function ERR_SCT_get0_extensions(const sct : PSCT; ext : PPIdAnsiChar) : TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_get0_extensions_procname);
end;

procedure ERR_SCT_set0_extensions(sct : PSCT; ext : PIdAnsiChar; ext_len : TIdC_SIZET); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_set0_extensions_procname);
end;

function ERR_SCT_set1_extensions(sct : PSCT; const ext : PIdAnsiChar;  ext_len : TIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set1_extensions_procname);
end;

function ERR_SCT_get0_signature(const sct : PSCT; sig : PPIdAnsiChar) : TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_get0_signature_procname);
end;

procedure ERR_SCT_set0_signature(sct : PSCT; sig : PIdAnsiChar; sig_len : TIdC_SIZET); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_set0_signature_procname);
end;

function ERR_SCT_set1_signature(sct : PSCT; const sig : PIdAnsiChar; sig_len : TIdC_SIZET) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_set1_signature_procname);
end;

function ERR_SCT_get_source(const sct : PSCT) : sct_source_t; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_source_procname);
end;

function ERR_SCT_set_source(sct : PSCT;  source : sct_source_t) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_source_procname);
end;

function ERR_SCT_validation_status_string(const sct : PSCT) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_validation_status_string_procname);
end;

procedure ERR_SCT_print(const sct : PSCT; _out : PBIO; indent : TIdC_INT; const logs : PCTLOG_STORE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_print_procname );
end;

procedure ERR_SCT_LIST_print(const sct_list : PSTACK_OF_SCT; _out : PBIO; indent : TIdC_INT;
                    const separator : PIdAnsiChar; const logs : PCTLOG_STORE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_LIST_print_procname);
end;

function ERR_SCT_get_validation_status(const sct : PSCT) : sct_validation_status_t; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_validation_status_procname);
end;

function ERR_SCT_validate(sct : PSCT; const ctx : PCT_POLICY_EVAL_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_validate_procname);
end;

function ERR_SCT_LIST_validate(const scts : PSTACK_OF_SCT; ctx : PCT_POLICY_EVAL_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SCT_LIST_validate_procname);
end;

function ERR_i2o_SCT_LIST(const a : PSTACK_OF_SCT; pp : PPIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2o_SCT_LIST_procname);
end;

function ERR_o2i_SCT_LIST(a : PSTACK_OF_SCT; const pp : PIdAnsiChar;
                            len : TIdC_SIZET) : PSTACK_OF_SCT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(o2i_SCT_LIST_procname);
end;

function ERR_i2d_SCT_LIST(const a : PSTACK_OF_SCT; pp : PPIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_SCT_LIST_procname);
end;

function ERR_d2i_SCT_LIST(a : PPSTACK_OF_SCT; const pp : PPIdAnsiChar;
                      len : TIdC_LONG) : PSTACK_OF_SCT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( d2i_SCT_LIST_procname);
end;

function ERR_i2o_SCT(const sct : PSCT; _out : PPIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( i2o_SCT_procname);
end;

function ERR_o2i_SCT(psct : PPSCT; const _in : PPIdAnsiChar; len : TIdC_SIZET) : PSCT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(o2i_SCT_procname);
end;

function ERR_CTLOG_new(public_key : PEVP_PKEY; const name : PIdAnsiChar) : PCTLOG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_new_procname);
end;

function ERR_CTLOG_new_from_base64(ct_log : PPCTLOG;
                          const pkey_base64, name : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_new_from_base64_procname);
end;

procedure ERR_CTLOG_free(log : PCTLOG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_free_procname);
end;

function ERR_CTLOG_get0_name(const log : PCTLOG) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_get0_name_procname);
end;

procedure ERR_CTLOG_get0_log_id(const log : PCTLOG; const log_id : PPIdAnsiChar;
                            log_id_len : TIdC_SIZET); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_get0_log_id_procname);
end;

function ERR_CTLOG_get0_public_key(const log : PCTLOG) : PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_get0_public_key_procname);
end;

function ERR_CTLOG_STORE_new : PCTLOG_STORE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( CTLOG_STORE_new_procname);
end;

procedure ERR_CTLOG_STORE_free(store : PCTLOG_STORE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( CTLOG_STORE_free_procname);
end;

function ERR_CTLOG_STORE_get0_log_by_id(const store : PCTLOG_STORE;
                                    const log_id : PIdAnsiChar;
                                    log_id_len : TIdC_SIZET) : PCTLOG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( CTLOG_STORE_get0_log_by_id_procname);
end;

function ERR_CTLOG_STORE_load_file(store : PCTLOG_STORE; const _file : PIdAnsiChar) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( CTLOG_STORE_load_file_procname);
end;

function ERR_CTLOG_STORE_load_default_file(store : PCTLOG_STORE) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_STORE_load_default_file_procname);
end;

function ERR_ERR_load_CT_strings : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_CT_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc}

  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: boolean;

begin
  CT_POLICY_EVAL_CTX_new := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_new_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_new);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_new_allownil)}
    CT_POLICY_EVAL_CTX_new := ERR_CT_POLICY_EVAL_CTX_new;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_new_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_new_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_new)}
      CT_POLICY_EVAL_CTX_new := FC_CT_POLICY_EVAL_CTX_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_new_removed)}
    if CT_POLICY_EVAL_CTX_new_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_new)}
      CT_POLICY_EVAL_CTX_new := _CT_POLICY_EVAL_CTX_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_new');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_free := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_free_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_free);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_free_allownil)}
    CT_POLICY_EVAL_CTX_free := ERR_CT_POLICY_EVAL_CTX_free;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_free_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_free_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_free)}
      CT_POLICY_EVAL_CTX_free := FC_CT_POLICY_EVAL_CTX_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_free_removed)}
    if CT_POLICY_EVAL_CTX_free_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_free)}
      CT_POLICY_EVAL_CTX_free := _CT_POLICY_EVAL_CTX_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_free');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_get0_cert := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_get0_cert_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_get0_cert);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_get0_cert_allownil)}
    CT_POLICY_EVAL_CTX_get0_cert := ERR_CT_POLICY_EVAL_CTX_get0_cert;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_get0_cert_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get0_cert_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_get0_cert)}
      CT_POLICY_EVAL_CTX_get0_cert := FC_CT_POLICY_EVAL_CTX_get0_cert;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_get0_cert_removed)}
    if CT_POLICY_EVAL_CTX_get0_cert_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_get0_cert)}
      CT_POLICY_EVAL_CTX_get0_cert := _CT_POLICY_EVAL_CTX_get0_cert;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_get0_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get0_cert');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_set1_cert := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_set1_cert_procname);
  FuncLoadError := not Assigned(CT_POLICY_EVAL_CTX_set1_cert);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_set1_cert_allownil)}
    CT_POLICY_EVAL_CTX_set1_cert := ERR_CT_POLICY_EVAL_CTX_set1_cert;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_set1_cert_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set1_cert_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_set1_cert)}
      CT_POLICY_EVAL_CTX_set1_cert := FC_CT_POLICY_EVAL_CTX_set1_cert;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_set1_cert_removed)}
    if CT_POLICY_EVAL_CTX_set1_cert_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_set1_cert)}
      CT_POLICY_EVAL_CTX_set1_cert := _CT_POLICY_EVAL_CTX_set1_cert;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_set1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set1_cert');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_get0_issuer := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_get0_issuer_procname);
  FuncLoadError := not Assigned(CT_POLICY_EVAL_CTX_get0_issuer);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_get0_issuer_allownil)}
    CT_POLICY_EVAL_CTX_get0_issuer := ERR_CT_POLICY_EVAL_CTX_get0_issuer;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_get0_issuer_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get0_issuer_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_get0_issuer)}
      CT_POLICY_EVAL_CTX_get0_issuer := FC_CT_POLICY_EVAL_CTX_get0_issuer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_get0_issuer_removed)}
    if CT_POLICY_EVAL_CTX_get0_issuer_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_get0_issuer)}
      CT_POLICY_EVAL_CTX_get0_issuer := _CT_POLICY_EVAL_CTX_get0_issuer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_get0_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get0_issuer');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_set1_issuer := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_set1_issuer_procname);
  FuncLoadError := not Assigned(CT_POLICY_EVAL_CTX_set1_issuer);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_set1_issuer_allownil)}
    CT_POLICY_EVAL_CTX_set1_issuer := ERR_CT_POLICY_EVAL_CTX_set1_issuer;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_set1_issuer_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set1_issuer_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_set1_issuer)}
      CT_POLICY_EVAL_CTX_set1_issuer := FC_CT_POLICY_EVAL_CTX_set1_issuer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_set1_issuer_removed)}
    if CT_POLICY_EVAL_CTX_set1_issuer_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_set1_issuer)}
      CT_POLICY_EVAL_CTX_set1_issuer := _CT_POLICY_EVAL_CTX_set1_issuer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_set1_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set1_issuer');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_get0_log_store := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_get0_log_store_procname);
  FuncLoadError := not Assigned(CT_POLICY_EVAL_CTX_get0_log_store);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_get0_log_store_allownil)}
    CT_POLICY_EVAL_CTX_get0_log_store := ERR_CT_POLICY_EVAL_CTX_get0_log_store;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_get0_log_store_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get0_log_store_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_get0_log_store)}
      CT_POLICY_EVAL_CTX_get0_log_store := FC_CT_POLICY_EVAL_CTX_get0_log_store;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_get0_log_store_removed)}
    if CT_POLICY_EVAL_CTX_get0_log_store_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_get0_log_store)}
      CT_POLICY_EVAL_CTX_get0_log_store := _CT_POLICY_EVAL_CTX_get0_log_store;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_get0_log_store_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get0_log_store');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := LoadLibFunction(ADllHandle,
    CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_procname);
  FuncLoadError := not Assigned(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE);
  if FuncLoadError then
  begin
{$IF not defined(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_allownil)}
    CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := ERR_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_introduced then
    begin
{$IF declared(FC_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE)}
      CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := FC_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_removed)}
    if CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_removed <= LibVersion then
    begin
{$IF declared(_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE)}
      CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := _CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE');
{$IFEND}
  end;

  CT_POLICY_EVAL_CTX_get_time := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_get_time_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_get_time);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_get_time_allownil)}
    CT_POLICY_EVAL_CTX_get_time := ERR_CT_POLICY_EVAL_CTX_get_time;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get_time_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get_time_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_get_time)}
      CT_POLICY_EVAL_CTX_get_time := FC_CT_POLICY_EVAL_CTX_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get_time_removed)}
    if CT_POLICY_EVAL_CTX_get_time_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_get_time)}
      CT_POLICY_EVAL_CTX_get_time := _CT_POLICY_EVAL_CTX_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_get_time_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get_time');
    {$ifend}
  end;

  CT_POLICY_EVAL_CTX_set_time := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_set_time_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_set_time);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_set_time_allownil)}
    CT_POLICY_EVAL_CTX_set_time := ERR_CT_POLICY_EVAL_CTX_set_time;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set_time_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set_time_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_set_time)}
      CT_POLICY_EVAL_CTX_set_time := FC_CT_POLICY_EVAL_CTX_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set_time_removed)}
    if CT_POLICY_EVAL_CTX_set_time_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_set_time)}
      CT_POLICY_EVAL_CTX_set_time := _CT_POLICY_EVAL_CTX_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_set_time_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set_time');
    {$ifend}
  end;

  SCT_new := LoadLibFunction(ADllHandle, SCT_new_procname);
  FuncLoadError := not assigned(SCT_new);
  if FuncLoadError then
  begin
    {$if not defined(SCT_new_allownil)}
    SCT_new := ERR_SCT_new;
    {$ifend}
    {$if declared(SCT_new_introduced)}
    if LibVersion < SCT_new_introduced then
    begin
      {$if declared(FC_SCT_new)}
      SCT_new := FC_SCT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_new_removed)}
    if SCT_new_removed <= LibVersion then
    begin
      {$if declared(_SCT_new)}
      SCT_new := _SCT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_new');
    {$ifend}
  end;

  SCT_new_from_base64 := LoadLibFunction(ADllHandle, SCT_new_from_base64_procname);
  FuncLoadError := not assigned(SCT_new_from_base64);
  if FuncLoadError then
  begin
    {$if not defined(SCT_new_from_base64_allownil)}
    SCT_new_from_base64 := ERR_SCT_new_from_base64;
    {$ifend}
    {$if declared(SCT_new_from_base64_introduced)}
    if LibVersion < SCT_new_from_base64_introduced then
    begin
      {$if declared(FC_SCT_new_from_base64)}
      SCT_new_from_base64 := FC_SCT_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_new_from_base64_removed)}
    if SCT_new_from_base64_removed <= LibVersion then
    begin
      {$if declared(_SCT_new_from_base64)}
      SCT_new_from_base64 := _SCT_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_new_from_base64_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_new_from_base64');
    {$ifend}
  end;

  SCT_free := LoadLibFunction(ADllHandle, SCT_free_procname);
  FuncLoadError := not assigned(SCT_free);
  if FuncLoadError then
  begin
    {$if not defined(SCT_free_allownil)}
    SCT_free := ERR_SCT_free;
    {$ifend}
    {$if declared(SCT_free_introduced)}
    if LibVersion < SCT_free_introduced then
    begin
      {$if declared(FC_SCT_free)}
      SCT_free := FC_SCT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_free_removed)}
    if SCT_free_removed <= LibVersion then
    begin
      {$if declared(_SCT_free)}
      SCT_free := _SCT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_free');
    {$ifend}
  end;

  SCT_LIST_free := LoadLibFunction(ADllHandle, SCT_LIST_free_procname);
  FuncLoadError := not assigned(SCT_LIST_free);
  if FuncLoadError then
  begin
    {$if not defined(SCT_LIST_free_allownil)}
    SCT_LIST_free := ERR_SCT_LIST_free;
    {$ifend}
    {$if declared(SCT_LIST_free_introduced)}
    if LibVersion < SCT_LIST_free_introduced then
    begin
      {$if declared(FC_SCT_LIST_free)}
      SCT_LIST_free := FC_SCT_LIST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_LIST_free_removed)}
    if SCT_LIST_free_removed <= LibVersion then
    begin
      {$if declared(_SCT_LIST_free)}
      SCT_LIST_free := _SCT_LIST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_LIST_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_LIST_free');
    {$ifend}
  end;

  SCT_get_version := LoadLibFunction(ADllHandle, SCT_get_version_procname);
  FuncLoadError := not assigned(SCT_get_version);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_version_allownil)}
    SCT_get_version := ERR_SCT_get_version;
    {$ifend}
    {$if declared(SCT_get_version_introduced)}
    if LibVersion < SCT_get_version_introduced then
    begin
      {$if declared(FC_SCT_get_version)}
      SCT_get_version := FC_SCT_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_version_removed)}
    if SCT_get_version_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_version)}
      SCT_get_version := _SCT_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_version');
    {$ifend}
  end;

  SCT_set_version := LoadLibFunction(ADllHandle, SCT_set_version_procname);
  FuncLoadError := not assigned(SCT_set_version);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_version_allownil)}
    SCT_set_version := ERR_SCT_set_version;
    {$ifend}
    {$if declared(SCT_set_version_introduced)}
    if LibVersion < SCT_set_version_introduced then
    begin
      {$if declared(FC_SCT_set_version)}
      SCT_set_version := FC_SCT_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_version_removed)}
    if SCT_set_version_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_version)}
      SCT_set_version := _SCT_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_version');
    {$ifend}
  end;

  SCT_get_log_entry_type := LoadLibFunction(ADllHandle, SCT_get_log_entry_type_procname);
  FuncLoadError := not assigned(SCT_get_log_entry_type);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_log_entry_type_allownil)}
    SCT_get_log_entry_type := ERR_SCT_get_log_entry_type;
    {$ifend}
    {$if declared(SCT_get_log_entry_type_introduced)}
    if LibVersion < SCT_get_log_entry_type_introduced then
    begin
      {$if declared(FC_SCT_get_log_entry_type)}
      SCT_get_log_entry_type := FC_SCT_get_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_log_entry_type_removed)}
    if SCT_get_log_entry_type_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_log_entry_type)}
      SCT_get_log_entry_type := _SCT_get_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_log_entry_type_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_log_entry_type');
    {$ifend}
  end;

  SCT_set_log_entry_type := LoadLibFunction(ADllHandle, SCT_set_log_entry_type_procname);
  FuncLoadError := not assigned(SCT_set_log_entry_type);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_log_entry_type_allownil)}
    SCT_set_log_entry_type := ERR_SCT_set_log_entry_type;
    {$ifend}
    {$if declared(SCT_set_log_entry_type_introduced)}
    if LibVersion < SCT_set_log_entry_type_introduced then
    begin
      {$if declared(FC_SCT_set_log_entry_type)}
      SCT_set_log_entry_type := FC_SCT_set_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_log_entry_type_removed)}
    if SCT_set_log_entry_type_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_log_entry_type)}
      SCT_set_log_entry_type := _SCT_set_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_log_entry_type_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_log_entry_type');
    {$ifend}
  end;

  SCT_get0_log_id := LoadLibFunction(ADllHandle, SCT_get0_log_id_procname);
  FuncLoadError := not assigned(SCT_get0_log_id);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get0_log_id_allownil)}
    SCT_get0_log_id := ERR_SCT_get0_log_id;
    {$ifend}
    {$if declared(SCT_get0_log_id_introduced)}
    if LibVersion < SCT_get0_log_id_introduced then
    begin
      {$if declared(FC_SCT_get0_log_id)}
      SCT_get0_log_id := FC_SCT_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get0_log_id_removed)}
    if SCT_get0_log_id_removed <= LibVersion then
    begin
      {$if declared(_SCT_get0_log_id)}
      SCT_get0_log_id := _SCT_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get0_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get0_log_id');
    {$ifend}
  end;

  SCT_set0_log_id := LoadLibFunction(ADllHandle, SCT_set0_log_id_procname);
  FuncLoadError := not assigned(SCT_set0_log_id);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set0_log_id_allownil)}
    SCT_set0_log_id := ERR_SCT_set0_log_id;
    {$ifend}
    {$if declared(SCT_set0_log_id_introduced)}
    if LibVersion < SCT_set0_log_id_introduced then
    begin
      {$if declared(FC_SCT_set0_log_id)}
      SCT_set0_log_id := FC_SCT_set0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set0_log_id_removed)}
    if SCT_set0_log_id_removed <= LibVersion then
    begin
      {$if declared(_SCT_set0_log_id)}
      SCT_set0_log_id := _SCT_set0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set0_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set0_log_id');
    {$ifend}
  end;

  SCT_set1_log_id := LoadLibFunction(ADllHandle, SCT_set1_log_id_procname);
  FuncLoadError := not assigned(SCT_set1_log_id);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set1_log_id_allownil)}
    SCT_set1_log_id := ERR_SCT_set1_log_id;
    {$ifend}
    {$if declared(SCT_set1_log_id_introduced)}
    if LibVersion < SCT_set1_log_id_introduced then
    begin
      {$if declared(FC_SCT_set1_log_id)}
      SCT_set1_log_id := FC_SCT_set1_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set1_log_id_removed)}
    if SCT_set1_log_id_removed <= LibVersion then
    begin
      {$if declared(_SCT_set1_log_id)}
      SCT_set1_log_id := _SCT_set1_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set1_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set1_log_id');
    {$ifend}
  end;
  SCT_get_timestamp := LoadLibFunction(ADllHandle, SCT_get_timestamp_procname);
  FuncLoadError := not assigned(SCT_get_timestamp);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_timestamp_allownil)}
    SCT_get_timestamp := ERR_SCT_get_timestamp;
    {$ifend}
    {$if declared(SCT_get_timestamp_introduced)}
    if LibVersion < SCT_get_timestamp_introduced then
    begin
      {$if declared(FC_SCT_get_timestamp)}
      SCT_get_timestamp := FC_SCT_get_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_timestamp_removed)}
    if SCT_get_timestamp_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_timestamp)}
      SCT_get_timestamp := _SCT_get_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_timestamp_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_timestamp');
    {$ifend}
  end;

  SCT_set_timestamp := LoadLibFunction(ADllHandle, SCT_set_timestamp_procname);
  FuncLoadError := not assigned(SCT_set_timestamp);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_timestamp_allownil)}
    SCT_set_timestamp := ERR_SCT_set_timestamp;
    {$ifend}
    {$if declared(SCT_set_timestamp_introduced)}
    if LibVersion < SCT_set_timestamp_introduced then
    begin
      {$if declared(FC_SCT_set_timestamp)}
      SCT_set_timestamp := FC_SCT_set_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_timestamp_removed)}
    if SCT_set_timestamp_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_timestamp)}
      SCT_set_timestamp := _SCT_set_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_timestamp_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_timestamp');
    {$ifend}
  end;

  SCT_get_signature_nid := LoadLibFunction(ADllHandle, SCT_get_signature_nid_procname);
  FuncLoadError := not assigned(SCT_get_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_signature_nid_allownil)}
    SCT_get_signature_nid := ERR_SCT_get_signature_nid;
    {$ifend}
    {$if declared(SCT_get_signature_nid_introduced)}
    if LibVersion < SCT_get_signature_nid_introduced then
    begin
      {$if declared(FC_SCT_get_signature_nid)}
      SCT_get_signature_nid := FC_SCT_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_signature_nid_removed)}
    if SCT_get_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_signature_nid)}
      SCT_get_signature_nid := _SCT_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_signature_nid');
    {$ifend}
  end;

  SCT_set_signature_nid := LoadLibFunction(ADllHandle, SCT_set_signature_nid_procname);
  FuncLoadError := not assigned(SCT_set_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_signature_nid_allownil)}
    SCT_set_signature_nid := ERR_SCT_set_signature_nid;
    {$ifend}
    {$if declared(SCT_set_signature_nid_introduced)}
    if LibVersion < SCT_set_signature_nid_introduced then
    begin
      {$if declared(FC_SCT_set_signature_nid)}
      SCT_set_signature_nid := FC_SCT_set_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_signature_nid_removed)}
    if SCT_set_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_signature_nid)}
      SCT_set_signature_nid := _SCT_set_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_signature_nid');
    {$ifend}
  end;

  SCT_get0_extensions := LoadLibFunction(ADllHandle, SCT_get0_extensions_procname);
  FuncLoadError := not assigned(SCT_get0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get0_extensions_allownil)}
    SCT_get0_extensions := ERR_SCT_get0_extensions;
    {$ifend}
    {$if declared(SCT_get0_extensions_introduced)}
    if LibVersion < SCT_get0_extensions_introduced then
    begin
      {$if declared(FC_SCT_get0_extensions)}
      SCT_get0_extensions := FC_SCT_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get0_extensions_removed)}
    if SCT_get0_extensions_removed <= LibVersion then
    begin
      {$if declared(_SCT_get0_extensions)}
      SCT_get0_extensions := _SCT_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get0_extensions');
    {$ifend}
  end;
  SCT_set0_extensions := LoadLibFunction(ADllHandle, SCT_set0_extensions_procname);
  FuncLoadError := not assigned(SCT_set0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set0_extensions_allownil)}
    SCT_set0_extensions := ERR_SCT_set0_extensions;
    {$ifend}
    {$if declared(SCT_set0_extensions_introduced)}
    if LibVersion < SCT_set0_extensions_introduced then
    begin
      {$if declared(FC_SCT_set0_extensions)}
      SCT_set0_extensions := FC_SCT_set0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set0_extensions_removed)}
    if SCT_set0_extensions_removed <= LibVersion then
    begin
      {$if declared(_SCT_set0_extensions)}
      SCT_set0_extensions := _SCT_set0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set0_extensions');
    {$ifend}
  end;
  SCT_set1_extensions := LoadLibFunction(ADllHandle, SCT_set1_extensions_procname);
  FuncLoadError := not assigned(SCT_set1_extensions);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set1_extensions_allownil)}
    SCT_set1_extensions := ERR_SCT_set1_extensions;
    {$ifend}
    {$if declared(SCT_set1_extensions_introduced)}
    if LibVersion < SCT_set1_extensions_introduced then
    begin
      {$if declared(FC_SCT_set1_extensions)}
      SCT_set1_extensions := FC_SCT_set1_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set1_extensions_removed)}
    if SCT_set1_extensions_removed <= LibVersion then
    begin
      {$if declared(_SCT_set1_extensions)}
      SCT_set1_extensions := _SCT_set1_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set1_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set1_extensions');
    {$ifend}
  end;
  SCT_get0_signature := LoadLibFunction(ADllHandle, SCT_get0_signature_procname);
  FuncLoadError := not assigned(SCT_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get0_signature_allownil)}
    SCT_get0_signature := ERR_SCT_get0_signature;
    {$ifend}
    {$if declared(SCT_get0_signature_introduced)}
    if LibVersion < SCT_get0_signature_introduced then
    begin
      {$if declared(FC_SCT_get0_signature)}
      SCT_get0_signature := FC_SCT_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get0_signature_removed)}
    if SCT_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_SCT_get0_signature)}
      SCT_get0_signature := _SCT_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get0_signature');
    {$ifend}
  end;
  SCT_set0_signature := LoadLibFunction(ADllHandle, SCT_set0_signature_procname);
  FuncLoadError := not assigned(SCT_set0_signature);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set0_signature_allownil)}
    SCT_set0_signature := ERR_SCT_set0_signature;
    {$ifend}
    {$if declared(SCT_set0_signature_introduced)}
    if LibVersion < SCT_set0_signature_introduced then
    begin
      {$if declared(FC_SCT_set0_signature)}
      SCT_set0_signature := FC_SCT_set0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set0_signature_removed)}
    if SCT_set0_signature_removed <= LibVersion then
    begin
      {$if declared(_SCT_set0_signature)}
      SCT_set0_signature := _SCT_set0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set0_signature');
    {$ifend}
  end;
  SCT_set1_signature := LoadLibFunction(ADllHandle, SCT_set1_signature_procname);
  FuncLoadError := not assigned(SCT_set1_signature);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set1_signature_allownil)}
    SCT_set1_signature := ERR_SCT_set1_signature;
    {$ifend}
    {$if declared(SCT_set1_signature_introduced)}
    if LibVersion < SCT_set1_signature_introduced then
    begin
      {$if declared(FC_SCT_set1_signature)}
      SCT_set1_signature := FC_SCT_set1_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set1_signature_removed)}
    if SCT_set1_signature_removed <= LibVersion then
    begin
      {$if declared(_SCT_set1_signature)}
      SCT_set1_signature := _SCT_set1_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set1_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set1_signature');
    {$ifend}
  end;

  SCT_get_source := LoadLibFunction(ADllHandle, SCT_get_source_procname);
  FuncLoadError := not assigned(SCT_get_source);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_source_allownil)}
    SCT_get_source := ERR_SCT_get_source;
    {$ifend}
    {$if declared(SCT_get_source_introduced)}
    if LibVersion < SCT_get_source_introduced then
    begin
      {$if declared(FC_SCT_get_source)}
      SCT_get_source := FC_SCT_get_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_source_removed)}
    if SCT_get_source_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_source)}
      SCT_get_source := _SCT_get_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_source_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_source');
    {$ifend}
  end;
  SCT_set_source := LoadLibFunction(ADllHandle, SCT_set_source_procname);
  FuncLoadError := not assigned(SCT_set_source);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_source_allownil)}
    SCT_set_source := ERR_SCT_set_source;
    {$ifend}
    {$if declared(SCT_set_source_introduced)}
    if LibVersion < SCT_set_source_introduced then
    begin
      {$if declared(FC_SCT_set_source)}
      SCT_set_source := FC_SCT_set_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_source_removed)}
    if SCT_set_source_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_source)}
      SCT_set_source := _SCT_set_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_source_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_source');
    {$ifend}
  end;

  SCT_validation_status_string := LoadLibFunction(ADllHandle, SCT_validation_status_string_procname);
  FuncLoadError := not assigned(SCT_validation_status_string);
  if FuncLoadError then
  begin
    {$if not defined(SCT_validation_status_string_allownil)}
    SCT_validation_status_string := ERR_SCT_validation_status_string;
    {$ifend}
    {$if declared(SCT_validation_status_string_introduced)}
    if LibVersion < SCT_validation_status_string_introduced then
    begin
      {$if declared(FC_SCT_validation_status_string)}
      SCT_validation_status_string := FC_SCT_validation_status_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_validation_status_string_removed)}
    if SCT_validation_status_string_removed <= LibVersion then
    begin
      {$if declared(_SCT_validation_status_string)}
      SCT_validation_status_string := _SCT_validation_status_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_validation_status_string_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_validation_status_string');
    {$ifend}
  end;
  SCT_print := LoadLibFunction(ADllHandle, SCT_print_procname);
  FuncLoadError := not assigned(SCT_print);
  if FuncLoadError then
  begin
    {$if not defined(SCT_print_allownil)}
    SCT_print := ERR_SCT_print;
    {$ifend}
    {$if declared(SCT_print_introduced)}
    if LibVersion < SCT_print_introduced then
    begin
      {$if declared(FC_SCT_print)}
      SCT_print := FC_SCT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_print_removed)}
    if SCT_print_removed <= LibVersion then
    begin
      {$if declared(_SCT_print)}
      SCT_print := _SCT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_print_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_print');
    {$ifend}
  end;

  SCT_LIST_print := LoadLibFunction(ADllHandle, SCT_LIST_print_procname);
  FuncLoadError := not assigned(SCT_LIST_print);
  if FuncLoadError then
  begin
    {$if not defined(SCT_LIST_print_allownil)}
    SCT_LIST_print := ERR_SCT_LIST_print;
    {$ifend}
    {$if declared(SCT_LIST_print_introduced)}
    if LibVersion < SCT_LIST_print_introduced then
    begin
      {$if declared(FC_SCT_LIST_print)}
      SCT_LIST_print := FC_SCT_LIST_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_LIST_print_removed)}
    if SCT_LIST_print_removed <= LibVersion then
    begin
      {$if declared(_SCT_LIST_print)}
      SCT_LIST_print := _SCT_LIST_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_LIST_print_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_LIST_print');
    {$ifend}
  end;
  SCT_get_validation_status := LoadLibFunction(ADllHandle, SCT_get_validation_status_procname);
  FuncLoadError := not assigned(SCT_get_validation_status);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_validation_status_allownil)}
    SCT_get_validation_status := ERR_SCT_get_validation_status;
    {$ifend}
    {$if declared(SCT_get_validation_status_introduced)}
    if LibVersion < SCT_get_validation_status_introduced then
    begin
      {$if declared(FC_SCT_get_validation_status)}
      SCT_get_validation_status := FC_SCT_get_validation_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_validation_status_removed)}
    if SCT_get_validation_status_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_validation_status)}
      SCT_get_validation_status := _SCT_get_validation_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_validation_status_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_validation_status');
    {$ifend}
  end;
  SCT_validate := LoadLibFunction(ADllHandle, SCT_validate_procname);
  FuncLoadError := not assigned(SCT_validate);
  if FuncLoadError then
  begin
    {$if not defined(SCT_validate_allownil)}
    SCT_validate := ERR_SCT_validate;
    {$ifend}
    {$if declared(SCT_validate_introduced)}
    if LibVersion < SCT_validate_introduced then
    begin
      {$if declared(FC_SCT_validate)}
      SCT_validate := FC_SCT_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_validate_removed)}
    if SCT_validate_removed <= LibVersion then
    begin
      {$if declared(_SCT_validate)}
      SCT_validate := _SCT_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_validate_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_validate');
    {$ifend}
  end;

  SCT_LIST_validate := LoadLibFunction(ADllHandle, SCT_LIST_validate_procname);
  FuncLoadError := not assigned(SCT_LIST_validate);
  if FuncLoadError then
  begin
    {$if not defined(SCT_LIST_validate_allownil)}
    SCT_LIST_validate := ERR_SCT_LIST_validate;
    {$ifend}
    {$if declared(SCT_LIST_validate_introduced)}
    if LibVersion < SCT_LIST_validate_introduced then
    begin
      {$if declared(FC_SCT_LIST_validate)}
      SCT_LIST_validate := FC_SCT_LIST_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_LIST_validate_removed)}
    if SCT_LIST_validate_removed <= LibVersion then
    begin
      {$if declared(_SCT_LIST_validate)}
      SCT_LIST_validate := _SCT_LIST_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_LIST_validate_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_LIST_validate');
    {$ifend}
  end;

  i2o_SCT_LIST := LoadLibFunction(ADllHandle, i2o_SCT_LIST_procname);
  FuncLoadError := not assigned(i2o_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(i2o_SCT_LIST_allownil)}
    i2o_SCT_LIST := ERR_i2o_SCT_LIST;
    {$ifend}
    {$if declared(i2o_SCT_LIST_introduced)}
    if LibVersion < i2o_SCT_LIST_introduced then
    begin
      {$if declared(FC_i2o_SCT_LIST)}
      i2o_SCT_LIST := FC_i2o_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2o_SCT_LIST_removed)}
    if i2o_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_i2o_SCT_LIST)}
      i2o_SCT_LIST := _i2o_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2o_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('i2o_SCT_LIST');
    {$ifend}
  end;
  o2i_SCT_LIST := LoadLibFunction(ADllHandle, o2i_SCT_LIST_procname);
  FuncLoadError := not assigned(o2i_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(o2i_SCT_LIST_allownil)}
    o2i_SCT_LIST := ERR_o2i_SCT_LIST;
    {$ifend}
    {$if declared(o2i_SCT_LIST_introduced)}
    if LibVersion < o2i_SCT_LIST_introduced then
    begin
      {$if declared(FC_o2i_SCT_LIST)}
      o2i_SCT_LIST := FC_o2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(o2i_SCT_LIST_removed)}
    if o2i_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_o2i_SCT_LIST)}
      o2i_SCT_LIST := _o2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(o2i_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('o2i_SCT_LIST');
    {$ifend}
  end;
  i2d_SCT_LIST := LoadLibFunction(ADllHandle, i2d_SCT_LIST_procname);
  FuncLoadError := not assigned(i2d_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(i2d_SCT_LIST_allownil)}
    i2d_SCT_LIST := ERR_i2d_SCT_LIST;
    {$ifend}
    {$if declared(i2d_SCT_LIST_introduced)}
    if LibVersion < i2d_SCT_LIST_introduced then
    begin
      {$if declared(FC_i2d_SCT_LIST)}
      i2d_SCT_LIST := FC_i2d_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_SCT_LIST_removed)}
    if i2d_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_i2d_SCT_LIST)}
      i2d_SCT_LIST := _i2d_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_SCT_LIST');
    {$ifend}
  end;
  d2i_SCT_LIST := LoadLibFunction(ADllHandle, d2i_SCT_LIST_procname);
  FuncLoadError := not assigned(d2i_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(d2i_SCT_LIST_allownil)}
    d2i_SCT_LIST := ERR_d2i_SCT_LIST;
    {$ifend}
    {$if declared(d2i_SCT_LIST_introduced)}
    if LibVersion < d2i_SCT_LIST_introduced then
    begin
      {$if declared(FC_d2i_SCT_LIST)}
      d2i_SCT_LIST := FC_d2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_SCT_LIST_removed)}
    if d2i_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_d2i_SCT_LIST)}
      d2i_SCT_LIST := _d2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_SCT_LIST');
    {$ifend}
  end;
  i2o_SCT := LoadLibFunction(ADllHandle, i2o_SCT_procname);
  FuncLoadError := not assigned(i2o_SCT);
  if FuncLoadError then
  begin
    {$if not defined(i2o_SCT_allownil)}
    i2o_SCT := ERR_i2o_SCT;
    {$ifend}
    {$if declared(i2o_SCT_introduced)}
    if LibVersion < i2o_SCT_introduced then
    begin
      {$if declared(FC_i2o_SCT)}
      i2o_SCT := FC_i2o_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2o_SCT_removed)}
    if i2o_SCT_removed <= LibVersion then
    begin
      {$if declared(_i2o_SCT)}
      i2o_SCT := _i2o_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2o_SCT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2o_SCT');
    {$ifend}
  end;
  o2i_SCT := LoadLibFunction(ADllHandle, o2i_SCT_procname);
  FuncLoadError := not assigned(o2i_SCT);
  if FuncLoadError then
  begin
    {$if not defined(o2i_SCT_allownil)}
    o2i_SCT := ERR_o2i_SCT;
    {$ifend}
    {$if declared(o2i_SCT_introduced)}
    if LibVersion < o2i_SCT_introduced then
    begin
      {$if declared(FC_o2i_SCT)}
      o2i_SCT := FC_o2i_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(o2i_SCT_removed)}
    if o2i_SCT_removed <= LibVersion then
    begin
      {$if declared(_o2i_SCT)}
      o2i_SCT := _o2i_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(o2i_SCT_allownil)}
    if FuncLoadError then
      AFailed.Add('o2i_SCT');
    {$ifend}
  end;

  CTLOG_new := LoadLibFunction(ADllHandle, CTLOG_new_procname);
  FuncLoadError := not assigned(CTLOG_new);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_new_allownil)}
    CTLOG_new := ERR_CTLOG_new;
    {$ifend}
    {$if declared(CTLOG_new_introduced)}
    if LibVersion < CTLOG_new_introduced then
    begin
      {$if declared(FC_CTLOG_new)}
      CTLOG_new := FC_CTLOG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_new_removed)}
    if CTLOG_new_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_new)}
      CTLOG_new := _CTLOG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_new');
    {$ifend}
  end;
  CTLOG_new_from_base64 := LoadLibFunction(ADllHandle, CTLOG_new_from_base64_procname);
  FuncLoadError := not assigned(CTLOG_new_from_base64);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_new_from_base64_allownil)}
    CTLOG_new_from_base64 := ERR_CTLOG_new_from_base64;
    {$ifend}
    {$if declared(CTLOG_new_from_base64_introduced)}
    if LibVersion < CTLOG_new_from_base64_introduced then
    begin
      {$if declared(FC_CTLOG_new_from_base64)}
      CTLOG_new_from_base64 := FC_CTLOG_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_new_from_base64_removed)}
    if CTLOG_new_from_base64_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_new_from_base64)}
      CTLOG_new_from_base64 := _CTLOG_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_new_from_base64_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_new_from_base64');
    {$ifend}
  end;
  CTLOG_free := LoadLibFunction(ADllHandle, CTLOG_free_procname);
  FuncLoadError := not assigned(CTLOG_free);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_free_allownil)}
    CTLOG_free := ERR_CTLOG_free;
    {$ifend}
    {$if declared(CTLOG_free_introduced)}
    if LibVersion < CTLOG_free_introduced then
    begin
      {$if declared(FC_CTLOG_free)}
      CTLOG_free := FC_CTLOG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_free_removed)}
    if CTLOG_free_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_free)}
      CTLOG_free := _CTLOG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_free');
    {$ifend}
  end;
  CTLOG_get0_name := LoadLibFunction(ADllHandle, CTLOG_get0_name_procname);
  FuncLoadError := not assigned(CTLOG_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_get0_name_allownil)}
    CTLOG_get0_name := ERR_CTLOG_get0_name;
    {$ifend}
    {$if declared(CTLOG_get0_name_introduced)}
    if LibVersion < CTLOG_get0_name_introduced then
    begin
      {$if declared(FC_CTLOG_get0_name)}
      CTLOG_get0_name := FC_CTLOG_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_get0_name_removed)}
    if CTLOG_get0_name_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_get0_name)}
      CTLOG_get0_name := _CTLOG_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_get0_name');
    {$ifend}
  end;
  CTLOG_get0_log_id := LoadLibFunction(ADllHandle, CTLOG_get0_log_id_procname);
  FuncLoadError := not assigned(CTLOG_get0_log_id);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_get0_log_id_allownil)}
    CTLOG_get0_log_id := ERR_CTLOG_get0_log_id;
    {$ifend}
    {$if declared(CTLOG_get0_log_id_introduced)}
    if LibVersion < CTLOG_get0_log_id_introduced then
    begin
      {$if declared(FC_CTLOG_get0_log_id)}
      CTLOG_get0_log_id := FC_CTLOG_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(get0_log_id_removed)}
    if CTLOG_get0_log_id_removed <= LibVersion then
    begin
      {$if declared(_get0_log_id)}
      CTLOG_get0_log_id := _CTLOG_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(get0_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_get0_log_id');
    {$ifend}
  end;
  CTLOG_get0_public_key := LoadLibFunction(ADllHandle, CTLOG_get0_public_key_procname);
  FuncLoadError := not assigned(CTLOG_get0_public_key);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_get0_public_key_allownil)}
    CTLOG_get0_public_key := ERR_CTLOG_get0_public_key;
    {$ifend}
    {$if declared(CTLOG_get0_public_key_introduced)}
    if LibVersion < CTLOG_get0_public_key_introduced then
    begin
      {$if declared(FC_CTLOG_get0_public_key)}
      CTLOG_get0_public_key := FC_CTLOG_get0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_get0_public_key_removed)}
    if CTLOG_get0_public_key_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_get0_public_key)}
      CTLOG_get0_public_key := _CTLOG_get0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_get0_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_get0_public_key');
    {$ifend}
  end;

  CTLOG_STORE_new := LoadLibFunction(ADllHandle, CTLOG_STORE_new_procname);
  FuncLoadError := not assigned(CTLOG_STORE_new);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_new_allownil)}
    CTLOG_STORE_new := ERR_CTLOG_STORE_new;
    {$ifend}
    {$if declared(CTLOG_STORE_new_introduced)}
    if LibVersion < CTLOG_STORE_new_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_new)}
      CTLOG_STORE_new := FC_CTLOG_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_new_removed)}
    if CTLOG_STORE_new_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_new)}
      CTLOG_STORE_new := _CTLOG_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_new');
    {$ifend}
  end;
  CTLOG_STORE_free := LoadLibFunction(ADllHandle, CTLOG_STORE_free_procname);
  FuncLoadError := not assigned(CTLOG_STORE_free);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_free_allownil)}
    CTLOG_STORE_free := ERR_CTLOG_STORE_free;
    {$ifend}
    {$if declared(CTLOG_STORE_free_introduced)}
    if LibVersion < CTLOG_STORE_free_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_free)}
      CTLOG_STORE_free := FC_CTLOG_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_free_removed)}
    if CTLOG_STORE_free_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_free)}
      CTLOG_STORE_free := _CTLOG_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_free');
    {$ifend}
  end;
  CTLOG_STORE_get0_log_by_id := LoadLibFunction(ADllHandle, CTLOG_STORE_get0_log_by_id_procname);
  FuncLoadError := not assigned(CTLOG_STORE_get0_log_by_id);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_get0_log_by_id_allownil)}
    CTLOG_STORE_get0_log_by_id := ERR_CTLOG_STORE_get0_log_by_id;
    {$ifend}
    {$if declared(CTLOG_STORE_get0_log_by_id_introduced)}
    if LibVersion < CTLOG_STORE_get0_log_by_id_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_get0_log_by_id)}
      CTLOG_STORE_get0_log_by_id := FC_CTLOG_STORE_get0_log_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_get0_log_by_id_removed)}
    if CTLOG_STORE_get0_log_by_id_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_get0_log_by_id)}
      CTLOG_STORE_get0_log_by_id := _CTLOG_STORE_get0_log_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_get0_log_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_get0_log_by_id');
    {$ifend}
  end;
  CTLOG_STORE_load_file := LoadLibFunction(ADllHandle, CTLOG_STORE_load_file_procname);
  FuncLoadError := not assigned(CTLOG_STORE_load_file);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_load_file_allownil)}
    CTLOG_STORE_load_file := ERR_CTLOG_STORE_load_file;
    {$ifend}
    {$if declared(CTLOG_STORE_load_file_introduced)}
    if LibVersion < CTLOG_STORE_load_file_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_load_file)}
      CTLOG_STORE_load_file := FC_CTLOG_STORE_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_load_file_removed)}
    if CTLOG_STORE_load_file_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_load_file)}
      CTLOG_STORE_load_file := _CTLOG_STORE_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_load_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_load_file');
    {$ifend}
  end;
  CTLOG_STORE_load_default_file := LoadLibFunction(ADllHandle, CTLOG_STORE_load_default_file_procname);
  FuncLoadError := not assigned(CTLOG_STORE_load_default_file);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_load_default_file_allownil)}
    CTLOG_STORE_load_default_file := ERR_CTLOG_STORE_load_default_file;
    {$ifend}
    {$if declared(CTLOG_STORE_load_default_file_introduced)}
    if LibVersion < CTLOG_STORE_load_default_file_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_load_default_file)}
      CTLOG_STORE_load_default_file := FC_CTLOG_STORE_load_default_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_load_default_file_removed)}
    if CTLOG_STORE_load_default_file_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_load_default_file)}
      CTLOG_STORE_load_default_file := _CTLOG_STORE_load_default_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_load_default_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_load_default_file');
    {$ifend}
  end;
  ERR_load_CT_strings := LoadLibFunction(ADllHandle, ERR_load_CT_strings_procname);
  FuncLoadError := not assigned(ERR_load_CT_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_CT_strings_allownil)}
    ERR_load_CT_strings := ERR_ERR_load_CT_strings;
    {$ifend}
    {$if declared(ERR_load_CT_strings_introduced)}
    if LibVersion < ERR_load_CT_strings_introduced then
    begin
      {$if declared(FC_ERR_load_CT_strings)}
      ERR_load_CT_strings := FC_ERR_load_CT_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_CT_strings_removed)}
    if ERR_load_CT_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_CT_strings)}
      ERR_load_CT_strings := _ERR_load_CT_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_CT_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_CT_strings');
    {$ifend}
  end;

  // Stack of macros
  LoadStackFunctions(ADllHandle,libVersion,AFailed);
  //Disable PAL warnings for Bad Typecast
  sk_SCT_new := Tsk_SCT_new(sk_new);  //PALOFF
  sk_SCT_new_null := Tsk_SCT_new_null(sk_new_null);  //PALOFF
  sk_SCT_free := Tsk_SCT_free(sk_free);  //PALOFF
  sk_SCT_num := Tsk_SCT_num(sk_num);  //PALOFF
  sk_SCT_value := Tsk_SCT_value(sk_value); //PALOFF
  sk_SCT_push := Tsk_SCT_push(sk_push);  //PALOFF
  sk_SCT_dup := Tsk_SCT_dup(sk_dup);  //PALOFF
  sk_SCT_find := Tsk_SCT_find(sk_find);  //PALOFF
  sk_SCT_pop_free := Tsk_SCT_pop_free(sk_pop_free); //PALOFF

  sk_CTLOG_new := Tsk_CTLOG_new(sk_new);  //PALOFF
  sk_CTLOG_new_null := Tsk_CTLOG_new_null(sk_new_null);  //PALOFF
  sk_CTLOG_free := Tsk_CTLOG_free(sk_free);  //PALOFF
  sk_CTLOG_num := Tsk_CTLOG_num(sk_num);  //PALOFF
  sk_CTLOG_value := Tsk_CTLOG_value(sk_value);  //PALOFF
  sk_CTLOG_push := Tsk_CTLOG_push(sk_push);  //PALOFF
  sk_CTLOG_dup := Tsk_CTLOG_dup(sk_dup);  //PALOFF
  sk_CTLOG_find := Tsk_CTLOG_find(sk_find);  //PALOFF
  sk_CTLOG_pop_free := Tsk_CTLOG_pop_free(sk_pop_free); //PALOFF
end;
 {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  CT_POLICY_EVAL_CTX_new := nil;
  CT_POLICY_EVAL_CTX_free := nil;
  CT_POLICY_EVAL_CTX_get0_cert := nil;
  CT_POLICY_EVAL_CTX_set1_cert := nil;
  CT_POLICY_EVAL_CTX_get0_issuer := nil;
  CT_POLICY_EVAL_CTX_set1_issuer := nil;
  CT_POLICY_EVAL_CTX_get0_log_store := nil;
  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := nil;
  CT_POLICY_EVAL_CTX_get_time := nil;
  CT_POLICY_EVAL_CTX_set_time := nil;

  SCT_new := nil;
  SCT_new_from_base64 := nil;
  SCT_free := nil;
  SCT_LIST_free := nil;
  SCT_get_version := nil;
  SCT_set_version := nil;
  SCT_get_log_entry_type := nil;
  SCT_set_log_entry_type := nil;
  SCT_get0_log_id := nil;
  SCT_set0_log_id := nil;
  SCT_set1_log_id := nil;
  SCT_get_timestamp := nil;
  SCT_set_timestamp := nil;
  SCT_get_signature_nid := nil;
  SCT_set_signature_nid := nil;
  SCT_get0_extensions := nil;
  SCT_set0_extensions := nil;
  SCT_set1_extensions := nil;
  SCT_get0_signature := nil;
  SCT_set0_signature := nil;
  SCT_set1_signature := nil;
  SCT_get_source := nil;
  SCT_set_source := nil;
  SCT_validation_status_string := nil;
  SCT_print := nil;
  SCT_LIST_print := nil;
  SCT_get_validation_status := nil;
  SCT_validate := nil;
  SCT_LIST_validate := nil;

  i2o_SCT_LIST := nil;
  o2i_SCT_LIST := nil;
  i2d_SCT_LIST := nil;
  d2i_SCT_LIST := nil;
  i2o_SCT := nil;
  o2i_SCT := nil;

  CTLOG_new := nil;
  CTLOG_new_from_base64 := nil;
  CTLOG_free := nil;
  CTLOG_get0_name := nil;
  CTLOG_get0_log_id := nil;
  CTLOG_get0_public_key := nil;

  CTLOG_STORE_new := nil;
  CTLOG_STORE_free := nil;
  CTLOG_STORE_get0_log_by_id := nil;
  CTLOG_STORE_load_file := nil;
  CTLOG_STORE_load_default_file := nil;

  ERR_load_CT_strings := nil;

  // Stack of macros
  sk_SCT_new := nil;
  sk_SCT_new_null := nil;
  sk_SCT_free := nil;
  sk_SCT_num := nil;
  sk_SCT_value := nil;
  sk_SCT_push := nil;
  sk_SCT_dup := nil;
  sk_SCT_find := nil;
  sk_SCT_pop_free := nil;

  sk_CTLOG_new := nil;
  sk_CTLOG_new_null := nil;
  sk_CTLOG_free := nil;
  sk_CTLOG_num := nil;
  sk_CTLOG_value := nil;
  sk_CTLOG_push := nil;
  sk_CTLOG_dup := nil;
  sk_CTLOG_find := nil;
  sk_CTLOG_pop_free := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
