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

unit TaurusTLSHeaders_cmp;

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
  POSSL_CMP_PKIFAILUREINFO = ^TOSSL_CMP_PKIFAILUREINFO;
  TOSSL_CMP_PKIFAILUREINFO = TASN1_BIT_STRING;
  {$EXTERNALSYM POSSL_CMP_PKIFAILUREINFO}

  POSSL_CMP_PKISTATUS = ^TOSSL_CMP_PKISTATUS;
  TOSSL_CMP_PKISTATUS = TASN1_INTEGER;
  {$EXTERNALSYM POSSL_CMP_PKISTATUS}

  Possl_cmp_ctx_st = ^Tossl_cmp_ctx_st;
  Tossl_cmp_ctx_st = record end;
  {$EXTERNALSYM Possl_cmp_ctx_st}

  POSSL_CMP_CTX = ^TOSSL_CMP_CTX;
  TOSSL_CMP_CTX = Tossl_cmp_ctx_st;
  {$EXTERNALSYM POSSL_CMP_CTX}

  Possl_cmp_pkiheader_st = ^Tossl_cmp_pkiheader_st;
  Tossl_cmp_pkiheader_st = record end;
  {$EXTERNALSYM Possl_cmp_pkiheader_st}

  POSSL_CMP_PKIHEADER = ^TOSSL_CMP_PKIHEADER;
  TOSSL_CMP_PKIHEADER = Tossl_cmp_pkiheader_st;
  {$EXTERNALSYM POSSL_CMP_PKIHEADER}

  Possl_cmp_msg_st = ^Tossl_cmp_msg_st;
  Tossl_cmp_msg_st = record end;
  {$EXTERNALSYM Possl_cmp_msg_st}

  POSSL_CMP_MSG = ^TOSSL_CMP_MSG;
  TOSSL_CMP_MSG = Tossl_cmp_msg_st;
  {$EXTERNALSYM POSSL_CMP_MSG}

  Possl_cmp_certstatus_st = ^Tossl_cmp_certstatus_st;
  Tossl_cmp_certstatus_st = record end;
  {$EXTERNALSYM Possl_cmp_certstatus_st}

  POSSL_CMP_CERTSTATUS = ^TOSSL_CMP_CERTSTATUS;
  TOSSL_CMP_CERTSTATUS = Tossl_cmp_certstatus_st;
  {$EXTERNALSYM POSSL_CMP_CERTSTATUS}

  Pstack_st_OSSL_CMP_CERTSTATUS = ^Tstack_st_OSSL_CMP_CERTSTATUS;
  Tstack_st_OSSL_CMP_CERTSTATUS = record end;
  {$EXTERNALSYM Pstack_st_OSSL_CMP_CERTSTATUS}

  Possl_cmp_itav_st = ^Tossl_cmp_itav_st;
  Tossl_cmp_itav_st = record end;
  {$EXTERNALSYM Possl_cmp_itav_st}

  POSSL_CMP_ITAV = ^TOSSL_CMP_ITAV;
  TOSSL_CMP_ITAV = Tossl_cmp_itav_st;
  {$EXTERNALSYM POSSL_CMP_ITAV}

  Pstack_st_OSSL_CMP_ITAV = ^Tstack_st_OSSL_CMP_ITAV;
  Tstack_st_OSSL_CMP_ITAV = record end;
  {$EXTERNALSYM Pstack_st_OSSL_CMP_ITAV}

  Possl_cmp_crlstatus_st = ^Tossl_cmp_crlstatus_st;
  Tossl_cmp_crlstatus_st = record end;
  {$EXTERNALSYM Possl_cmp_crlstatus_st}

  POSSL_CMP_CRLSTATUS = ^TOSSL_CMP_CRLSTATUS;
  TOSSL_CMP_CRLSTATUS = Tossl_cmp_crlstatus_st;
  {$EXTERNALSYM POSSL_CMP_CRLSTATUS}

  Pstack_st_OSSL_CMP_CRLSTATUS = ^Tstack_st_OSSL_CMP_CRLSTATUS;
  Tstack_st_OSSL_CMP_CRLSTATUS = record end;
  {$EXTERNALSYM Pstack_st_OSSL_CMP_CRLSTATUS}

  POSSL_CMP_ATAV = ^TOSSL_CMP_ATAV;
  TOSSL_CMP_ATAV = TOSSL_CRMF_ATTRIBUTETYPEANDVALUE;
  {$EXTERNALSYM POSSL_CMP_ATAV}

  POSSL_CMP_ATAVS = ^TOSSL_CMP_ATAVS;
  TOSSL_CMP_ATAVS = Tstack_st_OSSL_CRMF_ATTRIBUTETYPEANDVALUE;
  {$EXTERNALSYM POSSL_CMP_ATAVS}

  Possl_cmp_revrepcontent_st = ^Tossl_cmp_revrepcontent_st;
  Tossl_cmp_revrepcontent_st = record end;
  {$EXTERNALSYM Possl_cmp_revrepcontent_st}

  POSSL_CMP_REVREPCONTENT = ^TOSSL_CMP_REVREPCONTENT;
  TOSSL_CMP_REVREPCONTENT = Tossl_cmp_revrepcontent_st;
  {$EXTERNALSYM POSSL_CMP_REVREPCONTENT}

  Possl_cmp_pkisi_st = ^Tossl_cmp_pkisi_st;
  Tossl_cmp_pkisi_st = record end;
  {$EXTERNALSYM Possl_cmp_pkisi_st}

  POSSL_CMP_PKISI = ^TOSSL_CMP_PKISI;
  TOSSL_CMP_PKISI = Tossl_cmp_pkisi_st;
  {$EXTERNALSYM POSSL_CMP_PKISI}

  Pstack_st_OSSL_CMP_PKISI = ^Tstack_st_OSSL_CMP_PKISI;
  Tstack_st_OSSL_CMP_PKISI = record end;
  {$EXTERNALSYM Pstack_st_OSSL_CMP_PKISI}

  Possl_cmp_certrepmessage_st = ^Tossl_cmp_certrepmessage_st;
  Tossl_cmp_certrepmessage_st = record end;
  {$EXTERNALSYM Possl_cmp_certrepmessage_st}

  POSSL_CMP_CERTREPMESSAGE = ^TOSSL_CMP_CERTREPMESSAGE;
  TOSSL_CMP_CERTREPMESSAGE = Tossl_cmp_certrepmessage_st;
  {$EXTERNALSYM POSSL_CMP_CERTREPMESSAGE}

  Pstack_st_OSSL_CMP_CERTREPMESSAGE = ^Tstack_st_OSSL_CMP_CERTREPMESSAGE;
  Tstack_st_OSSL_CMP_CERTREPMESSAGE = record end;
  {$EXTERNALSYM Pstack_st_OSSL_CMP_CERTREPMESSAGE}

  Possl_cmp_pollrep_st = ^Tossl_cmp_pollrep_st;
  Tossl_cmp_pollrep_st = record end;
  {$EXTERNALSYM Possl_cmp_pollrep_st}

  POSSL_CMP_POLLREP = ^TOSSL_CMP_POLLREP;
  TOSSL_CMP_POLLREP = Tossl_cmp_pollrep_st;
  {$EXTERNALSYM POSSL_CMP_POLLREP}

  Pstack_st_OSSL_CMP_POLLREP = ^Tstack_st_OSSL_CMP_POLLREP;
  Tstack_st_OSSL_CMP_POLLREP = record end;
  {$EXTERNALSYM Pstack_st_OSSL_CMP_POLLREP}

  POSSL_CMP_POLLREPCONTENT = ^TOSSL_CMP_POLLREPCONTENT;
  TOSSL_CMP_POLLREPCONTENT = Tstack_st_OSSL_CMP_POLLREP;
  {$EXTERNALSYM POSSL_CMP_POLLREPCONTENT}

  Possl_cmp_certresponse_st = ^Tossl_cmp_certresponse_st;
  Tossl_cmp_certresponse_st = record end;
  {$EXTERNALSYM Possl_cmp_certresponse_st}

  POSSL_CMP_CERTRESPONSE = ^TOSSL_CMP_CERTRESPONSE;
  TOSSL_CMP_CERTRESPONSE = Tossl_cmp_certresponse_st;
  {$EXTERNALSYM POSSL_CMP_CERTRESPONSE}

  Pstack_st_OSSL_CMP_CERTRESPONSE = ^Tstack_st_OSSL_CMP_CERTRESPONSE;
  Tstack_st_OSSL_CMP_CERTRESPONSE = record end;
  {$EXTERNALSYM Pstack_st_OSSL_CMP_CERTRESPONSE}

  POSSL_CMP_PKIFREETEXT = ^TOSSL_CMP_PKIFREETEXT;
  TOSSL_CMP_PKIFREETEXT = Tstack_st_ASN1_UTF8STRING;
  {$EXTERNALSYM POSSL_CMP_PKIFREETEXT}

  Possl_cmp_srv_ctx_st = ^Tossl_cmp_srv_ctx_st;
  Tossl_cmp_srv_ctx_st = record end;
  {$EXTERNALSYM Possl_cmp_srv_ctx_st}

  POSSL_CMP_SRV_CTX = ^TOSSL_CMP_SRV_CTX;
  TOSSL_CMP_SRV_CTX = Tossl_cmp_srv_ctx_st;
  {$EXTERNALSYM POSSL_CMP_SRV_CTX}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tsk_OSSL_CMP_CERTSTATUS_compfunc_func_cb = function(arg1: PPOSSL_CMP_CERTSTATUS; arg2: PPOSSL_CMP_CERTSTATUS): TIdC_INT; cdecl;
  Tsk_OSSL_CMP_CERTSTATUS_freefunc_func_cb = procedure(arg1: POSSL_CMP_CERTSTATUS); cdecl;
  Tsk_OSSL_CMP_CERTSTATUS_copyfunc_func_cb = function(arg1: POSSL_CMP_CERTSTATUS): POSSL_CMP_CERTSTATUS; cdecl;
  Tsk_OSSL_CMP_ITAV_compfunc_func_cb = function(arg1: PPOSSL_CMP_ITAV; arg2: PPOSSL_CMP_ITAV): TIdC_INT; cdecl;
  Tsk_OSSL_CMP_ITAV_freefunc_func_cb = procedure(arg1: POSSL_CMP_ITAV); cdecl;
  Tsk_OSSL_CMP_ITAV_copyfunc_func_cb = function(arg1: POSSL_CMP_ITAV): POSSL_CMP_ITAV; cdecl;
  Tsk_OSSL_CMP_CRLSTATUS_compfunc_func_cb = function(arg1: PPOSSL_CMP_CRLSTATUS; arg2: PPOSSL_CMP_CRLSTATUS): TIdC_INT; cdecl;
  Tsk_OSSL_CMP_CRLSTATUS_freefunc_func_cb = procedure(arg1: POSSL_CMP_CRLSTATUS); cdecl;
  Tsk_OSSL_CMP_CRLSTATUS_copyfunc_func_cb = function(arg1: POSSL_CMP_CRLSTATUS): POSSL_CMP_CRLSTATUS; cdecl;
  Tsk_OSSL_CMP_PKISI_compfunc_func_cb = function(arg1: PPOSSL_CMP_PKISI; arg2: PPOSSL_CMP_PKISI): TIdC_INT; cdecl;
  Tsk_OSSL_CMP_PKISI_freefunc_func_cb = procedure(arg1: POSSL_CMP_PKISI); cdecl;
  Tsk_OSSL_CMP_PKISI_copyfunc_func_cb = function(arg1: POSSL_CMP_PKISI): POSSL_CMP_PKISI; cdecl;
  Tsk_OSSL_CMP_CERTREPMESSAGE_compfunc_func_cb = function(arg1: PPOSSL_CMP_CERTREPMESSAGE; arg2: PPOSSL_CMP_CERTREPMESSAGE): TIdC_INT; cdecl;
  Tsk_OSSL_CMP_CERTREPMESSAGE_freefunc_func_cb = procedure(arg1: POSSL_CMP_CERTREPMESSAGE); cdecl;
  Tsk_OSSL_CMP_CERTREPMESSAGE_copyfunc_func_cb = function(arg1: POSSL_CMP_CERTREPMESSAGE): POSSL_CMP_CERTREPMESSAGE; cdecl;
  Tsk_OSSL_CMP_CERTRESPONSE_compfunc_func_cb = function(arg1: PPOSSL_CMP_CERTRESPONSE; arg2: PPOSSL_CMP_CERTRESPONSE): TIdC_INT; cdecl;
  Tsk_OSSL_CMP_CERTRESPONSE_freefunc_func_cb = procedure(arg1: POSSL_CMP_CERTRESPONSE); cdecl;
  Tsk_OSSL_CMP_CERTRESPONSE_copyfunc_func_cb = function(arg1: POSSL_CMP_CERTRESPONSE): POSSL_CMP_CERTRESPONSE; cdecl;
  TOSSL_CMP_CTX_set_log_cb_cb_cb = function: T; cdecl;
  TOSSL_CMP_CTX_set_http_cb_cb_cb = function: T; cdecl;
  TOSSL_CMP_transfer_cb_t_func_cb = function(arg1: POSSL_CMP_CTX; arg2: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl;
  TOSSL_CMP_certConf_cb_t_func_cb = function(arg1: POSSL_CMP_CTX; arg2: PX509; arg3: TIdC_INT; arg4: PPIdAnsiChar): TIdC_INT; cdecl;
  TOSSL_CMP_SRV_cert_request_cb_t_func_cb = function(arg1: POSSL_CMP_SRV_CTX; arg2: POSSL_CMP_MSG; arg3: TIdC_INT; arg4: POSSL_CRMF_MSG; arg5: PX509_REQ; arg6: PPX509; arg7: PPstack_st_X509; arg8: PPstack_st_X509): POSSL_CMP_PKISI; cdecl;
  TOSSL_CMP_SRV_rr_cb_t_func_cb = function(arg1: POSSL_CMP_SRV_CTX; arg2: POSSL_CMP_MSG; arg3: PX509_NAME; arg4: PASN1_INTEGER): POSSL_CMP_PKISI; cdecl;
  TOSSL_CMP_SRV_genm_cb_t_func_cb = function(arg1: POSSL_CMP_SRV_CTX; arg2: POSSL_CMP_MSG; arg3: Pstack_st_OSSL_CMP_ITAV; arg4: PPstack_st_OSSL_CMP_ITAV): TIdC_INT; cdecl;
  TOSSL_CMP_SRV_error_cb_t_func_cb = procedure(arg1: POSSL_CMP_SRV_CTX; arg2: POSSL_CMP_MSG; arg3: POSSL_CMP_PKISI; arg4: PASN1_INTEGER; arg5: POSSL_CMP_PKIFREETEXT); cdecl;
  TOSSL_CMP_SRV_certConf_cb_t_func_cb = function(arg1: POSSL_CMP_SRV_CTX; arg2: POSSL_CMP_MSG; arg3: TIdC_INT; arg4: PASN1_OCTET_STRING; arg5: POSSL_CMP_PKISI): TIdC_INT; cdecl;
  TOSSL_CMP_SRV_pollReq_cb_t_func_cb = function(arg1: POSSL_CMP_SRV_CTX; arg2: POSSL_CMP_MSG; arg3: TIdC_INT; arg4: PPOSSL_CMP_MSG; arg5: PInt64): TIdC_INT; cdecl;
  TOSSL_CMP_SRV_delayed_delivery_cb_t_func_cb = function(arg1: POSSL_CMP_SRV_CTX; arg2: POSSL_CMP_MSG): TIdC_INT; cdecl;
  TOSSL_CMP_SRV_clean_transaction_cb_t_func_cb = function(arg1: POSSL_CMP_SRV_CTX; arg2: PASN1_OCTET_STRING): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_CMP_PVNO_2 = 2;
  OSSL_CMP_PVNO_3 = 3;
  OSSL_CMP_PVNO = OSSL_CMP_PVNO_2;
  OSSL_CMP_PKIFAILUREINFO_badAlg = 0;
  OSSL_CMP_PKIFAILUREINFO_badMessageCheck = 1;
  OSSL_CMP_PKIFAILUREINFO_badRequest = 2;
  OSSL_CMP_PKIFAILUREINFO_badTime = 3;
  OSSL_CMP_PKIFAILUREINFO_badCertId = 4;
  OSSL_CMP_PKIFAILUREINFO_badDataFormat = 5;
  OSSL_CMP_PKIFAILUREINFO_wrongAuthority = 6;
  OSSL_CMP_PKIFAILUREINFO_incorrectData = 7;
  OSSL_CMP_PKIFAILUREINFO_missingTimeStamp = 8;
  OSSL_CMP_PKIFAILUREINFO_badPOP = 9;
  OSSL_CMP_PKIFAILUREINFO_certRevoked = 10;
  OSSL_CMP_PKIFAILUREINFO_certConfirmed = 11;
  OSSL_CMP_PKIFAILUREINFO_wrongIntegrity = 12;
  OSSL_CMP_PKIFAILUREINFO_badRecipientNonce = 13;
  OSSL_CMP_PKIFAILUREINFO_timeNotAvailable = 14;
  OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy = 15;
  OSSL_CMP_PKIFAILUREINFO_unacceptedExtension = 16;
  OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable = 17;
  OSSL_CMP_PKIFAILUREINFO_badSenderNonce = 18;
  OSSL_CMP_PKIFAILUREINFO_badCertTemplate = 19;
  OSSL_CMP_PKIFAILUREINFO_signerNotTrusted = 20;
  OSSL_CMP_PKIFAILUREINFO_transactionIdInUse = 21;
  OSSL_CMP_PKIFAILUREINFO_unsupportedVersion = 22;
  OSSL_CMP_PKIFAILUREINFO_notAuthorized = 23;
  OSSL_CMP_PKIFAILUREINFO_systemUnavail = 24;
  OSSL_CMP_PKIFAILUREINFO_systemFailure = 25;
  OSSL_CMP_PKIFAILUREINFO_duplicateCertReq = 26;
  OSSL_CMP_PKIFAILUREINFO_MAX = 26;
  OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN = ((1 shl (OSSL_CMP_PKIFAILUREINFO_MAX+1))-1);
  OSSL_CMP_CTX_FAILINFO_badAlg = (1 shl 0);
  OSSL_CMP_CTX_FAILINFO_badMessageCheck = (1 shl 1);
  OSSL_CMP_CTX_FAILINFO_badRequest = (1 shl 2);
  OSSL_CMP_CTX_FAILINFO_badTime = (1 shl 3);
  OSSL_CMP_CTX_FAILINFO_badCertId = (1 shl 4);
  OSSL_CMP_CTX_FAILINFO_badDataFormat = (1 shl 5);
  OSSL_CMP_CTX_FAILINFO_wrongAuthority = (1 shl 6);
  OSSL_CMP_CTX_FAILINFO_incorrectData = (1 shl 7);
  OSSL_CMP_CTX_FAILINFO_missingTimeStamp = (1 shl 8);
  OSSL_CMP_CTX_FAILINFO_badPOP = (1 shl 9);
  OSSL_CMP_CTX_FAILINFO_certRevoked = (1 shl 10);
  OSSL_CMP_CTX_FAILINFO_certConfirmed = (1 shl 11);
  OSSL_CMP_CTX_FAILINFO_wrongIntegrity = (1 shl 12);
  OSSL_CMP_CTX_FAILINFO_badRecipientNonce = (1 shl 13);
  OSSL_CMP_CTX_FAILINFO_timeNotAvailable = (1 shl 14);
  OSSL_CMP_CTX_FAILINFO_unacceptedPolicy = (1 shl 15);
  OSSL_CMP_CTX_FAILINFO_unacceptedExtension = (1 shl 16);
  OSSL_CMP_CTX_FAILINFO_addInfoNotAvailable = (1 shl 17);
  OSSL_CMP_CTX_FAILINFO_badSenderNonce = (1 shl 18);
  OSSL_CMP_CTX_FAILINFO_badCertTemplate = (1 shl 19);
  OSSL_CMP_CTX_FAILINFO_signerNotTrusted = (1 shl 20);
  OSSL_CMP_CTX_FAILINFO_transactionIdInUse = (1 shl 21);
  OSSL_CMP_CTX_FAILINFO_unsupportedVersion = (1 shl 22);
  OSSL_CMP_CTX_FAILINFO_notAuthorized = (1 shl 23);
  OSSL_CMP_CTX_FAILINFO_systemUnavail = (1 shl 24);
  OSSL_CMP_CTX_FAILINFO_systemFailure = (1 shl 25);
  OSSL_CMP_CTX_FAILINFO_duplicateCertReq = (1 shl 26);
  OSSL_CMP_PKISTATUS_rejected_by_client = -5;
  OSSL_CMP_PKISTATUS_checking_response = -4;
  OSSL_CMP_PKISTATUS_request = -3;
  OSSL_CMP_PKISTATUS_trans = -2;
  OSSL_CMP_PKISTATUS_unspecified = -1;
  OSSL_CMP_PKISTATUS_accepted = 0;
  OSSL_CMP_PKISTATUS_grantedWithMods = 1;
  OSSL_CMP_PKISTATUS_rejection = 2;
  OSSL_CMP_PKISTATUS_waiting = 3;
  OSSL_CMP_PKISTATUS_revocationWarning = 4;
  OSSL_CMP_PKISTATUS_revocationNotification = 5;
  OSSL_CMP_PKISTATUS_keyUpdateWarning = 6;
  OSSL_CMP_CERTORENCCERT_CERTIFICATE = 0;
  OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT = 1;
  OSSL_CMP_ATAV_free = OSSL_CRMF_ATTRIBUTETYPEANDVALUE_free;
  stack_st_OSSL_CMP_ATAV = stack_st_OSSL_CRMF_ATTRIBUTETYPEANDVALUE;
  sk_OSSL_CMP_ATAV_num = sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_num;
  sk_OSSL_CMP_ATAV_value = sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_value;
  sk_OSSL_CMP_ATAV_push = sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_push;
  sk_OSSL_CMP_ATAV_pop_free = sk_OSSL_CRMF_ATTRIBUTETYPEANDVALUE_pop_free;
  OSSL_CMP_OPT_LOG_VERBOSITY = 0;
  OSSL_CMP_OPT_KEEP_ALIVE = 10;
  OSSL_CMP_OPT_MSG_TIMEOUT = 11;
  OSSL_CMP_OPT_TOTAL_TIMEOUT = 12;
  OSSL_CMP_OPT_USE_TLS = 13;
  OSSL_CMP_OPT_VALIDITY_DAYS = 20;
  OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT = 21;
  OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL = 22;
  OSSL_CMP_OPT_POLICIES_CRITICAL = 23;
  OSSL_CMP_OPT_POPO_METHOD = 24;
  OSSL_CMP_OPT_IMPLICIT_CONFIRM = 25;
  OSSL_CMP_OPT_DISABLE_CONFIRM = 26;
  OSSL_CMP_OPT_REVOCATION_REASON = 27;
  OSSL_CMP_OPT_UNPROTECTED_SEND = 30;
  OSSL_CMP_OPT_UNPROTECTED_ERRORS = 31;
  OSSL_CMP_OPT_OWF_ALGNID = 32;
  OSSL_CMP_OPT_MAC_ALGNID = 33;
  OSSL_CMP_OPT_DIGEST_ALGNID = 34;
  OSSL_CMP_OPT_IGNORE_KEYUSAGE = 35;
  OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR = 36;
  OSSL_CMP_OPT_NO_CACHE_EXTRACERTS = 37;
  OSSL_CMP_PKISI_BUFLEN = 1024;
  OSSL_CMP_IR = 0;
  OSSL_CMP_CR = 2;
  OSSL_CMP_P10CR = 4;
  OSSL_CMP_KUR = 7;
  OSSL_CMP_GENM = 21;
  OSSL_CMP_ERROR = 23;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_CMP_PKISTATUS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKISTATUS_it}

  OSSL_CMP_PKIHEADER_new: function: POSSL_CMP_PKIHEADER; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKIHEADER_new}

  OSSL_CMP_PKIHEADER_free: procedure(a: POSSL_CMP_PKIHEADER); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKIHEADER_free}

  d2i_OSSL_CMP_PKIHEADER: function(a: PPOSSL_CMP_PKIHEADER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKIHEADER; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CMP_PKIHEADER}

  i2d_OSSL_CMP_PKIHEADER: function(a: POSSL_CMP_PKIHEADER; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CMP_PKIHEADER}

  OSSL_CMP_PKIHEADER_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKIHEADER_it}

  OSSL_CMP_MSG_dup: function(a: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_dup}

  d2i_OSSL_CMP_MSG: function(a: PPOSSL_CMP_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_MSG; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CMP_MSG}

  i2d_OSSL_CMP_MSG: function(a: POSSL_CMP_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CMP_MSG}

  OSSL_CMP_MSG_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_it}

  OSSL_CMP_ITAV_dup: function(a: POSSL_CMP_ITAV): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_dup}

  OSSL_CMP_ATAVS_new: function: POSSL_CMP_ATAVS; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAVS_new}

  OSSL_CMP_ATAVS_free: procedure(a: POSSL_CMP_ATAVS); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAVS_free}

  d2i_OSSL_CMP_ATAVS: function(a: PPOSSL_CMP_ATAVS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_ATAVS; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CMP_ATAVS}

  i2d_OSSL_CMP_ATAVS: function(a: POSSL_CMP_ATAVS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CMP_ATAVS}

  OSSL_CMP_ATAVS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAVS_it}

  OSSL_CMP_PKISI_new: function: POSSL_CMP_PKISI; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKISI_new}

  OSSL_CMP_PKISI_free: procedure(a: POSSL_CMP_PKISI); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKISI_free}

  d2i_OSSL_CMP_PKISI: function(a: PPOSSL_CMP_PKISI; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKISI; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CMP_PKISI}

  i2d_OSSL_CMP_PKISI: function(a: POSSL_CMP_PKISI; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CMP_PKISI}

  OSSL_CMP_PKISI_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKISI_it}

  OSSL_CMP_PKISI_dup: function(a: POSSL_CMP_PKISI): POSSL_CMP_PKISI; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_PKISI_dup}

  OSSL_CMP_ITAV_create: function(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_create}

  OSSL_CMP_ITAV_set0: procedure(itav: POSSL_CMP_ITAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_set0}

  OSSL_CMP_ITAV_get0_type: function(itav: POSSL_CMP_ITAV): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_type}

  OSSL_CMP_ITAV_get0_value: function(itav: POSSL_CMP_ITAV): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_value}

  OSSL_CMP_ITAV_push0_stack_item: function(sk_p: PPstack_st_OSSL_CMP_ITAV; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_push0_stack_item}

  OSSL_CMP_ITAV_free: procedure(itav: POSSL_CMP_ITAV); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_free}

  OSSL_CMP_ITAV_new0_certProfile: function(certProfile: Pstack_st_ASN1_UTF8STRING): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_new0_certProfile}

  OSSL_CMP_ITAV_get0_certProfile: function(itav: POSSL_CMP_ITAV; _out: PPstack_st_ASN1_UTF8STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_certProfile}

  OSSL_CMP_ITAV_new_caCerts: function(caCerts: Pstack_st_X509): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_new_caCerts}

  OSSL_CMP_ITAV_get0_caCerts: function(itav: POSSL_CMP_ITAV; _out: PPstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_caCerts}

  OSSL_CMP_ITAV_new_rootCaCert: function(rootCaCert: PX509): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_new_rootCaCert}

  OSSL_CMP_ITAV_get0_rootCaCert: function(itav: POSSL_CMP_ITAV; _out: PPX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_rootCaCert}

  OSSL_CMP_ITAV_new_rootCaKeyUpdate: function(newWithNew: PX509; newWithOld: PX509; oldWithNew: PX509): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_new_rootCaKeyUpdate}

  OSSL_CMP_ITAV_get0_rootCaKeyUpdate: function(itav: POSSL_CMP_ITAV; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_rootCaKeyUpdate}

  OSSL_CMP_CRLSTATUS_create: function(crl: PX509_CRL; cert: PX509; only_DN: TIdC_INT): POSSL_CMP_CRLSTATUS; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CRLSTATUS_create}

  OSSL_CMP_CRLSTATUS_new1: function(dpn: PDIST_POINT_NAME; issuer: PGENERAL_NAMES; thisUpdate: PASN1_TIME): POSSL_CMP_CRLSTATUS; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CRLSTATUS_new1}

  OSSL_CMP_CRLSTATUS_get0: function(crlstatus: POSSL_CMP_CRLSTATUS; dpn: PPDIST_POINT_NAME; issuer: PPGENERAL_NAMES; thisUpdate: PPASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CRLSTATUS_get0}

  OSSL_CMP_CRLSTATUS_free: procedure(crlstatus: POSSL_CMP_CRLSTATUS); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CRLSTATUS_free}

  OSSL_CMP_ITAV_new0_crlStatusList: function(crlStatusList: Pstack_st_OSSL_CMP_CRLSTATUS): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_new0_crlStatusList}

  OSSL_CMP_ITAV_get0_crlStatusList: function(itav: POSSL_CMP_ITAV; _out: PPstack_st_OSSL_CMP_CRLSTATUS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_crlStatusList}

  OSSL_CMP_ITAV_new_crls: function(crls: PX509_CRL): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_new_crls}

  OSSL_CMP_ITAV_get0_crls: function(it: POSSL_CMP_ITAV; _out: PPstack_st_X509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get0_crls}

  OSSL_CMP_ITAV_new0_certReqTemplate: function(certTemplate: POSSL_CRMF_CERTTEMPLATE; keySpec: POSSL_CMP_ATAVS): POSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_new0_certReqTemplate}

  OSSL_CMP_ITAV_get1_certReqTemplate: function(itav: POSSL_CMP_ITAV; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ITAV_get1_certReqTemplate}

  OSSL_CMP_ATAV_create: function(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ATAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_create}

  OSSL_CMP_ATAV_set0: procedure(itav: POSSL_CMP_ATAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_set0}

  OSSL_CMP_ATAV_get0_type: function(itav: POSSL_CMP_ATAV): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_get0_type}

  OSSL_CMP_ATAV_get0_value: function(itav: POSSL_CMP_ATAV): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_get0_value}

  OSSL_CMP_ATAV_new_algId: function(alg: PX509_ALGOR): POSSL_CMP_ATAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_new_algId}

  OSSL_CMP_ATAV_get0_algId: function(atav: POSSL_CMP_ATAV): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_get0_algId}

  OSSL_CMP_ATAV_new_rsaKeyLen: function(len: TIdC_INT): POSSL_CMP_ATAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_new_rsaKeyLen}

  OSSL_CMP_ATAV_get_rsaKeyLen: function(atav: POSSL_CMP_ATAV): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_get_rsaKeyLen}

  OSSL_CMP_ATAV_push1: function(sk_p: PPOSSL_CMP_ATAVS; atav: POSSL_CMP_ATAV): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_ATAV_push1}

  OSSL_CMP_MSG_free: procedure(msg: POSSL_CMP_MSG); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_free}

  OSSL_CMP_CTX_new: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_new}

  OSSL_CMP_CTX_free: procedure(ctx: POSSL_CMP_CTX); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_free}

  OSSL_CMP_CTX_reinit: function(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_reinit}

  OSSL_CMP_CTX_get0_libctx: function(ctx: POSSL_CMP_CTX): POSSL_LIB_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_libctx}

  OSSL_CMP_CTX_get0_propq: function(ctx: POSSL_CMP_CTX): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_propq}

  OSSL_CMP_CTX_set_option: function(ctx: POSSL_CMP_CTX; opt: TIdC_INT; val: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_option}

  OSSL_CMP_CTX_get_option: function(ctx: POSSL_CMP_CTX; opt: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get_option}

  OSSL_CMP_CTX_set_log_cb: function(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_log_cb_cb_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_log_cb}

  OSSL_CMP_CTX_print_errors: procedure(ctx: POSSL_CMP_CTX); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_print_errors}

  OSSL_CMP_CTX_set1_serverPath: function(ctx: POSSL_CMP_CTX; path: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_serverPath}

  OSSL_CMP_CTX_set1_server: function(ctx: POSSL_CMP_CTX; address: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_server}

  OSSL_CMP_CTX_set_serverPort: function(ctx: POSSL_CMP_CTX; port: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_serverPort}

  OSSL_CMP_CTX_set1_proxy: function(ctx: POSSL_CMP_CTX; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_proxy}

  OSSL_CMP_CTX_set1_no_proxy: function(ctx: POSSL_CMP_CTX; names: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_no_proxy}

  OSSL_CMP_CTX_set_http_cb: function(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_http_cb_cb_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_http_cb}

  OSSL_CMP_CTX_set_http_cb_arg: function(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_http_cb_arg}

  OSSL_CMP_CTX_get_http_cb_arg: function(ctx: POSSL_CMP_CTX): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get_http_cb_arg}

  OSSL_CMP_CTX_set_transfer_cb: function(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_transfer_cb_t_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_transfer_cb}

  OSSL_CMP_CTX_set_transfer_cb_arg: function(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_transfer_cb_arg}

  OSSL_CMP_CTX_get_transfer_cb_arg: function(ctx: POSSL_CMP_CTX): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get_transfer_cb_arg}

  OSSL_CMP_CTX_set1_srvCert: function(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_srvCert}

  OSSL_CMP_CTX_set1_expected_sender: function(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_expected_sender}

  OSSL_CMP_CTX_set0_trustedStore: function(ctx: POSSL_CMP_CTX; store: PX509_STORE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set0_trustedStore}

  OSSL_CMP_CTX_get0_trustedStore: function(ctx: POSSL_CMP_CTX): PX509_STORE; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_trustedStore}

  OSSL_CMP_CTX_set1_untrusted: function(ctx: POSSL_CMP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_untrusted}

  OSSL_CMP_CTX_get0_untrusted: function(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_untrusted}

  OSSL_CMP_CTX_set1_cert: function(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_cert}

  OSSL_CMP_CTX_build_cert_chain: function(ctx: POSSL_CMP_CTX; own_trusted: PX509_STORE; candidates: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_build_cert_chain}

  OSSL_CMP_CTX_set1_pkey: function(ctx: POSSL_CMP_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_pkey}

  OSSL_CMP_CTX_set1_referenceValue: function(ctx: POSSL_CMP_CTX; ref: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_referenceValue}

  OSSL_CMP_CTX_set1_secretValue: function(ctx: POSSL_CMP_CTX; sec: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_secretValue}

  OSSL_CMP_CTX_set1_recipient: function(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_recipient}

  OSSL_CMP_CTX_push0_geninfo_ITAV: function(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_push0_geninfo_ITAV}

  OSSL_CMP_CTX_reset_geninfo_ITAVs: function(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_reset_geninfo_ITAVs}

  OSSL_CMP_CTX_get0_geninfo_ITAVs: function(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_geninfo_ITAVs}

  OSSL_CMP_CTX_set1_extraCertsOut: function(ctx: POSSL_CMP_CTX; extraCertsOut: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_extraCertsOut}

  OSSL_CMP_CTX_set0_newPkey: function(ctx: POSSL_CMP_CTX; priv: TIdC_INT; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set0_newPkey}

  OSSL_CMP_CTX_get0_newPkey: function(ctx: POSSL_CMP_CTX; priv: TIdC_INT): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_newPkey}

  OSSL_CMP_CTX_set1_issuer: function(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_issuer}

  OSSL_CMP_CTX_set1_serialNumber: function(ctx: POSSL_CMP_CTX; sn: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_serialNumber}

  OSSL_CMP_CTX_set1_subjectName: function(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_subjectName}

  OSSL_CMP_CTX_push1_subjectAltName: function(ctx: POSSL_CMP_CTX; name: PGENERAL_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_push1_subjectAltName}

  OSSL_CMP_CTX_set0_reqExtensions: function(ctx: POSSL_CMP_CTX; exts: PX509_EXTENSIONS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set0_reqExtensions}

  OSSL_CMP_CTX_reqExtensions_have_SAN: function(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_reqExtensions_have_SAN}

  OSSL_CMP_CTX_push0_policy: function(ctx: POSSL_CMP_CTX; pinfo: PPOLICYINFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_push0_policy}

  OSSL_CMP_CTX_set1_oldCert: function(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_oldCert}

  OSSL_CMP_CTX_set1_p10CSR: function(ctx: POSSL_CMP_CTX; csr: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_p10CSR}

  OSSL_CMP_CTX_push0_genm_ITAV: function(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_push0_genm_ITAV}

  OSSL_CMP_certConf_cb: function(ctx: POSSL_CMP_CTX; cert: PX509; fail_info: TIdC_INT; text: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_certConf_cb}

  OSSL_CMP_CTX_set_certConf_cb: function(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_certConf_cb_t_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_certConf_cb}

  OSSL_CMP_CTX_set_certConf_cb_arg: function(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set_certConf_cb_arg}

  OSSL_CMP_CTX_get_certConf_cb_arg: function(ctx: POSSL_CMP_CTX): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get_certConf_cb_arg}

  OSSL_CMP_CTX_get_status: function(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get_status}

  OSSL_CMP_CTX_get0_statusString: function(ctx: POSSL_CMP_CTX): POSSL_CMP_PKIFREETEXT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_statusString}

  OSSL_CMP_CTX_get_failInfoCode: function(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get_failInfoCode}

  OSSL_CMP_CTX_get0_validatedSrvCert: function(ctx: POSSL_CMP_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_validatedSrvCert}

  OSSL_CMP_CTX_get0_newCert: function(ctx: POSSL_CMP_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get0_newCert}

  OSSL_CMP_CTX_get1_newChain: function(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get1_newChain}

  OSSL_CMP_CTX_get1_caPubs: function(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get1_caPubs}

  OSSL_CMP_CTX_get1_extraCertsIn: function(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_get1_extraCertsIn}

  OSSL_CMP_CTX_set1_transactionID: function(ctx: POSSL_CMP_CTX; id: PASN1_OCTET_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_transactionID}

  OSSL_CMP_CTX_set1_senderNonce: function(ctx: POSSL_CMP_CTX; nonce: PASN1_OCTET_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_set1_senderNonce}

  OSSL_CMP_CTX_snprint_PKIStatus: function(ctx: POSSL_CMP_CTX; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_snprint_PKIStatus}

  OSSL_CMP_snprint_PKIStatusInfo: function(statusInfo: POSSL_CMP_PKISI; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_snprint_PKIStatusInfo}

  OSSL_CMP_STATUSINFO_new: function(status: TIdC_INT; fail_info: TIdC_INT; text: PIdAnsiChar): POSSL_CMP_PKISI; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_STATUSINFO_new}

  OSSL_CMP_HDR_get0_transactionID: function(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_HDR_get0_transactionID}

  OSSL_CMP_HDR_get0_recipNonce: function(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_HDR_get0_recipNonce}

  OSSL_CMP_HDR_get0_geninfo_ITAVs: function(hdr: POSSL_CMP_PKIHEADER): Pstack_st_OSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_HDR_get0_geninfo_ITAVs}

  OSSL_CMP_MSG_get0_header: function(msg: POSSL_CMP_MSG): POSSL_CMP_PKIHEADER; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_get0_header}

  OSSL_CMP_MSG_get_bodytype: function(msg: POSSL_CMP_MSG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_get_bodytype}

  OSSL_CMP_MSG_get0_certreq_publickey: function(msg: POSSL_CMP_MSG): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_get0_certreq_publickey}

  OSSL_CMP_MSG_update_transactionID: function(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_update_transactionID}

  OSSL_CMP_MSG_update_recipNonce: function(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_update_recipNonce}

  OSSL_CMP_CTX_setup_CRM: function(ctx: POSSL_CMP_CTX; for_KUR: TIdC_INT; rid: TIdC_INT): POSSL_CRMF_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_setup_CRM}

  OSSL_CMP_MSG_read: function(_file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_read}

  OSSL_CMP_MSG_write: function(_file: PIdAnsiChar; msg: POSSL_CMP_MSG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_write}

  d2i_OSSL_CMP_MSG_bio: function(bio: PBIO; msg: PPOSSL_CMP_MSG): POSSL_CMP_MSG; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_CMP_MSG_bio}

  i2d_OSSL_CMP_MSG_bio: function(bio: PBIO; msg: POSSL_CMP_MSG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_CMP_MSG_bio}

  OSSL_CMP_validate_msg: function(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_validate_msg}

  OSSL_CMP_validate_cert_path: function(ctx: POSSL_CMP_CTX; trusted_store: PX509_STORE; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_validate_cert_path}

  OSSL_CMP_MSG_http_perform: function(ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_MSG_http_perform}

  OSSL_CMP_SRV_process_request: function(srv_ctx: POSSL_CMP_SRV_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_process_request}

  OSSL_CMP_CTX_server_perform: function(client_ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_CTX_server_perform}

  OSSL_CMP_SRV_CTX_new: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_SRV_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_new}

  OSSL_CMP_SRV_CTX_free: procedure(srv_ctx: POSSL_CMP_SRV_CTX); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_free}

  OSSL_CMP_SRV_CTX_init: function(srv_ctx: POSSL_CMP_SRV_CTX; custom_ctx: Pointer; process_cert_request: TOSSL_CMP_SRV_cert_request_cb_t_func_cb; process_rr: TOSSL_CMP_SRV_rr_cb_t_func_cb; process_genm: TOSSL_CMP_SRV_genm_cb_t_func_cb; process_error: TOSSL_CMP_SRV_error_cb_t_func_cb; process_certConf: TOSSL_CMP_SRV_certConf_cb_t_func_cb; process_pollReq: TOSSL_CMP_SRV_pollReq_cb_t_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_init}

  OSSL_CMP_SRV_CTX_init_trans: function(srv_ctx: POSSL_CMP_SRV_CTX; delay: TOSSL_CMP_SRV_delayed_delivery_cb_t_func_cb; clean: TOSSL_CMP_SRV_clean_transaction_cb_t_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_init_trans}

  OSSL_CMP_SRV_CTX_get0_cmp_ctx: function(srv_ctx: POSSL_CMP_SRV_CTX): POSSL_CMP_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_get0_cmp_ctx}

  OSSL_CMP_SRV_CTX_get0_custom_ctx: function(srv_ctx: POSSL_CMP_SRV_CTX): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_get0_custom_ctx}

  OSSL_CMP_SRV_CTX_set_send_unprotected_errors: function(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_set_send_unprotected_errors}

  OSSL_CMP_SRV_CTX_set_accept_unprotected: function(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_set_accept_unprotected}

  OSSL_CMP_SRV_CTX_set_accept_raverified: function(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_set_accept_raverified}

  OSSL_CMP_SRV_CTX_set_grant_implicit_confirm: function(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_SRV_CTX_set_grant_implicit_confirm}

  OSSL_CMP_exec_certreq: function(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG): PX509; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_exec_certreq}

  OSSL_CMP_try_certreq: function(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG; checkAfter: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_try_certreq}

  OSSL_CMP_exec_RR_ses: function(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_exec_RR_ses}

  OSSL_CMP_exec_GENM_ses: function(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_exec_GENM_ses}

  OSSL_CMP_get1_caCerts: function(ctx: POSSL_CMP_CTX; _out: PPstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_get1_caCerts}

  OSSL_CMP_get1_rootCaKeyUpdate: function(ctx: POSSL_CMP_CTX; oldWithOld: PX509; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_get1_rootCaKeyUpdate}

  OSSL_CMP_get1_crlUpdate: function(ctx: POSSL_CMP_CTX; crlcert: PX509; last_crl: PX509_CRL; crl: PPX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_get1_crlUpdate}

  OSSL_CMP_get1_certReqTemplate: function(ctx: POSSL_CMP_CTX; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_get1_certReqTemplate}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_CMP_PKISTATUS_it: PASN1_ITEM; cdecl;
function OSSL_CMP_PKIHEADER_new: POSSL_CMP_PKIHEADER; cdecl;
procedure OSSL_CMP_PKIHEADER_free(a: POSSL_CMP_PKIHEADER); cdecl;
function d2i_OSSL_CMP_PKIHEADER(a: PPOSSL_CMP_PKIHEADER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKIHEADER; cdecl;
function i2d_OSSL_CMP_PKIHEADER(a: POSSL_CMP_PKIHEADER; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_PKIHEADER_it: PASN1_ITEM; cdecl;
function OSSL_CMP_MSG_dup(a: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl;
function d2i_OSSL_CMP_MSG(a: PPOSSL_CMP_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_MSG; cdecl;
function i2d_OSSL_CMP_MSG(a: POSSL_CMP_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_MSG_it: PASN1_ITEM; cdecl;
function OSSL_CMP_ITAV_dup(a: POSSL_CMP_ITAV): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ATAVS_new: POSSL_CMP_ATAVS; cdecl;
procedure OSSL_CMP_ATAVS_free(a: POSSL_CMP_ATAVS); cdecl;
function d2i_OSSL_CMP_ATAVS(a: PPOSSL_CMP_ATAVS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_ATAVS; cdecl;
function i2d_OSSL_CMP_ATAVS(a: POSSL_CMP_ATAVS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_ATAVS_it: PASN1_ITEM; cdecl;
function OSSL_CMP_PKISI_new: POSSL_CMP_PKISI; cdecl;
procedure OSSL_CMP_PKISI_free(a: POSSL_CMP_PKISI); cdecl;
function d2i_OSSL_CMP_PKISI(a: PPOSSL_CMP_PKISI; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKISI; cdecl;
function i2d_OSSL_CMP_PKISI(a: POSSL_CMP_PKISI; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_PKISI_it: PASN1_ITEM; cdecl;
function OSSL_CMP_PKISI_dup(a: POSSL_CMP_PKISI): POSSL_CMP_PKISI; cdecl;
function OSSL_CMP_ITAV_create(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ITAV; cdecl;
procedure OSSL_CMP_ITAV_set0(itav: POSSL_CMP_ITAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl;
function OSSL_CMP_ITAV_get0_type(itav: POSSL_CMP_ITAV): PASN1_OBJECT; cdecl;
function OSSL_CMP_ITAV_get0_value(itav: POSSL_CMP_ITAV): PASN1_TYPE; cdecl;
function OSSL_CMP_ITAV_push0_stack_item(sk_p: PPstack_st_OSSL_CMP_ITAV; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl;
procedure OSSL_CMP_ITAV_free(itav: POSSL_CMP_ITAV); cdecl;
function OSSL_CMP_ITAV_new0_certProfile(certProfile: Pstack_st_ASN1_UTF8STRING): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ITAV_get0_certProfile(itav: POSSL_CMP_ITAV; _out: PPstack_st_ASN1_UTF8STRING): TIdC_INT; cdecl;
function OSSL_CMP_ITAV_new_caCerts(caCerts: Pstack_st_X509): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ITAV_get0_caCerts(itav: POSSL_CMP_ITAV; _out: PPstack_st_X509): TIdC_INT; cdecl;
function OSSL_CMP_ITAV_new_rootCaCert(rootCaCert: PX509): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ITAV_get0_rootCaCert(itav: POSSL_CMP_ITAV; _out: PPX509): TIdC_INT; cdecl;
function OSSL_CMP_ITAV_new_rootCaKeyUpdate(newWithNew: PX509; newWithOld: PX509; oldWithNew: PX509): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav: POSSL_CMP_ITAV; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl;
function OSSL_CMP_CRLSTATUS_create(crl: PX509_CRL; cert: PX509; only_DN: TIdC_INT): POSSL_CMP_CRLSTATUS; cdecl;
function OSSL_CMP_CRLSTATUS_new1(dpn: PDIST_POINT_NAME; issuer: PGENERAL_NAMES; thisUpdate: PASN1_TIME): POSSL_CMP_CRLSTATUS; cdecl;
function OSSL_CMP_CRLSTATUS_get0(crlstatus: POSSL_CMP_CRLSTATUS; dpn: PPDIST_POINT_NAME; issuer: PPGENERAL_NAMES; thisUpdate: PPASN1_TIME): TIdC_INT; cdecl;
procedure OSSL_CMP_CRLSTATUS_free(crlstatus: POSSL_CMP_CRLSTATUS); cdecl;
function OSSL_CMP_ITAV_new0_crlStatusList(crlStatusList: Pstack_st_OSSL_CMP_CRLSTATUS): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ITAV_get0_crlStatusList(itav: POSSL_CMP_ITAV; _out: PPstack_st_OSSL_CMP_CRLSTATUS): TIdC_INT; cdecl;
function OSSL_CMP_ITAV_new_crls(crls: PX509_CRL): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ITAV_get0_crls(it: POSSL_CMP_ITAV; _out: PPstack_st_X509_CRL): TIdC_INT; cdecl;
function OSSL_CMP_ITAV_new0_certReqTemplate(certTemplate: POSSL_CRMF_CERTTEMPLATE; keySpec: POSSL_CMP_ATAVS): POSSL_CMP_ITAV; cdecl;
function OSSL_CMP_ITAV_get1_certReqTemplate(itav: POSSL_CMP_ITAV; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl;
function OSSL_CMP_ATAV_create(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ATAV; cdecl;
procedure OSSL_CMP_ATAV_set0(itav: POSSL_CMP_ATAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl;
function OSSL_CMP_ATAV_get0_type(itav: POSSL_CMP_ATAV): PASN1_OBJECT; cdecl;
function OSSL_CMP_ATAV_get0_value(itav: POSSL_CMP_ATAV): PASN1_TYPE; cdecl;
function OSSL_CMP_ATAV_new_algId(alg: PX509_ALGOR): POSSL_CMP_ATAV; cdecl;
function OSSL_CMP_ATAV_get0_algId(atav: POSSL_CMP_ATAV): PX509_ALGOR; cdecl;
function OSSL_CMP_ATAV_new_rsaKeyLen(len: TIdC_INT): POSSL_CMP_ATAV; cdecl;
function OSSL_CMP_ATAV_get_rsaKeyLen(atav: POSSL_CMP_ATAV): TIdC_INT; cdecl;
function OSSL_CMP_ATAV_push1(sk_p: PPOSSL_CMP_ATAVS; atav: POSSL_CMP_ATAV): TIdC_INT; cdecl;
procedure OSSL_CMP_MSG_free(msg: POSSL_CMP_MSG); cdecl;
function OSSL_CMP_CTX_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_CTX; cdecl;
procedure OSSL_CMP_CTX_free(ctx: POSSL_CMP_CTX); cdecl;
function OSSL_CMP_CTX_reinit(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get0_libctx(ctx: POSSL_CMP_CTX): POSSL_LIB_CTX; cdecl;
function OSSL_CMP_CTX_get0_propq(ctx: POSSL_CMP_CTX): PIdAnsiChar; cdecl;
function OSSL_CMP_CTX_set_option(ctx: POSSL_CMP_CTX; opt: TIdC_INT; val: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get_option(ctx: POSSL_CMP_CTX; opt: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set_log_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_log_cb_cb_cb): TIdC_INT; cdecl;
procedure OSSL_CMP_CTX_print_errors(ctx: POSSL_CMP_CTX); cdecl;
function OSSL_CMP_CTX_set1_serverPath(ctx: POSSL_CMP_CTX; path: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_server(ctx: POSSL_CMP_CTX; address: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set_serverPort(ctx: POSSL_CMP_CTX; port: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_proxy(ctx: POSSL_CMP_CTX; name: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_no_proxy(ctx: POSSL_CMP_CTX; names: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set_http_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_http_cb_cb_cb): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set_http_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get_http_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl;
function OSSL_CMP_CTX_set_transfer_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_transfer_cb_t_func_cb): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set_transfer_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get_transfer_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl;
function OSSL_CMP_CTX_set1_srvCert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_expected_sender(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set0_trustedStore(ctx: POSSL_CMP_CTX; store: PX509_STORE): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get0_trustedStore(ctx: POSSL_CMP_CTX): PX509_STORE; cdecl;
function OSSL_CMP_CTX_set1_untrusted(ctx: POSSL_CMP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get0_untrusted(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl;
function OSSL_CMP_CTX_set1_cert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl;
function OSSL_CMP_CTX_build_cert_chain(ctx: POSSL_CMP_CTX; own_trusted: PX509_STORE; candidates: Pstack_st_X509): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_pkey(ctx: POSSL_CMP_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_referenceValue(ctx: POSSL_CMP_CTX; ref: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_secretValue(ctx: POSSL_CMP_CTX; sec: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_recipient(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl;
function OSSL_CMP_CTX_push0_geninfo_ITAV(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl;
function OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl;
function OSSL_CMP_CTX_set1_extraCertsOut(ctx: POSSL_CMP_CTX; extraCertsOut: Pstack_st_X509): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set0_newPkey(ctx: POSSL_CMP_CTX; priv: TIdC_INT; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get0_newPkey(ctx: POSSL_CMP_CTX; priv: TIdC_INT): PEVP_PKEY; cdecl;
function OSSL_CMP_CTX_set1_issuer(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_serialNumber(ctx: POSSL_CMP_CTX; sn: PASN1_INTEGER): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_subjectName(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl;
function OSSL_CMP_CTX_push1_subjectAltName(ctx: POSSL_CMP_CTX; name: PGENERAL_NAME): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set0_reqExtensions(ctx: POSSL_CMP_CTX; exts: PX509_EXTENSIONS): TIdC_INT; cdecl;
function OSSL_CMP_CTX_reqExtensions_have_SAN(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl;
function OSSL_CMP_CTX_push0_policy(ctx: POSSL_CMP_CTX; pinfo: PPOLICYINFO): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_oldCert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_p10CSR(ctx: POSSL_CMP_CTX; csr: PX509_REQ): TIdC_INT; cdecl;
function OSSL_CMP_CTX_push0_genm_ITAV(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl;
function OSSL_CMP_certConf_cb(ctx: POSSL_CMP_CTX; cert: PX509; fail_info: TIdC_INT; text: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set_certConf_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_certConf_cb_t_func_cb): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set_certConf_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get_certConf_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl;
function OSSL_CMP_CTX_get_status(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get0_statusString(ctx: POSSL_CMP_CTX): POSSL_CMP_PKIFREETEXT; cdecl;
function OSSL_CMP_CTX_get_failInfoCode(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl;
function OSSL_CMP_CTX_get0_validatedSrvCert(ctx: POSSL_CMP_CTX): PX509; cdecl;
function OSSL_CMP_CTX_get0_newCert(ctx: POSSL_CMP_CTX): PX509; cdecl;
function OSSL_CMP_CTX_get1_newChain(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl;
function OSSL_CMP_CTX_get1_caPubs(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl;
function OSSL_CMP_CTX_get1_extraCertsIn(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl;
function OSSL_CMP_CTX_set1_transactionID(ctx: POSSL_CMP_CTX; id: PASN1_OCTET_STRING): TIdC_INT; cdecl;
function OSSL_CMP_CTX_set1_senderNonce(ctx: POSSL_CMP_CTX; nonce: PASN1_OCTET_STRING): TIdC_INT; cdecl;
function OSSL_CMP_CTX_snprint_PKIStatus(ctx: POSSL_CMP_CTX; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl;
function OSSL_CMP_snprint_PKIStatusInfo(statusInfo: POSSL_CMP_PKISI; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl;
function OSSL_CMP_STATUSINFO_new(status: TIdC_INT; fail_info: TIdC_INT; text: PIdAnsiChar): POSSL_CMP_PKISI; cdecl;
function OSSL_CMP_HDR_get0_transactionID(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl;
function OSSL_CMP_HDR_get0_recipNonce(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl;
function OSSL_CMP_HDR_get0_geninfo_ITAVs(hdr: POSSL_CMP_PKIHEADER): Pstack_st_OSSL_CMP_ITAV; cdecl;
function OSSL_CMP_MSG_get0_header(msg: POSSL_CMP_MSG): POSSL_CMP_PKIHEADER; cdecl;
function OSSL_CMP_MSG_get_bodytype(msg: POSSL_CMP_MSG): TIdC_INT; cdecl;
function OSSL_CMP_MSG_get0_certreq_publickey(msg: POSSL_CMP_MSG): PX509_PUBKEY; cdecl;
function OSSL_CMP_MSG_update_transactionID(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl;
function OSSL_CMP_MSG_update_recipNonce(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl;
function OSSL_CMP_CTX_setup_CRM(ctx: POSSL_CMP_CTX; for_KUR: TIdC_INT; rid: TIdC_INT): POSSL_CRMF_MSG; cdecl;
function OSSL_CMP_MSG_read(_file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_MSG; cdecl;
function OSSL_CMP_MSG_write(_file: PIdAnsiChar; msg: POSSL_CMP_MSG): TIdC_INT; cdecl;
function d2i_OSSL_CMP_MSG_bio(bio: PBIO; msg: PPOSSL_CMP_MSG): POSSL_CMP_MSG; cdecl;
function i2d_OSSL_CMP_MSG_bio(bio: PBIO; msg: POSSL_CMP_MSG): TIdC_INT; cdecl;
function OSSL_CMP_validate_msg(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl;
function OSSL_CMP_validate_cert_path(ctx: POSSL_CMP_CTX; trusted_store: PX509_STORE; cert: PX509): TIdC_INT; cdecl;
function OSSL_CMP_MSG_http_perform(ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl;
function OSSL_CMP_SRV_process_request(srv_ctx: POSSL_CMP_SRV_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl;
function OSSL_CMP_CTX_server_perform(client_ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl;
function OSSL_CMP_SRV_CTX_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_SRV_CTX; cdecl;
procedure OSSL_CMP_SRV_CTX_free(srv_ctx: POSSL_CMP_SRV_CTX); cdecl;
function OSSL_CMP_SRV_CTX_init(srv_ctx: POSSL_CMP_SRV_CTX; custom_ctx: Pointer; process_cert_request: TOSSL_CMP_SRV_cert_request_cb_t_func_cb; process_rr: TOSSL_CMP_SRV_rr_cb_t_func_cb; process_genm: TOSSL_CMP_SRV_genm_cb_t_func_cb; process_error: TOSSL_CMP_SRV_error_cb_t_func_cb; process_certConf: TOSSL_CMP_SRV_certConf_cb_t_func_cb; process_pollReq: TOSSL_CMP_SRV_pollReq_cb_t_func_cb): TIdC_INT; cdecl;
function OSSL_CMP_SRV_CTX_init_trans(srv_ctx: POSSL_CMP_SRV_CTX; delay: TOSSL_CMP_SRV_delayed_delivery_cb_t_func_cb; clean: TOSSL_CMP_SRV_clean_transaction_cb_t_func_cb): TIdC_INT; cdecl;
function OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv_ctx: POSSL_CMP_SRV_CTX): POSSL_CMP_CTX; cdecl;
function OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx: POSSL_CMP_SRV_CTX): Pointer; cdecl;
function OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_SRV_CTX_set_accept_unprotected(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_SRV_CTX_set_accept_raverified(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_exec_certreq(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG): PX509; cdecl;
function OSSL_CMP_try_certreq(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG; checkAfter: PIdC_INT): TIdC_INT; cdecl;
function OSSL_CMP_exec_RR_ses(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl;
function OSSL_CMP_exec_GENM_ses(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl;
function OSSL_CMP_get1_caCerts(ctx: POSSL_CMP_CTX; _out: PPstack_st_X509): TIdC_INT; cdecl;
function OSSL_CMP_get1_rootCaKeyUpdate(ctx: POSSL_CMP_CTX; oldWithOld: PX509; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl;
function OSSL_CMP_get1_crlUpdate(ctx: POSSL_CMP_CTX; crlcert: PX509; last_crl: PX509_CRL; crl: PPX509_CRL): TIdC_INT; cdecl;
function OSSL_CMP_get1_certReqTemplate(ctx: POSSL_CMP_CTX; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function OSSL_CMP_CTX_set_log_verbosity(ctx: Pointer; level: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_CMP_exec_IR_ses(ctx: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_CMP_exec_CR_ses(ctx: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_CMP_exec_P10CR_ses(ctx: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_CMP_exec_KUR_ses(ctx: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_CMP_CTX_set0_trusted(ctx: POSSL_CMP_CTX; store: PX509_STORE): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_CMP_CTX_get0_trusted(ctx: POSSL_CMP_CTX): PX509_STORE; cdecl;
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

function OSSL_CMP_PKISTATUS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CMP_PKISTATUS_it';
function OSSL_CMP_PKIHEADER_new: POSSL_CMP_PKIHEADER; cdecl external CLibCrypto name 'OSSL_CMP_PKIHEADER_new';
procedure OSSL_CMP_PKIHEADER_free(a: POSSL_CMP_PKIHEADER); cdecl external CLibCrypto name 'OSSL_CMP_PKIHEADER_free';
function d2i_OSSL_CMP_PKIHEADER(a: PPOSSL_CMP_PKIHEADER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKIHEADER; cdecl external CLibCrypto name 'd2i_OSSL_CMP_PKIHEADER';
function i2d_OSSL_CMP_PKIHEADER(a: POSSL_CMP_PKIHEADER; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CMP_PKIHEADER';
function OSSL_CMP_PKIHEADER_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CMP_PKIHEADER_it';
function OSSL_CMP_MSG_dup(a: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl external CLibCrypto name 'OSSL_CMP_MSG_dup';
function d2i_OSSL_CMP_MSG(a: PPOSSL_CMP_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_MSG; cdecl external CLibCrypto name 'd2i_OSSL_CMP_MSG';
function i2d_OSSL_CMP_MSG(a: POSSL_CMP_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CMP_MSG';
function OSSL_CMP_MSG_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CMP_MSG_it';
function OSSL_CMP_ITAV_dup(a: POSSL_CMP_ITAV): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_dup';
function OSSL_CMP_ATAVS_new: POSSL_CMP_ATAVS; cdecl external CLibCrypto name 'OSSL_CMP_ATAVS_new';
procedure OSSL_CMP_ATAVS_free(a: POSSL_CMP_ATAVS); cdecl external CLibCrypto name 'OSSL_CMP_ATAVS_free';
function d2i_OSSL_CMP_ATAVS(a: PPOSSL_CMP_ATAVS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_ATAVS; cdecl external CLibCrypto name 'd2i_OSSL_CMP_ATAVS';
function i2d_OSSL_CMP_ATAVS(a: POSSL_CMP_ATAVS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CMP_ATAVS';
function OSSL_CMP_ATAVS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CMP_ATAVS_it';
function OSSL_CMP_PKISI_new: POSSL_CMP_PKISI; cdecl external CLibCrypto name 'OSSL_CMP_PKISI_new';
procedure OSSL_CMP_PKISI_free(a: POSSL_CMP_PKISI); cdecl external CLibCrypto name 'OSSL_CMP_PKISI_free';
function d2i_OSSL_CMP_PKISI(a: PPOSSL_CMP_PKISI; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKISI; cdecl external CLibCrypto name 'd2i_OSSL_CMP_PKISI';
function i2d_OSSL_CMP_PKISI(a: POSSL_CMP_PKISI; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CMP_PKISI';
function OSSL_CMP_PKISI_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_CMP_PKISI_it';
function OSSL_CMP_PKISI_dup(a: POSSL_CMP_PKISI): POSSL_CMP_PKISI; cdecl external CLibCrypto name 'OSSL_CMP_PKISI_dup';
function OSSL_CMP_ITAV_create(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_create';
procedure OSSL_CMP_ITAV_set0(itav: POSSL_CMP_ITAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl external CLibCrypto name 'OSSL_CMP_ITAV_set0';
function OSSL_CMP_ITAV_get0_type(itav: POSSL_CMP_ITAV): PASN1_OBJECT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_type';
function OSSL_CMP_ITAV_get0_value(itav: POSSL_CMP_ITAV): PASN1_TYPE; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_value';
function OSSL_CMP_ITAV_push0_stack_item(sk_p: PPstack_st_OSSL_CMP_ITAV; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_push0_stack_item';
procedure OSSL_CMP_ITAV_free(itav: POSSL_CMP_ITAV); cdecl external CLibCrypto name 'OSSL_CMP_ITAV_free';
function OSSL_CMP_ITAV_new0_certProfile(certProfile: Pstack_st_ASN1_UTF8STRING): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_new0_certProfile';
function OSSL_CMP_ITAV_get0_certProfile(itav: POSSL_CMP_ITAV; _out: PPstack_st_ASN1_UTF8STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_certProfile';
function OSSL_CMP_ITAV_new_caCerts(caCerts: Pstack_st_X509): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_new_caCerts';
function OSSL_CMP_ITAV_get0_caCerts(itav: POSSL_CMP_ITAV; _out: PPstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_caCerts';
function OSSL_CMP_ITAV_new_rootCaCert(rootCaCert: PX509): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_new_rootCaCert';
function OSSL_CMP_ITAV_get0_rootCaCert(itav: POSSL_CMP_ITAV; _out: PPX509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_rootCaCert';
function OSSL_CMP_ITAV_new_rootCaKeyUpdate(newWithNew: PX509; newWithOld: PX509; oldWithNew: PX509): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_new_rootCaKeyUpdate';
function OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav: POSSL_CMP_ITAV; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_rootCaKeyUpdate';
function OSSL_CMP_CRLSTATUS_create(crl: PX509_CRL; cert: PX509; only_DN: TIdC_INT): POSSL_CMP_CRLSTATUS; cdecl external CLibCrypto name 'OSSL_CMP_CRLSTATUS_create';
function OSSL_CMP_CRLSTATUS_new1(dpn: PDIST_POINT_NAME; issuer: PGENERAL_NAMES; thisUpdate: PASN1_TIME): POSSL_CMP_CRLSTATUS; cdecl external CLibCrypto name 'OSSL_CMP_CRLSTATUS_new1';
function OSSL_CMP_CRLSTATUS_get0(crlstatus: POSSL_CMP_CRLSTATUS; dpn: PPDIST_POINT_NAME; issuer: PPGENERAL_NAMES; thisUpdate: PPASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CRLSTATUS_get0';
procedure OSSL_CMP_CRLSTATUS_free(crlstatus: POSSL_CMP_CRLSTATUS); cdecl external CLibCrypto name 'OSSL_CMP_CRLSTATUS_free';
function OSSL_CMP_ITAV_new0_crlStatusList(crlStatusList: Pstack_st_OSSL_CMP_CRLSTATUS): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_new0_crlStatusList';
function OSSL_CMP_ITAV_get0_crlStatusList(itav: POSSL_CMP_ITAV; _out: PPstack_st_OSSL_CMP_CRLSTATUS): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_crlStatusList';
function OSSL_CMP_ITAV_new_crls(crls: PX509_CRL): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_new_crls';
function OSSL_CMP_ITAV_get0_crls(it: POSSL_CMP_ITAV; _out: PPstack_st_X509_CRL): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get0_crls';
function OSSL_CMP_ITAV_new0_certReqTemplate(certTemplate: POSSL_CRMF_CERTTEMPLATE; keySpec: POSSL_CMP_ATAVS): POSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_new0_certReqTemplate';
function OSSL_CMP_ITAV_get1_certReqTemplate(itav: POSSL_CMP_ITAV; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ITAV_get1_certReqTemplate';
function OSSL_CMP_ATAV_create(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ATAV; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_create';
procedure OSSL_CMP_ATAV_set0(itav: POSSL_CMP_ATAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl external CLibCrypto name 'OSSL_CMP_ATAV_set0';
function OSSL_CMP_ATAV_get0_type(itav: POSSL_CMP_ATAV): PASN1_OBJECT; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_get0_type';
function OSSL_CMP_ATAV_get0_value(itav: POSSL_CMP_ATAV): PASN1_TYPE; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_get0_value';
function OSSL_CMP_ATAV_new_algId(alg: PX509_ALGOR): POSSL_CMP_ATAV; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_new_algId';
function OSSL_CMP_ATAV_get0_algId(atav: POSSL_CMP_ATAV): PX509_ALGOR; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_get0_algId';
function OSSL_CMP_ATAV_new_rsaKeyLen(len: TIdC_INT): POSSL_CMP_ATAV; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_new_rsaKeyLen';
function OSSL_CMP_ATAV_get_rsaKeyLen(atav: POSSL_CMP_ATAV): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_get_rsaKeyLen';
function OSSL_CMP_ATAV_push1(sk_p: PPOSSL_CMP_ATAVS; atav: POSSL_CMP_ATAV): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_ATAV_push1';
procedure OSSL_CMP_MSG_free(msg: POSSL_CMP_MSG); cdecl external CLibCrypto name 'OSSL_CMP_MSG_free';
function OSSL_CMP_CTX_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_CTX; cdecl external CLibCrypto name 'OSSL_CMP_CTX_new';
procedure OSSL_CMP_CTX_free(ctx: POSSL_CMP_CTX); cdecl external CLibCrypto name 'OSSL_CMP_CTX_free';
function OSSL_CMP_CTX_reinit(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_reinit';
function OSSL_CMP_CTX_get0_libctx(ctx: POSSL_CMP_CTX): POSSL_LIB_CTX; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_libctx';
function OSSL_CMP_CTX_get0_propq(ctx: POSSL_CMP_CTX): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_propq';
function OSSL_CMP_CTX_set_option(ctx: POSSL_CMP_CTX; opt: TIdC_INT; val: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_option';
function OSSL_CMP_CTX_get_option(ctx: POSSL_CMP_CTX; opt: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get_option';
function OSSL_CMP_CTX_set_log_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_log_cb_cb_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_log_cb';
procedure OSSL_CMP_CTX_print_errors(ctx: POSSL_CMP_CTX); cdecl external CLibCrypto name 'OSSL_CMP_CTX_print_errors';
function OSSL_CMP_CTX_set1_serverPath(ctx: POSSL_CMP_CTX; path: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_serverPath';
function OSSL_CMP_CTX_set1_server(ctx: POSSL_CMP_CTX; address: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_server';
function OSSL_CMP_CTX_set_serverPort(ctx: POSSL_CMP_CTX; port: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_serverPort';
function OSSL_CMP_CTX_set1_proxy(ctx: POSSL_CMP_CTX; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_proxy';
function OSSL_CMP_CTX_set1_no_proxy(ctx: POSSL_CMP_CTX; names: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_no_proxy';
function OSSL_CMP_CTX_set_http_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_http_cb_cb_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_http_cb';
function OSSL_CMP_CTX_set_http_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_http_cb_arg';
function OSSL_CMP_CTX_get_http_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get_http_cb_arg';
function OSSL_CMP_CTX_set_transfer_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_transfer_cb_t_func_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_transfer_cb';
function OSSL_CMP_CTX_set_transfer_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_transfer_cb_arg';
function OSSL_CMP_CTX_get_transfer_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get_transfer_cb_arg';
function OSSL_CMP_CTX_set1_srvCert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_srvCert';
function OSSL_CMP_CTX_set1_expected_sender(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_expected_sender';
function OSSL_CMP_CTX_set0_trustedStore(ctx: POSSL_CMP_CTX; store: PX509_STORE): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set0_trustedStore';
function OSSL_CMP_CTX_get0_trustedStore(ctx: POSSL_CMP_CTX): PX509_STORE; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_trustedStore';
function OSSL_CMP_CTX_set1_untrusted(ctx: POSSL_CMP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_untrusted';
function OSSL_CMP_CTX_get0_untrusted(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_untrusted';
function OSSL_CMP_CTX_set1_cert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_cert';
function OSSL_CMP_CTX_build_cert_chain(ctx: POSSL_CMP_CTX; own_trusted: PX509_STORE; candidates: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_build_cert_chain';
function OSSL_CMP_CTX_set1_pkey(ctx: POSSL_CMP_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_pkey';
function OSSL_CMP_CTX_set1_referenceValue(ctx: POSSL_CMP_CTX; ref: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_referenceValue';
function OSSL_CMP_CTX_set1_secretValue(ctx: POSSL_CMP_CTX; sec: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_secretValue';
function OSSL_CMP_CTX_set1_recipient(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_recipient';
function OSSL_CMP_CTX_push0_geninfo_ITAV(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_push0_geninfo_ITAV';
function OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_reset_geninfo_ITAVs';
function OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_geninfo_ITAVs';
function OSSL_CMP_CTX_set1_extraCertsOut(ctx: POSSL_CMP_CTX; extraCertsOut: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_extraCertsOut';
function OSSL_CMP_CTX_set0_newPkey(ctx: POSSL_CMP_CTX; priv: TIdC_INT; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set0_newPkey';
function OSSL_CMP_CTX_get0_newPkey(ctx: POSSL_CMP_CTX; priv: TIdC_INT): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_newPkey';
function OSSL_CMP_CTX_set1_issuer(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_issuer';
function OSSL_CMP_CTX_set1_serialNumber(ctx: POSSL_CMP_CTX; sn: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_serialNumber';
function OSSL_CMP_CTX_set1_subjectName(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_subjectName';
function OSSL_CMP_CTX_push1_subjectAltName(ctx: POSSL_CMP_CTX; name: PGENERAL_NAME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_push1_subjectAltName';
function OSSL_CMP_CTX_set0_reqExtensions(ctx: POSSL_CMP_CTX; exts: PX509_EXTENSIONS): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set0_reqExtensions';
function OSSL_CMP_CTX_reqExtensions_have_SAN(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_reqExtensions_have_SAN';
function OSSL_CMP_CTX_push0_policy(ctx: POSSL_CMP_CTX; pinfo: PPOLICYINFO): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_push0_policy';
function OSSL_CMP_CTX_set1_oldCert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_oldCert';
function OSSL_CMP_CTX_set1_p10CSR(ctx: POSSL_CMP_CTX; csr: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_p10CSR';
function OSSL_CMP_CTX_push0_genm_ITAV(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_push0_genm_ITAV';
function OSSL_CMP_certConf_cb(ctx: POSSL_CMP_CTX; cert: PX509; fail_info: TIdC_INT; text: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_certConf_cb';
function OSSL_CMP_CTX_set_certConf_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_certConf_cb_t_func_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_certConf_cb';
function OSSL_CMP_CTX_set_certConf_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set_certConf_cb_arg';
function OSSL_CMP_CTX_get_certConf_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get_certConf_cb_arg';
function OSSL_CMP_CTX_get_status(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get_status';
function OSSL_CMP_CTX_get0_statusString(ctx: POSSL_CMP_CTX): POSSL_CMP_PKIFREETEXT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_statusString';
function OSSL_CMP_CTX_get_failInfoCode(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get_failInfoCode';
function OSSL_CMP_CTX_get0_validatedSrvCert(ctx: POSSL_CMP_CTX): PX509; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_validatedSrvCert';
function OSSL_CMP_CTX_get0_newCert(ctx: POSSL_CMP_CTX): PX509; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get0_newCert';
function OSSL_CMP_CTX_get1_newChain(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get1_newChain';
function OSSL_CMP_CTX_get1_caPubs(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get1_caPubs';
function OSSL_CMP_CTX_get1_extraCertsIn(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl external CLibCrypto name 'OSSL_CMP_CTX_get1_extraCertsIn';
function OSSL_CMP_CTX_set1_transactionID(ctx: POSSL_CMP_CTX; id: PASN1_OCTET_STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_transactionID';
function OSSL_CMP_CTX_set1_senderNonce(ctx: POSSL_CMP_CTX; nonce: PASN1_OCTET_STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_CTX_set1_senderNonce';
function OSSL_CMP_CTX_snprint_PKIStatus(ctx: POSSL_CMP_CTX; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_CMP_CTX_snprint_PKIStatus';
function OSSL_CMP_snprint_PKIStatusInfo(statusInfo: POSSL_CMP_PKISI; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_CMP_snprint_PKIStatusInfo';
function OSSL_CMP_STATUSINFO_new(status: TIdC_INT; fail_info: TIdC_INT; text: PIdAnsiChar): POSSL_CMP_PKISI; cdecl external CLibCrypto name 'OSSL_CMP_STATUSINFO_new';
function OSSL_CMP_HDR_get0_transactionID(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'OSSL_CMP_HDR_get0_transactionID';
function OSSL_CMP_HDR_get0_recipNonce(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'OSSL_CMP_HDR_get0_recipNonce';
function OSSL_CMP_HDR_get0_geninfo_ITAVs(hdr: POSSL_CMP_PKIHEADER): Pstack_st_OSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_HDR_get0_geninfo_ITAVs';
function OSSL_CMP_MSG_get0_header(msg: POSSL_CMP_MSG): POSSL_CMP_PKIHEADER; cdecl external CLibCrypto name 'OSSL_CMP_MSG_get0_header';
function OSSL_CMP_MSG_get_bodytype(msg: POSSL_CMP_MSG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_MSG_get_bodytype';
function OSSL_CMP_MSG_get0_certreq_publickey(msg: POSSL_CMP_MSG): PX509_PUBKEY; cdecl external CLibCrypto name 'OSSL_CMP_MSG_get0_certreq_publickey';
function OSSL_CMP_MSG_update_transactionID(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_MSG_update_transactionID';
function OSSL_CMP_MSG_update_recipNonce(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_MSG_update_recipNonce';
function OSSL_CMP_CTX_setup_CRM(ctx: POSSL_CMP_CTX; for_KUR: TIdC_INT; rid: TIdC_INT): POSSL_CRMF_MSG; cdecl external CLibCrypto name 'OSSL_CMP_CTX_setup_CRM';
function OSSL_CMP_MSG_read(_file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_MSG; cdecl external CLibCrypto name 'OSSL_CMP_MSG_read';
function OSSL_CMP_MSG_write(_file: PIdAnsiChar; msg: POSSL_CMP_MSG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_MSG_write';
function d2i_OSSL_CMP_MSG_bio(bio: PBIO; msg: PPOSSL_CMP_MSG): POSSL_CMP_MSG; cdecl external CLibCrypto name 'd2i_OSSL_CMP_MSG_bio';
function i2d_OSSL_CMP_MSG_bio(bio: PBIO; msg: POSSL_CMP_MSG): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_CMP_MSG_bio';
function OSSL_CMP_validate_msg(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_validate_msg';
function OSSL_CMP_validate_cert_path(ctx: POSSL_CMP_CTX; trusted_store: PX509_STORE; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_validate_cert_path';
function OSSL_CMP_MSG_http_perform(ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl external CLibCrypto name 'OSSL_CMP_MSG_http_perform';
function OSSL_CMP_SRV_process_request(srv_ctx: POSSL_CMP_SRV_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl external CLibCrypto name 'OSSL_CMP_SRV_process_request';
function OSSL_CMP_CTX_server_perform(client_ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl external CLibCrypto name 'OSSL_CMP_CTX_server_perform';
function OSSL_CMP_SRV_CTX_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_SRV_CTX; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_new';
procedure OSSL_CMP_SRV_CTX_free(srv_ctx: POSSL_CMP_SRV_CTX); cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_free';
function OSSL_CMP_SRV_CTX_init(srv_ctx: POSSL_CMP_SRV_CTX; custom_ctx: Pointer; process_cert_request: TOSSL_CMP_SRV_cert_request_cb_t_func_cb; process_rr: TOSSL_CMP_SRV_rr_cb_t_func_cb; process_genm: TOSSL_CMP_SRV_genm_cb_t_func_cb; process_error: TOSSL_CMP_SRV_error_cb_t_func_cb; process_certConf: TOSSL_CMP_SRV_certConf_cb_t_func_cb; process_pollReq: TOSSL_CMP_SRV_pollReq_cb_t_func_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_init';
function OSSL_CMP_SRV_CTX_init_trans(srv_ctx: POSSL_CMP_SRV_CTX; delay: TOSSL_CMP_SRV_delayed_delivery_cb_t_func_cb; clean: TOSSL_CMP_SRV_clean_transaction_cb_t_func_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_init_trans';
function OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv_ctx: POSSL_CMP_SRV_CTX): POSSL_CMP_CTX; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_get0_cmp_ctx';
function OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx: POSSL_CMP_SRV_CTX): Pointer; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_get0_custom_ctx';
function OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_set_send_unprotected_errors';
function OSSL_CMP_SRV_CTX_set_accept_unprotected(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_set_accept_unprotected';
function OSSL_CMP_SRV_CTX_set_accept_raverified(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_set_accept_raverified';
function OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_SRV_CTX_set_grant_implicit_confirm';
function OSSL_CMP_exec_certreq(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG): PX509; cdecl external CLibCrypto name 'OSSL_CMP_exec_certreq';
function OSSL_CMP_try_certreq(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG; checkAfter: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_try_certreq';
function OSSL_CMP_exec_RR_ses(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_exec_RR_ses';
function OSSL_CMP_exec_GENM_ses(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl external CLibCrypto name 'OSSL_CMP_exec_GENM_ses';
function OSSL_CMP_get1_caCerts(ctx: POSSL_CMP_CTX; _out: PPstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_get1_caCerts';
function OSSL_CMP_get1_rootCaKeyUpdate(ctx: POSSL_CMP_CTX; oldWithOld: PX509; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_get1_rootCaKeyUpdate';
function OSSL_CMP_get1_crlUpdate(ctx: POSSL_CMP_CTX; crlcert: PX509; last_crl: PX509_CRL; crl: PPX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_get1_crlUpdate';
function OSSL_CMP_get1_certReqTemplate(ctx: POSSL_CMP_CTX; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_get1_certReqTemplate';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_CMP_PKISTATUS_it_procname = 'OSSL_CMP_PKISTATUS_it';
  OSSL_CMP_PKISTATUS_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_PKIHEADER_new_procname = 'OSSL_CMP_PKIHEADER_new';
  OSSL_CMP_PKIHEADER_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_PKIHEADER_free_procname = 'OSSL_CMP_PKIHEADER_free';
  OSSL_CMP_PKIHEADER_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CMP_PKIHEADER_procname = 'd2i_OSSL_CMP_PKIHEADER';
  d2i_OSSL_CMP_PKIHEADER_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CMP_PKIHEADER_procname = 'i2d_OSSL_CMP_PKIHEADER';
  i2d_OSSL_CMP_PKIHEADER_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_PKIHEADER_it_procname = 'OSSL_CMP_PKIHEADER_it';
  OSSL_CMP_PKIHEADER_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_dup_procname = 'OSSL_CMP_MSG_dup';
  OSSL_CMP_MSG_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CMP_MSG_procname = 'd2i_OSSL_CMP_MSG';
  d2i_OSSL_CMP_MSG_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CMP_MSG_procname = 'i2d_OSSL_CMP_MSG';
  i2d_OSSL_CMP_MSG_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_it_procname = 'OSSL_CMP_MSG_it';
  OSSL_CMP_MSG_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_dup_procname = 'OSSL_CMP_ITAV_dup';
  OSSL_CMP_ITAV_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ATAVS_new_procname = 'OSSL_CMP_ATAVS_new';
  OSSL_CMP_ATAVS_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAVS_free_procname = 'OSSL_CMP_ATAVS_free';
  OSSL_CMP_ATAVS_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_CMP_ATAVS_procname = 'd2i_OSSL_CMP_ATAVS';
  d2i_OSSL_CMP_ATAVS_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_CMP_ATAVS_procname = 'i2d_OSSL_CMP_ATAVS';
  i2d_OSSL_CMP_ATAVS_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAVS_it_procname = 'OSSL_CMP_ATAVS_it';
  OSSL_CMP_ATAVS_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_PKISI_new_procname = 'OSSL_CMP_PKISI_new';
  OSSL_CMP_PKISI_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_PKISI_free_procname = 'OSSL_CMP_PKISI_free';
  OSSL_CMP_PKISI_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CMP_PKISI_procname = 'd2i_OSSL_CMP_PKISI';
  d2i_OSSL_CMP_PKISI_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CMP_PKISI_procname = 'i2d_OSSL_CMP_PKISI';
  i2d_OSSL_CMP_PKISI_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_PKISI_it_procname = 'OSSL_CMP_PKISI_it';
  OSSL_CMP_PKISI_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_PKISI_dup_procname = 'OSSL_CMP_PKISI_dup';
  OSSL_CMP_PKISI_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_create_procname = 'OSSL_CMP_ITAV_create';
  OSSL_CMP_ITAV_create_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_set0_procname = 'OSSL_CMP_ITAV_set0';
  OSSL_CMP_ITAV_set0_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_type_procname = 'OSSL_CMP_ITAV_get0_type';
  OSSL_CMP_ITAV_get0_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_value_procname = 'OSSL_CMP_ITAV_get0_value';
  OSSL_CMP_ITAV_get0_value_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_push0_stack_item_procname = 'OSSL_CMP_ITAV_push0_stack_item';
  OSSL_CMP_ITAV_push0_stack_item_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_free_procname = 'OSSL_CMP_ITAV_free';
  OSSL_CMP_ITAV_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_ITAV_new0_certProfile_procname = 'OSSL_CMP_ITAV_new0_certProfile';
  OSSL_CMP_ITAV_new0_certProfile_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_certProfile_procname = 'OSSL_CMP_ITAV_get0_certProfile';
  OSSL_CMP_ITAV_get0_certProfile_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_CMP_ITAV_new_caCerts_procname = 'OSSL_CMP_ITAV_new_caCerts';
  OSSL_CMP_ITAV_new_caCerts_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_caCerts_procname = 'OSSL_CMP_ITAV_get0_caCerts';
  OSSL_CMP_ITAV_get0_caCerts_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_ITAV_new_rootCaCert_procname = 'OSSL_CMP_ITAV_new_rootCaCert';
  OSSL_CMP_ITAV_new_rootCaCert_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_rootCaCert_procname = 'OSSL_CMP_ITAV_get0_rootCaCert';
  OSSL_CMP_ITAV_get0_rootCaCert_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_ITAV_new_rootCaKeyUpdate_procname = 'OSSL_CMP_ITAV_new_rootCaKeyUpdate';
  OSSL_CMP_ITAV_new_rootCaKeyUpdate_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_rootCaKeyUpdate_procname = 'OSSL_CMP_ITAV_get0_rootCaKeyUpdate';
  OSSL_CMP_ITAV_get0_rootCaKeyUpdate_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_CRLSTATUS_create_procname = 'OSSL_CMP_CRLSTATUS_create';
  OSSL_CMP_CRLSTATUS_create_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_CRLSTATUS_new1_procname = 'OSSL_CMP_CRLSTATUS_new1';
  OSSL_CMP_CRLSTATUS_new1_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_CRLSTATUS_get0_procname = 'OSSL_CMP_CRLSTATUS_get0';
  OSSL_CMP_CRLSTATUS_get0_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_CRLSTATUS_free_procname = 'OSSL_CMP_CRLSTATUS_free';
  OSSL_CMP_CRLSTATUS_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ITAV_new0_crlStatusList_procname = 'OSSL_CMP_ITAV_new0_crlStatusList';
  OSSL_CMP_ITAV_new0_crlStatusList_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_crlStatusList_procname = 'OSSL_CMP_ITAV_get0_crlStatusList';
  OSSL_CMP_ITAV_get0_crlStatusList_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ITAV_new_crls_procname = 'OSSL_CMP_ITAV_new_crls';
  OSSL_CMP_ITAV_new_crls_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get0_crls_procname = 'OSSL_CMP_ITAV_get0_crls';
  OSSL_CMP_ITAV_get0_crls_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ITAV_new0_certReqTemplate_procname = 'OSSL_CMP_ITAV_new0_certReqTemplate';
  OSSL_CMP_ITAV_new0_certReqTemplate_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ITAV_get1_certReqTemplate_procname = 'OSSL_CMP_ITAV_get1_certReqTemplate';
  OSSL_CMP_ITAV_get1_certReqTemplate_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_create_procname = 'OSSL_CMP_ATAV_create';
  OSSL_CMP_ATAV_create_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_set0_procname = 'OSSL_CMP_ATAV_set0';
  OSSL_CMP_ATAV_set0_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_get0_type_procname = 'OSSL_CMP_ATAV_get0_type';
  OSSL_CMP_ATAV_get0_type_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_get0_value_procname = 'OSSL_CMP_ATAV_get0_value';
  OSSL_CMP_ATAV_get0_value_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_new_algId_procname = 'OSSL_CMP_ATAV_new_algId';
  OSSL_CMP_ATAV_new_algId_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_get0_algId_procname = 'OSSL_CMP_ATAV_get0_algId';
  OSSL_CMP_ATAV_get0_algId_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_new_rsaKeyLen_procname = 'OSSL_CMP_ATAV_new_rsaKeyLen';
  OSSL_CMP_ATAV_new_rsaKeyLen_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_get_rsaKeyLen_procname = 'OSSL_CMP_ATAV_get_rsaKeyLen';
  OSSL_CMP_ATAV_get_rsaKeyLen_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_ATAV_push1_procname = 'OSSL_CMP_ATAV_push1';
  OSSL_CMP_ATAV_push1_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_MSG_free_procname = 'OSSL_CMP_MSG_free';
  OSSL_CMP_MSG_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_new_procname = 'OSSL_CMP_CTX_new';
  OSSL_CMP_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_free_procname = 'OSSL_CMP_CTX_free';
  OSSL_CMP_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_reinit_procname = 'OSSL_CMP_CTX_reinit';
  OSSL_CMP_CTX_reinit_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_libctx_procname = 'OSSL_CMP_CTX_get0_libctx';
  OSSL_CMP_CTX_get0_libctx_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_propq_procname = 'OSSL_CMP_CTX_get0_propq';
  OSSL_CMP_CTX_get0_propq_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_option_procname = 'OSSL_CMP_CTX_set_option';
  OSSL_CMP_CTX_set_option_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get_option_procname = 'OSSL_CMP_CTX_get_option';
  OSSL_CMP_CTX_get_option_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_log_cb_procname = 'OSSL_CMP_CTX_set_log_cb';
  OSSL_CMP_CTX_set_log_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_print_errors_procname = 'OSSL_CMP_CTX_print_errors';
  OSSL_CMP_CTX_print_errors_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_serverPath_procname = 'OSSL_CMP_CTX_set1_serverPath';
  OSSL_CMP_CTX_set1_serverPath_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_server_procname = 'OSSL_CMP_CTX_set1_server';
  OSSL_CMP_CTX_set1_server_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_serverPort_procname = 'OSSL_CMP_CTX_set_serverPort';
  OSSL_CMP_CTX_set_serverPort_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_proxy_procname = 'OSSL_CMP_CTX_set1_proxy';
  OSSL_CMP_CTX_set1_proxy_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_no_proxy_procname = 'OSSL_CMP_CTX_set1_no_proxy';
  OSSL_CMP_CTX_set1_no_proxy_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_http_cb_procname = 'OSSL_CMP_CTX_set_http_cb';
  OSSL_CMP_CTX_set_http_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_http_cb_arg_procname = 'OSSL_CMP_CTX_set_http_cb_arg';
  OSSL_CMP_CTX_set_http_cb_arg_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get_http_cb_arg_procname = 'OSSL_CMP_CTX_get_http_cb_arg';
  OSSL_CMP_CTX_get_http_cb_arg_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_transfer_cb_procname = 'OSSL_CMP_CTX_set_transfer_cb';
  OSSL_CMP_CTX_set_transfer_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_transfer_cb_arg_procname = 'OSSL_CMP_CTX_set_transfer_cb_arg';
  OSSL_CMP_CTX_set_transfer_cb_arg_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get_transfer_cb_arg_procname = 'OSSL_CMP_CTX_get_transfer_cb_arg';
  OSSL_CMP_CTX_get_transfer_cb_arg_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_srvCert_procname = 'OSSL_CMP_CTX_set1_srvCert';
  OSSL_CMP_CTX_set1_srvCert_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_expected_sender_procname = 'OSSL_CMP_CTX_set1_expected_sender';
  OSSL_CMP_CTX_set1_expected_sender_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set0_trustedStore_procname = 'OSSL_CMP_CTX_set0_trustedStore';
  OSSL_CMP_CTX_set0_trustedStore_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_trustedStore_procname = 'OSSL_CMP_CTX_get0_trustedStore';
  OSSL_CMP_CTX_get0_trustedStore_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_untrusted_procname = 'OSSL_CMP_CTX_set1_untrusted';
  OSSL_CMP_CTX_set1_untrusted_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_untrusted_procname = 'OSSL_CMP_CTX_get0_untrusted';
  OSSL_CMP_CTX_get0_untrusted_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_cert_procname = 'OSSL_CMP_CTX_set1_cert';
  OSSL_CMP_CTX_set1_cert_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_build_cert_chain_procname = 'OSSL_CMP_CTX_build_cert_chain';
  OSSL_CMP_CTX_build_cert_chain_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_pkey_procname = 'OSSL_CMP_CTX_set1_pkey';
  OSSL_CMP_CTX_set1_pkey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_referenceValue_procname = 'OSSL_CMP_CTX_set1_referenceValue';
  OSSL_CMP_CTX_set1_referenceValue_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_secretValue_procname = 'OSSL_CMP_CTX_set1_secretValue';
  OSSL_CMP_CTX_set1_secretValue_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_recipient_procname = 'OSSL_CMP_CTX_set1_recipient';
  OSSL_CMP_CTX_set1_recipient_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_push0_geninfo_ITAV_procname = 'OSSL_CMP_CTX_push0_geninfo_ITAV';
  OSSL_CMP_CTX_push0_geninfo_ITAV_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_reset_geninfo_ITAVs_procname = 'OSSL_CMP_CTX_reset_geninfo_ITAVs';
  OSSL_CMP_CTX_reset_geninfo_ITAVs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(8);

  OSSL_CMP_CTX_get0_geninfo_ITAVs_procname = 'OSSL_CMP_CTX_get0_geninfo_ITAVs';
  OSSL_CMP_CTX_get0_geninfo_ITAVs_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_extraCertsOut_procname = 'OSSL_CMP_CTX_set1_extraCertsOut';
  OSSL_CMP_CTX_set1_extraCertsOut_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set0_newPkey_procname = 'OSSL_CMP_CTX_set0_newPkey';
  OSSL_CMP_CTX_set0_newPkey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_newPkey_procname = 'OSSL_CMP_CTX_get0_newPkey';
  OSSL_CMP_CTX_get0_newPkey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_issuer_procname = 'OSSL_CMP_CTX_set1_issuer';
  OSSL_CMP_CTX_set1_issuer_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_serialNumber_procname = 'OSSL_CMP_CTX_set1_serialNumber';
  OSSL_CMP_CTX_set1_serialNumber_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_subjectName_procname = 'OSSL_CMP_CTX_set1_subjectName';
  OSSL_CMP_CTX_set1_subjectName_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_push1_subjectAltName_procname = 'OSSL_CMP_CTX_push1_subjectAltName';
  OSSL_CMP_CTX_push1_subjectAltName_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set0_reqExtensions_procname = 'OSSL_CMP_CTX_set0_reqExtensions';
  OSSL_CMP_CTX_set0_reqExtensions_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_reqExtensions_have_SAN_procname = 'OSSL_CMP_CTX_reqExtensions_have_SAN';
  OSSL_CMP_CTX_reqExtensions_have_SAN_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_push0_policy_procname = 'OSSL_CMP_CTX_push0_policy';
  OSSL_CMP_CTX_push0_policy_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_oldCert_procname = 'OSSL_CMP_CTX_set1_oldCert';
  OSSL_CMP_CTX_set1_oldCert_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_p10CSR_procname = 'OSSL_CMP_CTX_set1_p10CSR';
  OSSL_CMP_CTX_set1_p10CSR_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_push0_genm_ITAV_procname = 'OSSL_CMP_CTX_push0_genm_ITAV';
  OSSL_CMP_CTX_push0_genm_ITAV_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_certConf_cb_procname = 'OSSL_CMP_certConf_cb';
  OSSL_CMP_certConf_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_certConf_cb_procname = 'OSSL_CMP_CTX_set_certConf_cb';
  OSSL_CMP_CTX_set_certConf_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set_certConf_cb_arg_procname = 'OSSL_CMP_CTX_set_certConf_cb_arg';
  OSSL_CMP_CTX_set_certConf_cb_arg_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get_certConf_cb_arg_procname = 'OSSL_CMP_CTX_get_certConf_cb_arg';
  OSSL_CMP_CTX_get_certConf_cb_arg_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get_status_procname = 'OSSL_CMP_CTX_get_status';
  OSSL_CMP_CTX_get_status_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_statusString_procname = 'OSSL_CMP_CTX_get0_statusString';
  OSSL_CMP_CTX_get0_statusString_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get_failInfoCode_procname = 'OSSL_CMP_CTX_get_failInfoCode';
  OSSL_CMP_CTX_get_failInfoCode_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_validatedSrvCert_procname = 'OSSL_CMP_CTX_get0_validatedSrvCert';
  OSSL_CMP_CTX_get0_validatedSrvCert_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_CTX_get0_newCert_procname = 'OSSL_CMP_CTX_get0_newCert';
  OSSL_CMP_CTX_get0_newCert_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get1_newChain_procname = 'OSSL_CMP_CTX_get1_newChain';
  OSSL_CMP_CTX_get1_newChain_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get1_caPubs_procname = 'OSSL_CMP_CTX_get1_caPubs';
  OSSL_CMP_CTX_get1_caPubs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_get1_extraCertsIn_procname = 'OSSL_CMP_CTX_get1_extraCertsIn';
  OSSL_CMP_CTX_get1_extraCertsIn_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_transactionID_procname = 'OSSL_CMP_CTX_set1_transactionID';
  OSSL_CMP_CTX_set1_transactionID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_set1_senderNonce_procname = 'OSSL_CMP_CTX_set1_senderNonce';
  OSSL_CMP_CTX_set1_senderNonce_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_snprint_PKIStatus_procname = 'OSSL_CMP_CTX_snprint_PKIStatus';
  OSSL_CMP_CTX_snprint_PKIStatus_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_snprint_PKIStatusInfo_procname = 'OSSL_CMP_snprint_PKIStatusInfo';
  OSSL_CMP_snprint_PKIStatusInfo_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_STATUSINFO_new_procname = 'OSSL_CMP_STATUSINFO_new';
  OSSL_CMP_STATUSINFO_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_HDR_get0_transactionID_procname = 'OSSL_CMP_HDR_get0_transactionID';
  OSSL_CMP_HDR_get0_transactionID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_HDR_get0_recipNonce_procname = 'OSSL_CMP_HDR_get0_recipNonce';
  OSSL_CMP_HDR_get0_recipNonce_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_HDR_get0_geninfo_ITAVs_procname = 'OSSL_CMP_HDR_get0_geninfo_ITAVs';
  OSSL_CMP_HDR_get0_geninfo_ITAVs_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_CMP_MSG_get0_header_procname = 'OSSL_CMP_MSG_get0_header';
  OSSL_CMP_MSG_get0_header_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_get_bodytype_procname = 'OSSL_CMP_MSG_get_bodytype';
  OSSL_CMP_MSG_get_bodytype_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_get0_certreq_publickey_procname = 'OSSL_CMP_MSG_get0_certreq_publickey';
  OSSL_CMP_MSG_get0_certreq_publickey_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_CMP_MSG_update_transactionID_procname = 'OSSL_CMP_MSG_update_transactionID';
  OSSL_CMP_MSG_update_transactionID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_update_recipNonce_procname = 'OSSL_CMP_MSG_update_recipNonce';
  OSSL_CMP_MSG_update_recipNonce_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(9);

  OSSL_CMP_CTX_setup_CRM_procname = 'OSSL_CMP_CTX_setup_CRM';
  OSSL_CMP_CTX_setup_CRM_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_read_procname = 'OSSL_CMP_MSG_read';
  OSSL_CMP_MSG_read_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_write_procname = 'OSSL_CMP_MSG_write';
  OSSL_CMP_MSG_write_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_OSSL_CMP_MSG_bio_procname = 'd2i_OSSL_CMP_MSG_bio';
  d2i_OSSL_CMP_MSG_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_OSSL_CMP_MSG_bio_procname = 'i2d_OSSL_CMP_MSG_bio';
  i2d_OSSL_CMP_MSG_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_validate_msg_procname = 'OSSL_CMP_validate_msg';
  OSSL_CMP_validate_msg_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_validate_cert_path_procname = 'OSSL_CMP_validate_cert_path';
  OSSL_CMP_validate_cert_path_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_MSG_http_perform_procname = 'OSSL_CMP_MSG_http_perform';
  OSSL_CMP_MSG_http_perform_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_process_request_procname = 'OSSL_CMP_SRV_process_request';
  OSSL_CMP_SRV_process_request_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_CTX_server_perform_procname = 'OSSL_CMP_CTX_server_perform';
  OSSL_CMP_CTX_server_perform_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_new_procname = 'OSSL_CMP_SRV_CTX_new';
  OSSL_CMP_SRV_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_free_procname = 'OSSL_CMP_SRV_CTX_free';
  OSSL_CMP_SRV_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_init_procname = 'OSSL_CMP_SRV_CTX_init';
  OSSL_CMP_SRV_CTX_init_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_init_trans_procname = 'OSSL_CMP_SRV_CTX_init_trans';
  OSSL_CMP_SRV_CTX_init_trans_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_get0_cmp_ctx_procname = 'OSSL_CMP_SRV_CTX_get0_cmp_ctx';
  OSSL_CMP_SRV_CTX_get0_cmp_ctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_get0_custom_ctx_procname = 'OSSL_CMP_SRV_CTX_get0_custom_ctx';
  OSSL_CMP_SRV_CTX_get0_custom_ctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_set_send_unprotected_errors_procname = 'OSSL_CMP_SRV_CTX_set_send_unprotected_errors';
  OSSL_CMP_SRV_CTX_set_send_unprotected_errors_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_set_accept_unprotected_procname = 'OSSL_CMP_SRV_CTX_set_accept_unprotected';
  OSSL_CMP_SRV_CTX_set_accept_unprotected_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_set_accept_raverified_procname = 'OSSL_CMP_SRV_CTX_set_accept_raverified';
  OSSL_CMP_SRV_CTX_set_accept_raverified_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_procname = 'OSSL_CMP_SRV_CTX_set_grant_implicit_confirm';
  OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_exec_certreq_procname = 'OSSL_CMP_exec_certreq';
  OSSL_CMP_exec_certreq_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_try_certreq_procname = 'OSSL_CMP_try_certreq';
  OSSL_CMP_try_certreq_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_exec_RR_ses_procname = 'OSSL_CMP_exec_RR_ses';
  OSSL_CMP_exec_RR_ses_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_exec_GENM_ses_procname = 'OSSL_CMP_exec_GENM_ses';
  OSSL_CMP_exec_GENM_ses_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_get1_caCerts_procname = 'OSSL_CMP_get1_caCerts';
  OSSL_CMP_get1_caCerts_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_get1_rootCaKeyUpdate_procname = 'OSSL_CMP_get1_rootCaKeyUpdate';
  OSSL_CMP_get1_rootCaKeyUpdate_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_CMP_get1_crlUpdate_procname = 'OSSL_CMP_get1_crlUpdate';
  OSSL_CMP_get1_crlUpdate_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_CMP_get1_certReqTemplate_procname = 'OSSL_CMP_get1_certReqTemplate';
  OSSL_CMP_get1_certReqTemplate_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OSSL_CMP_CTX_set_log_verbosity(ctx: Pointer; level: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CMP_CTX_set_log_verbosity(ctx, level) \
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_LOG_VERBOSITY, level)
  }
end;

function OSSL_CMP_exec_IR_ses(ctx: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CMP_exec_IR_ses(ctx) \
    OSSL_CMP_exec_certreq(ctx, OSSL_CMP_IR, NULL)
  }
end;

function OSSL_CMP_exec_CR_ses(ctx: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CMP_exec_CR_ses(ctx) \
    OSSL_CMP_exec_certreq(ctx, OSSL_CMP_CR, NULL)
  }
end;

function OSSL_CMP_exec_P10CR_ses(ctx: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CMP_exec_P10CR_ses(ctx) \
    OSSL_CMP_exec_certreq(ctx, OSSL_CMP_P10CR, NULL)
  }
end;

function OSSL_CMP_exec_KUR_ses(ctx: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CMP_exec_KUR_ses(ctx) \
    OSSL_CMP_exec_certreq(ctx, OSSL_CMP_KUR, NULL)
  }
end;

function OSSL_CMP_CTX_set0_trusted(ctx: POSSL_CMP_CTX; store: PX509_STORE): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CMP_CTX_set0_trusted OSSL_CMP_CTX_set0_trustedStore
  }
end;

function OSSL_CMP_CTX_get0_trusted(ctx: POSSL_CMP_CTX): PX509_STORE; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CMP_CTX_get0_trusted OSSL_CMP_CTX_get0_trustedStore
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_CMP_PKISTATUS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKISTATUS_it_procname);
end;

function ERR_OSSL_CMP_PKIHEADER_new: POSSL_CMP_PKIHEADER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKIHEADER_new_procname);
end;

procedure ERR_OSSL_CMP_PKIHEADER_free(a: POSSL_CMP_PKIHEADER); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKIHEADER_free_procname);
end;

function ERR_d2i_OSSL_CMP_PKIHEADER(a: PPOSSL_CMP_PKIHEADER; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKIHEADER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CMP_PKIHEADER_procname);
end;

function ERR_i2d_OSSL_CMP_PKIHEADER(a: POSSL_CMP_PKIHEADER; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CMP_PKIHEADER_procname);
end;

function ERR_OSSL_CMP_PKIHEADER_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKIHEADER_it_procname);
end;

function ERR_OSSL_CMP_MSG_dup(a: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_dup_procname);
end;

function ERR_d2i_OSSL_CMP_MSG(a: PPOSSL_CMP_MSG; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CMP_MSG_procname);
end;

function ERR_i2d_OSSL_CMP_MSG(a: POSSL_CMP_MSG; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CMP_MSG_procname);
end;

function ERR_OSSL_CMP_MSG_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_it_procname);
end;

function ERR_OSSL_CMP_ITAV_dup(a: POSSL_CMP_ITAV): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_dup_procname);
end;

function ERR_OSSL_CMP_ATAVS_new: POSSL_CMP_ATAVS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAVS_new_procname);
end;

procedure ERR_OSSL_CMP_ATAVS_free(a: POSSL_CMP_ATAVS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAVS_free_procname);
end;

function ERR_d2i_OSSL_CMP_ATAVS(a: PPOSSL_CMP_ATAVS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_ATAVS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CMP_ATAVS_procname);
end;

function ERR_i2d_OSSL_CMP_ATAVS(a: POSSL_CMP_ATAVS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CMP_ATAVS_procname);
end;

function ERR_OSSL_CMP_ATAVS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAVS_it_procname);
end;

function ERR_OSSL_CMP_PKISI_new: POSSL_CMP_PKISI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKISI_new_procname);
end;

procedure ERR_OSSL_CMP_PKISI_free(a: POSSL_CMP_PKISI); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKISI_free_procname);
end;

function ERR_d2i_OSSL_CMP_PKISI(a: PPOSSL_CMP_PKISI; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_CMP_PKISI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CMP_PKISI_procname);
end;

function ERR_i2d_OSSL_CMP_PKISI(a: POSSL_CMP_PKISI; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CMP_PKISI_procname);
end;

function ERR_OSSL_CMP_PKISI_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKISI_it_procname);
end;

function ERR_OSSL_CMP_PKISI_dup(a: POSSL_CMP_PKISI): POSSL_CMP_PKISI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_PKISI_dup_procname);
end;

function ERR_OSSL_CMP_ITAV_create(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_create_procname);
end;

procedure ERR_OSSL_CMP_ITAV_set0(itav: POSSL_CMP_ITAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_set0_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_type(itav: POSSL_CMP_ITAV): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_type_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_value(itav: POSSL_CMP_ITAV): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_value_procname);
end;

function ERR_OSSL_CMP_ITAV_push0_stack_item(sk_p: PPstack_st_OSSL_CMP_ITAV; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_push0_stack_item_procname);
end;

procedure ERR_OSSL_CMP_ITAV_free(itav: POSSL_CMP_ITAV); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_free_procname);
end;

function ERR_OSSL_CMP_ITAV_new0_certProfile(certProfile: Pstack_st_ASN1_UTF8STRING): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_new0_certProfile_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_certProfile(itav: POSSL_CMP_ITAV; _out: PPstack_st_ASN1_UTF8STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_certProfile_procname);
end;

function ERR_OSSL_CMP_ITAV_new_caCerts(caCerts: Pstack_st_X509): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_new_caCerts_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_caCerts(itav: POSSL_CMP_ITAV; _out: PPstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_caCerts_procname);
end;

function ERR_OSSL_CMP_ITAV_new_rootCaCert(rootCaCert: PX509): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_new_rootCaCert_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_rootCaCert(itav: POSSL_CMP_ITAV; _out: PPX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_rootCaCert_procname);
end;

function ERR_OSSL_CMP_ITAV_new_rootCaKeyUpdate(newWithNew: PX509; newWithOld: PX509; oldWithNew: PX509): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_new_rootCaKeyUpdate_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_rootCaKeyUpdate(itav: POSSL_CMP_ITAV; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_rootCaKeyUpdate_procname);
end;

function ERR_OSSL_CMP_CRLSTATUS_create(crl: PX509_CRL; cert: PX509; only_DN: TIdC_INT): POSSL_CMP_CRLSTATUS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CRLSTATUS_create_procname);
end;

function ERR_OSSL_CMP_CRLSTATUS_new1(dpn: PDIST_POINT_NAME; issuer: PGENERAL_NAMES; thisUpdate: PASN1_TIME): POSSL_CMP_CRLSTATUS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CRLSTATUS_new1_procname);
end;

function ERR_OSSL_CMP_CRLSTATUS_get0(crlstatus: POSSL_CMP_CRLSTATUS; dpn: PPDIST_POINT_NAME; issuer: PPGENERAL_NAMES; thisUpdate: PPASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CRLSTATUS_get0_procname);
end;

procedure ERR_OSSL_CMP_CRLSTATUS_free(crlstatus: POSSL_CMP_CRLSTATUS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CRLSTATUS_free_procname);
end;

function ERR_OSSL_CMP_ITAV_new0_crlStatusList(crlStatusList: Pstack_st_OSSL_CMP_CRLSTATUS): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_new0_crlStatusList_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_crlStatusList(itav: POSSL_CMP_ITAV; _out: PPstack_st_OSSL_CMP_CRLSTATUS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_crlStatusList_procname);
end;

function ERR_OSSL_CMP_ITAV_new_crls(crls: PX509_CRL): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_new_crls_procname);
end;

function ERR_OSSL_CMP_ITAV_get0_crls(it: POSSL_CMP_ITAV; _out: PPstack_st_X509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get0_crls_procname);
end;

function ERR_OSSL_CMP_ITAV_new0_certReqTemplate(certTemplate: POSSL_CRMF_CERTTEMPLATE; keySpec: POSSL_CMP_ATAVS): POSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_new0_certReqTemplate_procname);
end;

function ERR_OSSL_CMP_ITAV_get1_certReqTemplate(itav: POSSL_CMP_ITAV; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ITAV_get1_certReqTemplate_procname);
end;

function ERR_OSSL_CMP_ATAV_create(_type: PASN1_OBJECT; value: PASN1_TYPE): POSSL_CMP_ATAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_create_procname);
end;

procedure ERR_OSSL_CMP_ATAV_set0(itav: POSSL_CMP_ATAV; _type: PASN1_OBJECT; value: PASN1_TYPE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_set0_procname);
end;

function ERR_OSSL_CMP_ATAV_get0_type(itav: POSSL_CMP_ATAV): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_get0_type_procname);
end;

function ERR_OSSL_CMP_ATAV_get0_value(itav: POSSL_CMP_ATAV): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_get0_value_procname);
end;

function ERR_OSSL_CMP_ATAV_new_algId(alg: PX509_ALGOR): POSSL_CMP_ATAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_new_algId_procname);
end;

function ERR_OSSL_CMP_ATAV_get0_algId(atav: POSSL_CMP_ATAV): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_get0_algId_procname);
end;

function ERR_OSSL_CMP_ATAV_new_rsaKeyLen(len: TIdC_INT): POSSL_CMP_ATAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_new_rsaKeyLen_procname);
end;

function ERR_OSSL_CMP_ATAV_get_rsaKeyLen(atav: POSSL_CMP_ATAV): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_get_rsaKeyLen_procname);
end;

function ERR_OSSL_CMP_ATAV_push1(sk_p: PPOSSL_CMP_ATAVS; atav: POSSL_CMP_ATAV): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_ATAV_push1_procname);
end;

procedure ERR_OSSL_CMP_MSG_free(msg: POSSL_CMP_MSG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_free_procname);
end;

function ERR_OSSL_CMP_CTX_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_new_procname);
end;

procedure ERR_OSSL_CMP_CTX_free(ctx: POSSL_CMP_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_free_procname);
end;

function ERR_OSSL_CMP_CTX_reinit(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_reinit_procname);
end;

function ERR_OSSL_CMP_CTX_get0_libctx(ctx: POSSL_CMP_CTX): POSSL_LIB_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_libctx_procname);
end;

function ERR_OSSL_CMP_CTX_get0_propq(ctx: POSSL_CMP_CTX): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_propq_procname);
end;

function ERR_OSSL_CMP_CTX_set_option(ctx: POSSL_CMP_CTX; opt: TIdC_INT; val: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_option_procname);
end;

function ERR_OSSL_CMP_CTX_get_option(ctx: POSSL_CMP_CTX; opt: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get_option_procname);
end;

function ERR_OSSL_CMP_CTX_set_log_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_log_cb_cb_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_log_cb_procname);
end;

procedure ERR_OSSL_CMP_CTX_print_errors(ctx: POSSL_CMP_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_print_errors_procname);
end;

function ERR_OSSL_CMP_CTX_set1_serverPath(ctx: POSSL_CMP_CTX; path: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_serverPath_procname);
end;

function ERR_OSSL_CMP_CTX_set1_server(ctx: POSSL_CMP_CTX; address: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_server_procname);
end;

function ERR_OSSL_CMP_CTX_set_serverPort(ctx: POSSL_CMP_CTX; port: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_serverPort_procname);
end;

function ERR_OSSL_CMP_CTX_set1_proxy(ctx: POSSL_CMP_CTX; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_proxy_procname);
end;

function ERR_OSSL_CMP_CTX_set1_no_proxy(ctx: POSSL_CMP_CTX; names: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_no_proxy_procname);
end;

function ERR_OSSL_CMP_CTX_set_http_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_CTX_set_http_cb_cb_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_http_cb_procname);
end;

function ERR_OSSL_CMP_CTX_set_http_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_http_cb_arg_procname);
end;

function ERR_OSSL_CMP_CTX_get_http_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get_http_cb_arg_procname);
end;

function ERR_OSSL_CMP_CTX_set_transfer_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_transfer_cb_t_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_transfer_cb_procname);
end;

function ERR_OSSL_CMP_CTX_set_transfer_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_transfer_cb_arg_procname);
end;

function ERR_OSSL_CMP_CTX_get_transfer_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get_transfer_cb_arg_procname);
end;

function ERR_OSSL_CMP_CTX_set1_srvCert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_srvCert_procname);
end;

function ERR_OSSL_CMP_CTX_set1_expected_sender(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_expected_sender_procname);
end;

function ERR_OSSL_CMP_CTX_set0_trustedStore(ctx: POSSL_CMP_CTX; store: PX509_STORE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set0_trustedStore_procname);
end;

function ERR_OSSL_CMP_CTX_get0_trustedStore(ctx: POSSL_CMP_CTX): PX509_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_trustedStore_procname);
end;

function ERR_OSSL_CMP_CTX_set1_untrusted(ctx: POSSL_CMP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_untrusted_procname);
end;

function ERR_OSSL_CMP_CTX_get0_untrusted(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_untrusted_procname);
end;

function ERR_OSSL_CMP_CTX_set1_cert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_cert_procname);
end;

function ERR_OSSL_CMP_CTX_build_cert_chain(ctx: POSSL_CMP_CTX; own_trusted: PX509_STORE; candidates: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_build_cert_chain_procname);
end;

function ERR_OSSL_CMP_CTX_set1_pkey(ctx: POSSL_CMP_CTX; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_pkey_procname);
end;

function ERR_OSSL_CMP_CTX_set1_referenceValue(ctx: POSSL_CMP_CTX; ref: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_referenceValue_procname);
end;

function ERR_OSSL_CMP_CTX_set1_secretValue(ctx: POSSL_CMP_CTX; sec: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_secretValue_procname);
end;

function ERR_OSSL_CMP_CTX_set1_recipient(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_recipient_procname);
end;

function ERR_OSSL_CMP_CTX_push0_geninfo_ITAV(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_push0_geninfo_ITAV_procname);
end;

function ERR_OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_reset_geninfo_ITAVs_procname);
end;

function ERR_OSSL_CMP_CTX_get0_geninfo_ITAVs(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_geninfo_ITAVs_procname);
end;

function ERR_OSSL_CMP_CTX_set1_extraCertsOut(ctx: POSSL_CMP_CTX; extraCertsOut: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_extraCertsOut_procname);
end;

function ERR_OSSL_CMP_CTX_set0_newPkey(ctx: POSSL_CMP_CTX; priv: TIdC_INT; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set0_newPkey_procname);
end;

function ERR_OSSL_CMP_CTX_get0_newPkey(ctx: POSSL_CMP_CTX; priv: TIdC_INT): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_newPkey_procname);
end;

function ERR_OSSL_CMP_CTX_set1_issuer(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_issuer_procname);
end;

function ERR_OSSL_CMP_CTX_set1_serialNumber(ctx: POSSL_CMP_CTX; sn: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_serialNumber_procname);
end;

function ERR_OSSL_CMP_CTX_set1_subjectName(ctx: POSSL_CMP_CTX; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_subjectName_procname);
end;

function ERR_OSSL_CMP_CTX_push1_subjectAltName(ctx: POSSL_CMP_CTX; name: PGENERAL_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_push1_subjectAltName_procname);
end;

function ERR_OSSL_CMP_CTX_set0_reqExtensions(ctx: POSSL_CMP_CTX; exts: PX509_EXTENSIONS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set0_reqExtensions_procname);
end;

function ERR_OSSL_CMP_CTX_reqExtensions_have_SAN(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_reqExtensions_have_SAN_procname);
end;

function ERR_OSSL_CMP_CTX_push0_policy(ctx: POSSL_CMP_CTX; pinfo: PPOLICYINFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_push0_policy_procname);
end;

function ERR_OSSL_CMP_CTX_set1_oldCert(ctx: POSSL_CMP_CTX; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_oldCert_procname);
end;

function ERR_OSSL_CMP_CTX_set1_p10CSR(ctx: POSSL_CMP_CTX; csr: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_p10CSR_procname);
end;

function ERR_OSSL_CMP_CTX_push0_genm_ITAV(ctx: POSSL_CMP_CTX; itav: POSSL_CMP_ITAV): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_push0_genm_ITAV_procname);
end;

function ERR_OSSL_CMP_certConf_cb(ctx: POSSL_CMP_CTX; cert: PX509; fail_info: TIdC_INT; text: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_certConf_cb_procname);
end;

function ERR_OSSL_CMP_CTX_set_certConf_cb(ctx: POSSL_CMP_CTX; cb: TOSSL_CMP_certConf_cb_t_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_certConf_cb_procname);
end;

function ERR_OSSL_CMP_CTX_set_certConf_cb_arg(ctx: POSSL_CMP_CTX; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set_certConf_cb_arg_procname);
end;

function ERR_OSSL_CMP_CTX_get_certConf_cb_arg(ctx: POSSL_CMP_CTX): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get_certConf_cb_arg_procname);
end;

function ERR_OSSL_CMP_CTX_get_status(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get_status_procname);
end;

function ERR_OSSL_CMP_CTX_get0_statusString(ctx: POSSL_CMP_CTX): POSSL_CMP_PKIFREETEXT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_statusString_procname);
end;

function ERR_OSSL_CMP_CTX_get_failInfoCode(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get_failInfoCode_procname);
end;

function ERR_OSSL_CMP_CTX_get0_validatedSrvCert(ctx: POSSL_CMP_CTX): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_validatedSrvCert_procname);
end;

function ERR_OSSL_CMP_CTX_get0_newCert(ctx: POSSL_CMP_CTX): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get0_newCert_procname);
end;

function ERR_OSSL_CMP_CTX_get1_newChain(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get1_newChain_procname);
end;

function ERR_OSSL_CMP_CTX_get1_caPubs(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get1_caPubs_procname);
end;

function ERR_OSSL_CMP_CTX_get1_extraCertsIn(ctx: POSSL_CMP_CTX): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_get1_extraCertsIn_procname);
end;

function ERR_OSSL_CMP_CTX_set1_transactionID(ctx: POSSL_CMP_CTX; id: PASN1_OCTET_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_transactionID_procname);
end;

function ERR_OSSL_CMP_CTX_set1_senderNonce(ctx: POSSL_CMP_CTX; nonce: PASN1_OCTET_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_set1_senderNonce_procname);
end;

function ERR_OSSL_CMP_CTX_snprint_PKIStatus(ctx: POSSL_CMP_CTX; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_snprint_PKIStatus_procname);
end;

function ERR_OSSL_CMP_snprint_PKIStatusInfo(statusInfo: POSSL_CMP_PKISI; buf: PIdAnsiChar; bufsize: TIdC_SIZET): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_snprint_PKIStatusInfo_procname);
end;

function ERR_OSSL_CMP_STATUSINFO_new(status: TIdC_INT; fail_info: TIdC_INT; text: PIdAnsiChar): POSSL_CMP_PKISI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_STATUSINFO_new_procname);
end;

function ERR_OSSL_CMP_HDR_get0_transactionID(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_HDR_get0_transactionID_procname);
end;

function ERR_OSSL_CMP_HDR_get0_recipNonce(hdr: POSSL_CMP_PKIHEADER): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_HDR_get0_recipNonce_procname);
end;

function ERR_OSSL_CMP_HDR_get0_geninfo_ITAVs(hdr: POSSL_CMP_PKIHEADER): Pstack_st_OSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_HDR_get0_geninfo_ITAVs_procname);
end;

function ERR_OSSL_CMP_MSG_get0_header(msg: POSSL_CMP_MSG): POSSL_CMP_PKIHEADER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_get0_header_procname);
end;

function ERR_OSSL_CMP_MSG_get_bodytype(msg: POSSL_CMP_MSG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_get_bodytype_procname);
end;

function ERR_OSSL_CMP_MSG_get0_certreq_publickey(msg: POSSL_CMP_MSG): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_get0_certreq_publickey_procname);
end;

function ERR_OSSL_CMP_MSG_update_transactionID(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_update_transactionID_procname);
end;

function ERR_OSSL_CMP_MSG_update_recipNonce(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_update_recipNonce_procname);
end;

function ERR_OSSL_CMP_CTX_setup_CRM(ctx: POSSL_CMP_CTX; for_KUR: TIdC_INT; rid: TIdC_INT): POSSL_CRMF_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_setup_CRM_procname);
end;

function ERR_OSSL_CMP_MSG_read(_file: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_read_procname);
end;

function ERR_OSSL_CMP_MSG_write(_file: PIdAnsiChar; msg: POSSL_CMP_MSG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_write_procname);
end;

function ERR_d2i_OSSL_CMP_MSG_bio(bio: PBIO; msg: PPOSSL_CMP_MSG): POSSL_CMP_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_CMP_MSG_bio_procname);
end;

function ERR_i2d_OSSL_CMP_MSG_bio(bio: PBIO; msg: POSSL_CMP_MSG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_CMP_MSG_bio_procname);
end;

function ERR_OSSL_CMP_validate_msg(ctx: POSSL_CMP_CTX; msg: POSSL_CMP_MSG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_validate_msg_procname);
end;

function ERR_OSSL_CMP_validate_cert_path(ctx: POSSL_CMP_CTX; trusted_store: PX509_STORE; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_validate_cert_path_procname);
end;

function ERR_OSSL_CMP_MSG_http_perform(ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_MSG_http_perform_procname);
end;

function ERR_OSSL_CMP_SRV_process_request(srv_ctx: POSSL_CMP_SRV_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_process_request_procname);
end;

function ERR_OSSL_CMP_CTX_server_perform(client_ctx: POSSL_CMP_CTX; req: POSSL_CMP_MSG): POSSL_CMP_MSG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_CTX_server_perform_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_new(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): POSSL_CMP_SRV_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_new_procname);
end;

procedure ERR_OSSL_CMP_SRV_CTX_free(srv_ctx: POSSL_CMP_SRV_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_free_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_init(srv_ctx: POSSL_CMP_SRV_CTX; custom_ctx: Pointer; process_cert_request: TOSSL_CMP_SRV_cert_request_cb_t_func_cb; process_rr: TOSSL_CMP_SRV_rr_cb_t_func_cb; process_genm: TOSSL_CMP_SRV_genm_cb_t_func_cb; process_error: TOSSL_CMP_SRV_error_cb_t_func_cb; process_certConf: TOSSL_CMP_SRV_certConf_cb_t_func_cb; process_pollReq: TOSSL_CMP_SRV_pollReq_cb_t_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_init_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_init_trans(srv_ctx: POSSL_CMP_SRV_CTX; delay: TOSSL_CMP_SRV_delayed_delivery_cb_t_func_cb; clean: TOSSL_CMP_SRV_clean_transaction_cb_t_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_init_trans_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv_ctx: POSSL_CMP_SRV_CTX): POSSL_CMP_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_get0_cmp_ctx_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx: POSSL_CMP_SRV_CTX): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_get0_custom_ctx_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_set_send_unprotected_errors(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_set_send_unprotected_errors_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_set_accept_unprotected(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_set_accept_unprotected_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_set_accept_raverified(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_set_accept_raverified_procname);
end;

function ERR_OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv_ctx: POSSL_CMP_SRV_CTX; val: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_procname);
end;

function ERR_OSSL_CMP_exec_certreq(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_exec_certreq_procname);
end;

function ERR_OSSL_CMP_try_certreq(ctx: POSSL_CMP_CTX; req_type: TIdC_INT; crm: POSSL_CRMF_MSG; checkAfter: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_try_certreq_procname);
end;

function ERR_OSSL_CMP_exec_RR_ses(ctx: POSSL_CMP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_exec_RR_ses_procname);
end;

function ERR_OSSL_CMP_exec_GENM_ses(ctx: POSSL_CMP_CTX): Pstack_st_OSSL_CMP_ITAV; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_exec_GENM_ses_procname);
end;

function ERR_OSSL_CMP_get1_caCerts(ctx: POSSL_CMP_CTX; _out: PPstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_get1_caCerts_procname);
end;

function ERR_OSSL_CMP_get1_rootCaKeyUpdate(ctx: POSSL_CMP_CTX; oldWithOld: PX509; newWithNew: PPX509; newWithOld: PPX509; oldWithNew: PPX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_get1_rootCaKeyUpdate_procname);
end;

function ERR_OSSL_CMP_get1_crlUpdate(ctx: POSSL_CMP_CTX; crlcert: PX509; last_crl: PX509_CRL; crl: PPX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_get1_crlUpdate_procname);
end;

function ERR_OSSL_CMP_get1_certReqTemplate(ctx: POSSL_CMP_CTX; certTemplate: PPOSSL_CRMF_CERTTEMPLATE; keySpec: PPOSSL_CMP_ATAVS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_get1_certReqTemplate_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_CMP_PKISTATUS_it := LoadLibFunction(ADllHandle, OSSL_CMP_PKISTATUS_it_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKISTATUS_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKISTATUS_it_allownil)}
    OSSL_CMP_PKISTATUS_it := ERR_OSSL_CMP_PKISTATUS_it;
    {$ifend}
    {$if declared(OSSL_CMP_PKISTATUS_it_introduced)}
    if LibVersion < OSSL_CMP_PKISTATUS_it_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKISTATUS_it)}
      OSSL_CMP_PKISTATUS_it := FC_OSSL_CMP_PKISTATUS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKISTATUS_it_removed)}
    if OSSL_CMP_PKISTATUS_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKISTATUS_it)}
      OSSL_CMP_PKISTATUS_it := _OSSL_CMP_PKISTATUS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKISTATUS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKISTATUS_it');
    {$ifend}
  end;
  
  OSSL_CMP_PKIHEADER_new := LoadLibFunction(ADllHandle, OSSL_CMP_PKIHEADER_new_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKIHEADER_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKIHEADER_new_allownil)}
    OSSL_CMP_PKIHEADER_new := ERR_OSSL_CMP_PKIHEADER_new;
    {$ifend}
    {$if declared(OSSL_CMP_PKIHEADER_new_introduced)}
    if LibVersion < OSSL_CMP_PKIHEADER_new_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKIHEADER_new)}
      OSSL_CMP_PKIHEADER_new := FC_OSSL_CMP_PKIHEADER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKIHEADER_new_removed)}
    if OSSL_CMP_PKIHEADER_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKIHEADER_new)}
      OSSL_CMP_PKIHEADER_new := _OSSL_CMP_PKIHEADER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKIHEADER_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKIHEADER_new');
    {$ifend}
  end;
  
  OSSL_CMP_PKIHEADER_free := LoadLibFunction(ADllHandle, OSSL_CMP_PKIHEADER_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKIHEADER_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKIHEADER_free_allownil)}
    OSSL_CMP_PKIHEADER_free := ERR_OSSL_CMP_PKIHEADER_free;
    {$ifend}
    {$if declared(OSSL_CMP_PKIHEADER_free_introduced)}
    if LibVersion < OSSL_CMP_PKIHEADER_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKIHEADER_free)}
      OSSL_CMP_PKIHEADER_free := FC_OSSL_CMP_PKIHEADER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKIHEADER_free_removed)}
    if OSSL_CMP_PKIHEADER_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKIHEADER_free)}
      OSSL_CMP_PKIHEADER_free := _OSSL_CMP_PKIHEADER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKIHEADER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKIHEADER_free');
    {$ifend}
  end;
  
  d2i_OSSL_CMP_PKIHEADER := LoadLibFunction(ADllHandle, d2i_OSSL_CMP_PKIHEADER_procname);
  FuncLoadError := not assigned(d2i_OSSL_CMP_PKIHEADER);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CMP_PKIHEADER_allownil)}
    d2i_OSSL_CMP_PKIHEADER := ERR_d2i_OSSL_CMP_PKIHEADER;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_PKIHEADER_introduced)}
    if LibVersion < d2i_OSSL_CMP_PKIHEADER_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CMP_PKIHEADER)}
      d2i_OSSL_CMP_PKIHEADER := FC_d2i_OSSL_CMP_PKIHEADER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_PKIHEADER_removed)}
    if d2i_OSSL_CMP_PKIHEADER_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CMP_PKIHEADER)}
      d2i_OSSL_CMP_PKIHEADER := _d2i_OSSL_CMP_PKIHEADER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CMP_PKIHEADER_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CMP_PKIHEADER');
    {$ifend}
  end;
  
  i2d_OSSL_CMP_PKIHEADER := LoadLibFunction(ADllHandle, i2d_OSSL_CMP_PKIHEADER_procname);
  FuncLoadError := not assigned(i2d_OSSL_CMP_PKIHEADER);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CMP_PKIHEADER_allownil)}
    i2d_OSSL_CMP_PKIHEADER := ERR_i2d_OSSL_CMP_PKIHEADER;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_PKIHEADER_introduced)}
    if LibVersion < i2d_OSSL_CMP_PKIHEADER_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CMP_PKIHEADER)}
      i2d_OSSL_CMP_PKIHEADER := FC_i2d_OSSL_CMP_PKIHEADER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_PKIHEADER_removed)}
    if i2d_OSSL_CMP_PKIHEADER_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CMP_PKIHEADER)}
      i2d_OSSL_CMP_PKIHEADER := _i2d_OSSL_CMP_PKIHEADER;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CMP_PKIHEADER_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CMP_PKIHEADER');
    {$ifend}
  end;
  
  OSSL_CMP_PKIHEADER_it := LoadLibFunction(ADllHandle, OSSL_CMP_PKIHEADER_it_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKIHEADER_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKIHEADER_it_allownil)}
    OSSL_CMP_PKIHEADER_it := ERR_OSSL_CMP_PKIHEADER_it;
    {$ifend}
    {$if declared(OSSL_CMP_PKIHEADER_it_introduced)}
    if LibVersion < OSSL_CMP_PKIHEADER_it_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKIHEADER_it)}
      OSSL_CMP_PKIHEADER_it := FC_OSSL_CMP_PKIHEADER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKIHEADER_it_removed)}
    if OSSL_CMP_PKIHEADER_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKIHEADER_it)}
      OSSL_CMP_PKIHEADER_it := _OSSL_CMP_PKIHEADER_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKIHEADER_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKIHEADER_it');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_dup := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_dup_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_dup_allownil)}
    OSSL_CMP_MSG_dup := ERR_OSSL_CMP_MSG_dup;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_dup_introduced)}
    if LibVersion < OSSL_CMP_MSG_dup_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_dup)}
      OSSL_CMP_MSG_dup := FC_OSSL_CMP_MSG_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_dup_removed)}
    if OSSL_CMP_MSG_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_dup)}
      OSSL_CMP_MSG_dup := _OSSL_CMP_MSG_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_dup');
    {$ifend}
  end;
  
  d2i_OSSL_CMP_MSG := LoadLibFunction(ADllHandle, d2i_OSSL_CMP_MSG_procname);
  FuncLoadError := not assigned(d2i_OSSL_CMP_MSG);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CMP_MSG_allownil)}
    d2i_OSSL_CMP_MSG := ERR_d2i_OSSL_CMP_MSG;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_MSG_introduced)}
    if LibVersion < d2i_OSSL_CMP_MSG_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CMP_MSG)}
      d2i_OSSL_CMP_MSG := FC_d2i_OSSL_CMP_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_MSG_removed)}
    if d2i_OSSL_CMP_MSG_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CMP_MSG)}
      d2i_OSSL_CMP_MSG := _d2i_OSSL_CMP_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CMP_MSG_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CMP_MSG');
    {$ifend}
  end;
  
  i2d_OSSL_CMP_MSG := LoadLibFunction(ADllHandle, i2d_OSSL_CMP_MSG_procname);
  FuncLoadError := not assigned(i2d_OSSL_CMP_MSG);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CMP_MSG_allownil)}
    i2d_OSSL_CMP_MSG := ERR_i2d_OSSL_CMP_MSG;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_MSG_introduced)}
    if LibVersion < i2d_OSSL_CMP_MSG_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CMP_MSG)}
      i2d_OSSL_CMP_MSG := FC_i2d_OSSL_CMP_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_MSG_removed)}
    if i2d_OSSL_CMP_MSG_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CMP_MSG)}
      i2d_OSSL_CMP_MSG := _i2d_OSSL_CMP_MSG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CMP_MSG_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CMP_MSG');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_it := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_it_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_it_allownil)}
    OSSL_CMP_MSG_it := ERR_OSSL_CMP_MSG_it;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_it_introduced)}
    if LibVersion < OSSL_CMP_MSG_it_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_it)}
      OSSL_CMP_MSG_it := FC_OSSL_CMP_MSG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_it_removed)}
    if OSSL_CMP_MSG_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_it)}
      OSSL_CMP_MSG_it := _OSSL_CMP_MSG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_it');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_dup := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_dup_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_dup_allownil)}
    OSSL_CMP_ITAV_dup := ERR_OSSL_CMP_ITAV_dup;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_dup_introduced)}
    if LibVersion < OSSL_CMP_ITAV_dup_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_dup)}
      OSSL_CMP_ITAV_dup := FC_OSSL_CMP_ITAV_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_dup_removed)}
    if OSSL_CMP_ITAV_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_dup)}
      OSSL_CMP_ITAV_dup := _OSSL_CMP_ITAV_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_dup');
    {$ifend}
  end;
  
  OSSL_CMP_ATAVS_new := LoadLibFunction(ADllHandle, OSSL_CMP_ATAVS_new_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAVS_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAVS_new_allownil)}
    OSSL_CMP_ATAVS_new := ERR_OSSL_CMP_ATAVS_new;
    {$ifend}
    {$if declared(OSSL_CMP_ATAVS_new_introduced)}
    if LibVersion < OSSL_CMP_ATAVS_new_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAVS_new)}
      OSSL_CMP_ATAVS_new := FC_OSSL_CMP_ATAVS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAVS_new_removed)}
    if OSSL_CMP_ATAVS_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAVS_new)}
      OSSL_CMP_ATAVS_new := _OSSL_CMP_ATAVS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAVS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAVS_new');
    {$ifend}
  end;
  
  OSSL_CMP_ATAVS_free := LoadLibFunction(ADllHandle, OSSL_CMP_ATAVS_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAVS_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAVS_free_allownil)}
    OSSL_CMP_ATAVS_free := ERR_OSSL_CMP_ATAVS_free;
    {$ifend}
    {$if declared(OSSL_CMP_ATAVS_free_introduced)}
    if LibVersion < OSSL_CMP_ATAVS_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAVS_free)}
      OSSL_CMP_ATAVS_free := FC_OSSL_CMP_ATAVS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAVS_free_removed)}
    if OSSL_CMP_ATAVS_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAVS_free)}
      OSSL_CMP_ATAVS_free := _OSSL_CMP_ATAVS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAVS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAVS_free');
    {$ifend}
  end;
  
  d2i_OSSL_CMP_ATAVS := LoadLibFunction(ADllHandle, d2i_OSSL_CMP_ATAVS_procname);
  FuncLoadError := not assigned(d2i_OSSL_CMP_ATAVS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CMP_ATAVS_allownil)}
    d2i_OSSL_CMP_ATAVS := ERR_d2i_OSSL_CMP_ATAVS;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_ATAVS_introduced)}
    if LibVersion < d2i_OSSL_CMP_ATAVS_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CMP_ATAVS)}
      d2i_OSSL_CMP_ATAVS := FC_d2i_OSSL_CMP_ATAVS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_ATAVS_removed)}
    if d2i_OSSL_CMP_ATAVS_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CMP_ATAVS)}
      d2i_OSSL_CMP_ATAVS := _d2i_OSSL_CMP_ATAVS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CMP_ATAVS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CMP_ATAVS');
    {$ifend}
  end;
  
  i2d_OSSL_CMP_ATAVS := LoadLibFunction(ADllHandle, i2d_OSSL_CMP_ATAVS_procname);
  FuncLoadError := not assigned(i2d_OSSL_CMP_ATAVS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CMP_ATAVS_allownil)}
    i2d_OSSL_CMP_ATAVS := ERR_i2d_OSSL_CMP_ATAVS;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_ATAVS_introduced)}
    if LibVersion < i2d_OSSL_CMP_ATAVS_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CMP_ATAVS)}
      i2d_OSSL_CMP_ATAVS := FC_i2d_OSSL_CMP_ATAVS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_ATAVS_removed)}
    if i2d_OSSL_CMP_ATAVS_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CMP_ATAVS)}
      i2d_OSSL_CMP_ATAVS := _i2d_OSSL_CMP_ATAVS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CMP_ATAVS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CMP_ATAVS');
    {$ifend}
  end;
  
  OSSL_CMP_ATAVS_it := LoadLibFunction(ADllHandle, OSSL_CMP_ATAVS_it_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAVS_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAVS_it_allownil)}
    OSSL_CMP_ATAVS_it := ERR_OSSL_CMP_ATAVS_it;
    {$ifend}
    {$if declared(OSSL_CMP_ATAVS_it_introduced)}
    if LibVersion < OSSL_CMP_ATAVS_it_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAVS_it)}
      OSSL_CMP_ATAVS_it := FC_OSSL_CMP_ATAVS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAVS_it_removed)}
    if OSSL_CMP_ATAVS_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAVS_it)}
      OSSL_CMP_ATAVS_it := _OSSL_CMP_ATAVS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAVS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAVS_it');
    {$ifend}
  end;
  
  OSSL_CMP_PKISI_new := LoadLibFunction(ADllHandle, OSSL_CMP_PKISI_new_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKISI_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKISI_new_allownil)}
    OSSL_CMP_PKISI_new := ERR_OSSL_CMP_PKISI_new;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_new_introduced)}
    if LibVersion < OSSL_CMP_PKISI_new_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKISI_new)}
      OSSL_CMP_PKISI_new := FC_OSSL_CMP_PKISI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_new_removed)}
    if OSSL_CMP_PKISI_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKISI_new)}
      OSSL_CMP_PKISI_new := _OSSL_CMP_PKISI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKISI_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKISI_new');
    {$ifend}
  end;
  
  OSSL_CMP_PKISI_free := LoadLibFunction(ADllHandle, OSSL_CMP_PKISI_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKISI_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKISI_free_allownil)}
    OSSL_CMP_PKISI_free := ERR_OSSL_CMP_PKISI_free;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_free_introduced)}
    if LibVersion < OSSL_CMP_PKISI_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKISI_free)}
      OSSL_CMP_PKISI_free := FC_OSSL_CMP_PKISI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_free_removed)}
    if OSSL_CMP_PKISI_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKISI_free)}
      OSSL_CMP_PKISI_free := _OSSL_CMP_PKISI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKISI_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKISI_free');
    {$ifend}
  end;
  
  d2i_OSSL_CMP_PKISI := LoadLibFunction(ADllHandle, d2i_OSSL_CMP_PKISI_procname);
  FuncLoadError := not assigned(d2i_OSSL_CMP_PKISI);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CMP_PKISI_allownil)}
    d2i_OSSL_CMP_PKISI := ERR_d2i_OSSL_CMP_PKISI;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_PKISI_introduced)}
    if LibVersion < d2i_OSSL_CMP_PKISI_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CMP_PKISI)}
      d2i_OSSL_CMP_PKISI := FC_d2i_OSSL_CMP_PKISI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_PKISI_removed)}
    if d2i_OSSL_CMP_PKISI_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CMP_PKISI)}
      d2i_OSSL_CMP_PKISI := _d2i_OSSL_CMP_PKISI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CMP_PKISI_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CMP_PKISI');
    {$ifend}
  end;
  
  i2d_OSSL_CMP_PKISI := LoadLibFunction(ADllHandle, i2d_OSSL_CMP_PKISI_procname);
  FuncLoadError := not assigned(i2d_OSSL_CMP_PKISI);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CMP_PKISI_allownil)}
    i2d_OSSL_CMP_PKISI := ERR_i2d_OSSL_CMP_PKISI;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_PKISI_introduced)}
    if LibVersion < i2d_OSSL_CMP_PKISI_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CMP_PKISI)}
      i2d_OSSL_CMP_PKISI := FC_i2d_OSSL_CMP_PKISI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_PKISI_removed)}
    if i2d_OSSL_CMP_PKISI_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CMP_PKISI)}
      i2d_OSSL_CMP_PKISI := _i2d_OSSL_CMP_PKISI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CMP_PKISI_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CMP_PKISI');
    {$ifend}
  end;
  
  OSSL_CMP_PKISI_it := LoadLibFunction(ADllHandle, OSSL_CMP_PKISI_it_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKISI_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKISI_it_allownil)}
    OSSL_CMP_PKISI_it := ERR_OSSL_CMP_PKISI_it;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_it_introduced)}
    if LibVersion < OSSL_CMP_PKISI_it_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKISI_it)}
      OSSL_CMP_PKISI_it := FC_OSSL_CMP_PKISI_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_it_removed)}
    if OSSL_CMP_PKISI_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKISI_it)}
      OSSL_CMP_PKISI_it := _OSSL_CMP_PKISI_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKISI_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKISI_it');
    {$ifend}
  end;
  
  OSSL_CMP_PKISI_dup := LoadLibFunction(ADllHandle, OSSL_CMP_PKISI_dup_procname);
  FuncLoadError := not assigned(OSSL_CMP_PKISI_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_PKISI_dup_allownil)}
    OSSL_CMP_PKISI_dup := ERR_OSSL_CMP_PKISI_dup;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_dup_introduced)}
    if LibVersion < OSSL_CMP_PKISI_dup_introduced then
    begin
      {$if declared(FC_OSSL_CMP_PKISI_dup)}
      OSSL_CMP_PKISI_dup := FC_OSSL_CMP_PKISI_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_PKISI_dup_removed)}
    if OSSL_CMP_PKISI_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_PKISI_dup)}
      OSSL_CMP_PKISI_dup := _OSSL_CMP_PKISI_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_PKISI_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_PKISI_dup');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_create := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_create_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_create);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_create_allownil)}
    OSSL_CMP_ITAV_create := ERR_OSSL_CMP_ITAV_create;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_create_introduced)}
    if LibVersion < OSSL_CMP_ITAV_create_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_create)}
      OSSL_CMP_ITAV_create := FC_OSSL_CMP_ITAV_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_create_removed)}
    if OSSL_CMP_ITAV_create_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_create)}
      OSSL_CMP_ITAV_create := _OSSL_CMP_ITAV_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_create_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_create');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_set0 := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_set0_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_set0);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_set0_allownil)}
    OSSL_CMP_ITAV_set0 := ERR_OSSL_CMP_ITAV_set0;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_set0_introduced)}
    if LibVersion < OSSL_CMP_ITAV_set0_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_set0)}
      OSSL_CMP_ITAV_set0 := FC_OSSL_CMP_ITAV_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_set0_removed)}
    if OSSL_CMP_ITAV_set0_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_set0)}
      OSSL_CMP_ITAV_set0 := _OSSL_CMP_ITAV_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_set0_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_set0');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_type := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_type_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_type_allownil)}
    OSSL_CMP_ITAV_get0_type := ERR_OSSL_CMP_ITAV_get0_type;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_type_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_type_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_type)}
      OSSL_CMP_ITAV_get0_type := FC_OSSL_CMP_ITAV_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_type_removed)}
    if OSSL_CMP_ITAV_get0_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_type)}
      OSSL_CMP_ITAV_get0_type := _OSSL_CMP_ITAV_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_type');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_value := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_value_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_value);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_value_allownil)}
    OSSL_CMP_ITAV_get0_value := ERR_OSSL_CMP_ITAV_get0_value;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_value_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_value_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_value)}
      OSSL_CMP_ITAV_get0_value := FC_OSSL_CMP_ITAV_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_value_removed)}
    if OSSL_CMP_ITAV_get0_value_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_value)}
      OSSL_CMP_ITAV_get0_value := _OSSL_CMP_ITAV_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_value');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_push0_stack_item := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_push0_stack_item_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_push0_stack_item);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_push0_stack_item_allownil)}
    OSSL_CMP_ITAV_push0_stack_item := ERR_OSSL_CMP_ITAV_push0_stack_item;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_push0_stack_item_introduced)}
    if LibVersion < OSSL_CMP_ITAV_push0_stack_item_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_push0_stack_item)}
      OSSL_CMP_ITAV_push0_stack_item := FC_OSSL_CMP_ITAV_push0_stack_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_push0_stack_item_removed)}
    if OSSL_CMP_ITAV_push0_stack_item_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_push0_stack_item)}
      OSSL_CMP_ITAV_push0_stack_item := _OSSL_CMP_ITAV_push0_stack_item;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_push0_stack_item_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_push0_stack_item');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_free := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_free_allownil)}
    OSSL_CMP_ITAV_free := ERR_OSSL_CMP_ITAV_free;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_free_introduced)}
    if LibVersion < OSSL_CMP_ITAV_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_free)}
      OSSL_CMP_ITAV_free := FC_OSSL_CMP_ITAV_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_free_removed)}
    if OSSL_CMP_ITAV_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_free)}
      OSSL_CMP_ITAV_free := _OSSL_CMP_ITAV_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_free');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_new0_certProfile := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_new0_certProfile_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_new0_certProfile);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_new0_certProfile_allownil)}
    OSSL_CMP_ITAV_new0_certProfile := ERR_OSSL_CMP_ITAV_new0_certProfile;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new0_certProfile_introduced)}
    if LibVersion < OSSL_CMP_ITAV_new0_certProfile_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_new0_certProfile)}
      OSSL_CMP_ITAV_new0_certProfile := FC_OSSL_CMP_ITAV_new0_certProfile;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new0_certProfile_removed)}
    if OSSL_CMP_ITAV_new0_certProfile_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_new0_certProfile)}
      OSSL_CMP_ITAV_new0_certProfile := _OSSL_CMP_ITAV_new0_certProfile;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_new0_certProfile_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_new0_certProfile');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_certProfile := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_certProfile_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_certProfile);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_certProfile_allownil)}
    OSSL_CMP_ITAV_get0_certProfile := ERR_OSSL_CMP_ITAV_get0_certProfile;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_certProfile_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_certProfile_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_certProfile)}
      OSSL_CMP_ITAV_get0_certProfile := FC_OSSL_CMP_ITAV_get0_certProfile;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_certProfile_removed)}
    if OSSL_CMP_ITAV_get0_certProfile_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_certProfile)}
      OSSL_CMP_ITAV_get0_certProfile := _OSSL_CMP_ITAV_get0_certProfile;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_certProfile_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_certProfile');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_new_caCerts := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_new_caCerts_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_new_caCerts);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_new_caCerts_allownil)}
    OSSL_CMP_ITAV_new_caCerts := ERR_OSSL_CMP_ITAV_new_caCerts;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_caCerts_introduced)}
    if LibVersion < OSSL_CMP_ITAV_new_caCerts_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_new_caCerts)}
      OSSL_CMP_ITAV_new_caCerts := FC_OSSL_CMP_ITAV_new_caCerts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_caCerts_removed)}
    if OSSL_CMP_ITAV_new_caCerts_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_new_caCerts)}
      OSSL_CMP_ITAV_new_caCerts := _OSSL_CMP_ITAV_new_caCerts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_new_caCerts_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_new_caCerts');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_caCerts := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_caCerts_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_caCerts);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_caCerts_allownil)}
    OSSL_CMP_ITAV_get0_caCerts := ERR_OSSL_CMP_ITAV_get0_caCerts;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_caCerts_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_caCerts_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_caCerts)}
      OSSL_CMP_ITAV_get0_caCerts := FC_OSSL_CMP_ITAV_get0_caCerts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_caCerts_removed)}
    if OSSL_CMP_ITAV_get0_caCerts_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_caCerts)}
      OSSL_CMP_ITAV_get0_caCerts := _OSSL_CMP_ITAV_get0_caCerts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_caCerts_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_caCerts');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_new_rootCaCert := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_new_rootCaCert_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_new_rootCaCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_new_rootCaCert_allownil)}
    OSSL_CMP_ITAV_new_rootCaCert := ERR_OSSL_CMP_ITAV_new_rootCaCert;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_rootCaCert_introduced)}
    if LibVersion < OSSL_CMP_ITAV_new_rootCaCert_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_new_rootCaCert)}
      OSSL_CMP_ITAV_new_rootCaCert := FC_OSSL_CMP_ITAV_new_rootCaCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_rootCaCert_removed)}
    if OSSL_CMP_ITAV_new_rootCaCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_new_rootCaCert)}
      OSSL_CMP_ITAV_new_rootCaCert := _OSSL_CMP_ITAV_new_rootCaCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_new_rootCaCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_new_rootCaCert');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_rootCaCert := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_rootCaCert_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_rootCaCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_rootCaCert_allownil)}
    OSSL_CMP_ITAV_get0_rootCaCert := ERR_OSSL_CMP_ITAV_get0_rootCaCert;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_rootCaCert_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_rootCaCert_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_rootCaCert)}
      OSSL_CMP_ITAV_get0_rootCaCert := FC_OSSL_CMP_ITAV_get0_rootCaCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_rootCaCert_removed)}
    if OSSL_CMP_ITAV_get0_rootCaCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_rootCaCert)}
      OSSL_CMP_ITAV_get0_rootCaCert := _OSSL_CMP_ITAV_get0_rootCaCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_rootCaCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_rootCaCert');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_new_rootCaKeyUpdate := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_new_rootCaKeyUpdate_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_new_rootCaKeyUpdate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_new_rootCaKeyUpdate_allownil)}
    OSSL_CMP_ITAV_new_rootCaKeyUpdate := ERR_OSSL_CMP_ITAV_new_rootCaKeyUpdate;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_rootCaKeyUpdate_introduced)}
    if LibVersion < OSSL_CMP_ITAV_new_rootCaKeyUpdate_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_new_rootCaKeyUpdate)}
      OSSL_CMP_ITAV_new_rootCaKeyUpdate := FC_OSSL_CMP_ITAV_new_rootCaKeyUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_rootCaKeyUpdate_removed)}
    if OSSL_CMP_ITAV_new_rootCaKeyUpdate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_new_rootCaKeyUpdate)}
      OSSL_CMP_ITAV_new_rootCaKeyUpdate := _OSSL_CMP_ITAV_new_rootCaKeyUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_new_rootCaKeyUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_new_rootCaKeyUpdate');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_rootCaKeyUpdate := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_rootCaKeyUpdate_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_rootCaKeyUpdate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_rootCaKeyUpdate_allownil)}
    OSSL_CMP_ITAV_get0_rootCaKeyUpdate := ERR_OSSL_CMP_ITAV_get0_rootCaKeyUpdate;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_rootCaKeyUpdate_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_rootCaKeyUpdate_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_rootCaKeyUpdate)}
      OSSL_CMP_ITAV_get0_rootCaKeyUpdate := FC_OSSL_CMP_ITAV_get0_rootCaKeyUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_rootCaKeyUpdate_removed)}
    if OSSL_CMP_ITAV_get0_rootCaKeyUpdate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_rootCaKeyUpdate)}
      OSSL_CMP_ITAV_get0_rootCaKeyUpdate := _OSSL_CMP_ITAV_get0_rootCaKeyUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_rootCaKeyUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_rootCaKeyUpdate');
    {$ifend}
  end;
  
  OSSL_CMP_CRLSTATUS_create := LoadLibFunction(ADllHandle, OSSL_CMP_CRLSTATUS_create_procname);
  FuncLoadError := not assigned(OSSL_CMP_CRLSTATUS_create);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CRLSTATUS_create_allownil)}
    OSSL_CMP_CRLSTATUS_create := ERR_OSSL_CMP_CRLSTATUS_create;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_create_introduced)}
    if LibVersion < OSSL_CMP_CRLSTATUS_create_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CRLSTATUS_create)}
      OSSL_CMP_CRLSTATUS_create := FC_OSSL_CMP_CRLSTATUS_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_create_removed)}
    if OSSL_CMP_CRLSTATUS_create_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CRLSTATUS_create)}
      OSSL_CMP_CRLSTATUS_create := _OSSL_CMP_CRLSTATUS_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CRLSTATUS_create_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CRLSTATUS_create');
    {$ifend}
  end;
  
  OSSL_CMP_CRLSTATUS_new1 := LoadLibFunction(ADllHandle, OSSL_CMP_CRLSTATUS_new1_procname);
  FuncLoadError := not assigned(OSSL_CMP_CRLSTATUS_new1);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CRLSTATUS_new1_allownil)}
    OSSL_CMP_CRLSTATUS_new1 := ERR_OSSL_CMP_CRLSTATUS_new1;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_new1_introduced)}
    if LibVersion < OSSL_CMP_CRLSTATUS_new1_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CRLSTATUS_new1)}
      OSSL_CMP_CRLSTATUS_new1 := FC_OSSL_CMP_CRLSTATUS_new1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_new1_removed)}
    if OSSL_CMP_CRLSTATUS_new1_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CRLSTATUS_new1)}
      OSSL_CMP_CRLSTATUS_new1 := _OSSL_CMP_CRLSTATUS_new1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CRLSTATUS_new1_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CRLSTATUS_new1');
    {$ifend}
  end;
  
  OSSL_CMP_CRLSTATUS_get0 := LoadLibFunction(ADllHandle, OSSL_CMP_CRLSTATUS_get0_procname);
  FuncLoadError := not assigned(OSSL_CMP_CRLSTATUS_get0);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CRLSTATUS_get0_allownil)}
    OSSL_CMP_CRLSTATUS_get0 := ERR_OSSL_CMP_CRLSTATUS_get0;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_get0_introduced)}
    if LibVersion < OSSL_CMP_CRLSTATUS_get0_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CRLSTATUS_get0)}
      OSSL_CMP_CRLSTATUS_get0 := FC_OSSL_CMP_CRLSTATUS_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_get0_removed)}
    if OSSL_CMP_CRLSTATUS_get0_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CRLSTATUS_get0)}
      OSSL_CMP_CRLSTATUS_get0 := _OSSL_CMP_CRLSTATUS_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CRLSTATUS_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CRLSTATUS_get0');
    {$ifend}
  end;
  
  OSSL_CMP_CRLSTATUS_free := LoadLibFunction(ADllHandle, OSSL_CMP_CRLSTATUS_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_CRLSTATUS_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CRLSTATUS_free_allownil)}
    OSSL_CMP_CRLSTATUS_free := ERR_OSSL_CMP_CRLSTATUS_free;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_free_introduced)}
    if LibVersion < OSSL_CMP_CRLSTATUS_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CRLSTATUS_free)}
      OSSL_CMP_CRLSTATUS_free := FC_OSSL_CMP_CRLSTATUS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CRLSTATUS_free_removed)}
    if OSSL_CMP_CRLSTATUS_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CRLSTATUS_free)}
      OSSL_CMP_CRLSTATUS_free := _OSSL_CMP_CRLSTATUS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CRLSTATUS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CRLSTATUS_free');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_new0_crlStatusList := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_new0_crlStatusList_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_new0_crlStatusList);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_new0_crlStatusList_allownil)}
    OSSL_CMP_ITAV_new0_crlStatusList := ERR_OSSL_CMP_ITAV_new0_crlStatusList;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new0_crlStatusList_introduced)}
    if LibVersion < OSSL_CMP_ITAV_new0_crlStatusList_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_new0_crlStatusList)}
      OSSL_CMP_ITAV_new0_crlStatusList := FC_OSSL_CMP_ITAV_new0_crlStatusList;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new0_crlStatusList_removed)}
    if OSSL_CMP_ITAV_new0_crlStatusList_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_new0_crlStatusList)}
      OSSL_CMP_ITAV_new0_crlStatusList := _OSSL_CMP_ITAV_new0_crlStatusList;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_new0_crlStatusList_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_new0_crlStatusList');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_crlStatusList := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_crlStatusList_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_crlStatusList);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_crlStatusList_allownil)}
    OSSL_CMP_ITAV_get0_crlStatusList := ERR_OSSL_CMP_ITAV_get0_crlStatusList;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_crlStatusList_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_crlStatusList_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_crlStatusList)}
      OSSL_CMP_ITAV_get0_crlStatusList := FC_OSSL_CMP_ITAV_get0_crlStatusList;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_crlStatusList_removed)}
    if OSSL_CMP_ITAV_get0_crlStatusList_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_crlStatusList)}
      OSSL_CMP_ITAV_get0_crlStatusList := _OSSL_CMP_ITAV_get0_crlStatusList;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_crlStatusList_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_crlStatusList');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_new_crls := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_new_crls_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_new_crls);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_new_crls_allownil)}
    OSSL_CMP_ITAV_new_crls := ERR_OSSL_CMP_ITAV_new_crls;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_crls_introduced)}
    if LibVersion < OSSL_CMP_ITAV_new_crls_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_new_crls)}
      OSSL_CMP_ITAV_new_crls := FC_OSSL_CMP_ITAV_new_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new_crls_removed)}
    if OSSL_CMP_ITAV_new_crls_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_new_crls)}
      OSSL_CMP_ITAV_new_crls := _OSSL_CMP_ITAV_new_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_new_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_new_crls');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get0_crls := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get0_crls_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get0_crls);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get0_crls_allownil)}
    OSSL_CMP_ITAV_get0_crls := ERR_OSSL_CMP_ITAV_get0_crls;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_crls_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get0_crls_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get0_crls)}
      OSSL_CMP_ITAV_get0_crls := FC_OSSL_CMP_ITAV_get0_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get0_crls_removed)}
    if OSSL_CMP_ITAV_get0_crls_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get0_crls)}
      OSSL_CMP_ITAV_get0_crls := _OSSL_CMP_ITAV_get0_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get0_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get0_crls');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_new0_certReqTemplate := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_new0_certReqTemplate_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_new0_certReqTemplate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_new0_certReqTemplate_allownil)}
    OSSL_CMP_ITAV_new0_certReqTemplate := ERR_OSSL_CMP_ITAV_new0_certReqTemplate;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new0_certReqTemplate_introduced)}
    if LibVersion < OSSL_CMP_ITAV_new0_certReqTemplate_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_new0_certReqTemplate)}
      OSSL_CMP_ITAV_new0_certReqTemplate := FC_OSSL_CMP_ITAV_new0_certReqTemplate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_new0_certReqTemplate_removed)}
    if OSSL_CMP_ITAV_new0_certReqTemplate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_new0_certReqTemplate)}
      OSSL_CMP_ITAV_new0_certReqTemplate := _OSSL_CMP_ITAV_new0_certReqTemplate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_new0_certReqTemplate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_new0_certReqTemplate');
    {$ifend}
  end;
  
  OSSL_CMP_ITAV_get1_certReqTemplate := LoadLibFunction(ADllHandle, OSSL_CMP_ITAV_get1_certReqTemplate_procname);
  FuncLoadError := not assigned(OSSL_CMP_ITAV_get1_certReqTemplate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ITAV_get1_certReqTemplate_allownil)}
    OSSL_CMP_ITAV_get1_certReqTemplate := ERR_OSSL_CMP_ITAV_get1_certReqTemplate;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get1_certReqTemplate_introduced)}
    if LibVersion < OSSL_CMP_ITAV_get1_certReqTemplate_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ITAV_get1_certReqTemplate)}
      OSSL_CMP_ITAV_get1_certReqTemplate := FC_OSSL_CMP_ITAV_get1_certReqTemplate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ITAV_get1_certReqTemplate_removed)}
    if OSSL_CMP_ITAV_get1_certReqTemplate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ITAV_get1_certReqTemplate)}
      OSSL_CMP_ITAV_get1_certReqTemplate := _OSSL_CMP_ITAV_get1_certReqTemplate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ITAV_get1_certReqTemplate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ITAV_get1_certReqTemplate');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_create := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_create_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_create);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_create_allownil)}
    OSSL_CMP_ATAV_create := ERR_OSSL_CMP_ATAV_create;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_create_introduced)}
    if LibVersion < OSSL_CMP_ATAV_create_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_create)}
      OSSL_CMP_ATAV_create := FC_OSSL_CMP_ATAV_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_create_removed)}
    if OSSL_CMP_ATAV_create_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_create)}
      OSSL_CMP_ATAV_create := _OSSL_CMP_ATAV_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_create_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_create');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_set0 := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_set0_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_set0);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_set0_allownil)}
    OSSL_CMP_ATAV_set0 := ERR_OSSL_CMP_ATAV_set0;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_set0_introduced)}
    if LibVersion < OSSL_CMP_ATAV_set0_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_set0)}
      OSSL_CMP_ATAV_set0 := FC_OSSL_CMP_ATAV_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_set0_removed)}
    if OSSL_CMP_ATAV_set0_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_set0)}
      OSSL_CMP_ATAV_set0 := _OSSL_CMP_ATAV_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_set0_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_set0');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_get0_type := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_get0_type_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_get0_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_get0_type_allownil)}
    OSSL_CMP_ATAV_get0_type := ERR_OSSL_CMP_ATAV_get0_type;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get0_type_introduced)}
    if LibVersion < OSSL_CMP_ATAV_get0_type_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_get0_type)}
      OSSL_CMP_ATAV_get0_type := FC_OSSL_CMP_ATAV_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get0_type_removed)}
    if OSSL_CMP_ATAV_get0_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_get0_type)}
      OSSL_CMP_ATAV_get0_type := _OSSL_CMP_ATAV_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_get0_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_get0_type');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_get0_value := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_get0_value_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_get0_value);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_get0_value_allownil)}
    OSSL_CMP_ATAV_get0_value := ERR_OSSL_CMP_ATAV_get0_value;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get0_value_introduced)}
    if LibVersion < OSSL_CMP_ATAV_get0_value_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_get0_value)}
      OSSL_CMP_ATAV_get0_value := FC_OSSL_CMP_ATAV_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get0_value_removed)}
    if OSSL_CMP_ATAV_get0_value_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_get0_value)}
      OSSL_CMP_ATAV_get0_value := _OSSL_CMP_ATAV_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_get0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_get0_value');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_new_algId := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_new_algId_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_new_algId);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_new_algId_allownil)}
    OSSL_CMP_ATAV_new_algId := ERR_OSSL_CMP_ATAV_new_algId;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_new_algId_introduced)}
    if LibVersion < OSSL_CMP_ATAV_new_algId_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_new_algId)}
      OSSL_CMP_ATAV_new_algId := FC_OSSL_CMP_ATAV_new_algId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_new_algId_removed)}
    if OSSL_CMP_ATAV_new_algId_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_new_algId)}
      OSSL_CMP_ATAV_new_algId := _OSSL_CMP_ATAV_new_algId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_new_algId_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_new_algId');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_get0_algId := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_get0_algId_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_get0_algId);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_get0_algId_allownil)}
    OSSL_CMP_ATAV_get0_algId := ERR_OSSL_CMP_ATAV_get0_algId;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get0_algId_introduced)}
    if LibVersion < OSSL_CMP_ATAV_get0_algId_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_get0_algId)}
      OSSL_CMP_ATAV_get0_algId := FC_OSSL_CMP_ATAV_get0_algId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get0_algId_removed)}
    if OSSL_CMP_ATAV_get0_algId_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_get0_algId)}
      OSSL_CMP_ATAV_get0_algId := _OSSL_CMP_ATAV_get0_algId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_get0_algId_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_get0_algId');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_new_rsaKeyLen := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_new_rsaKeyLen_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_new_rsaKeyLen);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_new_rsaKeyLen_allownil)}
    OSSL_CMP_ATAV_new_rsaKeyLen := ERR_OSSL_CMP_ATAV_new_rsaKeyLen;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_new_rsaKeyLen_introduced)}
    if LibVersion < OSSL_CMP_ATAV_new_rsaKeyLen_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_new_rsaKeyLen)}
      OSSL_CMP_ATAV_new_rsaKeyLen := FC_OSSL_CMP_ATAV_new_rsaKeyLen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_new_rsaKeyLen_removed)}
    if OSSL_CMP_ATAV_new_rsaKeyLen_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_new_rsaKeyLen)}
      OSSL_CMP_ATAV_new_rsaKeyLen := _OSSL_CMP_ATAV_new_rsaKeyLen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_new_rsaKeyLen_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_new_rsaKeyLen');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_get_rsaKeyLen := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_get_rsaKeyLen_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_get_rsaKeyLen);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_get_rsaKeyLen_allownil)}
    OSSL_CMP_ATAV_get_rsaKeyLen := ERR_OSSL_CMP_ATAV_get_rsaKeyLen;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get_rsaKeyLen_introduced)}
    if LibVersion < OSSL_CMP_ATAV_get_rsaKeyLen_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_get_rsaKeyLen)}
      OSSL_CMP_ATAV_get_rsaKeyLen := FC_OSSL_CMP_ATAV_get_rsaKeyLen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_get_rsaKeyLen_removed)}
    if OSSL_CMP_ATAV_get_rsaKeyLen_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_get_rsaKeyLen)}
      OSSL_CMP_ATAV_get_rsaKeyLen := _OSSL_CMP_ATAV_get_rsaKeyLen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_get_rsaKeyLen_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_get_rsaKeyLen');
    {$ifend}
  end;
  
  OSSL_CMP_ATAV_push1 := LoadLibFunction(ADllHandle, OSSL_CMP_ATAV_push1_procname);
  FuncLoadError := not assigned(OSSL_CMP_ATAV_push1);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_ATAV_push1_allownil)}
    OSSL_CMP_ATAV_push1 := ERR_OSSL_CMP_ATAV_push1;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_push1_introduced)}
    if LibVersion < OSSL_CMP_ATAV_push1_introduced then
    begin
      {$if declared(FC_OSSL_CMP_ATAV_push1)}
      OSSL_CMP_ATAV_push1 := FC_OSSL_CMP_ATAV_push1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_ATAV_push1_removed)}
    if OSSL_CMP_ATAV_push1_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_ATAV_push1)}
      OSSL_CMP_ATAV_push1 := _OSSL_CMP_ATAV_push1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_ATAV_push1_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_ATAV_push1');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_free := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_free_allownil)}
    OSSL_CMP_MSG_free := ERR_OSSL_CMP_MSG_free;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_free_introduced)}
    if LibVersion < OSSL_CMP_MSG_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_free)}
      OSSL_CMP_MSG_free := FC_OSSL_CMP_MSG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_free_removed)}
    if OSSL_CMP_MSG_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_free)}
      OSSL_CMP_MSG_free := _OSSL_CMP_MSG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_free');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_new := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_new_allownil)}
    OSSL_CMP_CTX_new := ERR_OSSL_CMP_CTX_new;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_new_introduced)}
    if LibVersion < OSSL_CMP_CTX_new_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_new)}
      OSSL_CMP_CTX_new := FC_OSSL_CMP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_new_removed)}
    if OSSL_CMP_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_new)}
      OSSL_CMP_CTX_new := _OSSL_CMP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_new');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_free := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_free_allownil)}
    OSSL_CMP_CTX_free := ERR_OSSL_CMP_CTX_free;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_free_introduced)}
    if LibVersion < OSSL_CMP_CTX_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_free)}
      OSSL_CMP_CTX_free := FC_OSSL_CMP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_free_removed)}
    if OSSL_CMP_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_free)}
      OSSL_CMP_CTX_free := _OSSL_CMP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_free');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_reinit := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_reinit_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_reinit);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_reinit_allownil)}
    OSSL_CMP_CTX_reinit := ERR_OSSL_CMP_CTX_reinit;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_reinit_introduced)}
    if LibVersion < OSSL_CMP_CTX_reinit_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_reinit)}
      OSSL_CMP_CTX_reinit := FC_OSSL_CMP_CTX_reinit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_reinit_removed)}
    if OSSL_CMP_CTX_reinit_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_reinit)}
      OSSL_CMP_CTX_reinit := _OSSL_CMP_CTX_reinit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_reinit_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_reinit');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_libctx := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_libctx_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_libctx);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_libctx_allownil)}
    OSSL_CMP_CTX_get0_libctx := ERR_OSSL_CMP_CTX_get0_libctx;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_libctx_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_libctx_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_libctx)}
      OSSL_CMP_CTX_get0_libctx := FC_OSSL_CMP_CTX_get0_libctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_libctx_removed)}
    if OSSL_CMP_CTX_get0_libctx_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_libctx)}
      OSSL_CMP_CTX_get0_libctx := _OSSL_CMP_CTX_get0_libctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_libctx_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_libctx');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_propq := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_propq_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_propq);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_propq_allownil)}
    OSSL_CMP_CTX_get0_propq := ERR_OSSL_CMP_CTX_get0_propq;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_propq_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_propq_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_propq)}
      OSSL_CMP_CTX_get0_propq := FC_OSSL_CMP_CTX_get0_propq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_propq_removed)}
    if OSSL_CMP_CTX_get0_propq_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_propq)}
      OSSL_CMP_CTX_get0_propq := _OSSL_CMP_CTX_get0_propq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_propq_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_propq');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_option := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_option_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_option);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_option_allownil)}
    OSSL_CMP_CTX_set_option := ERR_OSSL_CMP_CTX_set_option;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_option_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_option_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_option)}
      OSSL_CMP_CTX_set_option := FC_OSSL_CMP_CTX_set_option;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_option_removed)}
    if OSSL_CMP_CTX_set_option_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_option)}
      OSSL_CMP_CTX_set_option := _OSSL_CMP_CTX_set_option;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_option_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_option');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get_option := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get_option_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get_option);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get_option_allownil)}
    OSSL_CMP_CTX_get_option := ERR_OSSL_CMP_CTX_get_option;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_option_introduced)}
    if LibVersion < OSSL_CMP_CTX_get_option_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get_option)}
      OSSL_CMP_CTX_get_option := FC_OSSL_CMP_CTX_get_option;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_option_removed)}
    if OSSL_CMP_CTX_get_option_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get_option)}
      OSSL_CMP_CTX_get_option := _OSSL_CMP_CTX_get_option;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get_option_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get_option');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_log_cb := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_log_cb_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_log_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_log_cb_allownil)}
    OSSL_CMP_CTX_set_log_cb := ERR_OSSL_CMP_CTX_set_log_cb;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_log_cb_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_log_cb_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_log_cb)}
      OSSL_CMP_CTX_set_log_cb := FC_OSSL_CMP_CTX_set_log_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_log_cb_removed)}
    if OSSL_CMP_CTX_set_log_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_log_cb)}
      OSSL_CMP_CTX_set_log_cb := _OSSL_CMP_CTX_set_log_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_log_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_log_cb');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_print_errors := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_print_errors_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_print_errors);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_print_errors_allownil)}
    OSSL_CMP_CTX_print_errors := ERR_OSSL_CMP_CTX_print_errors;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_print_errors_introduced)}
    if LibVersion < OSSL_CMP_CTX_print_errors_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_print_errors)}
      OSSL_CMP_CTX_print_errors := FC_OSSL_CMP_CTX_print_errors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_print_errors_removed)}
    if OSSL_CMP_CTX_print_errors_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_print_errors)}
      OSSL_CMP_CTX_print_errors := _OSSL_CMP_CTX_print_errors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_print_errors_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_print_errors');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_serverPath := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_serverPath_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_serverPath);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_serverPath_allownil)}
    OSSL_CMP_CTX_set1_serverPath := ERR_OSSL_CMP_CTX_set1_serverPath;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_serverPath_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_serverPath_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_serverPath)}
      OSSL_CMP_CTX_set1_serverPath := FC_OSSL_CMP_CTX_set1_serverPath;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_serverPath_removed)}
    if OSSL_CMP_CTX_set1_serverPath_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_serverPath)}
      OSSL_CMP_CTX_set1_serverPath := _OSSL_CMP_CTX_set1_serverPath;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_serverPath_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_serverPath');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_server := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_server_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_server);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_server_allownil)}
    OSSL_CMP_CTX_set1_server := ERR_OSSL_CMP_CTX_set1_server;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_server_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_server_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_server)}
      OSSL_CMP_CTX_set1_server := FC_OSSL_CMP_CTX_set1_server;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_server_removed)}
    if OSSL_CMP_CTX_set1_server_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_server)}
      OSSL_CMP_CTX_set1_server := _OSSL_CMP_CTX_set1_server;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_server_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_server');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_serverPort := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_serverPort_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_serverPort);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_serverPort_allownil)}
    OSSL_CMP_CTX_set_serverPort := ERR_OSSL_CMP_CTX_set_serverPort;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_serverPort_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_serverPort_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_serverPort)}
      OSSL_CMP_CTX_set_serverPort := FC_OSSL_CMP_CTX_set_serverPort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_serverPort_removed)}
    if OSSL_CMP_CTX_set_serverPort_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_serverPort)}
      OSSL_CMP_CTX_set_serverPort := _OSSL_CMP_CTX_set_serverPort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_serverPort_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_serverPort');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_proxy := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_proxy_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_proxy);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_proxy_allownil)}
    OSSL_CMP_CTX_set1_proxy := ERR_OSSL_CMP_CTX_set1_proxy;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_proxy_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_proxy_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_proxy)}
      OSSL_CMP_CTX_set1_proxy := FC_OSSL_CMP_CTX_set1_proxy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_proxy_removed)}
    if OSSL_CMP_CTX_set1_proxy_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_proxy)}
      OSSL_CMP_CTX_set1_proxy := _OSSL_CMP_CTX_set1_proxy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_proxy_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_proxy');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_no_proxy := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_no_proxy_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_no_proxy);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_no_proxy_allownil)}
    OSSL_CMP_CTX_set1_no_proxy := ERR_OSSL_CMP_CTX_set1_no_proxy;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_no_proxy_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_no_proxy_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_no_proxy)}
      OSSL_CMP_CTX_set1_no_proxy := FC_OSSL_CMP_CTX_set1_no_proxy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_no_proxy_removed)}
    if OSSL_CMP_CTX_set1_no_proxy_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_no_proxy)}
      OSSL_CMP_CTX_set1_no_proxy := _OSSL_CMP_CTX_set1_no_proxy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_no_proxy_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_no_proxy');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_http_cb := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_http_cb_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_http_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_http_cb_allownil)}
    OSSL_CMP_CTX_set_http_cb := ERR_OSSL_CMP_CTX_set_http_cb;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_http_cb_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_http_cb_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_http_cb)}
      OSSL_CMP_CTX_set_http_cb := FC_OSSL_CMP_CTX_set_http_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_http_cb_removed)}
    if OSSL_CMP_CTX_set_http_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_http_cb)}
      OSSL_CMP_CTX_set_http_cb := _OSSL_CMP_CTX_set_http_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_http_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_http_cb');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_http_cb_arg := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_http_cb_arg_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_http_cb_arg);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_http_cb_arg_allownil)}
    OSSL_CMP_CTX_set_http_cb_arg := ERR_OSSL_CMP_CTX_set_http_cb_arg;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_http_cb_arg_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_http_cb_arg_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_http_cb_arg)}
      OSSL_CMP_CTX_set_http_cb_arg := FC_OSSL_CMP_CTX_set_http_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_http_cb_arg_removed)}
    if OSSL_CMP_CTX_set_http_cb_arg_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_http_cb_arg)}
      OSSL_CMP_CTX_set_http_cb_arg := _OSSL_CMP_CTX_set_http_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_http_cb_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_http_cb_arg');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get_http_cb_arg := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get_http_cb_arg_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get_http_cb_arg);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get_http_cb_arg_allownil)}
    OSSL_CMP_CTX_get_http_cb_arg := ERR_OSSL_CMP_CTX_get_http_cb_arg;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_http_cb_arg_introduced)}
    if LibVersion < OSSL_CMP_CTX_get_http_cb_arg_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get_http_cb_arg)}
      OSSL_CMP_CTX_get_http_cb_arg := FC_OSSL_CMP_CTX_get_http_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_http_cb_arg_removed)}
    if OSSL_CMP_CTX_get_http_cb_arg_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get_http_cb_arg)}
      OSSL_CMP_CTX_get_http_cb_arg := _OSSL_CMP_CTX_get_http_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get_http_cb_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get_http_cb_arg');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_transfer_cb := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_transfer_cb_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_transfer_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_transfer_cb_allownil)}
    OSSL_CMP_CTX_set_transfer_cb := ERR_OSSL_CMP_CTX_set_transfer_cb;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_transfer_cb_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_transfer_cb_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_transfer_cb)}
      OSSL_CMP_CTX_set_transfer_cb := FC_OSSL_CMP_CTX_set_transfer_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_transfer_cb_removed)}
    if OSSL_CMP_CTX_set_transfer_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_transfer_cb)}
      OSSL_CMP_CTX_set_transfer_cb := _OSSL_CMP_CTX_set_transfer_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_transfer_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_transfer_cb');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_transfer_cb_arg := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_transfer_cb_arg_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_transfer_cb_arg);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_transfer_cb_arg_allownil)}
    OSSL_CMP_CTX_set_transfer_cb_arg := ERR_OSSL_CMP_CTX_set_transfer_cb_arg;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_transfer_cb_arg_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_transfer_cb_arg_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_transfer_cb_arg)}
      OSSL_CMP_CTX_set_transfer_cb_arg := FC_OSSL_CMP_CTX_set_transfer_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_transfer_cb_arg_removed)}
    if OSSL_CMP_CTX_set_transfer_cb_arg_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_transfer_cb_arg)}
      OSSL_CMP_CTX_set_transfer_cb_arg := _OSSL_CMP_CTX_set_transfer_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_transfer_cb_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_transfer_cb_arg');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get_transfer_cb_arg := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get_transfer_cb_arg_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get_transfer_cb_arg);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get_transfer_cb_arg_allownil)}
    OSSL_CMP_CTX_get_transfer_cb_arg := ERR_OSSL_CMP_CTX_get_transfer_cb_arg;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_transfer_cb_arg_introduced)}
    if LibVersion < OSSL_CMP_CTX_get_transfer_cb_arg_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get_transfer_cb_arg)}
      OSSL_CMP_CTX_get_transfer_cb_arg := FC_OSSL_CMP_CTX_get_transfer_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_transfer_cb_arg_removed)}
    if OSSL_CMP_CTX_get_transfer_cb_arg_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get_transfer_cb_arg)}
      OSSL_CMP_CTX_get_transfer_cb_arg := _OSSL_CMP_CTX_get_transfer_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get_transfer_cb_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get_transfer_cb_arg');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_srvCert := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_srvCert_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_srvCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_srvCert_allownil)}
    OSSL_CMP_CTX_set1_srvCert := ERR_OSSL_CMP_CTX_set1_srvCert;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_srvCert_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_srvCert_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_srvCert)}
      OSSL_CMP_CTX_set1_srvCert := FC_OSSL_CMP_CTX_set1_srvCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_srvCert_removed)}
    if OSSL_CMP_CTX_set1_srvCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_srvCert)}
      OSSL_CMP_CTX_set1_srvCert := _OSSL_CMP_CTX_set1_srvCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_srvCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_srvCert');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_expected_sender := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_expected_sender_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_expected_sender);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_expected_sender_allownil)}
    OSSL_CMP_CTX_set1_expected_sender := ERR_OSSL_CMP_CTX_set1_expected_sender;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_expected_sender_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_expected_sender_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_expected_sender)}
      OSSL_CMP_CTX_set1_expected_sender := FC_OSSL_CMP_CTX_set1_expected_sender;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_expected_sender_removed)}
    if OSSL_CMP_CTX_set1_expected_sender_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_expected_sender)}
      OSSL_CMP_CTX_set1_expected_sender := _OSSL_CMP_CTX_set1_expected_sender;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_expected_sender_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_expected_sender');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set0_trustedStore := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set0_trustedStore_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set0_trustedStore);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set0_trustedStore_allownil)}
    OSSL_CMP_CTX_set0_trustedStore := ERR_OSSL_CMP_CTX_set0_trustedStore;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set0_trustedStore_introduced)}
    if LibVersion < OSSL_CMP_CTX_set0_trustedStore_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set0_trustedStore)}
      OSSL_CMP_CTX_set0_trustedStore := FC_OSSL_CMP_CTX_set0_trustedStore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set0_trustedStore_removed)}
    if OSSL_CMP_CTX_set0_trustedStore_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set0_trustedStore)}
      OSSL_CMP_CTX_set0_trustedStore := _OSSL_CMP_CTX_set0_trustedStore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set0_trustedStore_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set0_trustedStore');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_trustedStore := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_trustedStore_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_trustedStore);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_trustedStore_allownil)}
    OSSL_CMP_CTX_get0_trustedStore := ERR_OSSL_CMP_CTX_get0_trustedStore;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_trustedStore_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_trustedStore_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_trustedStore)}
      OSSL_CMP_CTX_get0_trustedStore := FC_OSSL_CMP_CTX_get0_trustedStore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_trustedStore_removed)}
    if OSSL_CMP_CTX_get0_trustedStore_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_trustedStore)}
      OSSL_CMP_CTX_get0_trustedStore := _OSSL_CMP_CTX_get0_trustedStore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_trustedStore_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_trustedStore');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_untrusted := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_untrusted_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_untrusted);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_untrusted_allownil)}
    OSSL_CMP_CTX_set1_untrusted := ERR_OSSL_CMP_CTX_set1_untrusted;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_untrusted_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_untrusted_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_untrusted)}
      OSSL_CMP_CTX_set1_untrusted := FC_OSSL_CMP_CTX_set1_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_untrusted_removed)}
    if OSSL_CMP_CTX_set1_untrusted_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_untrusted)}
      OSSL_CMP_CTX_set1_untrusted := _OSSL_CMP_CTX_set1_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_untrusted_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_untrusted');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_untrusted := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_untrusted_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_untrusted);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_untrusted_allownil)}
    OSSL_CMP_CTX_get0_untrusted := ERR_OSSL_CMP_CTX_get0_untrusted;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_untrusted_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_untrusted_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_untrusted)}
      OSSL_CMP_CTX_get0_untrusted := FC_OSSL_CMP_CTX_get0_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_untrusted_removed)}
    if OSSL_CMP_CTX_get0_untrusted_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_untrusted)}
      OSSL_CMP_CTX_get0_untrusted := _OSSL_CMP_CTX_get0_untrusted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_untrusted_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_untrusted');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_cert := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_cert_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_cert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_cert_allownil)}
    OSSL_CMP_CTX_set1_cert := ERR_OSSL_CMP_CTX_set1_cert;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_cert_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_cert_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_cert)}
      OSSL_CMP_CTX_set1_cert := FC_OSSL_CMP_CTX_set1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_cert_removed)}
    if OSSL_CMP_CTX_set1_cert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_cert)}
      OSSL_CMP_CTX_set1_cert := _OSSL_CMP_CTX_set1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_cert');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_build_cert_chain := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_build_cert_chain_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_build_cert_chain);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_build_cert_chain_allownil)}
    OSSL_CMP_CTX_build_cert_chain := ERR_OSSL_CMP_CTX_build_cert_chain;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_build_cert_chain_introduced)}
    if LibVersion < OSSL_CMP_CTX_build_cert_chain_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_build_cert_chain)}
      OSSL_CMP_CTX_build_cert_chain := FC_OSSL_CMP_CTX_build_cert_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_build_cert_chain_removed)}
    if OSSL_CMP_CTX_build_cert_chain_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_build_cert_chain)}
      OSSL_CMP_CTX_build_cert_chain := _OSSL_CMP_CTX_build_cert_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_build_cert_chain_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_build_cert_chain');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_pkey := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_pkey_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_pkey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_pkey_allownil)}
    OSSL_CMP_CTX_set1_pkey := ERR_OSSL_CMP_CTX_set1_pkey;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_pkey_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_pkey_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_pkey)}
      OSSL_CMP_CTX_set1_pkey := FC_OSSL_CMP_CTX_set1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_pkey_removed)}
    if OSSL_CMP_CTX_set1_pkey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_pkey)}
      OSSL_CMP_CTX_set1_pkey := _OSSL_CMP_CTX_set1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_pkey');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_referenceValue := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_referenceValue_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_referenceValue);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_referenceValue_allownil)}
    OSSL_CMP_CTX_set1_referenceValue := ERR_OSSL_CMP_CTX_set1_referenceValue;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_referenceValue_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_referenceValue_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_referenceValue)}
      OSSL_CMP_CTX_set1_referenceValue := FC_OSSL_CMP_CTX_set1_referenceValue;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_referenceValue_removed)}
    if OSSL_CMP_CTX_set1_referenceValue_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_referenceValue)}
      OSSL_CMP_CTX_set1_referenceValue := _OSSL_CMP_CTX_set1_referenceValue;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_referenceValue_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_referenceValue');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_secretValue := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_secretValue_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_secretValue);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_secretValue_allownil)}
    OSSL_CMP_CTX_set1_secretValue := ERR_OSSL_CMP_CTX_set1_secretValue;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_secretValue_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_secretValue_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_secretValue)}
      OSSL_CMP_CTX_set1_secretValue := FC_OSSL_CMP_CTX_set1_secretValue;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_secretValue_removed)}
    if OSSL_CMP_CTX_set1_secretValue_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_secretValue)}
      OSSL_CMP_CTX_set1_secretValue := _OSSL_CMP_CTX_set1_secretValue;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_secretValue_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_secretValue');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_recipient := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_recipient_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_recipient);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_recipient_allownil)}
    OSSL_CMP_CTX_set1_recipient := ERR_OSSL_CMP_CTX_set1_recipient;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_recipient_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_recipient_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_recipient)}
      OSSL_CMP_CTX_set1_recipient := FC_OSSL_CMP_CTX_set1_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_recipient_removed)}
    if OSSL_CMP_CTX_set1_recipient_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_recipient)}
      OSSL_CMP_CTX_set1_recipient := _OSSL_CMP_CTX_set1_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_recipient_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_recipient');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_push0_geninfo_ITAV := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_push0_geninfo_ITAV_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_push0_geninfo_ITAV);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_push0_geninfo_ITAV_allownil)}
    OSSL_CMP_CTX_push0_geninfo_ITAV := ERR_OSSL_CMP_CTX_push0_geninfo_ITAV;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push0_geninfo_ITAV_introduced)}
    if LibVersion < OSSL_CMP_CTX_push0_geninfo_ITAV_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_push0_geninfo_ITAV)}
      OSSL_CMP_CTX_push0_geninfo_ITAV := FC_OSSL_CMP_CTX_push0_geninfo_ITAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push0_geninfo_ITAV_removed)}
    if OSSL_CMP_CTX_push0_geninfo_ITAV_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_push0_geninfo_ITAV)}
      OSSL_CMP_CTX_push0_geninfo_ITAV := _OSSL_CMP_CTX_push0_geninfo_ITAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_push0_geninfo_ITAV_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_push0_geninfo_ITAV');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_reset_geninfo_ITAVs := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_reset_geninfo_ITAVs_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_reset_geninfo_ITAVs);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_reset_geninfo_ITAVs_allownil)}
    OSSL_CMP_CTX_reset_geninfo_ITAVs := ERR_OSSL_CMP_CTX_reset_geninfo_ITAVs;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_reset_geninfo_ITAVs_introduced)}
    if LibVersion < OSSL_CMP_CTX_reset_geninfo_ITAVs_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_reset_geninfo_ITAVs)}
      OSSL_CMP_CTX_reset_geninfo_ITAVs := FC_OSSL_CMP_CTX_reset_geninfo_ITAVs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_reset_geninfo_ITAVs_removed)}
    if OSSL_CMP_CTX_reset_geninfo_ITAVs_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_reset_geninfo_ITAVs)}
      OSSL_CMP_CTX_reset_geninfo_ITAVs := _OSSL_CMP_CTX_reset_geninfo_ITAVs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_reset_geninfo_ITAVs_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_reset_geninfo_ITAVs');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_geninfo_ITAVs := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_geninfo_ITAVs_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_geninfo_ITAVs);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_geninfo_ITAVs_allownil)}
    OSSL_CMP_CTX_get0_geninfo_ITAVs := ERR_OSSL_CMP_CTX_get0_geninfo_ITAVs;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_geninfo_ITAVs_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_geninfo_ITAVs_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_geninfo_ITAVs)}
      OSSL_CMP_CTX_get0_geninfo_ITAVs := FC_OSSL_CMP_CTX_get0_geninfo_ITAVs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_geninfo_ITAVs_removed)}
    if OSSL_CMP_CTX_get0_geninfo_ITAVs_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_geninfo_ITAVs)}
      OSSL_CMP_CTX_get0_geninfo_ITAVs := _OSSL_CMP_CTX_get0_geninfo_ITAVs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_geninfo_ITAVs_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_geninfo_ITAVs');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_extraCertsOut := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_extraCertsOut_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_extraCertsOut);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_extraCertsOut_allownil)}
    OSSL_CMP_CTX_set1_extraCertsOut := ERR_OSSL_CMP_CTX_set1_extraCertsOut;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_extraCertsOut_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_extraCertsOut_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_extraCertsOut)}
      OSSL_CMP_CTX_set1_extraCertsOut := FC_OSSL_CMP_CTX_set1_extraCertsOut;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_extraCertsOut_removed)}
    if OSSL_CMP_CTX_set1_extraCertsOut_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_extraCertsOut)}
      OSSL_CMP_CTX_set1_extraCertsOut := _OSSL_CMP_CTX_set1_extraCertsOut;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_extraCertsOut_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_extraCertsOut');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set0_newPkey := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set0_newPkey_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set0_newPkey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set0_newPkey_allownil)}
    OSSL_CMP_CTX_set0_newPkey := ERR_OSSL_CMP_CTX_set0_newPkey;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set0_newPkey_introduced)}
    if LibVersion < OSSL_CMP_CTX_set0_newPkey_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set0_newPkey)}
      OSSL_CMP_CTX_set0_newPkey := FC_OSSL_CMP_CTX_set0_newPkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set0_newPkey_removed)}
    if OSSL_CMP_CTX_set0_newPkey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set0_newPkey)}
      OSSL_CMP_CTX_set0_newPkey := _OSSL_CMP_CTX_set0_newPkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set0_newPkey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set0_newPkey');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_newPkey := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_newPkey_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_newPkey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_newPkey_allownil)}
    OSSL_CMP_CTX_get0_newPkey := ERR_OSSL_CMP_CTX_get0_newPkey;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_newPkey_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_newPkey_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_newPkey)}
      OSSL_CMP_CTX_get0_newPkey := FC_OSSL_CMP_CTX_get0_newPkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_newPkey_removed)}
    if OSSL_CMP_CTX_get0_newPkey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_newPkey)}
      OSSL_CMP_CTX_get0_newPkey := _OSSL_CMP_CTX_get0_newPkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_newPkey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_newPkey');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_issuer := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_issuer_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_issuer);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_issuer_allownil)}
    OSSL_CMP_CTX_set1_issuer := ERR_OSSL_CMP_CTX_set1_issuer;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_issuer_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_issuer_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_issuer)}
      OSSL_CMP_CTX_set1_issuer := FC_OSSL_CMP_CTX_set1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_issuer_removed)}
    if OSSL_CMP_CTX_set1_issuer_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_issuer)}
      OSSL_CMP_CTX_set1_issuer := _OSSL_CMP_CTX_set1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_issuer');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_serialNumber := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_serialNumber_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_serialNumber_allownil)}
    OSSL_CMP_CTX_set1_serialNumber := ERR_OSSL_CMP_CTX_set1_serialNumber;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_serialNumber_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_serialNumber_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_serialNumber)}
      OSSL_CMP_CTX_set1_serialNumber := FC_OSSL_CMP_CTX_set1_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_serialNumber_removed)}
    if OSSL_CMP_CTX_set1_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_serialNumber)}
      OSSL_CMP_CTX_set1_serialNumber := _OSSL_CMP_CTX_set1_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_serialNumber');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_subjectName := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_subjectName_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_subjectName);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_subjectName_allownil)}
    OSSL_CMP_CTX_set1_subjectName := ERR_OSSL_CMP_CTX_set1_subjectName;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_subjectName_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_subjectName_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_subjectName)}
      OSSL_CMP_CTX_set1_subjectName := FC_OSSL_CMP_CTX_set1_subjectName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_subjectName_removed)}
    if OSSL_CMP_CTX_set1_subjectName_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_subjectName)}
      OSSL_CMP_CTX_set1_subjectName := _OSSL_CMP_CTX_set1_subjectName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_subjectName_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_subjectName');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_push1_subjectAltName := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_push1_subjectAltName_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_push1_subjectAltName);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_push1_subjectAltName_allownil)}
    OSSL_CMP_CTX_push1_subjectAltName := ERR_OSSL_CMP_CTX_push1_subjectAltName;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push1_subjectAltName_introduced)}
    if LibVersion < OSSL_CMP_CTX_push1_subjectAltName_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_push1_subjectAltName)}
      OSSL_CMP_CTX_push1_subjectAltName := FC_OSSL_CMP_CTX_push1_subjectAltName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push1_subjectAltName_removed)}
    if OSSL_CMP_CTX_push1_subjectAltName_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_push1_subjectAltName)}
      OSSL_CMP_CTX_push1_subjectAltName := _OSSL_CMP_CTX_push1_subjectAltName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_push1_subjectAltName_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_push1_subjectAltName');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set0_reqExtensions := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set0_reqExtensions_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set0_reqExtensions);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set0_reqExtensions_allownil)}
    OSSL_CMP_CTX_set0_reqExtensions := ERR_OSSL_CMP_CTX_set0_reqExtensions;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set0_reqExtensions_introduced)}
    if LibVersion < OSSL_CMP_CTX_set0_reqExtensions_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set0_reqExtensions)}
      OSSL_CMP_CTX_set0_reqExtensions := FC_OSSL_CMP_CTX_set0_reqExtensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set0_reqExtensions_removed)}
    if OSSL_CMP_CTX_set0_reqExtensions_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set0_reqExtensions)}
      OSSL_CMP_CTX_set0_reqExtensions := _OSSL_CMP_CTX_set0_reqExtensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set0_reqExtensions_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set0_reqExtensions');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_reqExtensions_have_SAN := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_reqExtensions_have_SAN_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_reqExtensions_have_SAN);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_reqExtensions_have_SAN_allownil)}
    OSSL_CMP_CTX_reqExtensions_have_SAN := ERR_OSSL_CMP_CTX_reqExtensions_have_SAN;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_reqExtensions_have_SAN_introduced)}
    if LibVersion < OSSL_CMP_CTX_reqExtensions_have_SAN_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_reqExtensions_have_SAN)}
      OSSL_CMP_CTX_reqExtensions_have_SAN := FC_OSSL_CMP_CTX_reqExtensions_have_SAN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_reqExtensions_have_SAN_removed)}
    if OSSL_CMP_CTX_reqExtensions_have_SAN_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_reqExtensions_have_SAN)}
      OSSL_CMP_CTX_reqExtensions_have_SAN := _OSSL_CMP_CTX_reqExtensions_have_SAN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_reqExtensions_have_SAN_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_reqExtensions_have_SAN');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_push0_policy := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_push0_policy_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_push0_policy);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_push0_policy_allownil)}
    OSSL_CMP_CTX_push0_policy := ERR_OSSL_CMP_CTX_push0_policy;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push0_policy_introduced)}
    if LibVersion < OSSL_CMP_CTX_push0_policy_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_push0_policy)}
      OSSL_CMP_CTX_push0_policy := FC_OSSL_CMP_CTX_push0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push0_policy_removed)}
    if OSSL_CMP_CTX_push0_policy_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_push0_policy)}
      OSSL_CMP_CTX_push0_policy := _OSSL_CMP_CTX_push0_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_push0_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_push0_policy');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_oldCert := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_oldCert_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_oldCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_oldCert_allownil)}
    OSSL_CMP_CTX_set1_oldCert := ERR_OSSL_CMP_CTX_set1_oldCert;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_oldCert_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_oldCert_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_oldCert)}
      OSSL_CMP_CTX_set1_oldCert := FC_OSSL_CMP_CTX_set1_oldCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_oldCert_removed)}
    if OSSL_CMP_CTX_set1_oldCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_oldCert)}
      OSSL_CMP_CTX_set1_oldCert := _OSSL_CMP_CTX_set1_oldCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_oldCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_oldCert');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_p10CSR := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_p10CSR_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_p10CSR);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_p10CSR_allownil)}
    OSSL_CMP_CTX_set1_p10CSR := ERR_OSSL_CMP_CTX_set1_p10CSR;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_p10CSR_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_p10CSR_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_p10CSR)}
      OSSL_CMP_CTX_set1_p10CSR := FC_OSSL_CMP_CTX_set1_p10CSR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_p10CSR_removed)}
    if OSSL_CMP_CTX_set1_p10CSR_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_p10CSR)}
      OSSL_CMP_CTX_set1_p10CSR := _OSSL_CMP_CTX_set1_p10CSR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_p10CSR_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_p10CSR');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_push0_genm_ITAV := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_push0_genm_ITAV_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_push0_genm_ITAV);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_push0_genm_ITAV_allownil)}
    OSSL_CMP_CTX_push0_genm_ITAV := ERR_OSSL_CMP_CTX_push0_genm_ITAV;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push0_genm_ITAV_introduced)}
    if LibVersion < OSSL_CMP_CTX_push0_genm_ITAV_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_push0_genm_ITAV)}
      OSSL_CMP_CTX_push0_genm_ITAV := FC_OSSL_CMP_CTX_push0_genm_ITAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_push0_genm_ITAV_removed)}
    if OSSL_CMP_CTX_push0_genm_ITAV_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_push0_genm_ITAV)}
      OSSL_CMP_CTX_push0_genm_ITAV := _OSSL_CMP_CTX_push0_genm_ITAV;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_push0_genm_ITAV_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_push0_genm_ITAV');
    {$ifend}
  end;
  
  OSSL_CMP_certConf_cb := LoadLibFunction(ADllHandle, OSSL_CMP_certConf_cb_procname);
  FuncLoadError := not assigned(OSSL_CMP_certConf_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_certConf_cb_allownil)}
    OSSL_CMP_certConf_cb := ERR_OSSL_CMP_certConf_cb;
    {$ifend}
    {$if declared(OSSL_CMP_certConf_cb_introduced)}
    if LibVersion < OSSL_CMP_certConf_cb_introduced then
    begin
      {$if declared(FC_OSSL_CMP_certConf_cb)}
      OSSL_CMP_certConf_cb := FC_OSSL_CMP_certConf_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_certConf_cb_removed)}
    if OSSL_CMP_certConf_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_certConf_cb)}
      OSSL_CMP_certConf_cb := _OSSL_CMP_certConf_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_certConf_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_certConf_cb');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_certConf_cb := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_certConf_cb_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_certConf_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_certConf_cb_allownil)}
    OSSL_CMP_CTX_set_certConf_cb := ERR_OSSL_CMP_CTX_set_certConf_cb;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_certConf_cb_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_certConf_cb_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_certConf_cb)}
      OSSL_CMP_CTX_set_certConf_cb := FC_OSSL_CMP_CTX_set_certConf_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_certConf_cb_removed)}
    if OSSL_CMP_CTX_set_certConf_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_certConf_cb)}
      OSSL_CMP_CTX_set_certConf_cb := _OSSL_CMP_CTX_set_certConf_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_certConf_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_certConf_cb');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set_certConf_cb_arg := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set_certConf_cb_arg_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set_certConf_cb_arg);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set_certConf_cb_arg_allownil)}
    OSSL_CMP_CTX_set_certConf_cb_arg := ERR_OSSL_CMP_CTX_set_certConf_cb_arg;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_certConf_cb_arg_introduced)}
    if LibVersion < OSSL_CMP_CTX_set_certConf_cb_arg_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set_certConf_cb_arg)}
      OSSL_CMP_CTX_set_certConf_cb_arg := FC_OSSL_CMP_CTX_set_certConf_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set_certConf_cb_arg_removed)}
    if OSSL_CMP_CTX_set_certConf_cb_arg_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set_certConf_cb_arg)}
      OSSL_CMP_CTX_set_certConf_cb_arg := _OSSL_CMP_CTX_set_certConf_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set_certConf_cb_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set_certConf_cb_arg');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get_certConf_cb_arg := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get_certConf_cb_arg_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get_certConf_cb_arg);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get_certConf_cb_arg_allownil)}
    OSSL_CMP_CTX_get_certConf_cb_arg := ERR_OSSL_CMP_CTX_get_certConf_cb_arg;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_certConf_cb_arg_introduced)}
    if LibVersion < OSSL_CMP_CTX_get_certConf_cb_arg_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get_certConf_cb_arg)}
      OSSL_CMP_CTX_get_certConf_cb_arg := FC_OSSL_CMP_CTX_get_certConf_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_certConf_cb_arg_removed)}
    if OSSL_CMP_CTX_get_certConf_cb_arg_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get_certConf_cb_arg)}
      OSSL_CMP_CTX_get_certConf_cb_arg := _OSSL_CMP_CTX_get_certConf_cb_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get_certConf_cb_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get_certConf_cb_arg');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get_status := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get_status_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get_status);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get_status_allownil)}
    OSSL_CMP_CTX_get_status := ERR_OSSL_CMP_CTX_get_status;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_status_introduced)}
    if LibVersion < OSSL_CMP_CTX_get_status_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get_status)}
      OSSL_CMP_CTX_get_status := FC_OSSL_CMP_CTX_get_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_status_removed)}
    if OSSL_CMP_CTX_get_status_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get_status)}
      OSSL_CMP_CTX_get_status := _OSSL_CMP_CTX_get_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get_status_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get_status');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_statusString := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_statusString_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_statusString);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_statusString_allownil)}
    OSSL_CMP_CTX_get0_statusString := ERR_OSSL_CMP_CTX_get0_statusString;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_statusString_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_statusString_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_statusString)}
      OSSL_CMP_CTX_get0_statusString := FC_OSSL_CMP_CTX_get0_statusString;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_statusString_removed)}
    if OSSL_CMP_CTX_get0_statusString_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_statusString)}
      OSSL_CMP_CTX_get0_statusString := _OSSL_CMP_CTX_get0_statusString;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_statusString_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_statusString');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get_failInfoCode := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get_failInfoCode_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get_failInfoCode);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get_failInfoCode_allownil)}
    OSSL_CMP_CTX_get_failInfoCode := ERR_OSSL_CMP_CTX_get_failInfoCode;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_failInfoCode_introduced)}
    if LibVersion < OSSL_CMP_CTX_get_failInfoCode_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get_failInfoCode)}
      OSSL_CMP_CTX_get_failInfoCode := FC_OSSL_CMP_CTX_get_failInfoCode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get_failInfoCode_removed)}
    if OSSL_CMP_CTX_get_failInfoCode_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get_failInfoCode)}
      OSSL_CMP_CTX_get_failInfoCode := _OSSL_CMP_CTX_get_failInfoCode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get_failInfoCode_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get_failInfoCode');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_validatedSrvCert := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_validatedSrvCert_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_validatedSrvCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_validatedSrvCert_allownil)}
    OSSL_CMP_CTX_get0_validatedSrvCert := ERR_OSSL_CMP_CTX_get0_validatedSrvCert;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_validatedSrvCert_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_validatedSrvCert_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_validatedSrvCert)}
      OSSL_CMP_CTX_get0_validatedSrvCert := FC_OSSL_CMP_CTX_get0_validatedSrvCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_validatedSrvCert_removed)}
    if OSSL_CMP_CTX_get0_validatedSrvCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_validatedSrvCert)}
      OSSL_CMP_CTX_get0_validatedSrvCert := _OSSL_CMP_CTX_get0_validatedSrvCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_validatedSrvCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_validatedSrvCert');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get0_newCert := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get0_newCert_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get0_newCert);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get0_newCert_allownil)}
    OSSL_CMP_CTX_get0_newCert := ERR_OSSL_CMP_CTX_get0_newCert;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_newCert_introduced)}
    if LibVersion < OSSL_CMP_CTX_get0_newCert_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get0_newCert)}
      OSSL_CMP_CTX_get0_newCert := FC_OSSL_CMP_CTX_get0_newCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get0_newCert_removed)}
    if OSSL_CMP_CTX_get0_newCert_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get0_newCert)}
      OSSL_CMP_CTX_get0_newCert := _OSSL_CMP_CTX_get0_newCert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get0_newCert_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get0_newCert');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get1_newChain := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get1_newChain_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get1_newChain);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get1_newChain_allownil)}
    OSSL_CMP_CTX_get1_newChain := ERR_OSSL_CMP_CTX_get1_newChain;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get1_newChain_introduced)}
    if LibVersion < OSSL_CMP_CTX_get1_newChain_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get1_newChain)}
      OSSL_CMP_CTX_get1_newChain := FC_OSSL_CMP_CTX_get1_newChain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get1_newChain_removed)}
    if OSSL_CMP_CTX_get1_newChain_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get1_newChain)}
      OSSL_CMP_CTX_get1_newChain := _OSSL_CMP_CTX_get1_newChain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get1_newChain_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get1_newChain');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get1_caPubs := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get1_caPubs_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get1_caPubs);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get1_caPubs_allownil)}
    OSSL_CMP_CTX_get1_caPubs := ERR_OSSL_CMP_CTX_get1_caPubs;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get1_caPubs_introduced)}
    if LibVersion < OSSL_CMP_CTX_get1_caPubs_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get1_caPubs)}
      OSSL_CMP_CTX_get1_caPubs := FC_OSSL_CMP_CTX_get1_caPubs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get1_caPubs_removed)}
    if OSSL_CMP_CTX_get1_caPubs_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get1_caPubs)}
      OSSL_CMP_CTX_get1_caPubs := _OSSL_CMP_CTX_get1_caPubs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get1_caPubs_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get1_caPubs');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_get1_extraCertsIn := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_get1_extraCertsIn_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_get1_extraCertsIn);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_get1_extraCertsIn_allownil)}
    OSSL_CMP_CTX_get1_extraCertsIn := ERR_OSSL_CMP_CTX_get1_extraCertsIn;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get1_extraCertsIn_introduced)}
    if LibVersion < OSSL_CMP_CTX_get1_extraCertsIn_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_get1_extraCertsIn)}
      OSSL_CMP_CTX_get1_extraCertsIn := FC_OSSL_CMP_CTX_get1_extraCertsIn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_get1_extraCertsIn_removed)}
    if OSSL_CMP_CTX_get1_extraCertsIn_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_get1_extraCertsIn)}
      OSSL_CMP_CTX_get1_extraCertsIn := _OSSL_CMP_CTX_get1_extraCertsIn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_get1_extraCertsIn_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_get1_extraCertsIn');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_transactionID := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_transactionID_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_transactionID);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_transactionID_allownil)}
    OSSL_CMP_CTX_set1_transactionID := ERR_OSSL_CMP_CTX_set1_transactionID;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_transactionID_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_transactionID_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_transactionID)}
      OSSL_CMP_CTX_set1_transactionID := FC_OSSL_CMP_CTX_set1_transactionID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_transactionID_removed)}
    if OSSL_CMP_CTX_set1_transactionID_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_transactionID)}
      OSSL_CMP_CTX_set1_transactionID := _OSSL_CMP_CTX_set1_transactionID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_transactionID_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_transactionID');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_set1_senderNonce := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_set1_senderNonce_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_set1_senderNonce);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_set1_senderNonce_allownil)}
    OSSL_CMP_CTX_set1_senderNonce := ERR_OSSL_CMP_CTX_set1_senderNonce;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_senderNonce_introduced)}
    if LibVersion < OSSL_CMP_CTX_set1_senderNonce_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_set1_senderNonce)}
      OSSL_CMP_CTX_set1_senderNonce := FC_OSSL_CMP_CTX_set1_senderNonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_set1_senderNonce_removed)}
    if OSSL_CMP_CTX_set1_senderNonce_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_set1_senderNonce)}
      OSSL_CMP_CTX_set1_senderNonce := _OSSL_CMP_CTX_set1_senderNonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_set1_senderNonce_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_set1_senderNonce');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_snprint_PKIStatus := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_snprint_PKIStatus_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_snprint_PKIStatus);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_snprint_PKIStatus_allownil)}
    OSSL_CMP_CTX_snprint_PKIStatus := ERR_OSSL_CMP_CTX_snprint_PKIStatus;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_snprint_PKIStatus_introduced)}
    if LibVersion < OSSL_CMP_CTX_snprint_PKIStatus_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_snprint_PKIStatus)}
      OSSL_CMP_CTX_snprint_PKIStatus := FC_OSSL_CMP_CTX_snprint_PKIStatus;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_snprint_PKIStatus_removed)}
    if OSSL_CMP_CTX_snprint_PKIStatus_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_snprint_PKIStatus)}
      OSSL_CMP_CTX_snprint_PKIStatus := _OSSL_CMP_CTX_snprint_PKIStatus;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_snprint_PKIStatus_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_snprint_PKIStatus');
    {$ifend}
  end;
  
  OSSL_CMP_snprint_PKIStatusInfo := LoadLibFunction(ADllHandle, OSSL_CMP_snprint_PKIStatusInfo_procname);
  FuncLoadError := not assigned(OSSL_CMP_snprint_PKIStatusInfo);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_snprint_PKIStatusInfo_allownil)}
    OSSL_CMP_snprint_PKIStatusInfo := ERR_OSSL_CMP_snprint_PKIStatusInfo;
    {$ifend}
    {$if declared(OSSL_CMP_snprint_PKIStatusInfo_introduced)}
    if LibVersion < OSSL_CMP_snprint_PKIStatusInfo_introduced then
    begin
      {$if declared(FC_OSSL_CMP_snprint_PKIStatusInfo)}
      OSSL_CMP_snprint_PKIStatusInfo := FC_OSSL_CMP_snprint_PKIStatusInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_snprint_PKIStatusInfo_removed)}
    if OSSL_CMP_snprint_PKIStatusInfo_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_snprint_PKIStatusInfo)}
      OSSL_CMP_snprint_PKIStatusInfo := _OSSL_CMP_snprint_PKIStatusInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_snprint_PKIStatusInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_snprint_PKIStatusInfo');
    {$ifend}
  end;
  
  OSSL_CMP_STATUSINFO_new := LoadLibFunction(ADllHandle, OSSL_CMP_STATUSINFO_new_procname);
  FuncLoadError := not assigned(OSSL_CMP_STATUSINFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_STATUSINFO_new_allownil)}
    OSSL_CMP_STATUSINFO_new := ERR_OSSL_CMP_STATUSINFO_new;
    {$ifend}
    {$if declared(OSSL_CMP_STATUSINFO_new_introduced)}
    if LibVersion < OSSL_CMP_STATUSINFO_new_introduced then
    begin
      {$if declared(FC_OSSL_CMP_STATUSINFO_new)}
      OSSL_CMP_STATUSINFO_new := FC_OSSL_CMP_STATUSINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_STATUSINFO_new_removed)}
    if OSSL_CMP_STATUSINFO_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_STATUSINFO_new)}
      OSSL_CMP_STATUSINFO_new := _OSSL_CMP_STATUSINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_STATUSINFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_STATUSINFO_new');
    {$ifend}
  end;
  
  OSSL_CMP_HDR_get0_transactionID := LoadLibFunction(ADllHandle, OSSL_CMP_HDR_get0_transactionID_procname);
  FuncLoadError := not assigned(OSSL_CMP_HDR_get0_transactionID);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_HDR_get0_transactionID_allownil)}
    OSSL_CMP_HDR_get0_transactionID := ERR_OSSL_CMP_HDR_get0_transactionID;
    {$ifend}
    {$if declared(OSSL_CMP_HDR_get0_transactionID_introduced)}
    if LibVersion < OSSL_CMP_HDR_get0_transactionID_introduced then
    begin
      {$if declared(FC_OSSL_CMP_HDR_get0_transactionID)}
      OSSL_CMP_HDR_get0_transactionID := FC_OSSL_CMP_HDR_get0_transactionID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_HDR_get0_transactionID_removed)}
    if OSSL_CMP_HDR_get0_transactionID_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_HDR_get0_transactionID)}
      OSSL_CMP_HDR_get0_transactionID := _OSSL_CMP_HDR_get0_transactionID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_HDR_get0_transactionID_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_HDR_get0_transactionID');
    {$ifend}
  end;
  
  OSSL_CMP_HDR_get0_recipNonce := LoadLibFunction(ADllHandle, OSSL_CMP_HDR_get0_recipNonce_procname);
  FuncLoadError := not assigned(OSSL_CMP_HDR_get0_recipNonce);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_HDR_get0_recipNonce_allownil)}
    OSSL_CMP_HDR_get0_recipNonce := ERR_OSSL_CMP_HDR_get0_recipNonce;
    {$ifend}
    {$if declared(OSSL_CMP_HDR_get0_recipNonce_introduced)}
    if LibVersion < OSSL_CMP_HDR_get0_recipNonce_introduced then
    begin
      {$if declared(FC_OSSL_CMP_HDR_get0_recipNonce)}
      OSSL_CMP_HDR_get0_recipNonce := FC_OSSL_CMP_HDR_get0_recipNonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_HDR_get0_recipNonce_removed)}
    if OSSL_CMP_HDR_get0_recipNonce_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_HDR_get0_recipNonce)}
      OSSL_CMP_HDR_get0_recipNonce := _OSSL_CMP_HDR_get0_recipNonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_HDR_get0_recipNonce_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_HDR_get0_recipNonce');
    {$ifend}
  end;
  
  OSSL_CMP_HDR_get0_geninfo_ITAVs := LoadLibFunction(ADllHandle, OSSL_CMP_HDR_get0_geninfo_ITAVs_procname);
  FuncLoadError := not assigned(OSSL_CMP_HDR_get0_geninfo_ITAVs);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_HDR_get0_geninfo_ITAVs_allownil)}
    OSSL_CMP_HDR_get0_geninfo_ITAVs := ERR_OSSL_CMP_HDR_get0_geninfo_ITAVs;
    {$ifend}
    {$if declared(OSSL_CMP_HDR_get0_geninfo_ITAVs_introduced)}
    if LibVersion < OSSL_CMP_HDR_get0_geninfo_ITAVs_introduced then
    begin
      {$if declared(FC_OSSL_CMP_HDR_get0_geninfo_ITAVs)}
      OSSL_CMP_HDR_get0_geninfo_ITAVs := FC_OSSL_CMP_HDR_get0_geninfo_ITAVs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_HDR_get0_geninfo_ITAVs_removed)}
    if OSSL_CMP_HDR_get0_geninfo_ITAVs_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_HDR_get0_geninfo_ITAVs)}
      OSSL_CMP_HDR_get0_geninfo_ITAVs := _OSSL_CMP_HDR_get0_geninfo_ITAVs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_HDR_get0_geninfo_ITAVs_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_HDR_get0_geninfo_ITAVs');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_get0_header := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_get0_header_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_get0_header);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_get0_header_allownil)}
    OSSL_CMP_MSG_get0_header := ERR_OSSL_CMP_MSG_get0_header;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_get0_header_introduced)}
    if LibVersion < OSSL_CMP_MSG_get0_header_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_get0_header)}
      OSSL_CMP_MSG_get0_header := FC_OSSL_CMP_MSG_get0_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_get0_header_removed)}
    if OSSL_CMP_MSG_get0_header_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_get0_header)}
      OSSL_CMP_MSG_get0_header := _OSSL_CMP_MSG_get0_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_get0_header_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_get0_header');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_get_bodytype := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_get_bodytype_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_get_bodytype);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_get_bodytype_allownil)}
    OSSL_CMP_MSG_get_bodytype := ERR_OSSL_CMP_MSG_get_bodytype;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_get_bodytype_introduced)}
    if LibVersion < OSSL_CMP_MSG_get_bodytype_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_get_bodytype)}
      OSSL_CMP_MSG_get_bodytype := FC_OSSL_CMP_MSG_get_bodytype;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_get_bodytype_removed)}
    if OSSL_CMP_MSG_get_bodytype_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_get_bodytype)}
      OSSL_CMP_MSG_get_bodytype := _OSSL_CMP_MSG_get_bodytype;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_get_bodytype_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_get_bodytype');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_get0_certreq_publickey := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_get0_certreq_publickey_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_get0_certreq_publickey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_get0_certreq_publickey_allownil)}
    OSSL_CMP_MSG_get0_certreq_publickey := ERR_OSSL_CMP_MSG_get0_certreq_publickey;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_get0_certreq_publickey_introduced)}
    if LibVersion < OSSL_CMP_MSG_get0_certreq_publickey_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_get0_certreq_publickey)}
      OSSL_CMP_MSG_get0_certreq_publickey := FC_OSSL_CMP_MSG_get0_certreq_publickey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_get0_certreq_publickey_removed)}
    if OSSL_CMP_MSG_get0_certreq_publickey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_get0_certreq_publickey)}
      OSSL_CMP_MSG_get0_certreq_publickey := _OSSL_CMP_MSG_get0_certreq_publickey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_get0_certreq_publickey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_get0_certreq_publickey');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_update_transactionID := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_update_transactionID_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_update_transactionID);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_update_transactionID_allownil)}
    OSSL_CMP_MSG_update_transactionID := ERR_OSSL_CMP_MSG_update_transactionID;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_update_transactionID_introduced)}
    if LibVersion < OSSL_CMP_MSG_update_transactionID_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_update_transactionID)}
      OSSL_CMP_MSG_update_transactionID := FC_OSSL_CMP_MSG_update_transactionID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_update_transactionID_removed)}
    if OSSL_CMP_MSG_update_transactionID_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_update_transactionID)}
      OSSL_CMP_MSG_update_transactionID := _OSSL_CMP_MSG_update_transactionID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_update_transactionID_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_update_transactionID');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_update_recipNonce := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_update_recipNonce_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_update_recipNonce);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_update_recipNonce_allownil)}
    OSSL_CMP_MSG_update_recipNonce := ERR_OSSL_CMP_MSG_update_recipNonce;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_update_recipNonce_introduced)}
    if LibVersion < OSSL_CMP_MSG_update_recipNonce_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_update_recipNonce)}
      OSSL_CMP_MSG_update_recipNonce := FC_OSSL_CMP_MSG_update_recipNonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_update_recipNonce_removed)}
    if OSSL_CMP_MSG_update_recipNonce_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_update_recipNonce)}
      OSSL_CMP_MSG_update_recipNonce := _OSSL_CMP_MSG_update_recipNonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_update_recipNonce_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_update_recipNonce');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_setup_CRM := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_setup_CRM_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_setup_CRM);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_setup_CRM_allownil)}
    OSSL_CMP_CTX_setup_CRM := ERR_OSSL_CMP_CTX_setup_CRM;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_setup_CRM_introduced)}
    if LibVersion < OSSL_CMP_CTX_setup_CRM_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_setup_CRM)}
      OSSL_CMP_CTX_setup_CRM := FC_OSSL_CMP_CTX_setup_CRM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_setup_CRM_removed)}
    if OSSL_CMP_CTX_setup_CRM_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_setup_CRM)}
      OSSL_CMP_CTX_setup_CRM := _OSSL_CMP_CTX_setup_CRM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_setup_CRM_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_setup_CRM');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_read := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_read_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_read);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_read_allownil)}
    OSSL_CMP_MSG_read := ERR_OSSL_CMP_MSG_read;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_read_introduced)}
    if LibVersion < OSSL_CMP_MSG_read_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_read)}
      OSSL_CMP_MSG_read := FC_OSSL_CMP_MSG_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_read_removed)}
    if OSSL_CMP_MSG_read_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_read)}
      OSSL_CMP_MSG_read := _OSSL_CMP_MSG_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_read_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_read');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_write := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_write_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_write);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_write_allownil)}
    OSSL_CMP_MSG_write := ERR_OSSL_CMP_MSG_write;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_write_introduced)}
    if LibVersion < OSSL_CMP_MSG_write_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_write)}
      OSSL_CMP_MSG_write := FC_OSSL_CMP_MSG_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_write_removed)}
    if OSSL_CMP_MSG_write_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_write)}
      OSSL_CMP_MSG_write := _OSSL_CMP_MSG_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_write_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_write');
    {$ifend}
  end;
  
  d2i_OSSL_CMP_MSG_bio := LoadLibFunction(ADllHandle, d2i_OSSL_CMP_MSG_bio_procname);
  FuncLoadError := not assigned(d2i_OSSL_CMP_MSG_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_CMP_MSG_bio_allownil)}
    d2i_OSSL_CMP_MSG_bio := ERR_d2i_OSSL_CMP_MSG_bio;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_MSG_bio_introduced)}
    if LibVersion < d2i_OSSL_CMP_MSG_bio_introduced then
    begin
      {$if declared(FC_d2i_OSSL_CMP_MSG_bio)}
      d2i_OSSL_CMP_MSG_bio := FC_d2i_OSSL_CMP_MSG_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_CMP_MSG_bio_removed)}
    if d2i_OSSL_CMP_MSG_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_CMP_MSG_bio)}
      d2i_OSSL_CMP_MSG_bio := _d2i_OSSL_CMP_MSG_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_CMP_MSG_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_CMP_MSG_bio');
    {$ifend}
  end;
  
  i2d_OSSL_CMP_MSG_bio := LoadLibFunction(ADllHandle, i2d_OSSL_CMP_MSG_bio_procname);
  FuncLoadError := not assigned(i2d_OSSL_CMP_MSG_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_CMP_MSG_bio_allownil)}
    i2d_OSSL_CMP_MSG_bio := ERR_i2d_OSSL_CMP_MSG_bio;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_MSG_bio_introduced)}
    if LibVersion < i2d_OSSL_CMP_MSG_bio_introduced then
    begin
      {$if declared(FC_i2d_OSSL_CMP_MSG_bio)}
      i2d_OSSL_CMP_MSG_bio := FC_i2d_OSSL_CMP_MSG_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_CMP_MSG_bio_removed)}
    if i2d_OSSL_CMP_MSG_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_CMP_MSG_bio)}
      i2d_OSSL_CMP_MSG_bio := _i2d_OSSL_CMP_MSG_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_CMP_MSG_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_CMP_MSG_bio');
    {$ifend}
  end;
  
  OSSL_CMP_validate_msg := LoadLibFunction(ADllHandle, OSSL_CMP_validate_msg_procname);
  FuncLoadError := not assigned(OSSL_CMP_validate_msg);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_validate_msg_allownil)}
    OSSL_CMP_validate_msg := ERR_OSSL_CMP_validate_msg;
    {$ifend}
    {$if declared(OSSL_CMP_validate_msg_introduced)}
    if LibVersion < OSSL_CMP_validate_msg_introduced then
    begin
      {$if declared(FC_OSSL_CMP_validate_msg)}
      OSSL_CMP_validate_msg := FC_OSSL_CMP_validate_msg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_validate_msg_removed)}
    if OSSL_CMP_validate_msg_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_validate_msg)}
      OSSL_CMP_validate_msg := _OSSL_CMP_validate_msg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_validate_msg_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_validate_msg');
    {$ifend}
  end;
  
  OSSL_CMP_validate_cert_path := LoadLibFunction(ADllHandle, OSSL_CMP_validate_cert_path_procname);
  FuncLoadError := not assigned(OSSL_CMP_validate_cert_path);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_validate_cert_path_allownil)}
    OSSL_CMP_validate_cert_path := ERR_OSSL_CMP_validate_cert_path;
    {$ifend}
    {$if declared(OSSL_CMP_validate_cert_path_introduced)}
    if LibVersion < OSSL_CMP_validate_cert_path_introduced then
    begin
      {$if declared(FC_OSSL_CMP_validate_cert_path)}
      OSSL_CMP_validate_cert_path := FC_OSSL_CMP_validate_cert_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_validate_cert_path_removed)}
    if OSSL_CMP_validate_cert_path_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_validate_cert_path)}
      OSSL_CMP_validate_cert_path := _OSSL_CMP_validate_cert_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_validate_cert_path_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_validate_cert_path');
    {$ifend}
  end;
  
  OSSL_CMP_MSG_http_perform := LoadLibFunction(ADllHandle, OSSL_CMP_MSG_http_perform_procname);
  FuncLoadError := not assigned(OSSL_CMP_MSG_http_perform);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_MSG_http_perform_allownil)}
    OSSL_CMP_MSG_http_perform := ERR_OSSL_CMP_MSG_http_perform;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_http_perform_introduced)}
    if LibVersion < OSSL_CMP_MSG_http_perform_introduced then
    begin
      {$if declared(FC_OSSL_CMP_MSG_http_perform)}
      OSSL_CMP_MSG_http_perform := FC_OSSL_CMP_MSG_http_perform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_MSG_http_perform_removed)}
    if OSSL_CMP_MSG_http_perform_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_MSG_http_perform)}
      OSSL_CMP_MSG_http_perform := _OSSL_CMP_MSG_http_perform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_MSG_http_perform_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_MSG_http_perform');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_process_request := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_process_request_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_process_request);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_process_request_allownil)}
    OSSL_CMP_SRV_process_request := ERR_OSSL_CMP_SRV_process_request;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_process_request_introduced)}
    if LibVersion < OSSL_CMP_SRV_process_request_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_process_request)}
      OSSL_CMP_SRV_process_request := FC_OSSL_CMP_SRV_process_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_process_request_removed)}
    if OSSL_CMP_SRV_process_request_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_process_request)}
      OSSL_CMP_SRV_process_request := _OSSL_CMP_SRV_process_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_process_request_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_process_request');
    {$ifend}
  end;
  
  OSSL_CMP_CTX_server_perform := LoadLibFunction(ADllHandle, OSSL_CMP_CTX_server_perform_procname);
  FuncLoadError := not assigned(OSSL_CMP_CTX_server_perform);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_CTX_server_perform_allownil)}
    OSSL_CMP_CTX_server_perform := ERR_OSSL_CMP_CTX_server_perform;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_server_perform_introduced)}
    if LibVersion < OSSL_CMP_CTX_server_perform_introduced then
    begin
      {$if declared(FC_OSSL_CMP_CTX_server_perform)}
      OSSL_CMP_CTX_server_perform := FC_OSSL_CMP_CTX_server_perform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_CTX_server_perform_removed)}
    if OSSL_CMP_CTX_server_perform_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_CTX_server_perform)}
      OSSL_CMP_CTX_server_perform := _OSSL_CMP_CTX_server_perform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_CTX_server_perform_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_CTX_server_perform');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_new := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_new_allownil)}
    OSSL_CMP_SRV_CTX_new := ERR_OSSL_CMP_SRV_CTX_new;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_new_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_new_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_new)}
      OSSL_CMP_SRV_CTX_new := FC_OSSL_CMP_SRV_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_new_removed)}
    if OSSL_CMP_SRV_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_new)}
      OSSL_CMP_SRV_CTX_new := _OSSL_CMP_SRV_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_new');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_free := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_free_allownil)}
    OSSL_CMP_SRV_CTX_free := ERR_OSSL_CMP_SRV_CTX_free;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_free_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_free_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_free)}
      OSSL_CMP_SRV_CTX_free := FC_OSSL_CMP_SRV_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_free_removed)}
    if OSSL_CMP_SRV_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_free)}
      OSSL_CMP_SRV_CTX_free := _OSSL_CMP_SRV_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_free');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_init := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_init_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_init);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_init_allownil)}
    OSSL_CMP_SRV_CTX_init := ERR_OSSL_CMP_SRV_CTX_init;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_init_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_init_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_init)}
      OSSL_CMP_SRV_CTX_init := FC_OSSL_CMP_SRV_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_init_removed)}
    if OSSL_CMP_SRV_CTX_init_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_init)}
      OSSL_CMP_SRV_CTX_init := _OSSL_CMP_SRV_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_init_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_init');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_init_trans := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_init_trans_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_init_trans);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_init_trans_allownil)}
    OSSL_CMP_SRV_CTX_init_trans := ERR_OSSL_CMP_SRV_CTX_init_trans;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_init_trans_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_init_trans_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_init_trans)}
      OSSL_CMP_SRV_CTX_init_trans := FC_OSSL_CMP_SRV_CTX_init_trans;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_init_trans_removed)}
    if OSSL_CMP_SRV_CTX_init_trans_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_init_trans)}
      OSSL_CMP_SRV_CTX_init_trans := _OSSL_CMP_SRV_CTX_init_trans;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_init_trans_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_init_trans');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_get0_cmp_ctx := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_get0_cmp_ctx_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_get0_cmp_ctx);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_get0_cmp_ctx_allownil)}
    OSSL_CMP_SRV_CTX_get0_cmp_ctx := ERR_OSSL_CMP_SRV_CTX_get0_cmp_ctx;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_get0_cmp_ctx_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_get0_cmp_ctx_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_get0_cmp_ctx)}
      OSSL_CMP_SRV_CTX_get0_cmp_ctx := FC_OSSL_CMP_SRV_CTX_get0_cmp_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_get0_cmp_ctx_removed)}
    if OSSL_CMP_SRV_CTX_get0_cmp_ctx_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_get0_cmp_ctx)}
      OSSL_CMP_SRV_CTX_get0_cmp_ctx := _OSSL_CMP_SRV_CTX_get0_cmp_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_get0_cmp_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_get0_cmp_ctx');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_get0_custom_ctx := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_get0_custom_ctx_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_get0_custom_ctx);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_get0_custom_ctx_allownil)}
    OSSL_CMP_SRV_CTX_get0_custom_ctx := ERR_OSSL_CMP_SRV_CTX_get0_custom_ctx;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_get0_custom_ctx_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_get0_custom_ctx_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_get0_custom_ctx)}
      OSSL_CMP_SRV_CTX_get0_custom_ctx := FC_OSSL_CMP_SRV_CTX_get0_custom_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_get0_custom_ctx_removed)}
    if OSSL_CMP_SRV_CTX_get0_custom_ctx_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_get0_custom_ctx)}
      OSSL_CMP_SRV_CTX_get0_custom_ctx := _OSSL_CMP_SRV_CTX_get0_custom_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_get0_custom_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_get0_custom_ctx');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_set_send_unprotected_errors := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_set_send_unprotected_errors_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_set_send_unprotected_errors);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_set_send_unprotected_errors_allownil)}
    OSSL_CMP_SRV_CTX_set_send_unprotected_errors := ERR_OSSL_CMP_SRV_CTX_set_send_unprotected_errors;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_send_unprotected_errors_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_set_send_unprotected_errors_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_set_send_unprotected_errors)}
      OSSL_CMP_SRV_CTX_set_send_unprotected_errors := FC_OSSL_CMP_SRV_CTX_set_send_unprotected_errors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_send_unprotected_errors_removed)}
    if OSSL_CMP_SRV_CTX_set_send_unprotected_errors_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_set_send_unprotected_errors)}
      OSSL_CMP_SRV_CTX_set_send_unprotected_errors := _OSSL_CMP_SRV_CTX_set_send_unprotected_errors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_set_send_unprotected_errors_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_set_send_unprotected_errors');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_set_accept_unprotected := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_set_accept_unprotected_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_set_accept_unprotected);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_set_accept_unprotected_allownil)}
    OSSL_CMP_SRV_CTX_set_accept_unprotected := ERR_OSSL_CMP_SRV_CTX_set_accept_unprotected;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_accept_unprotected_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_set_accept_unprotected_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_set_accept_unprotected)}
      OSSL_CMP_SRV_CTX_set_accept_unprotected := FC_OSSL_CMP_SRV_CTX_set_accept_unprotected;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_accept_unprotected_removed)}
    if OSSL_CMP_SRV_CTX_set_accept_unprotected_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_set_accept_unprotected)}
      OSSL_CMP_SRV_CTX_set_accept_unprotected := _OSSL_CMP_SRV_CTX_set_accept_unprotected;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_set_accept_unprotected_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_set_accept_unprotected');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_set_accept_raverified := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_set_accept_raverified_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_set_accept_raverified);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_set_accept_raverified_allownil)}
    OSSL_CMP_SRV_CTX_set_accept_raverified := ERR_OSSL_CMP_SRV_CTX_set_accept_raverified;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_accept_raverified_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_set_accept_raverified_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_set_accept_raverified)}
      OSSL_CMP_SRV_CTX_set_accept_raverified := FC_OSSL_CMP_SRV_CTX_set_accept_raverified;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_accept_raverified_removed)}
    if OSSL_CMP_SRV_CTX_set_accept_raverified_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_set_accept_raverified)}
      OSSL_CMP_SRV_CTX_set_accept_raverified := _OSSL_CMP_SRV_CTX_set_accept_raverified;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_set_accept_raverified_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_set_accept_raverified');
    {$ifend}
  end;
  
  OSSL_CMP_SRV_CTX_set_grant_implicit_confirm := LoadLibFunction(ADllHandle, OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_procname);
  FuncLoadError := not assigned(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_allownil)}
    OSSL_CMP_SRV_CTX_set_grant_implicit_confirm := ERR_OSSL_CMP_SRV_CTX_set_grant_implicit_confirm;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_introduced)}
    if LibVersion < OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_introduced then
    begin
      {$if declared(FC_OSSL_CMP_SRV_CTX_set_grant_implicit_confirm)}
      OSSL_CMP_SRV_CTX_set_grant_implicit_confirm := FC_OSSL_CMP_SRV_CTX_set_grant_implicit_confirm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_removed)}
    if OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_SRV_CTX_set_grant_implicit_confirm)}
      OSSL_CMP_SRV_CTX_set_grant_implicit_confirm := _OSSL_CMP_SRV_CTX_set_grant_implicit_confirm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_SRV_CTX_set_grant_implicit_confirm_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_SRV_CTX_set_grant_implicit_confirm');
    {$ifend}
  end;
  
  OSSL_CMP_exec_certreq := LoadLibFunction(ADllHandle, OSSL_CMP_exec_certreq_procname);
  FuncLoadError := not assigned(OSSL_CMP_exec_certreq);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_exec_certreq_allownil)}
    OSSL_CMP_exec_certreq := ERR_OSSL_CMP_exec_certreq;
    {$ifend}
    {$if declared(OSSL_CMP_exec_certreq_introduced)}
    if LibVersion < OSSL_CMP_exec_certreq_introduced then
    begin
      {$if declared(FC_OSSL_CMP_exec_certreq)}
      OSSL_CMP_exec_certreq := FC_OSSL_CMP_exec_certreq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_exec_certreq_removed)}
    if OSSL_CMP_exec_certreq_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_exec_certreq)}
      OSSL_CMP_exec_certreq := _OSSL_CMP_exec_certreq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_exec_certreq_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_exec_certreq');
    {$ifend}
  end;
  
  OSSL_CMP_try_certreq := LoadLibFunction(ADllHandle, OSSL_CMP_try_certreq_procname);
  FuncLoadError := not assigned(OSSL_CMP_try_certreq);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_try_certreq_allownil)}
    OSSL_CMP_try_certreq := ERR_OSSL_CMP_try_certreq;
    {$ifend}
    {$if declared(OSSL_CMP_try_certreq_introduced)}
    if LibVersion < OSSL_CMP_try_certreq_introduced then
    begin
      {$if declared(FC_OSSL_CMP_try_certreq)}
      OSSL_CMP_try_certreq := FC_OSSL_CMP_try_certreq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_try_certreq_removed)}
    if OSSL_CMP_try_certreq_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_try_certreq)}
      OSSL_CMP_try_certreq := _OSSL_CMP_try_certreq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_try_certreq_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_try_certreq');
    {$ifend}
  end;
  
  OSSL_CMP_exec_RR_ses := LoadLibFunction(ADllHandle, OSSL_CMP_exec_RR_ses_procname);
  FuncLoadError := not assigned(OSSL_CMP_exec_RR_ses);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_exec_RR_ses_allownil)}
    OSSL_CMP_exec_RR_ses := ERR_OSSL_CMP_exec_RR_ses;
    {$ifend}
    {$if declared(OSSL_CMP_exec_RR_ses_introduced)}
    if LibVersion < OSSL_CMP_exec_RR_ses_introduced then
    begin
      {$if declared(FC_OSSL_CMP_exec_RR_ses)}
      OSSL_CMP_exec_RR_ses := FC_OSSL_CMP_exec_RR_ses;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_exec_RR_ses_removed)}
    if OSSL_CMP_exec_RR_ses_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_exec_RR_ses)}
      OSSL_CMP_exec_RR_ses := _OSSL_CMP_exec_RR_ses;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_exec_RR_ses_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_exec_RR_ses');
    {$ifend}
  end;
  
  OSSL_CMP_exec_GENM_ses := LoadLibFunction(ADllHandle, OSSL_CMP_exec_GENM_ses_procname);
  FuncLoadError := not assigned(OSSL_CMP_exec_GENM_ses);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_exec_GENM_ses_allownil)}
    OSSL_CMP_exec_GENM_ses := ERR_OSSL_CMP_exec_GENM_ses;
    {$ifend}
    {$if declared(OSSL_CMP_exec_GENM_ses_introduced)}
    if LibVersion < OSSL_CMP_exec_GENM_ses_introduced then
    begin
      {$if declared(FC_OSSL_CMP_exec_GENM_ses)}
      OSSL_CMP_exec_GENM_ses := FC_OSSL_CMP_exec_GENM_ses;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_exec_GENM_ses_removed)}
    if OSSL_CMP_exec_GENM_ses_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_exec_GENM_ses)}
      OSSL_CMP_exec_GENM_ses := _OSSL_CMP_exec_GENM_ses;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_exec_GENM_ses_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_exec_GENM_ses');
    {$ifend}
  end;
  
  OSSL_CMP_get1_caCerts := LoadLibFunction(ADllHandle, OSSL_CMP_get1_caCerts_procname);
  FuncLoadError := not assigned(OSSL_CMP_get1_caCerts);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_get1_caCerts_allownil)}
    OSSL_CMP_get1_caCerts := ERR_OSSL_CMP_get1_caCerts;
    {$ifend}
    {$if declared(OSSL_CMP_get1_caCerts_introduced)}
    if LibVersion < OSSL_CMP_get1_caCerts_introduced then
    begin
      {$if declared(FC_OSSL_CMP_get1_caCerts)}
      OSSL_CMP_get1_caCerts := FC_OSSL_CMP_get1_caCerts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_get1_caCerts_removed)}
    if OSSL_CMP_get1_caCerts_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_get1_caCerts)}
      OSSL_CMP_get1_caCerts := _OSSL_CMP_get1_caCerts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_get1_caCerts_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_get1_caCerts');
    {$ifend}
  end;
  
  OSSL_CMP_get1_rootCaKeyUpdate := LoadLibFunction(ADllHandle, OSSL_CMP_get1_rootCaKeyUpdate_procname);
  FuncLoadError := not assigned(OSSL_CMP_get1_rootCaKeyUpdate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_get1_rootCaKeyUpdate_allownil)}
    OSSL_CMP_get1_rootCaKeyUpdate := ERR_OSSL_CMP_get1_rootCaKeyUpdate;
    {$ifend}
    {$if declared(OSSL_CMP_get1_rootCaKeyUpdate_introduced)}
    if LibVersion < OSSL_CMP_get1_rootCaKeyUpdate_introduced then
    begin
      {$if declared(FC_OSSL_CMP_get1_rootCaKeyUpdate)}
      OSSL_CMP_get1_rootCaKeyUpdate := FC_OSSL_CMP_get1_rootCaKeyUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_get1_rootCaKeyUpdate_removed)}
    if OSSL_CMP_get1_rootCaKeyUpdate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_get1_rootCaKeyUpdate)}
      OSSL_CMP_get1_rootCaKeyUpdate := _OSSL_CMP_get1_rootCaKeyUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_get1_rootCaKeyUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_get1_rootCaKeyUpdate');
    {$ifend}
  end;
  
  OSSL_CMP_get1_crlUpdate := LoadLibFunction(ADllHandle, OSSL_CMP_get1_crlUpdate_procname);
  FuncLoadError := not assigned(OSSL_CMP_get1_crlUpdate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_get1_crlUpdate_allownil)}
    OSSL_CMP_get1_crlUpdate := ERR_OSSL_CMP_get1_crlUpdate;
    {$ifend}
    {$if declared(OSSL_CMP_get1_crlUpdate_introduced)}
    if LibVersion < OSSL_CMP_get1_crlUpdate_introduced then
    begin
      {$if declared(FC_OSSL_CMP_get1_crlUpdate)}
      OSSL_CMP_get1_crlUpdate := FC_OSSL_CMP_get1_crlUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_get1_crlUpdate_removed)}
    if OSSL_CMP_get1_crlUpdate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_get1_crlUpdate)}
      OSSL_CMP_get1_crlUpdate := _OSSL_CMP_get1_crlUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_get1_crlUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_get1_crlUpdate');
    {$ifend}
  end;
  
  OSSL_CMP_get1_certReqTemplate := LoadLibFunction(ADllHandle, OSSL_CMP_get1_certReqTemplate_procname);
  FuncLoadError := not assigned(OSSL_CMP_get1_certReqTemplate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_get1_certReqTemplate_allownil)}
    OSSL_CMP_get1_certReqTemplate := ERR_OSSL_CMP_get1_certReqTemplate;
    {$ifend}
    {$if declared(OSSL_CMP_get1_certReqTemplate_introduced)}
    if LibVersion < OSSL_CMP_get1_certReqTemplate_introduced then
    begin
      {$if declared(FC_OSSL_CMP_get1_certReqTemplate)}
      OSSL_CMP_get1_certReqTemplate := FC_OSSL_CMP_get1_certReqTemplate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_get1_certReqTemplate_removed)}
    if OSSL_CMP_get1_certReqTemplate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_get1_certReqTemplate)}
      OSSL_CMP_get1_certReqTemplate := _OSSL_CMP_get1_certReqTemplate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_get1_certReqTemplate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_get1_certReqTemplate');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_CMP_PKISTATUS_it := nil;
  OSSL_CMP_PKIHEADER_new := nil;
  OSSL_CMP_PKIHEADER_free := nil;
  d2i_OSSL_CMP_PKIHEADER := nil;
  i2d_OSSL_CMP_PKIHEADER := nil;
  OSSL_CMP_PKIHEADER_it := nil;
  OSSL_CMP_MSG_dup := nil;
  d2i_OSSL_CMP_MSG := nil;
  i2d_OSSL_CMP_MSG := nil;
  OSSL_CMP_MSG_it := nil;
  OSSL_CMP_ITAV_dup := nil;
  OSSL_CMP_ATAVS_new := nil;
  OSSL_CMP_ATAVS_free := nil;
  d2i_OSSL_CMP_ATAVS := nil;
  i2d_OSSL_CMP_ATAVS := nil;
  OSSL_CMP_ATAVS_it := nil;
  OSSL_CMP_PKISI_new := nil;
  OSSL_CMP_PKISI_free := nil;
  d2i_OSSL_CMP_PKISI := nil;
  i2d_OSSL_CMP_PKISI := nil;
  OSSL_CMP_PKISI_it := nil;
  OSSL_CMP_PKISI_dup := nil;
  OSSL_CMP_ITAV_create := nil;
  OSSL_CMP_ITAV_set0 := nil;
  OSSL_CMP_ITAV_get0_type := nil;
  OSSL_CMP_ITAV_get0_value := nil;
  OSSL_CMP_ITAV_push0_stack_item := nil;
  OSSL_CMP_ITAV_free := nil;
  OSSL_CMP_ITAV_new0_certProfile := nil;
  OSSL_CMP_ITAV_get0_certProfile := nil;
  OSSL_CMP_ITAV_new_caCerts := nil;
  OSSL_CMP_ITAV_get0_caCerts := nil;
  OSSL_CMP_ITAV_new_rootCaCert := nil;
  OSSL_CMP_ITAV_get0_rootCaCert := nil;
  OSSL_CMP_ITAV_new_rootCaKeyUpdate := nil;
  OSSL_CMP_ITAV_get0_rootCaKeyUpdate := nil;
  OSSL_CMP_CRLSTATUS_create := nil;
  OSSL_CMP_CRLSTATUS_new1 := nil;
  OSSL_CMP_CRLSTATUS_get0 := nil;
  OSSL_CMP_CRLSTATUS_free := nil;
  OSSL_CMP_ITAV_new0_crlStatusList := nil;
  OSSL_CMP_ITAV_get0_crlStatusList := nil;
  OSSL_CMP_ITAV_new_crls := nil;
  OSSL_CMP_ITAV_get0_crls := nil;
  OSSL_CMP_ITAV_new0_certReqTemplate := nil;
  OSSL_CMP_ITAV_get1_certReqTemplate := nil;
  OSSL_CMP_ATAV_create := nil;
  OSSL_CMP_ATAV_set0 := nil;
  OSSL_CMP_ATAV_get0_type := nil;
  OSSL_CMP_ATAV_get0_value := nil;
  OSSL_CMP_ATAV_new_algId := nil;
  OSSL_CMP_ATAV_get0_algId := nil;
  OSSL_CMP_ATAV_new_rsaKeyLen := nil;
  OSSL_CMP_ATAV_get_rsaKeyLen := nil;
  OSSL_CMP_ATAV_push1 := nil;
  OSSL_CMP_MSG_free := nil;
  OSSL_CMP_CTX_new := nil;
  OSSL_CMP_CTX_free := nil;
  OSSL_CMP_CTX_reinit := nil;
  OSSL_CMP_CTX_get0_libctx := nil;
  OSSL_CMP_CTX_get0_propq := nil;
  OSSL_CMP_CTX_set_option := nil;
  OSSL_CMP_CTX_get_option := nil;
  OSSL_CMP_CTX_set_log_cb := nil;
  OSSL_CMP_CTX_print_errors := nil;
  OSSL_CMP_CTX_set1_serverPath := nil;
  OSSL_CMP_CTX_set1_server := nil;
  OSSL_CMP_CTX_set_serverPort := nil;
  OSSL_CMP_CTX_set1_proxy := nil;
  OSSL_CMP_CTX_set1_no_proxy := nil;
  OSSL_CMP_CTX_set_http_cb := nil;
  OSSL_CMP_CTX_set_http_cb_arg := nil;
  OSSL_CMP_CTX_get_http_cb_arg := nil;
  OSSL_CMP_CTX_set_transfer_cb := nil;
  OSSL_CMP_CTX_set_transfer_cb_arg := nil;
  OSSL_CMP_CTX_get_transfer_cb_arg := nil;
  OSSL_CMP_CTX_set1_srvCert := nil;
  OSSL_CMP_CTX_set1_expected_sender := nil;
  OSSL_CMP_CTX_set0_trustedStore := nil;
  OSSL_CMP_CTX_get0_trustedStore := nil;
  OSSL_CMP_CTX_set1_untrusted := nil;
  OSSL_CMP_CTX_get0_untrusted := nil;
  OSSL_CMP_CTX_set1_cert := nil;
  OSSL_CMP_CTX_build_cert_chain := nil;
  OSSL_CMP_CTX_set1_pkey := nil;
  OSSL_CMP_CTX_set1_referenceValue := nil;
  OSSL_CMP_CTX_set1_secretValue := nil;
  OSSL_CMP_CTX_set1_recipient := nil;
  OSSL_CMP_CTX_push0_geninfo_ITAV := nil;
  OSSL_CMP_CTX_reset_geninfo_ITAVs := nil;
  OSSL_CMP_CTX_get0_geninfo_ITAVs := nil;
  OSSL_CMP_CTX_set1_extraCertsOut := nil;
  OSSL_CMP_CTX_set0_newPkey := nil;
  OSSL_CMP_CTX_get0_newPkey := nil;
  OSSL_CMP_CTX_set1_issuer := nil;
  OSSL_CMP_CTX_set1_serialNumber := nil;
  OSSL_CMP_CTX_set1_subjectName := nil;
  OSSL_CMP_CTX_push1_subjectAltName := nil;
  OSSL_CMP_CTX_set0_reqExtensions := nil;
  OSSL_CMP_CTX_reqExtensions_have_SAN := nil;
  OSSL_CMP_CTX_push0_policy := nil;
  OSSL_CMP_CTX_set1_oldCert := nil;
  OSSL_CMP_CTX_set1_p10CSR := nil;
  OSSL_CMP_CTX_push0_genm_ITAV := nil;
  OSSL_CMP_certConf_cb := nil;
  OSSL_CMP_CTX_set_certConf_cb := nil;
  OSSL_CMP_CTX_set_certConf_cb_arg := nil;
  OSSL_CMP_CTX_get_certConf_cb_arg := nil;
  OSSL_CMP_CTX_get_status := nil;
  OSSL_CMP_CTX_get0_statusString := nil;
  OSSL_CMP_CTX_get_failInfoCode := nil;
  OSSL_CMP_CTX_get0_validatedSrvCert := nil;
  OSSL_CMP_CTX_get0_newCert := nil;
  OSSL_CMP_CTX_get1_newChain := nil;
  OSSL_CMP_CTX_get1_caPubs := nil;
  OSSL_CMP_CTX_get1_extraCertsIn := nil;
  OSSL_CMP_CTX_set1_transactionID := nil;
  OSSL_CMP_CTX_set1_senderNonce := nil;
  OSSL_CMP_CTX_snprint_PKIStatus := nil;
  OSSL_CMP_snprint_PKIStatusInfo := nil;
  OSSL_CMP_STATUSINFO_new := nil;
  OSSL_CMP_HDR_get0_transactionID := nil;
  OSSL_CMP_HDR_get0_recipNonce := nil;
  OSSL_CMP_HDR_get0_geninfo_ITAVs := nil;
  OSSL_CMP_MSG_get0_header := nil;
  OSSL_CMP_MSG_get_bodytype := nil;
  OSSL_CMP_MSG_get0_certreq_publickey := nil;
  OSSL_CMP_MSG_update_transactionID := nil;
  OSSL_CMP_MSG_update_recipNonce := nil;
  OSSL_CMP_CTX_setup_CRM := nil;
  OSSL_CMP_MSG_read := nil;
  OSSL_CMP_MSG_write := nil;
  d2i_OSSL_CMP_MSG_bio := nil;
  i2d_OSSL_CMP_MSG_bio := nil;
  OSSL_CMP_validate_msg := nil;
  OSSL_CMP_validate_cert_path := nil;
  OSSL_CMP_MSG_http_perform := nil;
  OSSL_CMP_SRV_process_request := nil;
  OSSL_CMP_CTX_server_perform := nil;
  OSSL_CMP_SRV_CTX_new := nil;
  OSSL_CMP_SRV_CTX_free := nil;
  OSSL_CMP_SRV_CTX_init := nil;
  OSSL_CMP_SRV_CTX_init_trans := nil;
  OSSL_CMP_SRV_CTX_get0_cmp_ctx := nil;
  OSSL_CMP_SRV_CTX_get0_custom_ctx := nil;
  OSSL_CMP_SRV_CTX_set_send_unprotected_errors := nil;
  OSSL_CMP_SRV_CTX_set_accept_unprotected := nil;
  OSSL_CMP_SRV_CTX_set_accept_raverified := nil;
  OSSL_CMP_SRV_CTX_set_grant_implicit_confirm := nil;
  OSSL_CMP_exec_certreq := nil;
  OSSL_CMP_try_certreq := nil;
  OSSL_CMP_exec_RR_ses := nil;
  OSSL_CMP_exec_GENM_ses := nil;
  OSSL_CMP_get1_caCerts := nil;
  OSSL_CMP_get1_rootCaKeyUpdate := nil;
  OSSL_CMP_get1_crlUpdate := nil;
  OSSL_CMP_get1_certReqTemplate := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.