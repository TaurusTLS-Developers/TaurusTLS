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

unit TaurusTLSHeaders_ts;

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
  PS_msg_imprint_st = ^TS_msg_imprint_st;
  TS_msg_imprint_st = record end;
  {$EXTERNALSYM PS_msg_imprint_st}

  PS_MSG_IMPRINT = ^TS_MSG_IMPRINT;
  TS_MSG_IMPRINT = TS_msg_imprint_st;
  {$EXTERNALSYM PS_MSG_IMPRINT}

  PS_req_st = ^TS_req_st;
  TS_req_st = record end;
  {$EXTERNALSYM PS_req_st}

  PS_REQ = ^TS_REQ;
  TS_REQ = TS_req_st;
  {$EXTERNALSYM PS_REQ}

  PS_accuracy_st = ^TS_accuracy_st;
  TS_accuracy_st = record end;
  {$EXTERNALSYM PS_accuracy_st}

  PS_ACCURACY = ^TS_ACCURACY;
  TS_ACCURACY = TS_accuracy_st;
  {$EXTERNALSYM PS_ACCURACY}

  PS_tst_info_st = ^TS_tst_info_st;
  TS_tst_info_st = record end;
  {$EXTERNALSYM PS_tst_info_st}

  PS_TST_INFO = ^TS_TST_INFO;
  TS_TST_INFO = TS_tst_info_st;
  {$EXTERNALSYM PS_TST_INFO}

  PS_status_info_st = ^TS_status_info_st;
  TS_status_info_st = record end;
  {$EXTERNALSYM PS_status_info_st}

  PS_STATUS_INFO = ^TS_STATUS_INFO;
  TS_STATUS_INFO = TS_status_info_st;
  {$EXTERNALSYM PS_STATUS_INFO}

  PS_resp_st = ^TS_resp_st;
  TS_resp_st = record end;
  {$EXTERNALSYM PS_resp_st}

  PS_RESP = ^TS_RESP;
  TS_RESP = TS_resp_st;
  {$EXTERNALSYM PS_RESP}

  PS_resp_ctx = ^TS_resp_ctx;
  TS_resp_ctx = record end;
  {$EXTERNALSYM PS_resp_ctx}

  { TODO 1 -cID Collision detected : Review it and update. }
  // Collision with TS_resp_ctx:
  // typedef struct TS_resp_ctx TS_RESP_CTX

  PS_verify_ctx = ^TS_verify_ctx;
  TS_verify_ctx = record end;
  {$EXTERNALSYM PS_verify_ctx}

  { TODO 1 -cID Collision detected : Review it and update. }
  // Collision with TS_verify_ctx:
  // typedef struct TS_verify_ctx TS_VERIFY_CTX


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TS_serial_cb_func_cb = function(arg1: PS_resp_ctx; arg2: Pointer): PASN1_INTEGER; cdecl;
  TS_time_cb_func_cb = function(arg1: PS_resp_ctx; arg2: Pointer; arg3: PIdC_LONG; arg4: PIdC_LONG): TIdC_INT; cdecl;
  TS_extension_cb_func_cb = function(arg1: PS_resp_ctx; arg2: PX509_EXTENSION; arg3: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  TS_STATUS_GRANTED = 0;
  TS_STATUS_GRANTED_WITH_MODS = 1;
  TS_STATUS_REJECTION = 2;
  TS_STATUS_WAITING = 3;
  TS_STATUS_REVOCATION_WARNING = 4;
  TS_STATUS_REVOCATION_NOTIFICATION = 5;
  TS_INFO_BAD_ALG = 0;
  TS_INFO_BAD_REQUEST = 2;
  TS_INFO_BAD_DATA_FORMAT = 5;
  TS_INFO_TIME_NOT_AVAILABLE = 14;
  TS_INFO_UNACCEPTED_POLICY = 15;
  TS_INFO_UNACCEPTED_EXTENSION = 16;
  TS_INFO_ADD_INFO_NOT_AVAILABLE = 17;
  TS_INFO_SYSTEM_FAILURE = 25;
  TS_TSA_NAME = $01;
  TS_ORDERING = $02;
  TS_ESS_CERT_ID_CHAIN = $04;
  TS_MAX_CLOCK_PRECISION_DIGITS = 6;
  TS_MAX_STATUS_LENGTH = (1024*1024);
  TS_VFY_SIGNATURE = (1u shl 0);
  TS_VFY_VERSION = (1u shl 1);
  TS_VFY_POLICY = (1u shl 2);
  TS_VFY_IMPRINT = (1u shl 3);
  TS_VFY_DATA = (1u shl 4);
  TS_VFY_NONCE = (1u shl 5);
  TS_VFY_SIGNER = (1u shl 6);
  TS_VFY_TSA_NAME = (1u shl 7);
  TS_VFY_ALL_IMPRINT = (TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY or TS_VFY_IMPRINT or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME);
  TS_VFY_ALL_DATA = (TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY or TS_VFY_DATA or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  TS_REQ_new: function: PS_REQ; cdecl = nil;
  {$EXTERNALSYM TS_REQ_new}

  TS_REQ_free: procedure(a: PS_REQ); cdecl = nil;
  {$EXTERNALSYM TS_REQ_free}

  d2i_TS_REQ: function(a: PPS_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PS_REQ; cdecl = nil;
  {$EXTERNALSYM d2i_TS_REQ}

  i2d_TS_REQ: function(a: PS_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_REQ}

  TS_REQ_dup: function(a: PS_REQ): PS_REQ; cdecl = nil;
  {$EXTERNALSYM TS_REQ_dup}

  d2i_TS_REQ_fp: function(fp: PFILE; a: PPS_REQ): PS_REQ; cdecl = nil;
  {$EXTERNALSYM d2i_TS_REQ_fp}

  i2d_TS_REQ_fp: function(fp: PFILE; a: PS_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_REQ_fp}

  d2i_TS_REQ_bio: function(fp: PBIO; a: PPS_REQ): PS_REQ; cdecl = nil;
  {$EXTERNALSYM d2i_TS_REQ_bio}

  i2d_TS_REQ_bio: function(fp: PBIO; a: PS_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_REQ_bio}

  TS_MSG_IMPRINT_new: function: PS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_new}

  TS_MSG_IMPRINT_free: procedure(a: PS_MSG_IMPRINT); cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_free}

  d2i_TS_MSG_IMPRINT: function(a: PPS_MSG_IMPRINT; _in: PPIdAnsiChar; len: TIdC_LONG): PS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT}

  i2d_TS_MSG_IMPRINT: function(a: PS_MSG_IMPRINT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT}

  TS_MSG_IMPRINT_dup: function(a: PS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_dup}

  d2i_TS_MSG_IMPRINT_fp: function(fp: PFILE; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT_fp}

  i2d_TS_MSG_IMPRINT_fp: function(fp: PFILE; a: PS_MSG_IMPRINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT_fp}

  d2i_TS_MSG_IMPRINT_bio: function(bio: PBIO; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT_bio}

  i2d_TS_MSG_IMPRINT_bio: function(bio: PBIO; a: PS_MSG_IMPRINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT_bio}

  TS_RESP_new: function: PS_RESP; cdecl = nil;
  {$EXTERNALSYM TS_RESP_new}

  TS_RESP_free: procedure(a: PS_RESP); cdecl = nil;
  {$EXTERNALSYM TS_RESP_free}

  d2i_TS_RESP: function(a: PPS_RESP; _in: PPIdAnsiChar; len: TIdC_LONG): PS_RESP; cdecl = nil;
  {$EXTERNALSYM d2i_TS_RESP}

  i2d_TS_RESP: function(a: PS_RESP; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_RESP}

  TS_RESP_dup: function(a: PS_RESP): PS_RESP; cdecl = nil;
  {$EXTERNALSYM TS_RESP_dup}

  d2i_TS_RESP_fp: function(fp: PFILE; a: PPS_RESP): PS_RESP; cdecl = nil;
  {$EXTERNALSYM d2i_TS_RESP_fp}

  i2d_TS_RESP_fp: function(fp: PFILE; a: PS_RESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_RESP_fp}

  d2i_TS_RESP_bio: function(bio: PBIO; a: PPS_RESP): PS_RESP; cdecl = nil;
  {$EXTERNALSYM d2i_TS_RESP_bio}

  i2d_TS_RESP_bio: function(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_RESP_bio}

  TS_STATUS_INFO_new: function: PS_STATUS_INFO; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_new}

  TS_STATUS_INFO_free: procedure(a: PS_STATUS_INFO); cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_free}

  d2i_TS_STATUS_INFO: function(a: PPS_STATUS_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_STATUS_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_TS_STATUS_INFO}

  i2d_TS_STATUS_INFO: function(a: PS_STATUS_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_STATUS_INFO}

  TS_STATUS_INFO_dup: function(a: PS_STATUS_INFO): PS_STATUS_INFO; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_dup}

  TS_TST_INFO_new: function: PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_new}

  TS_TST_INFO_free: procedure(a: PS_TST_INFO); cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_free}

  d2i_TS_TST_INFO: function(a: PPS_TST_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_TS_TST_INFO}

  i2d_TS_TST_INFO: function(a: PS_TST_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_TST_INFO}

  TS_TST_INFO_dup: function(a: PS_TST_INFO): PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_dup}

  PKCS7_to_TS_TST_INFO: function(token: PPKCS7): PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS7_to_TS_TST_INFO}

  d2i_TS_TST_INFO_fp: function(fp: PFILE; a: PPS_TST_INFO): PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_TS_TST_INFO_fp}

  i2d_TS_TST_INFO_fp: function(fp: PFILE; a: PS_TST_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_TST_INFO_fp}

  d2i_TS_TST_INFO_bio: function(bio: PBIO; a: PPS_TST_INFO): PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_TS_TST_INFO_bio}

  i2d_TS_TST_INFO_bio: function(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_TST_INFO_bio}

  TS_ACCURACY_new: function: PS_ACCURACY; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_new}

  TS_ACCURACY_free: procedure(a: PS_ACCURACY); cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_free}

  d2i_TS_ACCURACY: function(a: PPS_ACCURACY; _in: PPIdAnsiChar; len: TIdC_LONG): PS_ACCURACY; cdecl = nil;
  {$EXTERNALSYM d2i_TS_ACCURACY}

  i2d_TS_ACCURACY: function(a: PS_ACCURACY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_ACCURACY}

  TS_ACCURACY_dup: function(a: PS_ACCURACY): PS_ACCURACY; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_dup}

  TS_REQ_set_version: function(a: PS_REQ; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_set_version}

  TS_REQ_get_version: function(a: PS_REQ): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_version}

  TS_STATUS_INFO_set_status: function(a: PS_STATUS_INFO; i: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_set_status}

  TS_STATUS_INFO_get0_status: function(a: PS_STATUS_INFO): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_get0_status}

  TS_STATUS_INFO_get0_text: function(a: PS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_get0_text}

  TS_STATUS_INFO_get0_failure_info: function(a: PS_STATUS_INFO): PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_get0_failure_info}

  TS_REQ_set_msg_imprint: function(a: PS_REQ; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_set_msg_imprint}

  TS_REQ_get_msg_imprint: function(a: PS_REQ): PS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_msg_imprint}

  TS_MSG_IMPRINT_set_algo: function(a: PS_MSG_IMPRINT; alg: PX509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_set_algo}

  TS_MSG_IMPRINT_get_algo: function(a: PS_MSG_IMPRINT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_get_algo}

  TS_MSG_IMPRINT_set_msg: function(a: PS_MSG_IMPRINT; d: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_set_msg}

  TS_MSG_IMPRINT_get_msg: function(a: PS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_get_msg}

  TS_REQ_set_policy_id: function(a: PS_REQ; policy: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_set_policy_id}

  TS_REQ_get_policy_id: function(a: PS_REQ): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_policy_id}

  TS_REQ_set_nonce: function(a: PS_REQ; nonce: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_set_nonce}

  TS_REQ_get_nonce: function(a: PS_REQ): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_nonce}

  TS_REQ_set_cert_req: function(a: PS_REQ; cert_req: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_set_cert_req}

  TS_REQ_get_cert_req: function(a: PS_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_cert_req}

  TS_REQ_get_exts: function(a: PS_REQ): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_exts}

  TS_REQ_ext_free: procedure(a: PS_REQ); cdecl = nil;
  {$EXTERNALSYM TS_REQ_ext_free}

  TS_REQ_get_ext_count: function(a: PS_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_count}

  TS_REQ_get_ext_by_NID: function(a: PS_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_by_NID}

  TS_REQ_get_ext_by_OBJ: function(a: PS_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_by_OBJ}

  TS_REQ_get_ext_by_critical: function(a: PS_REQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_by_critical}

  TS_REQ_get_ext: function(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext}

  TS_REQ_delete_ext: function(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM TS_REQ_delete_ext}

  TS_REQ_add_ext: function(a: PS_REQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_add_ext}

  TS_REQ_get_ext_d2i: function(a: PS_REQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_d2i}

  TS_REQ_print_bio: function(bio: PBIO; a: PS_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_print_bio}

  TS_RESP_set_status_info: function(a: PS_RESP; info: PS_STATUS_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_set_status_info}

  TS_RESP_get_status_info: function(a: PS_RESP): PS_STATUS_INFO; cdecl = nil;
  {$EXTERNALSYM TS_RESP_get_status_info}

  TS_RESP_set_tst_info: procedure(a: PS_RESP; p7: PPKCS7; tst_info: PS_TST_INFO); cdecl = nil;
  {$EXTERNALSYM TS_RESP_set_tst_info}

  TS_RESP_get_token: function(a: PS_RESP): PPKCS7; cdecl = nil;
  {$EXTERNALSYM TS_RESP_get_token}

  TS_RESP_get_tst_info: function(a: PS_RESP): PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM TS_RESP_get_tst_info}

  TS_TST_INFO_set_version: function(a: PS_TST_INFO; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_version}

  TS_TST_INFO_get_version: function(a: PS_TST_INFO): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_version}

  TS_TST_INFO_set_policy_id: function(a: PS_TST_INFO; policy_id: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_policy_id}

  TS_TST_INFO_get_policy_id: function(a: PS_TST_INFO): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_policy_id}

  TS_TST_INFO_set_msg_imprint: function(a: PS_TST_INFO; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_msg_imprint}

  TS_TST_INFO_get_msg_imprint: function(a: PS_TST_INFO): PS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_msg_imprint}

  TS_TST_INFO_set_serial: function(a: PS_TST_INFO; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_serial}

  TS_TST_INFO_get_serial: function(a: PS_TST_INFO): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_serial}

  TS_TST_INFO_set_time: function(a: PS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_time}

  TS_TST_INFO_get_time: function(a: PS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_time}

  TS_TST_INFO_set_accuracy: function(a: PS_TST_INFO; accuracy: PS_ACCURACY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_accuracy}

  TS_TST_INFO_get_accuracy: function(a: PS_TST_INFO): PS_ACCURACY; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_accuracy}

  TS_ACCURACY_set_seconds: function(a: PS_ACCURACY; seconds: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_set_seconds}

  TS_ACCURACY_get_seconds: function(a: PS_ACCURACY): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_get_seconds}

  TS_ACCURACY_set_millis: function(a: PS_ACCURACY; millis: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_set_millis}

  TS_ACCURACY_get_millis: function(a: PS_ACCURACY): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_get_millis}

  TS_ACCURACY_set_micros: function(a: PS_ACCURACY; micros: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_set_micros}

  TS_ACCURACY_get_micros: function(a: PS_ACCURACY): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_get_micros}

  TS_TST_INFO_set_ordering: function(a: PS_TST_INFO; ordering: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_ordering}

  TS_TST_INFO_get_ordering: function(a: PS_TST_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ordering}

  TS_TST_INFO_set_nonce: function(a: PS_TST_INFO; nonce: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_nonce}

  TS_TST_INFO_get_nonce: function(a: PS_TST_INFO): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_nonce}

  TS_TST_INFO_set_tsa: function(a: PS_TST_INFO; tsa: PGENERAL_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_set_tsa}

  TS_TST_INFO_get_tsa: function(a: PS_TST_INFO): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_tsa}

  TS_TST_INFO_get_exts: function(a: PS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_exts}

  TS_TST_INFO_ext_free: procedure(a: PS_TST_INFO); cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_ext_free}

  TS_TST_INFO_get_ext_count: function(a: PS_TST_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_count}

  TS_TST_INFO_get_ext_by_NID: function(a: PS_TST_INFO; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_NID}

  TS_TST_INFO_get_ext_by_OBJ: function(a: PS_TST_INFO; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_OBJ}

  TS_TST_INFO_get_ext_by_critical: function(a: PS_TST_INFO; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_critical}

  TS_TST_INFO_get_ext: function(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext}

  TS_TST_INFO_delete_ext: function(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_delete_ext}

  TS_TST_INFO_add_ext: function(a: PS_TST_INFO; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_add_ext}

  TS_TST_INFO_get_ext_d2i: function(a: PS_TST_INFO; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_d2i}

  TS_RESP_CTX_new: function: PS_RESP_CTX; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_new}

  TS_RESP_CTX_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PS_RESP_CTX; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_new_ex}

  TS_RESP_CTX_free: procedure(ctx: PS_RESP_CTX); cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_free}

  TS_RESP_CTX_set_signer_cert: function(ctx: PS_RESP_CTX; signer: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_signer_cert}

  TS_RESP_CTX_set_signer_key: function(ctx: PS_RESP_CTX; key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_signer_key}

  TS_RESP_CTX_set_signer_digest: function(ctx: PS_RESP_CTX; signer_digest: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_signer_digest}

  TS_RESP_CTX_set_ess_cert_id_digest: function(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_ess_cert_id_digest}

  TS_RESP_CTX_set_def_policy: function(ctx: PS_RESP_CTX; def_policy: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_def_policy}

  TS_RESP_CTX_set_certs: function(ctx: PS_RESP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_certs}

  TS_RESP_CTX_add_policy: function(ctx: PS_RESP_CTX; policy: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_add_policy}

  TS_RESP_CTX_add_md: function(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_add_md}

  TS_RESP_CTX_set_accuracy: function(ctx: PS_RESP_CTX; secs: TIdC_INT; millis: TIdC_INT; micros: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_accuracy}

  TS_RESP_CTX_set_clock_precision_digits: function(ctx: PS_RESP_CTX; clock_precision_digits: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_clock_precision_digits}

  TS_RESP_CTX_add_flags: procedure(ctx: PS_RESP_CTX; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_add_flags}

  TS_RESP_CTX_set_serial_cb: procedure(ctx: PS_RESP_CTX; cb: TS_serial_cb_func_cb; data: Pointer); cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_serial_cb}

  TS_RESP_CTX_set_time_cb: procedure(ctx: PS_RESP_CTX; cb: TS_time_cb_func_cb; data: Pointer); cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_time_cb}

  TS_RESP_CTX_set_extension_cb: procedure(ctx: PS_RESP_CTX; cb: TS_extension_cb_func_cb; data: Pointer); cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_extension_cb}

  TS_RESP_CTX_set_status_info: function(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_status_info}

  TS_RESP_CTX_set_status_info_cond: function(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_status_info_cond}

  TS_RESP_CTX_add_failure_info: function(ctx: PS_RESP_CTX; failure: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_add_failure_info}

  TS_RESP_CTX_get_request: function(ctx: PS_RESP_CTX): PS_REQ; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_get_request}

  TS_RESP_CTX_get_tst_info: function(ctx: PS_RESP_CTX): PS_TST_INFO; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_get_tst_info}

  TS_RESP_create_response: function(ctx: PS_RESP_CTX; req_bio: PBIO): PS_RESP; cdecl = nil;
  {$EXTERNALSYM TS_RESP_create_response}

  TS_RESP_verify_signature: function(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_verify_signature}

  TS_RESP_verify_response: function(ctx: PS_VERIFY_CTX; response: PS_RESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_verify_response}

  TS_RESP_verify_token: function(ctx: PS_VERIFY_CTX; token: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_verify_token}

  TS_VERIFY_CTX_new: function: PS_VERIFY_CTX; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_new}

  TS_VERIFY_CTX_init: procedure(ctx: PS_VERIFY_CTX); cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_init}

  TS_VERIFY_CTX_free: procedure(ctx: PS_VERIFY_CTX); cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_free}

  TS_VERIFY_CTX_cleanup: procedure(ctx: PS_VERIFY_CTX); cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_cleanup}

  TS_VERIFY_CTX_set_flags: function(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set_flags}

  TS_VERIFY_CTX_add_flags: function(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_add_flags}

  TS_VERIFY_CTX_set_data: function(ctx: PS_VERIFY_CTX; b: PBIO): PBIO; cdecl = nil; // Deprecated in 3_4_0
  {$EXTERNALSYM TS_VERIFY_CTX_set_data}

  TS_VERIFY_CTX_set0_data: function(ctx: PS_VERIFY_CTX; b: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_data}

  TS_VERIFY_CTX_set_imprint: function(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): PIdAnsiChar; cdecl = nil; // Deprecated in 3_4_0
  {$EXTERNALSYM TS_VERIFY_CTX_set_imprint}

  TS_VERIFY_CTX_set0_imprint: function(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_imprint}

  TS_VERIFY_CTX_set_store: function(ctx: PS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl = nil; // Deprecated in 3_4_0
  {$EXTERNALSYM TS_VERIFY_CTX_set_store}

  TS_VERIFY_CTX_set0_store: function(ctx: PS_VERIFY_CTX; s: PX509_STORE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_store}

  TS_VERIFY_CTX_set_certs: function(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl = nil; // Deprecated in 3_4_0
  {$EXTERNALSYM TS_VERIFY_CTX_set_certs}

  TS_VERIFY_CTX_set0_certs: function(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_certs}

  TS_REQ_to_TS_VERIFY_CTX: function(req: PS_REQ; ctx: PS_VERIFY_CTX): PS_VERIFY_CTX; cdecl = nil;
  {$EXTERNALSYM TS_REQ_to_TS_VERIFY_CTX}

  TS_RESP_print_bio: function(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_print_bio}

  TS_STATUS_INFO_print_bio: function(bio: PBIO; a: PS_STATUS_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_print_bio}

  TS_TST_INFO_print_bio: function(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_print_bio}

  TS_ASN1_INTEGER_print_bio: function(bio: PBIO; num: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ASN1_INTEGER_print_bio}

  TS_OBJ_print_bio: function(bio: PBIO; obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_OBJ_print_bio}

  TS_ext_print_bio: function(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ext_print_bio}

  TS_X509_ALGOR_print_bio: function(bio: PBIO; alg: PX509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_X509_ALGOR_print_bio}

  TS_MSG_IMPRINT_print_bio: function(bio: PBIO; msg: PS_MSG_IMPRINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_print_bio}

  TS_CONF_load_cert: function(_file: PIdAnsiChar): PX509; cdecl = nil;
  {$EXTERNALSYM TS_CONF_load_cert}

  TS_CONF_load_certs: function(_file: PIdAnsiChar): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM TS_CONF_load_certs}

  TS_CONF_load_key: function(_file: PIdAnsiChar; pass: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM TS_CONF_load_key}

  TS_CONF_get_tsa_section: function(conf: PCONF; section: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM TS_CONF_get_tsa_section}

  TS_CONF_set_serial: function(conf: PCONF; section: PIdAnsiChar; cb: TS_serial_cb_func_cb; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_serial}

  TS_CONF_set_crypto_device: function(conf: PCONF; section: PIdAnsiChar; device: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_crypto_device}

  TS_CONF_set_default_engine: function(name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_default_engine}

  TS_CONF_set_signer_cert: function(conf: PCONF; section: PIdAnsiChar; cert: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_signer_cert}

  TS_CONF_set_certs: function(conf: PCONF; section: PIdAnsiChar; certs: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_certs}

  TS_CONF_set_signer_key: function(conf: PCONF; section: PIdAnsiChar; key: PIdAnsiChar; pass: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_signer_key}

  TS_CONF_set_signer_digest: function(conf: PCONF; section: PIdAnsiChar; md: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_signer_digest}

  TS_CONF_set_def_policy: function(conf: PCONF; section: PIdAnsiChar; policy: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_def_policy}

  TS_CONF_set_policies: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_policies}

  TS_CONF_set_digests: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_digests}

  TS_CONF_set_accuracy: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_accuracy}

  TS_CONF_set_clock_precision_digits: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_clock_precision_digits}

  TS_CONF_set_ordering: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_ordering}

  TS_CONF_set_tsa_name: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_tsa_name}

  TS_CONF_set_ess_cert_id_chain: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_chain}

  TS_CONF_set_ess_cert_id_digest: function(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_digest}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function TS_REQ_new: PS_REQ; cdecl;
procedure TS_REQ_free(a: PS_REQ); cdecl;
function d2i_TS_REQ(a: PPS_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PS_REQ; cdecl;
function i2d_TS_REQ(a: PS_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function TS_REQ_dup(a: PS_REQ): PS_REQ; cdecl;
function d2i_TS_REQ_fp(fp: PFILE; a: PPS_REQ): PS_REQ; cdecl;
function i2d_TS_REQ_fp(fp: PFILE; a: PS_REQ): TIdC_INT; cdecl;
function d2i_TS_REQ_bio(fp: PBIO; a: PPS_REQ): PS_REQ; cdecl;
function i2d_TS_REQ_bio(fp: PBIO; a: PS_REQ): TIdC_INT; cdecl;
function TS_MSG_IMPRINT_new: PS_MSG_IMPRINT; cdecl;
procedure TS_MSG_IMPRINT_free(a: PS_MSG_IMPRINT); cdecl;
function d2i_TS_MSG_IMPRINT(a: PPS_MSG_IMPRINT; _in: PPIdAnsiChar; len: TIdC_LONG): PS_MSG_IMPRINT; cdecl;
function i2d_TS_MSG_IMPRINT(a: PS_MSG_IMPRINT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function TS_MSG_IMPRINT_dup(a: PS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl;
function d2i_TS_MSG_IMPRINT_fp(fp: PFILE; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl;
function i2d_TS_MSG_IMPRINT_fp(fp: PFILE; a: PS_MSG_IMPRINT): TIdC_INT; cdecl;
function d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl;
function i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PS_MSG_IMPRINT): TIdC_INT; cdecl;
function TS_RESP_new: PS_RESP; cdecl;
procedure TS_RESP_free(a: PS_RESP); cdecl;
function d2i_TS_RESP(a: PPS_RESP; _in: PPIdAnsiChar; len: TIdC_LONG): PS_RESP; cdecl;
function i2d_TS_RESP(a: PS_RESP; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function TS_RESP_dup(a: PS_RESP): PS_RESP; cdecl;
function d2i_TS_RESP_fp(fp: PFILE; a: PPS_RESP): PS_RESP; cdecl;
function i2d_TS_RESP_fp(fp: PFILE; a: PS_RESP): TIdC_INT; cdecl;
function d2i_TS_RESP_bio(bio: PBIO; a: PPS_RESP): PS_RESP; cdecl;
function i2d_TS_RESP_bio(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl;
function TS_STATUS_INFO_new: PS_STATUS_INFO; cdecl;
procedure TS_STATUS_INFO_free(a: PS_STATUS_INFO); cdecl;
function d2i_TS_STATUS_INFO(a: PPS_STATUS_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_STATUS_INFO; cdecl;
function i2d_TS_STATUS_INFO(a: PS_STATUS_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function TS_STATUS_INFO_dup(a: PS_STATUS_INFO): PS_STATUS_INFO; cdecl;
function TS_TST_INFO_new: PS_TST_INFO; cdecl;
procedure TS_TST_INFO_free(a: PS_TST_INFO); cdecl;
function d2i_TS_TST_INFO(a: PPS_TST_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_TST_INFO; cdecl;
function i2d_TS_TST_INFO(a: PS_TST_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function TS_TST_INFO_dup(a: PS_TST_INFO): PS_TST_INFO; cdecl;
function PKCS7_to_TS_TST_INFO(token: PPKCS7): PS_TST_INFO; cdecl;
function d2i_TS_TST_INFO_fp(fp: PFILE; a: PPS_TST_INFO): PS_TST_INFO; cdecl;
function i2d_TS_TST_INFO_fp(fp: PFILE; a: PS_TST_INFO): TIdC_INT; cdecl;
function d2i_TS_TST_INFO_bio(bio: PBIO; a: PPS_TST_INFO): PS_TST_INFO; cdecl;
function i2d_TS_TST_INFO_bio(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl;
function TS_ACCURACY_new: PS_ACCURACY; cdecl;
procedure TS_ACCURACY_free(a: PS_ACCURACY); cdecl;
function d2i_TS_ACCURACY(a: PPS_ACCURACY; _in: PPIdAnsiChar; len: TIdC_LONG): PS_ACCURACY; cdecl;
function i2d_TS_ACCURACY(a: PS_ACCURACY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function TS_ACCURACY_dup(a: PS_ACCURACY): PS_ACCURACY; cdecl;
function TS_REQ_set_version(a: PS_REQ; version: TIdC_LONG): TIdC_INT; cdecl;
function TS_REQ_get_version(a: PS_REQ): TIdC_LONG; cdecl;
function TS_STATUS_INFO_set_status(a: PS_STATUS_INFO; i: TIdC_INT): TIdC_INT; cdecl;
function TS_STATUS_INFO_get0_status(a: PS_STATUS_INFO): PASN1_INTEGER; cdecl;
function TS_STATUS_INFO_get0_text(a: PS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl;
function TS_STATUS_INFO_get0_failure_info(a: PS_STATUS_INFO): PASN1_BIT_STRING; cdecl;
function TS_REQ_set_msg_imprint(a: PS_REQ; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl;
function TS_REQ_get_msg_imprint(a: PS_REQ): PS_MSG_IMPRINT; cdecl;
function TS_MSG_IMPRINT_set_algo(a: PS_MSG_IMPRINT; alg: PX509_ALGOR): TIdC_INT; cdecl;
function TS_MSG_IMPRINT_get_algo(a: PS_MSG_IMPRINT): PX509_ALGOR; cdecl;
function TS_MSG_IMPRINT_set_msg(a: PS_MSG_IMPRINT; d: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function TS_MSG_IMPRINT_get_msg(a: PS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl;
function TS_REQ_set_policy_id(a: PS_REQ; policy: PASN1_OBJECT): TIdC_INT; cdecl;
function TS_REQ_get_policy_id(a: PS_REQ): PASN1_OBJECT; cdecl;
function TS_REQ_set_nonce(a: PS_REQ; nonce: PASN1_INTEGER): TIdC_INT; cdecl;
function TS_REQ_get_nonce(a: PS_REQ): PASN1_INTEGER; cdecl;
function TS_REQ_set_cert_req(a: PS_REQ; cert_req: TIdC_INT): TIdC_INT; cdecl;
function TS_REQ_get_cert_req(a: PS_REQ): TIdC_INT; cdecl;
function TS_REQ_get_exts(a: PS_REQ): Pstack_st_X509_EXTENSION; cdecl;
procedure TS_REQ_ext_free(a: PS_REQ); cdecl;
function TS_REQ_get_ext_count(a: PS_REQ): TIdC_INT; cdecl;
function TS_REQ_get_ext_by_NID(a: PS_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function TS_REQ_get_ext_by_OBJ(a: PS_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function TS_REQ_get_ext_by_critical(a: PS_REQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function TS_REQ_get_ext(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function TS_REQ_delete_ext(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function TS_REQ_add_ext(a: PS_REQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function TS_REQ_get_ext_d2i(a: PS_REQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function TS_REQ_print_bio(bio: PBIO; a: PS_REQ): TIdC_INT; cdecl;
function TS_RESP_set_status_info(a: PS_RESP; info: PS_STATUS_INFO): TIdC_INT; cdecl;
function TS_RESP_get_status_info(a: PS_RESP): PS_STATUS_INFO; cdecl;
procedure TS_RESP_set_tst_info(a: PS_RESP; p7: PPKCS7; tst_info: PS_TST_INFO); cdecl;
function TS_RESP_get_token(a: PS_RESP): PPKCS7; cdecl;
function TS_RESP_get_tst_info(a: PS_RESP): PS_TST_INFO; cdecl;
function TS_TST_INFO_set_version(a: PS_TST_INFO; version: TIdC_LONG): TIdC_INT; cdecl;
function TS_TST_INFO_get_version(a: PS_TST_INFO): TIdC_LONG; cdecl;
function TS_TST_INFO_set_policy_id(a: PS_TST_INFO; policy_id: PASN1_OBJECT): TIdC_INT; cdecl;
function TS_TST_INFO_get_policy_id(a: PS_TST_INFO): PASN1_OBJECT; cdecl;
function TS_TST_INFO_set_msg_imprint(a: PS_TST_INFO; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl;
function TS_TST_INFO_get_msg_imprint(a: PS_TST_INFO): PS_MSG_IMPRINT; cdecl;
function TS_TST_INFO_set_serial(a: PS_TST_INFO; serial: PASN1_INTEGER): TIdC_INT; cdecl;
function TS_TST_INFO_get_serial(a: PS_TST_INFO): PASN1_INTEGER; cdecl;
function TS_TST_INFO_set_time(a: PS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
function TS_TST_INFO_get_time(a: PS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl;
function TS_TST_INFO_set_accuracy(a: PS_TST_INFO; accuracy: PS_ACCURACY): TIdC_INT; cdecl;
function TS_TST_INFO_get_accuracy(a: PS_TST_INFO): PS_ACCURACY; cdecl;
function TS_ACCURACY_set_seconds(a: PS_ACCURACY; seconds: PASN1_INTEGER): TIdC_INT; cdecl;
function TS_ACCURACY_get_seconds(a: PS_ACCURACY): PASN1_INTEGER; cdecl;
function TS_ACCURACY_set_millis(a: PS_ACCURACY; millis: PASN1_INTEGER): TIdC_INT; cdecl;
function TS_ACCURACY_get_millis(a: PS_ACCURACY): PASN1_INTEGER; cdecl;
function TS_ACCURACY_set_micros(a: PS_ACCURACY; micros: PASN1_INTEGER): TIdC_INT; cdecl;
function TS_ACCURACY_get_micros(a: PS_ACCURACY): PASN1_INTEGER; cdecl;
function TS_TST_INFO_set_ordering(a: PS_TST_INFO; ordering: TIdC_INT): TIdC_INT; cdecl;
function TS_TST_INFO_get_ordering(a: PS_TST_INFO): TIdC_INT; cdecl;
function TS_TST_INFO_set_nonce(a: PS_TST_INFO; nonce: PASN1_INTEGER): TIdC_INT; cdecl;
function TS_TST_INFO_get_nonce(a: PS_TST_INFO): PASN1_INTEGER; cdecl;
function TS_TST_INFO_set_tsa(a: PS_TST_INFO; tsa: PGENERAL_NAME): TIdC_INT; cdecl;
function TS_TST_INFO_get_tsa(a: PS_TST_INFO): PGENERAL_NAME; cdecl;
function TS_TST_INFO_get_exts(a: PS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl;
procedure TS_TST_INFO_ext_free(a: PS_TST_INFO); cdecl;
function TS_TST_INFO_get_ext_count(a: PS_TST_INFO): TIdC_INT; cdecl;
function TS_TST_INFO_get_ext_by_NID(a: PS_TST_INFO; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function TS_TST_INFO_get_ext_by_OBJ(a: PS_TST_INFO; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function TS_TST_INFO_get_ext_by_critical(a: PS_TST_INFO; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function TS_TST_INFO_get_ext(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function TS_TST_INFO_delete_ext(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function TS_TST_INFO_add_ext(a: PS_TST_INFO; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function TS_TST_INFO_get_ext_d2i(a: PS_TST_INFO; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function TS_RESP_CTX_new: PS_RESP_CTX; cdecl;
function TS_RESP_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PS_RESP_CTX; cdecl;
procedure TS_RESP_CTX_free(ctx: PS_RESP_CTX); cdecl;
function TS_RESP_CTX_set_signer_cert(ctx: PS_RESP_CTX; signer: PX509): TIdC_INT; cdecl;
function TS_RESP_CTX_set_signer_key(ctx: PS_RESP_CTX; key: PEVP_PKEY): TIdC_INT; cdecl;
function TS_RESP_CTX_set_signer_digest(ctx: PS_RESP_CTX; signer_digest: PEVP_MD): TIdC_INT; cdecl;
function TS_RESP_CTX_set_ess_cert_id_digest(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function TS_RESP_CTX_set_def_policy(ctx: PS_RESP_CTX; def_policy: PASN1_OBJECT): TIdC_INT; cdecl;
function TS_RESP_CTX_set_certs(ctx: PS_RESP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl;
function TS_RESP_CTX_add_policy(ctx: PS_RESP_CTX; policy: PASN1_OBJECT): TIdC_INT; cdecl;
function TS_RESP_CTX_add_md(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function TS_RESP_CTX_set_accuracy(ctx: PS_RESP_CTX; secs: TIdC_INT; millis: TIdC_INT; micros: TIdC_INT): TIdC_INT; cdecl;
function TS_RESP_CTX_set_clock_precision_digits(ctx: PS_RESP_CTX; clock_precision_digits: TIdC_UINT): TIdC_INT; cdecl;
procedure TS_RESP_CTX_add_flags(ctx: PS_RESP_CTX; flags: TIdC_INT); cdecl;
procedure TS_RESP_CTX_set_serial_cb(ctx: PS_RESP_CTX; cb: TS_serial_cb_func_cb; data: Pointer); cdecl;
procedure TS_RESP_CTX_set_time_cb(ctx: PS_RESP_CTX; cb: TS_time_cb_func_cb; data: Pointer); cdecl;
procedure TS_RESP_CTX_set_extension_cb(ctx: PS_RESP_CTX; cb: TS_extension_cb_func_cb; data: Pointer); cdecl;
function TS_RESP_CTX_set_status_info(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl;
function TS_RESP_CTX_set_status_info_cond(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl;
function TS_RESP_CTX_add_failure_info(ctx: PS_RESP_CTX; failure: TIdC_INT): TIdC_INT; cdecl;
function TS_RESP_CTX_get_request(ctx: PS_RESP_CTX): PS_REQ; cdecl;
function TS_RESP_CTX_get_tst_info(ctx: PS_RESP_CTX): PS_TST_INFO; cdecl;
function TS_RESP_create_response(ctx: PS_RESP_CTX; req_bio: PBIO): PS_RESP; cdecl;
function TS_RESP_verify_signature(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TIdC_INT; cdecl;
function TS_RESP_verify_response(ctx: PS_VERIFY_CTX; response: PS_RESP): TIdC_INT; cdecl;
function TS_RESP_verify_token(ctx: PS_VERIFY_CTX; token: PPKCS7): TIdC_INT; cdecl;
function TS_VERIFY_CTX_new: PS_VERIFY_CTX; cdecl;
procedure TS_VERIFY_CTX_init(ctx: PS_VERIFY_CTX); cdecl;
procedure TS_VERIFY_CTX_free(ctx: PS_VERIFY_CTX); cdecl;
procedure TS_VERIFY_CTX_cleanup(ctx: PS_VERIFY_CTX); cdecl;
function TS_VERIFY_CTX_set_flags(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl;
function TS_VERIFY_CTX_add_flags(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl;
function TS_VERIFY_CTX_set_data(ctx: PS_VERIFY_CTX; b: PBIO): PBIO; cdecl; deprecated 'In OpenSSL 3_4_0';
function TS_VERIFY_CTX_set0_data(ctx: PS_VERIFY_CTX; b: PBIO): TIdC_INT; cdecl;
function TS_VERIFY_CTX_set_imprint(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_4_0';
function TS_VERIFY_CTX_set0_imprint(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl;
function TS_VERIFY_CTX_set_store(ctx: PS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl; deprecated 'In OpenSSL 3_4_0';
function TS_VERIFY_CTX_set0_store(ctx: PS_VERIFY_CTX; s: PX509_STORE): TIdC_INT; cdecl;
function TS_VERIFY_CTX_set_certs(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl; deprecated 'In OpenSSL 3_4_0';
function TS_VERIFY_CTX_set0_certs(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl;
function TS_REQ_to_TS_VERIFY_CTX(req: PS_REQ; ctx: PS_VERIFY_CTX): PS_VERIFY_CTX; cdecl;
function TS_RESP_print_bio(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl;
function TS_STATUS_INFO_print_bio(bio: PBIO; a: PS_STATUS_INFO): TIdC_INT; cdecl;
function TS_TST_INFO_print_bio(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl;
function TS_ASN1_INTEGER_print_bio(bio: PBIO; num: PASN1_INTEGER): TIdC_INT; cdecl;
function TS_OBJ_print_bio(bio: PBIO; obj: PASN1_OBJECT): TIdC_INT; cdecl;
function TS_ext_print_bio(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl;
function TS_X509_ALGOR_print_bio(bio: PBIO; alg: PX509_ALGOR): TIdC_INT; cdecl;
function TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PS_MSG_IMPRINT): TIdC_INT; cdecl;
function TS_CONF_load_cert(_file: PIdAnsiChar): PX509; cdecl;
function TS_CONF_load_certs(_file: PIdAnsiChar): Pstack_st_X509; cdecl;
function TS_CONF_load_key(_file: PIdAnsiChar; pass: PIdAnsiChar): PEVP_PKEY; cdecl;
function TS_CONF_get_tsa_section(conf: PCONF; section: PIdAnsiChar): PIdAnsiChar; cdecl;
function TS_CONF_set_serial(conf: PCONF; section: PIdAnsiChar; cb: TS_serial_cb_func_cb; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_crypto_device(conf: PCONF; section: PIdAnsiChar; device: PIdAnsiChar): TIdC_INT; cdecl;
function TS_CONF_set_default_engine(name: PIdAnsiChar): TIdC_INT; cdecl;
function TS_CONF_set_signer_cert(conf: PCONF; section: PIdAnsiChar; cert: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_certs(conf: PCONF; section: PIdAnsiChar; certs: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_signer_key(conf: PCONF; section: PIdAnsiChar; key: PIdAnsiChar; pass: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_signer_digest(conf: PCONF; section: PIdAnsiChar; md: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_def_policy(conf: PCONF; section: PIdAnsiChar; policy: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_policies(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_digests(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_accuracy(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_clock_precision_digits(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_ordering(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_tsa_name(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
function TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function TS_VERIFY_CTS_set_certs(ctx: Pointer; cert: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function TS_REQ_new: PS_REQ; cdecl external CLibCrypto name 'TS_REQ_new';
procedure TS_REQ_free(a: PS_REQ); cdecl external CLibCrypto name 'TS_REQ_free';
function d2i_TS_REQ(a: PPS_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PS_REQ; cdecl external CLibCrypto name 'd2i_TS_REQ';
function i2d_TS_REQ(a: PS_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_REQ';
function TS_REQ_dup(a: PS_REQ): PS_REQ; cdecl external CLibCrypto name 'TS_REQ_dup';
function d2i_TS_REQ_fp(fp: PFILE; a: PPS_REQ): PS_REQ; cdecl external CLibCrypto name 'd2i_TS_REQ_fp';
function i2d_TS_REQ_fp(fp: PFILE; a: PS_REQ): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_REQ_fp';
function d2i_TS_REQ_bio(fp: PBIO; a: PPS_REQ): PS_REQ; cdecl external CLibCrypto name 'd2i_TS_REQ_bio';
function i2d_TS_REQ_bio(fp: PBIO; a: PS_REQ): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_REQ_bio';
function TS_MSG_IMPRINT_new: PS_MSG_IMPRINT; cdecl external CLibCrypto name 'TS_MSG_IMPRINT_new';
procedure TS_MSG_IMPRINT_free(a: PS_MSG_IMPRINT); cdecl external CLibCrypto name 'TS_MSG_IMPRINT_free';
function d2i_TS_MSG_IMPRINT(a: PPS_MSG_IMPRINT; _in: PPIdAnsiChar; len: TIdC_LONG): PS_MSG_IMPRINT; cdecl external CLibCrypto name 'd2i_TS_MSG_IMPRINT';
function i2d_TS_MSG_IMPRINT(a: PS_MSG_IMPRINT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_MSG_IMPRINT';
function TS_MSG_IMPRINT_dup(a: PS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl external CLibCrypto name 'TS_MSG_IMPRINT_dup';
function d2i_TS_MSG_IMPRINT_fp(fp: PFILE; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl external CLibCrypto name 'd2i_TS_MSG_IMPRINT_fp';
function i2d_TS_MSG_IMPRINT_fp(fp: PFILE; a: PS_MSG_IMPRINT): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_MSG_IMPRINT_fp';
function d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl external CLibCrypto name 'd2i_TS_MSG_IMPRINT_bio';
function i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PS_MSG_IMPRINT): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_MSG_IMPRINT_bio';
function TS_RESP_new: PS_RESP; cdecl external CLibCrypto name 'TS_RESP_new';
procedure TS_RESP_free(a: PS_RESP); cdecl external CLibCrypto name 'TS_RESP_free';
function d2i_TS_RESP(a: PPS_RESP; _in: PPIdAnsiChar; len: TIdC_LONG): PS_RESP; cdecl external CLibCrypto name 'd2i_TS_RESP';
function i2d_TS_RESP(a: PS_RESP; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_RESP';
function TS_RESP_dup(a: PS_RESP): PS_RESP; cdecl external CLibCrypto name 'TS_RESP_dup';
function d2i_TS_RESP_fp(fp: PFILE; a: PPS_RESP): PS_RESP; cdecl external CLibCrypto name 'd2i_TS_RESP_fp';
function i2d_TS_RESP_fp(fp: PFILE; a: PS_RESP): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_RESP_fp';
function d2i_TS_RESP_bio(bio: PBIO; a: PPS_RESP): PS_RESP; cdecl external CLibCrypto name 'd2i_TS_RESP_bio';
function i2d_TS_RESP_bio(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_RESP_bio';
function TS_STATUS_INFO_new: PS_STATUS_INFO; cdecl external CLibCrypto name 'TS_STATUS_INFO_new';
procedure TS_STATUS_INFO_free(a: PS_STATUS_INFO); cdecl external CLibCrypto name 'TS_STATUS_INFO_free';
function d2i_TS_STATUS_INFO(a: PPS_STATUS_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_STATUS_INFO; cdecl external CLibCrypto name 'd2i_TS_STATUS_INFO';
function i2d_TS_STATUS_INFO(a: PS_STATUS_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_STATUS_INFO';
function TS_STATUS_INFO_dup(a: PS_STATUS_INFO): PS_STATUS_INFO; cdecl external CLibCrypto name 'TS_STATUS_INFO_dup';
function TS_TST_INFO_new: PS_TST_INFO; cdecl external CLibCrypto name 'TS_TST_INFO_new';
procedure TS_TST_INFO_free(a: PS_TST_INFO); cdecl external CLibCrypto name 'TS_TST_INFO_free';
function d2i_TS_TST_INFO(a: PPS_TST_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_TST_INFO; cdecl external CLibCrypto name 'd2i_TS_TST_INFO';
function i2d_TS_TST_INFO(a: PS_TST_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_TST_INFO';
function TS_TST_INFO_dup(a: PS_TST_INFO): PS_TST_INFO; cdecl external CLibCrypto name 'TS_TST_INFO_dup';
function PKCS7_to_TS_TST_INFO(token: PPKCS7): PS_TST_INFO; cdecl external CLibCrypto name 'PKCS7_to_TS_TST_INFO';
function d2i_TS_TST_INFO_fp(fp: PFILE; a: PPS_TST_INFO): PS_TST_INFO; cdecl external CLibCrypto name 'd2i_TS_TST_INFO_fp';
function i2d_TS_TST_INFO_fp(fp: PFILE; a: PS_TST_INFO): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_TST_INFO_fp';
function d2i_TS_TST_INFO_bio(bio: PBIO; a: PPS_TST_INFO): PS_TST_INFO; cdecl external CLibCrypto name 'd2i_TS_TST_INFO_bio';
function i2d_TS_TST_INFO_bio(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_TST_INFO_bio';
function TS_ACCURACY_new: PS_ACCURACY; cdecl external CLibCrypto name 'TS_ACCURACY_new';
procedure TS_ACCURACY_free(a: PS_ACCURACY); cdecl external CLibCrypto name 'TS_ACCURACY_free';
function d2i_TS_ACCURACY(a: PPS_ACCURACY; _in: PPIdAnsiChar; len: TIdC_LONG): PS_ACCURACY; cdecl external CLibCrypto name 'd2i_TS_ACCURACY';
function i2d_TS_ACCURACY(a: PS_ACCURACY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_TS_ACCURACY';
function TS_ACCURACY_dup(a: PS_ACCURACY): PS_ACCURACY; cdecl external CLibCrypto name 'TS_ACCURACY_dup';
function TS_REQ_set_version(a: PS_REQ; version: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_set_version';
function TS_REQ_get_version(a: PS_REQ): TIdC_LONG; cdecl external CLibCrypto name 'TS_REQ_get_version';
function TS_STATUS_INFO_set_status(a: PS_STATUS_INFO; i: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_STATUS_INFO_set_status';
function TS_STATUS_INFO_get0_status(a: PS_STATUS_INFO): PASN1_INTEGER; cdecl external CLibCrypto name 'TS_STATUS_INFO_get0_status';
function TS_STATUS_INFO_get0_text(a: PS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl external CLibCrypto name 'TS_STATUS_INFO_get0_text';
function TS_STATUS_INFO_get0_failure_info(a: PS_STATUS_INFO): PASN1_BIT_STRING; cdecl external CLibCrypto name 'TS_STATUS_INFO_get0_failure_info';
function TS_REQ_set_msg_imprint(a: PS_REQ; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_set_msg_imprint';
function TS_REQ_get_msg_imprint(a: PS_REQ): PS_MSG_IMPRINT; cdecl external CLibCrypto name 'TS_REQ_get_msg_imprint';
function TS_MSG_IMPRINT_set_algo(a: PS_MSG_IMPRINT; alg: PX509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'TS_MSG_IMPRINT_set_algo';
function TS_MSG_IMPRINT_get_algo(a: PS_MSG_IMPRINT): PX509_ALGOR; cdecl external CLibCrypto name 'TS_MSG_IMPRINT_get_algo';
function TS_MSG_IMPRINT_set_msg(a: PS_MSG_IMPRINT; d: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_MSG_IMPRINT_set_msg';
function TS_MSG_IMPRINT_get_msg(a: PS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'TS_MSG_IMPRINT_get_msg';
function TS_REQ_set_policy_id(a: PS_REQ; policy: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_set_policy_id';
function TS_REQ_get_policy_id(a: PS_REQ): PASN1_OBJECT; cdecl external CLibCrypto name 'TS_REQ_get_policy_id';
function TS_REQ_set_nonce(a: PS_REQ; nonce: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_set_nonce';
function TS_REQ_get_nonce(a: PS_REQ): PASN1_INTEGER; cdecl external CLibCrypto name 'TS_REQ_get_nonce';
function TS_REQ_set_cert_req(a: PS_REQ; cert_req: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_set_cert_req';
function TS_REQ_get_cert_req(a: PS_REQ): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_get_cert_req';
function TS_REQ_get_exts(a: PS_REQ): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'TS_REQ_get_exts';
procedure TS_REQ_ext_free(a: PS_REQ); cdecl external CLibCrypto name 'TS_REQ_ext_free';
function TS_REQ_get_ext_count(a: PS_REQ): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_get_ext_count';
function TS_REQ_get_ext_by_NID(a: PS_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_get_ext_by_NID';
function TS_REQ_get_ext_by_OBJ(a: PS_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_get_ext_by_OBJ';
function TS_REQ_get_ext_by_critical(a: PS_REQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_get_ext_by_critical';
function TS_REQ_get_ext(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'TS_REQ_get_ext';
function TS_REQ_delete_ext(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'TS_REQ_delete_ext';
function TS_REQ_add_ext(a: PS_REQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_add_ext';
function TS_REQ_get_ext_d2i(a: PS_REQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'TS_REQ_get_ext_d2i';
function TS_REQ_print_bio(bio: PBIO; a: PS_REQ): TIdC_INT; cdecl external CLibCrypto name 'TS_REQ_print_bio';
function TS_RESP_set_status_info(a: PS_RESP; info: PS_STATUS_INFO): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_set_status_info';
function TS_RESP_get_status_info(a: PS_RESP): PS_STATUS_INFO; cdecl external CLibCrypto name 'TS_RESP_get_status_info';
procedure TS_RESP_set_tst_info(a: PS_RESP; p7: PPKCS7; tst_info: PS_TST_INFO); cdecl external CLibCrypto name 'TS_RESP_set_tst_info';
function TS_RESP_get_token(a: PS_RESP): PPKCS7; cdecl external CLibCrypto name 'TS_RESP_get_token';
function TS_RESP_get_tst_info(a: PS_RESP): PS_TST_INFO; cdecl external CLibCrypto name 'TS_RESP_get_tst_info';
function TS_TST_INFO_set_version(a: PS_TST_INFO; version: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_version';
function TS_TST_INFO_get_version(a: PS_TST_INFO): TIdC_LONG; cdecl external CLibCrypto name 'TS_TST_INFO_get_version';
function TS_TST_INFO_set_policy_id(a: PS_TST_INFO; policy_id: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_policy_id';
function TS_TST_INFO_get_policy_id(a: PS_TST_INFO): PASN1_OBJECT; cdecl external CLibCrypto name 'TS_TST_INFO_get_policy_id';
function TS_TST_INFO_set_msg_imprint(a: PS_TST_INFO; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_msg_imprint';
function TS_TST_INFO_get_msg_imprint(a: PS_TST_INFO): PS_MSG_IMPRINT; cdecl external CLibCrypto name 'TS_TST_INFO_get_msg_imprint';
function TS_TST_INFO_set_serial(a: PS_TST_INFO; serial: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_serial';
function TS_TST_INFO_get_serial(a: PS_TST_INFO): PASN1_INTEGER; cdecl external CLibCrypto name 'TS_TST_INFO_get_serial';
function TS_TST_INFO_set_time(a: PS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_time';
function TS_TST_INFO_get_time(a: PS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'TS_TST_INFO_get_time';
function TS_TST_INFO_set_accuracy(a: PS_TST_INFO; accuracy: PS_ACCURACY): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_accuracy';
function TS_TST_INFO_get_accuracy(a: PS_TST_INFO): PS_ACCURACY; cdecl external CLibCrypto name 'TS_TST_INFO_get_accuracy';
function TS_ACCURACY_set_seconds(a: PS_ACCURACY; seconds: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'TS_ACCURACY_set_seconds';
function TS_ACCURACY_get_seconds(a: PS_ACCURACY): PASN1_INTEGER; cdecl external CLibCrypto name 'TS_ACCURACY_get_seconds';
function TS_ACCURACY_set_millis(a: PS_ACCURACY; millis: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'TS_ACCURACY_set_millis';
function TS_ACCURACY_get_millis(a: PS_ACCURACY): PASN1_INTEGER; cdecl external CLibCrypto name 'TS_ACCURACY_get_millis';
function TS_ACCURACY_set_micros(a: PS_ACCURACY; micros: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'TS_ACCURACY_set_micros';
function TS_ACCURACY_get_micros(a: PS_ACCURACY): PASN1_INTEGER; cdecl external CLibCrypto name 'TS_ACCURACY_get_micros';
function TS_TST_INFO_set_ordering(a: PS_TST_INFO; ordering: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_ordering';
function TS_TST_INFO_get_ordering(a: PS_TST_INFO): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_get_ordering';
function TS_TST_INFO_set_nonce(a: PS_TST_INFO; nonce: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_nonce';
function TS_TST_INFO_get_nonce(a: PS_TST_INFO): PASN1_INTEGER; cdecl external CLibCrypto name 'TS_TST_INFO_get_nonce';
function TS_TST_INFO_set_tsa(a: PS_TST_INFO; tsa: PGENERAL_NAME): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_set_tsa';
function TS_TST_INFO_get_tsa(a: PS_TST_INFO): PGENERAL_NAME; cdecl external CLibCrypto name 'TS_TST_INFO_get_tsa';
function TS_TST_INFO_get_exts(a: PS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'TS_TST_INFO_get_exts';
procedure TS_TST_INFO_ext_free(a: PS_TST_INFO); cdecl external CLibCrypto name 'TS_TST_INFO_ext_free';
function TS_TST_INFO_get_ext_count(a: PS_TST_INFO): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_get_ext_count';
function TS_TST_INFO_get_ext_by_NID(a: PS_TST_INFO; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_get_ext_by_NID';
function TS_TST_INFO_get_ext_by_OBJ(a: PS_TST_INFO; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_get_ext_by_OBJ';
function TS_TST_INFO_get_ext_by_critical(a: PS_TST_INFO; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_get_ext_by_critical';
function TS_TST_INFO_get_ext(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'TS_TST_INFO_get_ext';
function TS_TST_INFO_delete_ext(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'TS_TST_INFO_delete_ext';
function TS_TST_INFO_add_ext(a: PS_TST_INFO; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_add_ext';
function TS_TST_INFO_get_ext_d2i(a: PS_TST_INFO; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'TS_TST_INFO_get_ext_d2i';
function TS_RESP_CTX_new: PS_RESP_CTX; cdecl external CLibCrypto name 'TS_RESP_CTX_new';
function TS_RESP_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PS_RESP_CTX; cdecl external CLibCrypto name 'TS_RESP_CTX_new_ex';
procedure TS_RESP_CTX_free(ctx: PS_RESP_CTX); cdecl external CLibCrypto name 'TS_RESP_CTX_free';
function TS_RESP_CTX_set_signer_cert(ctx: PS_RESP_CTX; signer: PX509): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_signer_cert';
function TS_RESP_CTX_set_signer_key(ctx: PS_RESP_CTX; key: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_signer_key';
function TS_RESP_CTX_set_signer_digest(ctx: PS_RESP_CTX; signer_digest: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_signer_digest';
function TS_RESP_CTX_set_ess_cert_id_digest(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_ess_cert_id_digest';
function TS_RESP_CTX_set_def_policy(ctx: PS_RESP_CTX; def_policy: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_def_policy';
function TS_RESP_CTX_set_certs(ctx: PS_RESP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_certs';
function TS_RESP_CTX_add_policy(ctx: PS_RESP_CTX; policy: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_add_policy';
function TS_RESP_CTX_add_md(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_add_md';
function TS_RESP_CTX_set_accuracy(ctx: PS_RESP_CTX; secs: TIdC_INT; millis: TIdC_INT; micros: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_accuracy';
function TS_RESP_CTX_set_clock_precision_digits(ctx: PS_RESP_CTX; clock_precision_digits: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_clock_precision_digits';
procedure TS_RESP_CTX_add_flags(ctx: PS_RESP_CTX; flags: TIdC_INT); cdecl external CLibCrypto name 'TS_RESP_CTX_add_flags';
procedure TS_RESP_CTX_set_serial_cb(ctx: PS_RESP_CTX; cb: TS_serial_cb_func_cb; data: Pointer); cdecl external CLibCrypto name 'TS_RESP_CTX_set_serial_cb';
procedure TS_RESP_CTX_set_time_cb(ctx: PS_RESP_CTX; cb: TS_time_cb_func_cb; data: Pointer); cdecl external CLibCrypto name 'TS_RESP_CTX_set_time_cb';
procedure TS_RESP_CTX_set_extension_cb(ctx: PS_RESP_CTX; cb: TS_extension_cb_func_cb; data: Pointer); cdecl external CLibCrypto name 'TS_RESP_CTX_set_extension_cb';
function TS_RESP_CTX_set_status_info(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_status_info';
function TS_RESP_CTX_set_status_info_cond(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_set_status_info_cond';
function TS_RESP_CTX_add_failure_info(ctx: PS_RESP_CTX; failure: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_CTX_add_failure_info';
function TS_RESP_CTX_get_request(ctx: PS_RESP_CTX): PS_REQ; cdecl external CLibCrypto name 'TS_RESP_CTX_get_request';
function TS_RESP_CTX_get_tst_info(ctx: PS_RESP_CTX): PS_TST_INFO; cdecl external CLibCrypto name 'TS_RESP_CTX_get_tst_info';
function TS_RESP_create_response(ctx: PS_RESP_CTX; req_bio: PBIO): PS_RESP; cdecl external CLibCrypto name 'TS_RESP_create_response';
function TS_RESP_verify_signature(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_verify_signature';
function TS_RESP_verify_response(ctx: PS_VERIFY_CTX; response: PS_RESP): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_verify_response';
function TS_RESP_verify_token(ctx: PS_VERIFY_CTX; token: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_verify_token';
function TS_VERIFY_CTX_new: PS_VERIFY_CTX; cdecl external CLibCrypto name 'TS_VERIFY_CTX_new';
procedure TS_VERIFY_CTX_init(ctx: PS_VERIFY_CTX); cdecl external CLibCrypto name 'TS_VERIFY_CTX_init';
procedure TS_VERIFY_CTX_free(ctx: PS_VERIFY_CTX); cdecl external CLibCrypto name 'TS_VERIFY_CTX_free';
procedure TS_VERIFY_CTX_cleanup(ctx: PS_VERIFY_CTX); cdecl external CLibCrypto name 'TS_VERIFY_CTX_cleanup';
function TS_VERIFY_CTX_set_flags(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set_flags';
function TS_VERIFY_CTX_add_flags(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'TS_VERIFY_CTX_add_flags';
function TS_VERIFY_CTX_set_data(ctx: PS_VERIFY_CTX; b: PBIO): PBIO; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set_data';
function TS_VERIFY_CTX_set0_data(ctx: PS_VERIFY_CTX; b: PBIO): TIdC_INT; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set0_data';
function TS_VERIFY_CTX_set_imprint(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): PIdAnsiChar; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set_imprint';
function TS_VERIFY_CTX_set0_imprint(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set0_imprint';
function TS_VERIFY_CTX_set_store(ctx: PS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set_store';
function TS_VERIFY_CTX_set0_store(ctx: PS_VERIFY_CTX; s: PX509_STORE): TIdC_INT; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set0_store';
function TS_VERIFY_CTX_set_certs(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set_certs';
function TS_VERIFY_CTX_set0_certs(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'TS_VERIFY_CTX_set0_certs';
function TS_REQ_to_TS_VERIFY_CTX(req: PS_REQ; ctx: PS_VERIFY_CTX): PS_VERIFY_CTX; cdecl external CLibCrypto name 'TS_REQ_to_TS_VERIFY_CTX';
function TS_RESP_print_bio(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl external CLibCrypto name 'TS_RESP_print_bio';
function TS_STATUS_INFO_print_bio(bio: PBIO; a: PS_STATUS_INFO): TIdC_INT; cdecl external CLibCrypto name 'TS_STATUS_INFO_print_bio';
function TS_TST_INFO_print_bio(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl external CLibCrypto name 'TS_TST_INFO_print_bio';
function TS_ASN1_INTEGER_print_bio(bio: PBIO; num: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'TS_ASN1_INTEGER_print_bio';
function TS_OBJ_print_bio(bio: PBIO; obj: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'TS_OBJ_print_bio';
function TS_ext_print_bio(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl external CLibCrypto name 'TS_ext_print_bio';
function TS_X509_ALGOR_print_bio(bio: PBIO; alg: PX509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'TS_X509_ALGOR_print_bio';
function TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PS_MSG_IMPRINT): TIdC_INT; cdecl external CLibCrypto name 'TS_MSG_IMPRINT_print_bio';
function TS_CONF_load_cert(_file: PIdAnsiChar): PX509; cdecl external CLibCrypto name 'TS_CONF_load_cert';
function TS_CONF_load_certs(_file: PIdAnsiChar): Pstack_st_X509; cdecl external CLibCrypto name 'TS_CONF_load_certs';
function TS_CONF_load_key(_file: PIdAnsiChar; pass: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'TS_CONF_load_key';
function TS_CONF_get_tsa_section(conf: PCONF; section: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'TS_CONF_get_tsa_section';
function TS_CONF_set_serial(conf: PCONF; section: PIdAnsiChar; cb: TS_serial_cb_func_cb; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_serial';
function TS_CONF_set_crypto_device(conf: PCONF; section: PIdAnsiChar; device: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_crypto_device';
function TS_CONF_set_default_engine(name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_default_engine';
function TS_CONF_set_signer_cert(conf: PCONF; section: PIdAnsiChar; cert: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_signer_cert';
function TS_CONF_set_certs(conf: PCONF; section: PIdAnsiChar; certs: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_certs';
function TS_CONF_set_signer_key(conf: PCONF; section: PIdAnsiChar; key: PIdAnsiChar; pass: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_signer_key';
function TS_CONF_set_signer_digest(conf: PCONF; section: PIdAnsiChar; md: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_signer_digest';
function TS_CONF_set_def_policy(conf: PCONF; section: PIdAnsiChar; policy: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_def_policy';
function TS_CONF_set_policies(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_policies';
function TS_CONF_set_digests(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_digests';
function TS_CONF_set_accuracy(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_accuracy';
function TS_CONF_set_clock_precision_digits(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_clock_precision_digits';
function TS_CONF_set_ordering(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_ordering';
function TS_CONF_set_tsa_name(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_tsa_name';
function TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_ess_cert_id_chain';
function TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl external CLibCrypto name 'TS_CONF_set_ess_cert_id_digest';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  TS_REQ_new_procname = 'TS_REQ_new';
  TS_REQ_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_free_procname = 'TS_REQ_free';
  TS_REQ_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_REQ_procname = 'd2i_TS_REQ';
  d2i_TS_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_REQ_procname = 'i2d_TS_REQ';
  i2d_TS_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_dup_procname = 'TS_REQ_dup';
  TS_REQ_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_REQ_fp_procname = 'd2i_TS_REQ_fp';
  d2i_TS_REQ_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_REQ_fp_procname = 'i2d_TS_REQ_fp';
  i2d_TS_REQ_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_REQ_bio_procname = 'd2i_TS_REQ_bio';
  d2i_TS_REQ_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_REQ_bio_procname = 'i2d_TS_REQ_bio';
  i2d_TS_REQ_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_new_procname = 'TS_MSG_IMPRINT_new';
  TS_MSG_IMPRINT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_free_procname = 'TS_MSG_IMPRINT_free';
  TS_MSG_IMPRINT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_MSG_IMPRINT_procname = 'd2i_TS_MSG_IMPRINT';
  d2i_TS_MSG_IMPRINT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_MSG_IMPRINT_procname = 'i2d_TS_MSG_IMPRINT';
  i2d_TS_MSG_IMPRINT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_dup_procname = 'TS_MSG_IMPRINT_dup';
  TS_MSG_IMPRINT_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_MSG_IMPRINT_fp_procname = 'd2i_TS_MSG_IMPRINT_fp';
  d2i_TS_MSG_IMPRINT_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_MSG_IMPRINT_fp_procname = 'i2d_TS_MSG_IMPRINT_fp';
  i2d_TS_MSG_IMPRINT_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_MSG_IMPRINT_bio_procname = 'd2i_TS_MSG_IMPRINT_bio';
  d2i_TS_MSG_IMPRINT_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_MSG_IMPRINT_bio_procname = 'i2d_TS_MSG_IMPRINT_bio';
  i2d_TS_MSG_IMPRINT_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_new_procname = 'TS_RESP_new';
  TS_RESP_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_free_procname = 'TS_RESP_free';
  TS_RESP_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_RESP_procname = 'd2i_TS_RESP';
  d2i_TS_RESP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_RESP_procname = 'i2d_TS_RESP';
  i2d_TS_RESP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_dup_procname = 'TS_RESP_dup';
  TS_RESP_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_RESP_fp_procname = 'd2i_TS_RESP_fp';
  d2i_TS_RESP_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_RESP_fp_procname = 'i2d_TS_RESP_fp';
  i2d_TS_RESP_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_RESP_bio_procname = 'd2i_TS_RESP_bio';
  d2i_TS_RESP_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_RESP_bio_procname = 'i2d_TS_RESP_bio';
  i2d_TS_RESP_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_new_procname = 'TS_STATUS_INFO_new';
  TS_STATUS_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_free_procname = 'TS_STATUS_INFO_free';
  TS_STATUS_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_STATUS_INFO_procname = 'd2i_TS_STATUS_INFO';
  d2i_TS_STATUS_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_STATUS_INFO_procname = 'i2d_TS_STATUS_INFO';
  i2d_TS_STATUS_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_dup_procname = 'TS_STATUS_INFO_dup';
  TS_STATUS_INFO_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_new_procname = 'TS_TST_INFO_new';
  TS_TST_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_free_procname = 'TS_TST_INFO_free';
  TS_TST_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_TST_INFO_procname = 'd2i_TS_TST_INFO';
  d2i_TS_TST_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_TST_INFO_procname = 'i2d_TS_TST_INFO';
  i2d_TS_TST_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_dup_procname = 'TS_TST_INFO_dup';
  TS_TST_INFO_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_to_TS_TST_INFO_procname = 'PKCS7_to_TS_TST_INFO';
  PKCS7_to_TS_TST_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_TST_INFO_fp_procname = 'd2i_TS_TST_INFO_fp';
  d2i_TS_TST_INFO_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_TST_INFO_fp_procname = 'i2d_TS_TST_INFO_fp';
  i2d_TS_TST_INFO_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_TST_INFO_bio_procname = 'd2i_TS_TST_INFO_bio';
  d2i_TS_TST_INFO_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_TST_INFO_bio_procname = 'i2d_TS_TST_INFO_bio';
  i2d_TS_TST_INFO_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_new_procname = 'TS_ACCURACY_new';
  TS_ACCURACY_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_free_procname = 'TS_ACCURACY_free';
  TS_ACCURACY_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_TS_ACCURACY_procname = 'd2i_TS_ACCURACY';
  d2i_TS_ACCURACY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_TS_ACCURACY_procname = 'i2d_TS_ACCURACY';
  i2d_TS_ACCURACY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_dup_procname = 'TS_ACCURACY_dup';
  TS_ACCURACY_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_set_version_procname = 'TS_REQ_set_version';
  TS_REQ_set_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_version_procname = 'TS_REQ_get_version';
  TS_REQ_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_set_status_procname = 'TS_STATUS_INFO_set_status';
  TS_STATUS_INFO_set_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_get0_status_procname = 'TS_STATUS_INFO_get0_status';
  TS_STATUS_INFO_get0_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_get0_text_procname = 'TS_STATUS_INFO_get0_text';
  TS_STATUS_INFO_get0_text_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_get0_failure_info_procname = 'TS_STATUS_INFO_get0_failure_info';
  TS_STATUS_INFO_get0_failure_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_set_msg_imprint_procname = 'TS_REQ_set_msg_imprint';
  TS_REQ_set_msg_imprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_msg_imprint_procname = 'TS_REQ_get_msg_imprint';
  TS_REQ_get_msg_imprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_set_algo_procname = 'TS_MSG_IMPRINT_set_algo';
  TS_MSG_IMPRINT_set_algo_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_get_algo_procname = 'TS_MSG_IMPRINT_get_algo';
  TS_MSG_IMPRINT_get_algo_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_set_msg_procname = 'TS_MSG_IMPRINT_set_msg';
  TS_MSG_IMPRINT_set_msg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_get_msg_procname = 'TS_MSG_IMPRINT_get_msg';
  TS_MSG_IMPRINT_get_msg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_set_policy_id_procname = 'TS_REQ_set_policy_id';
  TS_REQ_set_policy_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_policy_id_procname = 'TS_REQ_get_policy_id';
  TS_REQ_get_policy_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_set_nonce_procname = 'TS_REQ_set_nonce';
  TS_REQ_set_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_nonce_procname = 'TS_REQ_get_nonce';
  TS_REQ_get_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_set_cert_req_procname = 'TS_REQ_set_cert_req';
  TS_REQ_set_cert_req_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_cert_req_procname = 'TS_REQ_get_cert_req';
  TS_REQ_get_cert_req_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_exts_procname = 'TS_REQ_get_exts';
  TS_REQ_get_exts_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_ext_free_procname = 'TS_REQ_ext_free';
  TS_REQ_ext_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_ext_count_procname = 'TS_REQ_get_ext_count';
  TS_REQ_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_ext_by_NID_procname = 'TS_REQ_get_ext_by_NID';
  TS_REQ_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_ext_by_OBJ_procname = 'TS_REQ_get_ext_by_OBJ';
  TS_REQ_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_ext_by_critical_procname = 'TS_REQ_get_ext_by_critical';
  TS_REQ_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_ext_procname = 'TS_REQ_get_ext';
  TS_REQ_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_delete_ext_procname = 'TS_REQ_delete_ext';
  TS_REQ_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_add_ext_procname = 'TS_REQ_add_ext';
  TS_REQ_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_get_ext_d2i_procname = 'TS_REQ_get_ext_d2i';
  TS_REQ_get_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_REQ_print_bio_procname = 'TS_REQ_print_bio';
  TS_REQ_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_set_status_info_procname = 'TS_RESP_set_status_info';
  TS_RESP_set_status_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_get_status_info_procname = 'TS_RESP_get_status_info';
  TS_RESP_get_status_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_set_tst_info_procname = 'TS_RESP_set_tst_info';
  TS_RESP_set_tst_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_get_token_procname = 'TS_RESP_get_token';
  TS_RESP_get_token_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_get_tst_info_procname = 'TS_RESP_get_tst_info';
  TS_RESP_get_tst_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_version_procname = 'TS_TST_INFO_set_version';
  TS_TST_INFO_set_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_version_procname = 'TS_TST_INFO_get_version';
  TS_TST_INFO_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_policy_id_procname = 'TS_TST_INFO_set_policy_id';
  TS_TST_INFO_set_policy_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_policy_id_procname = 'TS_TST_INFO_get_policy_id';
  TS_TST_INFO_get_policy_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_msg_imprint_procname = 'TS_TST_INFO_set_msg_imprint';
  TS_TST_INFO_set_msg_imprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_msg_imprint_procname = 'TS_TST_INFO_get_msg_imprint';
  TS_TST_INFO_get_msg_imprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_serial_procname = 'TS_TST_INFO_set_serial';
  TS_TST_INFO_set_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_serial_procname = 'TS_TST_INFO_get_serial';
  TS_TST_INFO_get_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_time_procname = 'TS_TST_INFO_set_time';
  TS_TST_INFO_set_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_time_procname = 'TS_TST_INFO_get_time';
  TS_TST_INFO_get_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_accuracy_procname = 'TS_TST_INFO_set_accuracy';
  TS_TST_INFO_set_accuracy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_accuracy_procname = 'TS_TST_INFO_get_accuracy';
  TS_TST_INFO_get_accuracy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_set_seconds_procname = 'TS_ACCURACY_set_seconds';
  TS_ACCURACY_set_seconds_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_get_seconds_procname = 'TS_ACCURACY_get_seconds';
  TS_ACCURACY_get_seconds_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_set_millis_procname = 'TS_ACCURACY_set_millis';
  TS_ACCURACY_set_millis_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_get_millis_procname = 'TS_ACCURACY_get_millis';
  TS_ACCURACY_get_millis_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_set_micros_procname = 'TS_ACCURACY_set_micros';
  TS_ACCURACY_set_micros_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ACCURACY_get_micros_procname = 'TS_ACCURACY_get_micros';
  TS_ACCURACY_get_micros_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_ordering_procname = 'TS_TST_INFO_set_ordering';
  TS_TST_INFO_set_ordering_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_ordering_procname = 'TS_TST_INFO_get_ordering';
  TS_TST_INFO_get_ordering_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_nonce_procname = 'TS_TST_INFO_set_nonce';
  TS_TST_INFO_set_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_nonce_procname = 'TS_TST_INFO_get_nonce';
  TS_TST_INFO_get_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_set_tsa_procname = 'TS_TST_INFO_set_tsa';
  TS_TST_INFO_set_tsa_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_tsa_procname = 'TS_TST_INFO_get_tsa';
  TS_TST_INFO_get_tsa_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_exts_procname = 'TS_TST_INFO_get_exts';
  TS_TST_INFO_get_exts_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_ext_free_procname = 'TS_TST_INFO_ext_free';
  TS_TST_INFO_ext_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_ext_count_procname = 'TS_TST_INFO_get_ext_count';
  TS_TST_INFO_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_ext_by_NID_procname = 'TS_TST_INFO_get_ext_by_NID';
  TS_TST_INFO_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_ext_by_OBJ_procname = 'TS_TST_INFO_get_ext_by_OBJ';
  TS_TST_INFO_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_ext_by_critical_procname = 'TS_TST_INFO_get_ext_by_critical';
  TS_TST_INFO_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_ext_procname = 'TS_TST_INFO_get_ext';
  TS_TST_INFO_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_delete_ext_procname = 'TS_TST_INFO_delete_ext';
  TS_TST_INFO_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_add_ext_procname = 'TS_TST_INFO_add_ext';
  TS_TST_INFO_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_get_ext_d2i_procname = 'TS_TST_INFO_get_ext_d2i';
  TS_TST_INFO_get_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_new_procname = 'TS_RESP_CTX_new';
  TS_RESP_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_new_ex_procname = 'TS_RESP_CTX_new_ex';
  TS_RESP_CTX_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  TS_RESP_CTX_free_procname = 'TS_RESP_CTX_free';
  TS_RESP_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_signer_cert_procname = 'TS_RESP_CTX_set_signer_cert';
  TS_RESP_CTX_set_signer_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_signer_key_procname = 'TS_RESP_CTX_set_signer_key';
  TS_RESP_CTX_set_signer_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_signer_digest_procname = 'TS_RESP_CTX_set_signer_digest';
  TS_RESP_CTX_set_signer_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_ess_cert_id_digest_procname = 'TS_RESP_CTX_set_ess_cert_id_digest';
  TS_RESP_CTX_set_ess_cert_id_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  TS_RESP_CTX_set_def_policy_procname = 'TS_RESP_CTX_set_def_policy';
  TS_RESP_CTX_set_def_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_certs_procname = 'TS_RESP_CTX_set_certs';
  TS_RESP_CTX_set_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_add_policy_procname = 'TS_RESP_CTX_add_policy';
  TS_RESP_CTX_add_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_add_md_procname = 'TS_RESP_CTX_add_md';
  TS_RESP_CTX_add_md_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_accuracy_procname = 'TS_RESP_CTX_set_accuracy';
  TS_RESP_CTX_set_accuracy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_clock_precision_digits_procname = 'TS_RESP_CTX_set_clock_precision_digits';
  TS_RESP_CTX_set_clock_precision_digits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_add_flags_procname = 'TS_RESP_CTX_add_flags';
  TS_RESP_CTX_add_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_serial_cb_procname = 'TS_RESP_CTX_set_serial_cb';
  TS_RESP_CTX_set_serial_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_time_cb_procname = 'TS_RESP_CTX_set_time_cb';
  TS_RESP_CTX_set_time_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_extension_cb_procname = 'TS_RESP_CTX_set_extension_cb';
  TS_RESP_CTX_set_extension_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_status_info_procname = 'TS_RESP_CTX_set_status_info';
  TS_RESP_CTX_set_status_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_set_status_info_cond_procname = 'TS_RESP_CTX_set_status_info_cond';
  TS_RESP_CTX_set_status_info_cond_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_add_failure_info_procname = 'TS_RESP_CTX_add_failure_info';
  TS_RESP_CTX_add_failure_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_get_request_procname = 'TS_RESP_CTX_get_request';
  TS_RESP_CTX_get_request_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_CTX_get_tst_info_procname = 'TS_RESP_CTX_get_tst_info';
  TS_RESP_CTX_get_tst_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_create_response_procname = 'TS_RESP_create_response';
  TS_RESP_create_response_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_verify_signature_procname = 'TS_RESP_verify_signature';
  TS_RESP_verify_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_verify_response_procname = 'TS_RESP_verify_response';
  TS_RESP_verify_response_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_verify_token_procname = 'TS_RESP_verify_token';
  TS_RESP_verify_token_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_VERIFY_CTX_new_procname = 'TS_VERIFY_CTX_new';
  TS_VERIFY_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_VERIFY_CTX_init_procname = 'TS_VERIFY_CTX_init';
  TS_VERIFY_CTX_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_VERIFY_CTX_free_procname = 'TS_VERIFY_CTX_free';
  TS_VERIFY_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_VERIFY_CTX_cleanup_procname = 'TS_VERIFY_CTX_cleanup';
  TS_VERIFY_CTX_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_VERIFY_CTX_set_flags_procname = 'TS_VERIFY_CTX_set_flags';
  TS_VERIFY_CTX_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_VERIFY_CTX_add_flags_procname = 'TS_VERIFY_CTX_add_flags';
  TS_VERIFY_CTX_add_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_VERIFY_CTX_set_data_procname = 'TS_VERIFY_CTX_set_data';
  TS_VERIFY_CTX_set_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  TS_VERIFY_CTX_set_data_removed = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_VERIFY_CTX_set0_data_procname = 'TS_VERIFY_CTX_set0_data';
  TS_VERIFY_CTX_set0_data_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_VERIFY_CTX_set_imprint_procname = 'TS_VERIFY_CTX_set_imprint';
  TS_VERIFY_CTX_set_imprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  TS_VERIFY_CTX_set_imprint_removed = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_VERIFY_CTX_set0_imprint_procname = 'TS_VERIFY_CTX_set0_imprint';
  TS_VERIFY_CTX_set0_imprint_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_VERIFY_CTX_set_store_procname = 'TS_VERIFY_CTX_set_store';
  TS_VERIFY_CTX_set_store_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  TS_VERIFY_CTX_set_store_removed = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_VERIFY_CTX_set0_store_procname = 'TS_VERIFY_CTX_set0_store';
  TS_VERIFY_CTX_set0_store_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_VERIFY_CTX_set_certs_procname = 'TS_VERIFY_CTX_set_certs';
  TS_VERIFY_CTX_set_certs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  TS_VERIFY_CTX_set_certs_removed = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_VERIFY_CTX_set0_certs_procname = 'TS_VERIFY_CTX_set0_certs';
  TS_VERIFY_CTX_set0_certs_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  TS_REQ_to_TS_VERIFY_CTX_procname = 'TS_REQ_to_TS_VERIFY_CTX';
  TS_REQ_to_TS_VERIFY_CTX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_RESP_print_bio_procname = 'TS_RESP_print_bio';
  TS_RESP_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_STATUS_INFO_print_bio_procname = 'TS_STATUS_INFO_print_bio';
  TS_STATUS_INFO_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_TST_INFO_print_bio_procname = 'TS_TST_INFO_print_bio';
  TS_TST_INFO_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ASN1_INTEGER_print_bio_procname = 'TS_ASN1_INTEGER_print_bio';
  TS_ASN1_INTEGER_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_OBJ_print_bio_procname = 'TS_OBJ_print_bio';
  TS_OBJ_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_ext_print_bio_procname = 'TS_ext_print_bio';
  TS_ext_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_X509_ALGOR_print_bio_procname = 'TS_X509_ALGOR_print_bio';
  TS_X509_ALGOR_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_MSG_IMPRINT_print_bio_procname = 'TS_MSG_IMPRINT_print_bio';
  TS_MSG_IMPRINT_print_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_load_cert_procname = 'TS_CONF_load_cert';
  TS_CONF_load_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_load_certs_procname = 'TS_CONF_load_certs';
  TS_CONF_load_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_load_key_procname = 'TS_CONF_load_key';
  TS_CONF_load_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_get_tsa_section_procname = 'TS_CONF_get_tsa_section';
  TS_CONF_get_tsa_section_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_serial_procname = 'TS_CONF_set_serial';
  TS_CONF_set_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_crypto_device_procname = 'TS_CONF_set_crypto_device';
  TS_CONF_set_crypto_device_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_default_engine_procname = 'TS_CONF_set_default_engine';
  TS_CONF_set_default_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_signer_cert_procname = 'TS_CONF_set_signer_cert';
  TS_CONF_set_signer_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_certs_procname = 'TS_CONF_set_certs';
  TS_CONF_set_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_signer_key_procname = 'TS_CONF_set_signer_key';
  TS_CONF_set_signer_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_signer_digest_procname = 'TS_CONF_set_signer_digest';
  TS_CONF_set_signer_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_def_policy_procname = 'TS_CONF_set_def_policy';
  TS_CONF_set_def_policy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_policies_procname = 'TS_CONF_set_policies';
  TS_CONF_set_policies_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_digests_procname = 'TS_CONF_set_digests';
  TS_CONF_set_digests_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_accuracy_procname = 'TS_CONF_set_accuracy';
  TS_CONF_set_accuracy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_clock_precision_digits_procname = 'TS_CONF_set_clock_precision_digits';
  TS_CONF_set_clock_precision_digits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_ordering_procname = 'TS_CONF_set_ordering';
  TS_CONF_set_ordering_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_tsa_name_procname = 'TS_CONF_set_tsa_name';
  TS_CONF_set_tsa_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_ess_cert_id_chain_procname = 'TS_CONF_set_ess_cert_id_chain';
  TS_CONF_set_ess_cert_id_chain_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TS_CONF_set_ess_cert_id_digest_procname = 'TS_CONF_set_ess_cert_id_digest';
  TS_CONF_set_ess_cert_id_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function TS_VERIFY_CTS_set_certs(ctx: Pointer; cert: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    TS_VERIFY_CTS_set_certs(ctx, cert) TS_VERIFY_CTX_set_certs(ctx, cert)
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_TS_REQ_new: PS_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_new_procname);
end;

procedure ERR_TS_REQ_free(a: PS_REQ); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_free_procname);
end;

function ERR_d2i_TS_REQ(a: PPS_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PS_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_REQ_procname);
end;

function ERR_i2d_TS_REQ(a: PS_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_REQ_procname);
end;

function ERR_TS_REQ_dup(a: PS_REQ): PS_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_dup_procname);
end;

function ERR_d2i_TS_REQ_fp(fp: PFILE; a: PPS_REQ): PS_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_REQ_fp_procname);
end;

function ERR_i2d_TS_REQ_fp(fp: PFILE; a: PS_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_REQ_fp_procname);
end;

function ERR_d2i_TS_REQ_bio(fp: PBIO; a: PPS_REQ): PS_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_REQ_bio_procname);
end;

function ERR_i2d_TS_REQ_bio(fp: PBIO; a: PS_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_REQ_bio_procname);
end;

function ERR_TS_MSG_IMPRINT_new: PS_MSG_IMPRINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_new_procname);
end;

procedure ERR_TS_MSG_IMPRINT_free(a: PS_MSG_IMPRINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_free_procname);
end;

function ERR_d2i_TS_MSG_IMPRINT(a: PPS_MSG_IMPRINT; _in: PPIdAnsiChar; len: TIdC_LONG): PS_MSG_IMPRINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_MSG_IMPRINT_procname);
end;

function ERR_i2d_TS_MSG_IMPRINT(a: PS_MSG_IMPRINT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_MSG_IMPRINT_procname);
end;

function ERR_TS_MSG_IMPRINT_dup(a: PS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_dup_procname);
end;

function ERR_d2i_TS_MSG_IMPRINT_fp(fp: PFILE; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_MSG_IMPRINT_fp_procname);
end;

function ERR_i2d_TS_MSG_IMPRINT_fp(fp: PFILE; a: PS_MSG_IMPRINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_MSG_IMPRINT_fp_procname);
end;

function ERR_d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPS_MSG_IMPRINT): PS_MSG_IMPRINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_MSG_IMPRINT_bio_procname);
end;

function ERR_i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PS_MSG_IMPRINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_MSG_IMPRINT_bio_procname);
end;

function ERR_TS_RESP_new: PS_RESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_new_procname);
end;

procedure ERR_TS_RESP_free(a: PS_RESP); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_free_procname);
end;

function ERR_d2i_TS_RESP(a: PPS_RESP; _in: PPIdAnsiChar; len: TIdC_LONG): PS_RESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_RESP_procname);
end;

function ERR_i2d_TS_RESP(a: PS_RESP; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_RESP_procname);
end;

function ERR_TS_RESP_dup(a: PS_RESP): PS_RESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_dup_procname);
end;

function ERR_d2i_TS_RESP_fp(fp: PFILE; a: PPS_RESP): PS_RESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_RESP_fp_procname);
end;

function ERR_i2d_TS_RESP_fp(fp: PFILE; a: PS_RESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_RESP_fp_procname);
end;

function ERR_d2i_TS_RESP_bio(bio: PBIO; a: PPS_RESP): PS_RESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_RESP_bio_procname);
end;

function ERR_i2d_TS_RESP_bio(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_RESP_bio_procname);
end;

function ERR_TS_STATUS_INFO_new: PS_STATUS_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_new_procname);
end;

procedure ERR_TS_STATUS_INFO_free(a: PS_STATUS_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_free_procname);
end;

function ERR_d2i_TS_STATUS_INFO(a: PPS_STATUS_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_STATUS_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_STATUS_INFO_procname);
end;

function ERR_i2d_TS_STATUS_INFO(a: PS_STATUS_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_STATUS_INFO_procname);
end;

function ERR_TS_STATUS_INFO_dup(a: PS_STATUS_INFO): PS_STATUS_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_dup_procname);
end;

function ERR_TS_TST_INFO_new: PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_new_procname);
end;

procedure ERR_TS_TST_INFO_free(a: PS_TST_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_free_procname);
end;

function ERR_d2i_TS_TST_INFO(a: PPS_TST_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_TST_INFO_procname);
end;

function ERR_i2d_TS_TST_INFO(a: PS_TST_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_TST_INFO_procname);
end;

function ERR_TS_TST_INFO_dup(a: PS_TST_INFO): PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_dup_procname);
end;

function ERR_PKCS7_to_TS_TST_INFO(token: PPKCS7): PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_to_TS_TST_INFO_procname);
end;

function ERR_d2i_TS_TST_INFO_fp(fp: PFILE; a: PPS_TST_INFO): PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_TST_INFO_fp_procname);
end;

function ERR_i2d_TS_TST_INFO_fp(fp: PFILE; a: PS_TST_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_TST_INFO_fp_procname);
end;

function ERR_d2i_TS_TST_INFO_bio(bio: PBIO; a: PPS_TST_INFO): PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_TST_INFO_bio_procname);
end;

function ERR_i2d_TS_TST_INFO_bio(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_TST_INFO_bio_procname);
end;

function ERR_TS_ACCURACY_new: PS_ACCURACY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_new_procname);
end;

procedure ERR_TS_ACCURACY_free(a: PS_ACCURACY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_free_procname);
end;

function ERR_d2i_TS_ACCURACY(a: PPS_ACCURACY; _in: PPIdAnsiChar; len: TIdC_LONG): PS_ACCURACY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_ACCURACY_procname);
end;

function ERR_i2d_TS_ACCURACY(a: PS_ACCURACY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_ACCURACY_procname);
end;

function ERR_TS_ACCURACY_dup(a: PS_ACCURACY): PS_ACCURACY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_dup_procname);
end;

function ERR_TS_REQ_set_version(a: PS_REQ; version: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_version_procname);
end;

function ERR_TS_REQ_get_version(a: PS_REQ): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_version_procname);
end;

function ERR_TS_STATUS_INFO_set_status(a: PS_STATUS_INFO; i: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_set_status_procname);
end;

function ERR_TS_STATUS_INFO_get0_status(a: PS_STATUS_INFO): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_get0_status_procname);
end;

function ERR_TS_STATUS_INFO_get0_text(a: PS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_get0_text_procname);
end;

function ERR_TS_STATUS_INFO_get0_failure_info(a: PS_STATUS_INFO): PASN1_BIT_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_get0_failure_info_procname);
end;

function ERR_TS_REQ_set_msg_imprint(a: PS_REQ; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_msg_imprint_procname);
end;

function ERR_TS_REQ_get_msg_imprint(a: PS_REQ): PS_MSG_IMPRINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_msg_imprint_procname);
end;

function ERR_TS_MSG_IMPRINT_set_algo(a: PS_MSG_IMPRINT; alg: PX509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_set_algo_procname);
end;

function ERR_TS_MSG_IMPRINT_get_algo(a: PS_MSG_IMPRINT): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_get_algo_procname);
end;

function ERR_TS_MSG_IMPRINT_set_msg(a: PS_MSG_IMPRINT; d: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_set_msg_procname);
end;

function ERR_TS_MSG_IMPRINT_get_msg(a: PS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_get_msg_procname);
end;

function ERR_TS_REQ_set_policy_id(a: PS_REQ; policy: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_policy_id_procname);
end;

function ERR_TS_REQ_get_policy_id(a: PS_REQ): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_policy_id_procname);
end;

function ERR_TS_REQ_set_nonce(a: PS_REQ; nonce: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_nonce_procname);
end;

function ERR_TS_REQ_get_nonce(a: PS_REQ): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_nonce_procname);
end;

function ERR_TS_REQ_set_cert_req(a: PS_REQ; cert_req: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_cert_req_procname);
end;

function ERR_TS_REQ_get_cert_req(a: PS_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_cert_req_procname);
end;

function ERR_TS_REQ_get_exts(a: PS_REQ): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_exts_procname);
end;

procedure ERR_TS_REQ_ext_free(a: PS_REQ); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_ext_free_procname);
end;

function ERR_TS_REQ_get_ext_count(a: PS_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_count_procname);
end;

function ERR_TS_REQ_get_ext_by_NID(a: PS_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_by_NID_procname);
end;

function ERR_TS_REQ_get_ext_by_OBJ(a: PS_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_by_OBJ_procname);
end;

function ERR_TS_REQ_get_ext_by_critical(a: PS_REQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_by_critical_procname);
end;

function ERR_TS_REQ_get_ext(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_procname);
end;

function ERR_TS_REQ_delete_ext(a: PS_REQ; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_delete_ext_procname);
end;

function ERR_TS_REQ_add_ext(a: PS_REQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_add_ext_procname);
end;

function ERR_TS_REQ_get_ext_d2i(a: PS_REQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_d2i_procname);
end;

function ERR_TS_REQ_print_bio(bio: PBIO; a: PS_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_print_bio_procname);
end;

function ERR_TS_RESP_set_status_info(a: PS_RESP; info: PS_STATUS_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_set_status_info_procname);
end;

function ERR_TS_RESP_get_status_info(a: PS_RESP): PS_STATUS_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_get_status_info_procname);
end;

procedure ERR_TS_RESP_set_tst_info(a: PS_RESP; p7: PPKCS7; tst_info: PS_TST_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_set_tst_info_procname);
end;

function ERR_TS_RESP_get_token(a: PS_RESP): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_get_token_procname);
end;

function ERR_TS_RESP_get_tst_info(a: PS_RESP): PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_get_tst_info_procname);
end;

function ERR_TS_TST_INFO_set_version(a: PS_TST_INFO; version: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_version_procname);
end;

function ERR_TS_TST_INFO_get_version(a: PS_TST_INFO): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_version_procname);
end;

function ERR_TS_TST_INFO_set_policy_id(a: PS_TST_INFO; policy_id: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_policy_id_procname);
end;

function ERR_TS_TST_INFO_get_policy_id(a: PS_TST_INFO): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_policy_id_procname);
end;

function ERR_TS_TST_INFO_set_msg_imprint(a: PS_TST_INFO; msg_imprint: PS_MSG_IMPRINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_msg_imprint_procname);
end;

function ERR_TS_TST_INFO_get_msg_imprint(a: PS_TST_INFO): PS_MSG_IMPRINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_msg_imprint_procname);
end;

function ERR_TS_TST_INFO_set_serial(a: PS_TST_INFO; serial: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_serial_procname);
end;

function ERR_TS_TST_INFO_get_serial(a: PS_TST_INFO): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_serial_procname);
end;

function ERR_TS_TST_INFO_set_time(a: PS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_time_procname);
end;

function ERR_TS_TST_INFO_get_time(a: PS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_time_procname);
end;

function ERR_TS_TST_INFO_set_accuracy(a: PS_TST_INFO; accuracy: PS_ACCURACY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_accuracy_procname);
end;

function ERR_TS_TST_INFO_get_accuracy(a: PS_TST_INFO): PS_ACCURACY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_accuracy_procname);
end;

function ERR_TS_ACCURACY_set_seconds(a: PS_ACCURACY; seconds: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_set_seconds_procname);
end;

function ERR_TS_ACCURACY_get_seconds(a: PS_ACCURACY): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_get_seconds_procname);
end;

function ERR_TS_ACCURACY_set_millis(a: PS_ACCURACY; millis: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_set_millis_procname);
end;

function ERR_TS_ACCURACY_get_millis(a: PS_ACCURACY): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_get_millis_procname);
end;

function ERR_TS_ACCURACY_set_micros(a: PS_ACCURACY; micros: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_set_micros_procname);
end;

function ERR_TS_ACCURACY_get_micros(a: PS_ACCURACY): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_get_micros_procname);
end;

function ERR_TS_TST_INFO_set_ordering(a: PS_TST_INFO; ordering: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_ordering_procname);
end;

function ERR_TS_TST_INFO_get_ordering(a: PS_TST_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ordering_procname);
end;

function ERR_TS_TST_INFO_set_nonce(a: PS_TST_INFO; nonce: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_nonce_procname);
end;

function ERR_TS_TST_INFO_get_nonce(a: PS_TST_INFO): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_nonce_procname);
end;

function ERR_TS_TST_INFO_set_tsa(a: PS_TST_INFO; tsa: PGENERAL_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_tsa_procname);
end;

function ERR_TS_TST_INFO_get_tsa(a: PS_TST_INFO): PGENERAL_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_tsa_procname);
end;

function ERR_TS_TST_INFO_get_exts(a: PS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_exts_procname);
end;

procedure ERR_TS_TST_INFO_ext_free(a: PS_TST_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_ext_free_procname);
end;

function ERR_TS_TST_INFO_get_ext_count(a: PS_TST_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_count_procname);
end;

function ERR_TS_TST_INFO_get_ext_by_NID(a: PS_TST_INFO; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_by_NID_procname);
end;

function ERR_TS_TST_INFO_get_ext_by_OBJ(a: PS_TST_INFO; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_by_OBJ_procname);
end;

function ERR_TS_TST_INFO_get_ext_by_critical(a: PS_TST_INFO; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_by_critical_procname);
end;

function ERR_TS_TST_INFO_get_ext(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_procname);
end;

function ERR_TS_TST_INFO_delete_ext(a: PS_TST_INFO; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_delete_ext_procname);
end;

function ERR_TS_TST_INFO_add_ext(a: PS_TST_INFO; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_add_ext_procname);
end;

function ERR_TS_TST_INFO_get_ext_d2i(a: PS_TST_INFO; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_d2i_procname);
end;

function ERR_TS_RESP_CTX_new: PS_RESP_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_new_procname);
end;

function ERR_TS_RESP_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PS_RESP_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_new_ex_procname);
end;

procedure ERR_TS_RESP_CTX_free(ctx: PS_RESP_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_free_procname);
end;

function ERR_TS_RESP_CTX_set_signer_cert(ctx: PS_RESP_CTX; signer: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_signer_cert_procname);
end;

function ERR_TS_RESP_CTX_set_signer_key(ctx: PS_RESP_CTX; key: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_signer_key_procname);
end;

function ERR_TS_RESP_CTX_set_signer_digest(ctx: PS_RESP_CTX; signer_digest: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_signer_digest_procname);
end;

function ERR_TS_RESP_CTX_set_ess_cert_id_digest(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_ess_cert_id_digest_procname);
end;

function ERR_TS_RESP_CTX_set_def_policy(ctx: PS_RESP_CTX; def_policy: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_def_policy_procname);
end;

function ERR_TS_RESP_CTX_set_certs(ctx: PS_RESP_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_certs_procname);
end;

function ERR_TS_RESP_CTX_add_policy(ctx: PS_RESP_CTX; policy: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_policy_procname);
end;

function ERR_TS_RESP_CTX_add_md(ctx: PS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_md_procname);
end;

function ERR_TS_RESP_CTX_set_accuracy(ctx: PS_RESP_CTX; secs: TIdC_INT; millis: TIdC_INT; micros: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_accuracy_procname);
end;

function ERR_TS_RESP_CTX_set_clock_precision_digits(ctx: PS_RESP_CTX; clock_precision_digits: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_clock_precision_digits_procname);
end;

procedure ERR_TS_RESP_CTX_add_flags(ctx: PS_RESP_CTX; flags: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_flags_procname);
end;

procedure ERR_TS_RESP_CTX_set_serial_cb(ctx: PS_RESP_CTX; cb: TS_serial_cb_func_cb; data: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_serial_cb_procname);
end;

procedure ERR_TS_RESP_CTX_set_time_cb(ctx: PS_RESP_CTX; cb: TS_time_cb_func_cb; data: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_time_cb_procname);
end;

procedure ERR_TS_RESP_CTX_set_extension_cb(ctx: PS_RESP_CTX; cb: TS_extension_cb_func_cb; data: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_extension_cb_procname);
end;

function ERR_TS_RESP_CTX_set_status_info(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_status_info_procname);
end;

function ERR_TS_RESP_CTX_set_status_info_cond(ctx: PS_RESP_CTX; status: TIdC_INT; text: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_status_info_cond_procname);
end;

function ERR_TS_RESP_CTX_add_failure_info(ctx: PS_RESP_CTX; failure: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_failure_info_procname);
end;

function ERR_TS_RESP_CTX_get_request(ctx: PS_RESP_CTX): PS_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_get_request_procname);
end;

function ERR_TS_RESP_CTX_get_tst_info(ctx: PS_RESP_CTX): PS_TST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_get_tst_info_procname);
end;

function ERR_TS_RESP_create_response(ctx: PS_RESP_CTX; req_bio: PBIO): PS_RESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_create_response_procname);
end;

function ERR_TS_RESP_verify_signature(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_verify_signature_procname);
end;

function ERR_TS_RESP_verify_response(ctx: PS_VERIFY_CTX; response: PS_RESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_verify_response_procname);
end;

function ERR_TS_RESP_verify_token(ctx: PS_VERIFY_CTX; token: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_verify_token_procname);
end;

function ERR_TS_VERIFY_CTX_new: PS_VERIFY_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_new_procname);
end;

procedure ERR_TS_VERIFY_CTX_init(ctx: PS_VERIFY_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_init_procname);
end;

procedure ERR_TS_VERIFY_CTX_free(ctx: PS_VERIFY_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_free_procname);
end;

procedure ERR_TS_VERIFY_CTX_cleanup(ctx: PS_VERIFY_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_cleanup_procname);
end;

function ERR_TS_VERIFY_CTX_set_flags(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_flags_procname);
end;

function ERR_TS_VERIFY_CTX_add_flags(ctx: PS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_add_flags_procname);
end;

function ERR_TS_VERIFY_CTX_set_data(ctx: PS_VERIFY_CTX; b: PBIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_data_procname);
end;

function ERR_TS_VERIFY_CTX_set0_data(ctx: PS_VERIFY_CTX; b: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set0_data_procname);
end;

function ERR_TS_VERIFY_CTX_set_imprint(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_imprint_procname);
end;

function ERR_TS_VERIFY_CTX_set0_imprint(ctx: PS_VERIFY_CTX; hexstr: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set0_imprint_procname);
end;

function ERR_TS_VERIFY_CTX_set_store(ctx: PS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_store_procname);
end;

function ERR_TS_VERIFY_CTX_set0_store(ctx: PS_VERIFY_CTX; s: PX509_STORE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set0_store_procname);
end;

function ERR_TS_VERIFY_CTX_set_certs(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_certs_procname);
end;

function ERR_TS_VERIFY_CTX_set0_certs(ctx: PS_VERIFY_CTX; certs: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set0_certs_procname);
end;

function ERR_TS_REQ_to_TS_VERIFY_CTX(req: PS_REQ; ctx: PS_VERIFY_CTX): PS_VERIFY_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_to_TS_VERIFY_CTX_procname);
end;

function ERR_TS_RESP_print_bio(bio: PBIO; a: PS_RESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_print_bio_procname);
end;

function ERR_TS_STATUS_INFO_print_bio(bio: PBIO; a: PS_STATUS_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_print_bio_procname);
end;

function ERR_TS_TST_INFO_print_bio(bio: PBIO; a: PS_TST_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_print_bio_procname);
end;

function ERR_TS_ASN1_INTEGER_print_bio(bio: PBIO; num: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ASN1_INTEGER_print_bio_procname);
end;

function ERR_TS_OBJ_print_bio(bio: PBIO; obj: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_OBJ_print_bio_procname);
end;

function ERR_TS_ext_print_bio(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ext_print_bio_procname);
end;

function ERR_TS_X509_ALGOR_print_bio(bio: PBIO; alg: PX509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_X509_ALGOR_print_bio_procname);
end;

function ERR_TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PS_MSG_IMPRINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_print_bio_procname);
end;

function ERR_TS_CONF_load_cert(_file: PIdAnsiChar): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_load_cert_procname);
end;

function ERR_TS_CONF_load_certs(_file: PIdAnsiChar): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_load_certs_procname);
end;

function ERR_TS_CONF_load_key(_file: PIdAnsiChar; pass: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_load_key_procname);
end;

function ERR_TS_CONF_get_tsa_section(conf: PCONF; section: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_get_tsa_section_procname);
end;

function ERR_TS_CONF_set_serial(conf: PCONF; section: PIdAnsiChar; cb: TS_serial_cb_func_cb; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_serial_procname);
end;

function ERR_TS_CONF_set_crypto_device(conf: PCONF; section: PIdAnsiChar; device: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_crypto_device_procname);
end;

function ERR_TS_CONF_set_default_engine(name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_default_engine_procname);
end;

function ERR_TS_CONF_set_signer_cert(conf: PCONF; section: PIdAnsiChar; cert: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_signer_cert_procname);
end;

function ERR_TS_CONF_set_certs(conf: PCONF; section: PIdAnsiChar; certs: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_certs_procname);
end;

function ERR_TS_CONF_set_signer_key(conf: PCONF; section: PIdAnsiChar; key: PIdAnsiChar; pass: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_signer_key_procname);
end;

function ERR_TS_CONF_set_signer_digest(conf: PCONF; section: PIdAnsiChar; md: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_signer_digest_procname);
end;

function ERR_TS_CONF_set_def_policy(conf: PCONF; section: PIdAnsiChar; policy: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_def_policy_procname);
end;

function ERR_TS_CONF_set_policies(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_policies_procname);
end;

function ERR_TS_CONF_set_digests(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_digests_procname);
end;

function ERR_TS_CONF_set_accuracy(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_accuracy_procname);
end;

function ERR_TS_CONF_set_clock_precision_digits(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_clock_precision_digits_procname);
end;

function ERR_TS_CONF_set_ordering(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_ordering_procname);
end;

function ERR_TS_CONF_set_tsa_name(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_tsa_name_procname);
end;

function ERR_TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_ess_cert_id_chain_procname);
end;

function ERR_TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PIdAnsiChar; ctx: PS_RESP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_ess_cert_id_digest_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  TS_REQ_new := LoadLibFunction(ADllHandle, TS_REQ_new_procname);
  FuncLoadError := not assigned(TS_REQ_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_new_allownil)}
    TS_REQ_new := ERR_TS_REQ_new;
    {$ifend}
    {$if declared(TS_REQ_new_introduced)}
    if LibVersion < TS_REQ_new_introduced then
    begin
      {$if declared(FC_TS_REQ_new)}
      TS_REQ_new := FC_TS_REQ_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_new_removed)}
    if TS_REQ_new_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_new)}
      TS_REQ_new := _TS_REQ_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_new');
    {$ifend}
  end;
  
  TS_REQ_free := LoadLibFunction(ADllHandle, TS_REQ_free_procname);
  FuncLoadError := not assigned(TS_REQ_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_free_allownil)}
    TS_REQ_free := ERR_TS_REQ_free;
    {$ifend}
    {$if declared(TS_REQ_free_introduced)}
    if LibVersion < TS_REQ_free_introduced then
    begin
      {$if declared(FC_TS_REQ_free)}
      TS_REQ_free := FC_TS_REQ_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_free_removed)}
    if TS_REQ_free_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_free)}
      TS_REQ_free := _TS_REQ_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_free');
    {$ifend}
  end;
  
  d2i_TS_REQ := LoadLibFunction(ADllHandle, d2i_TS_REQ_procname);
  FuncLoadError := not assigned(d2i_TS_REQ);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_REQ_allownil)}
    d2i_TS_REQ := ERR_d2i_TS_REQ;
    {$ifend}
    {$if declared(d2i_TS_REQ_introduced)}
    if LibVersion < d2i_TS_REQ_introduced then
    begin
      {$if declared(FC_d2i_TS_REQ)}
      d2i_TS_REQ := FC_d2i_TS_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_REQ_removed)}
    if d2i_TS_REQ_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_REQ)}
      d2i_TS_REQ := _d2i_TS_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_REQ');
    {$ifend}
  end;
  
  i2d_TS_REQ := LoadLibFunction(ADllHandle, i2d_TS_REQ_procname);
  FuncLoadError := not assigned(i2d_TS_REQ);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_REQ_allownil)}
    i2d_TS_REQ := ERR_i2d_TS_REQ;
    {$ifend}
    {$if declared(i2d_TS_REQ_introduced)}
    if LibVersion < i2d_TS_REQ_introduced then
    begin
      {$if declared(FC_i2d_TS_REQ)}
      i2d_TS_REQ := FC_i2d_TS_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_REQ_removed)}
    if i2d_TS_REQ_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_REQ)}
      i2d_TS_REQ := _i2d_TS_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_REQ');
    {$ifend}
  end;
  
  TS_REQ_dup := LoadLibFunction(ADllHandle, TS_REQ_dup_procname);
  FuncLoadError := not assigned(TS_REQ_dup);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_dup_allownil)}
    TS_REQ_dup := ERR_TS_REQ_dup;
    {$ifend}
    {$if declared(TS_REQ_dup_introduced)}
    if LibVersion < TS_REQ_dup_introduced then
    begin
      {$if declared(FC_TS_REQ_dup)}
      TS_REQ_dup := FC_TS_REQ_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_dup_removed)}
    if TS_REQ_dup_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_dup)}
      TS_REQ_dup := _TS_REQ_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_dup');
    {$ifend}
  end;
  
  d2i_TS_REQ_fp := LoadLibFunction(ADllHandle, d2i_TS_REQ_fp_procname);
  FuncLoadError := not assigned(d2i_TS_REQ_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_REQ_fp_allownil)}
    d2i_TS_REQ_fp := ERR_d2i_TS_REQ_fp;
    {$ifend}
    {$if declared(d2i_TS_REQ_fp_introduced)}
    if LibVersion < d2i_TS_REQ_fp_introduced then
    begin
      {$if declared(FC_d2i_TS_REQ_fp)}
      d2i_TS_REQ_fp := FC_d2i_TS_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_REQ_fp_removed)}
    if d2i_TS_REQ_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_REQ_fp)}
      d2i_TS_REQ_fp := _d2i_TS_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_REQ_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_REQ_fp');
    {$ifend}
  end;
  
  i2d_TS_REQ_fp := LoadLibFunction(ADllHandle, i2d_TS_REQ_fp_procname);
  FuncLoadError := not assigned(i2d_TS_REQ_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_REQ_fp_allownil)}
    i2d_TS_REQ_fp := ERR_i2d_TS_REQ_fp;
    {$ifend}
    {$if declared(i2d_TS_REQ_fp_introduced)}
    if LibVersion < i2d_TS_REQ_fp_introduced then
    begin
      {$if declared(FC_i2d_TS_REQ_fp)}
      i2d_TS_REQ_fp := FC_i2d_TS_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_REQ_fp_removed)}
    if i2d_TS_REQ_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_REQ_fp)}
      i2d_TS_REQ_fp := _i2d_TS_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_REQ_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_REQ_fp');
    {$ifend}
  end;
  
  d2i_TS_REQ_bio := LoadLibFunction(ADllHandle, d2i_TS_REQ_bio_procname);
  FuncLoadError := not assigned(d2i_TS_REQ_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_REQ_bio_allownil)}
    d2i_TS_REQ_bio := ERR_d2i_TS_REQ_bio;
    {$ifend}
    {$if declared(d2i_TS_REQ_bio_introduced)}
    if LibVersion < d2i_TS_REQ_bio_introduced then
    begin
      {$if declared(FC_d2i_TS_REQ_bio)}
      d2i_TS_REQ_bio := FC_d2i_TS_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_REQ_bio_removed)}
    if d2i_TS_REQ_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_REQ_bio)}
      d2i_TS_REQ_bio := _d2i_TS_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_REQ_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_REQ_bio');
    {$ifend}
  end;
  
  i2d_TS_REQ_bio := LoadLibFunction(ADllHandle, i2d_TS_REQ_bio_procname);
  FuncLoadError := not assigned(i2d_TS_REQ_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_REQ_bio_allownil)}
    i2d_TS_REQ_bio := ERR_i2d_TS_REQ_bio;
    {$ifend}
    {$if declared(i2d_TS_REQ_bio_introduced)}
    if LibVersion < i2d_TS_REQ_bio_introduced then
    begin
      {$if declared(FC_i2d_TS_REQ_bio)}
      i2d_TS_REQ_bio := FC_i2d_TS_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_REQ_bio_removed)}
    if i2d_TS_REQ_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_REQ_bio)}
      i2d_TS_REQ_bio := _i2d_TS_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_REQ_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_REQ_bio');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_new := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_new_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_new_allownil)}
    TS_MSG_IMPRINT_new := ERR_TS_MSG_IMPRINT_new;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_new_introduced)}
    if LibVersion < TS_MSG_IMPRINT_new_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_new)}
      TS_MSG_IMPRINT_new := FC_TS_MSG_IMPRINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_new_removed)}
    if TS_MSG_IMPRINT_new_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_new)}
      TS_MSG_IMPRINT_new := _TS_MSG_IMPRINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_new');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_free := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_free_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_free_allownil)}
    TS_MSG_IMPRINT_free := ERR_TS_MSG_IMPRINT_free;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_free_introduced)}
    if LibVersion < TS_MSG_IMPRINT_free_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_free)}
      TS_MSG_IMPRINT_free := FC_TS_MSG_IMPRINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_free_removed)}
    if TS_MSG_IMPRINT_free_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_free)}
      TS_MSG_IMPRINT_free := _TS_MSG_IMPRINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_free');
    {$ifend}
  end;
  
  d2i_TS_MSG_IMPRINT := LoadLibFunction(ADllHandle, d2i_TS_MSG_IMPRINT_procname);
  FuncLoadError := not assigned(d2i_TS_MSG_IMPRINT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_MSG_IMPRINT_allownil)}
    d2i_TS_MSG_IMPRINT := ERR_d2i_TS_MSG_IMPRINT;
    {$ifend}
    {$if declared(d2i_TS_MSG_IMPRINT_introduced)}
    if LibVersion < d2i_TS_MSG_IMPRINT_introduced then
    begin
      {$if declared(FC_d2i_TS_MSG_IMPRINT)}
      d2i_TS_MSG_IMPRINT := FC_d2i_TS_MSG_IMPRINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_MSG_IMPRINT_removed)}
    if d2i_TS_MSG_IMPRINT_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_MSG_IMPRINT)}
      d2i_TS_MSG_IMPRINT := _d2i_TS_MSG_IMPRINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_MSG_IMPRINT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_MSG_IMPRINT');
    {$ifend}
  end;
  
  i2d_TS_MSG_IMPRINT := LoadLibFunction(ADllHandle, i2d_TS_MSG_IMPRINT_procname);
  FuncLoadError := not assigned(i2d_TS_MSG_IMPRINT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_MSG_IMPRINT_allownil)}
    i2d_TS_MSG_IMPRINT := ERR_i2d_TS_MSG_IMPRINT;
    {$ifend}
    {$if declared(i2d_TS_MSG_IMPRINT_introduced)}
    if LibVersion < i2d_TS_MSG_IMPRINT_introduced then
    begin
      {$if declared(FC_i2d_TS_MSG_IMPRINT)}
      i2d_TS_MSG_IMPRINT := FC_i2d_TS_MSG_IMPRINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_MSG_IMPRINT_removed)}
    if i2d_TS_MSG_IMPRINT_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_MSG_IMPRINT)}
      i2d_TS_MSG_IMPRINT := _i2d_TS_MSG_IMPRINT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_MSG_IMPRINT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_MSG_IMPRINT');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_dup := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_dup_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_dup);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_dup_allownil)}
    TS_MSG_IMPRINT_dup := ERR_TS_MSG_IMPRINT_dup;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_dup_introduced)}
    if LibVersion < TS_MSG_IMPRINT_dup_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_dup)}
      TS_MSG_IMPRINT_dup := FC_TS_MSG_IMPRINT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_dup_removed)}
    if TS_MSG_IMPRINT_dup_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_dup)}
      TS_MSG_IMPRINT_dup := _TS_MSG_IMPRINT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_dup');
    {$ifend}
  end;
  
  d2i_TS_MSG_IMPRINT_fp := LoadLibFunction(ADllHandle, d2i_TS_MSG_IMPRINT_fp_procname);
  FuncLoadError := not assigned(d2i_TS_MSG_IMPRINT_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_MSG_IMPRINT_fp_allownil)}
    d2i_TS_MSG_IMPRINT_fp := ERR_d2i_TS_MSG_IMPRINT_fp;
    {$ifend}
    {$if declared(d2i_TS_MSG_IMPRINT_fp_introduced)}
    if LibVersion < d2i_TS_MSG_IMPRINT_fp_introduced then
    begin
      {$if declared(FC_d2i_TS_MSG_IMPRINT_fp)}
      d2i_TS_MSG_IMPRINT_fp := FC_d2i_TS_MSG_IMPRINT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_MSG_IMPRINT_fp_removed)}
    if d2i_TS_MSG_IMPRINT_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_MSG_IMPRINT_fp)}
      d2i_TS_MSG_IMPRINT_fp := _d2i_TS_MSG_IMPRINT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_MSG_IMPRINT_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_MSG_IMPRINT_fp');
    {$ifend}
  end;
  
  i2d_TS_MSG_IMPRINT_fp := LoadLibFunction(ADllHandle, i2d_TS_MSG_IMPRINT_fp_procname);
  FuncLoadError := not assigned(i2d_TS_MSG_IMPRINT_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_MSG_IMPRINT_fp_allownil)}
    i2d_TS_MSG_IMPRINT_fp := ERR_i2d_TS_MSG_IMPRINT_fp;
    {$ifend}
    {$if declared(i2d_TS_MSG_IMPRINT_fp_introduced)}
    if LibVersion < i2d_TS_MSG_IMPRINT_fp_introduced then
    begin
      {$if declared(FC_i2d_TS_MSG_IMPRINT_fp)}
      i2d_TS_MSG_IMPRINT_fp := FC_i2d_TS_MSG_IMPRINT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_MSG_IMPRINT_fp_removed)}
    if i2d_TS_MSG_IMPRINT_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_MSG_IMPRINT_fp)}
      i2d_TS_MSG_IMPRINT_fp := _i2d_TS_MSG_IMPRINT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_MSG_IMPRINT_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_MSG_IMPRINT_fp');
    {$ifend}
  end;
  
  d2i_TS_MSG_IMPRINT_bio := LoadLibFunction(ADllHandle, d2i_TS_MSG_IMPRINT_bio_procname);
  FuncLoadError := not assigned(d2i_TS_MSG_IMPRINT_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_MSG_IMPRINT_bio_allownil)}
    d2i_TS_MSG_IMPRINT_bio := ERR_d2i_TS_MSG_IMPRINT_bio;
    {$ifend}
    {$if declared(d2i_TS_MSG_IMPRINT_bio_introduced)}
    if LibVersion < d2i_TS_MSG_IMPRINT_bio_introduced then
    begin
      {$if declared(FC_d2i_TS_MSG_IMPRINT_bio)}
      d2i_TS_MSG_IMPRINT_bio := FC_d2i_TS_MSG_IMPRINT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_MSG_IMPRINT_bio_removed)}
    if d2i_TS_MSG_IMPRINT_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_MSG_IMPRINT_bio)}
      d2i_TS_MSG_IMPRINT_bio := _d2i_TS_MSG_IMPRINT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_MSG_IMPRINT_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_MSG_IMPRINT_bio');
    {$ifend}
  end;
  
  i2d_TS_MSG_IMPRINT_bio := LoadLibFunction(ADllHandle, i2d_TS_MSG_IMPRINT_bio_procname);
  FuncLoadError := not assigned(i2d_TS_MSG_IMPRINT_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_MSG_IMPRINT_bio_allownil)}
    i2d_TS_MSG_IMPRINT_bio := ERR_i2d_TS_MSG_IMPRINT_bio;
    {$ifend}
    {$if declared(i2d_TS_MSG_IMPRINT_bio_introduced)}
    if LibVersion < i2d_TS_MSG_IMPRINT_bio_introduced then
    begin
      {$if declared(FC_i2d_TS_MSG_IMPRINT_bio)}
      i2d_TS_MSG_IMPRINT_bio := FC_i2d_TS_MSG_IMPRINT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_MSG_IMPRINT_bio_removed)}
    if i2d_TS_MSG_IMPRINT_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_MSG_IMPRINT_bio)}
      i2d_TS_MSG_IMPRINT_bio := _i2d_TS_MSG_IMPRINT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_MSG_IMPRINT_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_MSG_IMPRINT_bio');
    {$ifend}
  end;
  
  TS_RESP_new := LoadLibFunction(ADllHandle, TS_RESP_new_procname);
  FuncLoadError := not assigned(TS_RESP_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_new_allownil)}
    TS_RESP_new := ERR_TS_RESP_new;
    {$ifend}
    {$if declared(TS_RESP_new_introduced)}
    if LibVersion < TS_RESP_new_introduced then
    begin
      {$if declared(FC_TS_RESP_new)}
      TS_RESP_new := FC_TS_RESP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_new_removed)}
    if TS_RESP_new_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_new)}
      TS_RESP_new := _TS_RESP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_new');
    {$ifend}
  end;
  
  TS_RESP_free := LoadLibFunction(ADllHandle, TS_RESP_free_procname);
  FuncLoadError := not assigned(TS_RESP_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_free_allownil)}
    TS_RESP_free := ERR_TS_RESP_free;
    {$ifend}
    {$if declared(TS_RESP_free_introduced)}
    if LibVersion < TS_RESP_free_introduced then
    begin
      {$if declared(FC_TS_RESP_free)}
      TS_RESP_free := FC_TS_RESP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_free_removed)}
    if TS_RESP_free_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_free)}
      TS_RESP_free := _TS_RESP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_free');
    {$ifend}
  end;
  
  d2i_TS_RESP := LoadLibFunction(ADllHandle, d2i_TS_RESP_procname);
  FuncLoadError := not assigned(d2i_TS_RESP);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_RESP_allownil)}
    d2i_TS_RESP := ERR_d2i_TS_RESP;
    {$ifend}
    {$if declared(d2i_TS_RESP_introduced)}
    if LibVersion < d2i_TS_RESP_introduced then
    begin
      {$if declared(FC_d2i_TS_RESP)}
      d2i_TS_RESP := FC_d2i_TS_RESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_RESP_removed)}
    if d2i_TS_RESP_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_RESP)}
      d2i_TS_RESP := _d2i_TS_RESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_RESP_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_RESP');
    {$ifend}
  end;
  
  i2d_TS_RESP := LoadLibFunction(ADllHandle, i2d_TS_RESP_procname);
  FuncLoadError := not assigned(i2d_TS_RESP);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_RESP_allownil)}
    i2d_TS_RESP := ERR_i2d_TS_RESP;
    {$ifend}
    {$if declared(i2d_TS_RESP_introduced)}
    if LibVersion < i2d_TS_RESP_introduced then
    begin
      {$if declared(FC_i2d_TS_RESP)}
      i2d_TS_RESP := FC_i2d_TS_RESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_RESP_removed)}
    if i2d_TS_RESP_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_RESP)}
      i2d_TS_RESP := _i2d_TS_RESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_RESP_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_RESP');
    {$ifend}
  end;
  
  TS_RESP_dup := LoadLibFunction(ADllHandle, TS_RESP_dup_procname);
  FuncLoadError := not assigned(TS_RESP_dup);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_dup_allownil)}
    TS_RESP_dup := ERR_TS_RESP_dup;
    {$ifend}
    {$if declared(TS_RESP_dup_introduced)}
    if LibVersion < TS_RESP_dup_introduced then
    begin
      {$if declared(FC_TS_RESP_dup)}
      TS_RESP_dup := FC_TS_RESP_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_dup_removed)}
    if TS_RESP_dup_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_dup)}
      TS_RESP_dup := _TS_RESP_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_dup');
    {$ifend}
  end;
  
  d2i_TS_RESP_fp := LoadLibFunction(ADllHandle, d2i_TS_RESP_fp_procname);
  FuncLoadError := not assigned(d2i_TS_RESP_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_RESP_fp_allownil)}
    d2i_TS_RESP_fp := ERR_d2i_TS_RESP_fp;
    {$ifend}
    {$if declared(d2i_TS_RESP_fp_introduced)}
    if LibVersion < d2i_TS_RESP_fp_introduced then
    begin
      {$if declared(FC_d2i_TS_RESP_fp)}
      d2i_TS_RESP_fp := FC_d2i_TS_RESP_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_RESP_fp_removed)}
    if d2i_TS_RESP_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_RESP_fp)}
      d2i_TS_RESP_fp := _d2i_TS_RESP_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_RESP_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_RESP_fp');
    {$ifend}
  end;
  
  i2d_TS_RESP_fp := LoadLibFunction(ADllHandle, i2d_TS_RESP_fp_procname);
  FuncLoadError := not assigned(i2d_TS_RESP_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_RESP_fp_allownil)}
    i2d_TS_RESP_fp := ERR_i2d_TS_RESP_fp;
    {$ifend}
    {$if declared(i2d_TS_RESP_fp_introduced)}
    if LibVersion < i2d_TS_RESP_fp_introduced then
    begin
      {$if declared(FC_i2d_TS_RESP_fp)}
      i2d_TS_RESP_fp := FC_i2d_TS_RESP_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_RESP_fp_removed)}
    if i2d_TS_RESP_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_RESP_fp)}
      i2d_TS_RESP_fp := _i2d_TS_RESP_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_RESP_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_RESP_fp');
    {$ifend}
  end;
  
  d2i_TS_RESP_bio := LoadLibFunction(ADllHandle, d2i_TS_RESP_bio_procname);
  FuncLoadError := not assigned(d2i_TS_RESP_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_RESP_bio_allownil)}
    d2i_TS_RESP_bio := ERR_d2i_TS_RESP_bio;
    {$ifend}
    {$if declared(d2i_TS_RESP_bio_introduced)}
    if LibVersion < d2i_TS_RESP_bio_introduced then
    begin
      {$if declared(FC_d2i_TS_RESP_bio)}
      d2i_TS_RESP_bio := FC_d2i_TS_RESP_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_RESP_bio_removed)}
    if d2i_TS_RESP_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_RESP_bio)}
      d2i_TS_RESP_bio := _d2i_TS_RESP_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_RESP_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_RESP_bio');
    {$ifend}
  end;
  
  i2d_TS_RESP_bio := LoadLibFunction(ADllHandle, i2d_TS_RESP_bio_procname);
  FuncLoadError := not assigned(i2d_TS_RESP_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_RESP_bio_allownil)}
    i2d_TS_RESP_bio := ERR_i2d_TS_RESP_bio;
    {$ifend}
    {$if declared(i2d_TS_RESP_bio_introduced)}
    if LibVersion < i2d_TS_RESP_bio_introduced then
    begin
      {$if declared(FC_i2d_TS_RESP_bio)}
      i2d_TS_RESP_bio := FC_i2d_TS_RESP_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_RESP_bio_removed)}
    if i2d_TS_RESP_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_RESP_bio)}
      i2d_TS_RESP_bio := _i2d_TS_RESP_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_RESP_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_RESP_bio');
    {$ifend}
  end;
  
  TS_STATUS_INFO_new := LoadLibFunction(ADllHandle, TS_STATUS_INFO_new_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_new_allownil)}
    TS_STATUS_INFO_new := ERR_TS_STATUS_INFO_new;
    {$ifend}
    {$if declared(TS_STATUS_INFO_new_introduced)}
    if LibVersion < TS_STATUS_INFO_new_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_new)}
      TS_STATUS_INFO_new := FC_TS_STATUS_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_new_removed)}
    if TS_STATUS_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_new)}
      TS_STATUS_INFO_new := _TS_STATUS_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_new');
    {$ifend}
  end;
  
  TS_STATUS_INFO_free := LoadLibFunction(ADllHandle, TS_STATUS_INFO_free_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_free_allownil)}
    TS_STATUS_INFO_free := ERR_TS_STATUS_INFO_free;
    {$ifend}
    {$if declared(TS_STATUS_INFO_free_introduced)}
    if LibVersion < TS_STATUS_INFO_free_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_free)}
      TS_STATUS_INFO_free := FC_TS_STATUS_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_free_removed)}
    if TS_STATUS_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_free)}
      TS_STATUS_INFO_free := _TS_STATUS_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_free');
    {$ifend}
  end;
  
  d2i_TS_STATUS_INFO := LoadLibFunction(ADllHandle, d2i_TS_STATUS_INFO_procname);
  FuncLoadError := not assigned(d2i_TS_STATUS_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_STATUS_INFO_allownil)}
    d2i_TS_STATUS_INFO := ERR_d2i_TS_STATUS_INFO;
    {$ifend}
    {$if declared(d2i_TS_STATUS_INFO_introduced)}
    if LibVersion < d2i_TS_STATUS_INFO_introduced then
    begin
      {$if declared(FC_d2i_TS_STATUS_INFO)}
      d2i_TS_STATUS_INFO := FC_d2i_TS_STATUS_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_STATUS_INFO_removed)}
    if d2i_TS_STATUS_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_STATUS_INFO)}
      d2i_TS_STATUS_INFO := _d2i_TS_STATUS_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_STATUS_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_STATUS_INFO');
    {$ifend}
  end;
  
  i2d_TS_STATUS_INFO := LoadLibFunction(ADllHandle, i2d_TS_STATUS_INFO_procname);
  FuncLoadError := not assigned(i2d_TS_STATUS_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_STATUS_INFO_allownil)}
    i2d_TS_STATUS_INFO := ERR_i2d_TS_STATUS_INFO;
    {$ifend}
    {$if declared(i2d_TS_STATUS_INFO_introduced)}
    if LibVersion < i2d_TS_STATUS_INFO_introduced then
    begin
      {$if declared(FC_i2d_TS_STATUS_INFO)}
      i2d_TS_STATUS_INFO := FC_i2d_TS_STATUS_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_STATUS_INFO_removed)}
    if i2d_TS_STATUS_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_STATUS_INFO)}
      i2d_TS_STATUS_INFO := _i2d_TS_STATUS_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_STATUS_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_STATUS_INFO');
    {$ifend}
  end;
  
  TS_STATUS_INFO_dup := LoadLibFunction(ADllHandle, TS_STATUS_INFO_dup_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_dup);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_dup_allownil)}
    TS_STATUS_INFO_dup := ERR_TS_STATUS_INFO_dup;
    {$ifend}
    {$if declared(TS_STATUS_INFO_dup_introduced)}
    if LibVersion < TS_STATUS_INFO_dup_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_dup)}
      TS_STATUS_INFO_dup := FC_TS_STATUS_INFO_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_dup_removed)}
    if TS_STATUS_INFO_dup_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_dup)}
      TS_STATUS_INFO_dup := _TS_STATUS_INFO_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_dup');
    {$ifend}
  end;
  
  TS_TST_INFO_new := LoadLibFunction(ADllHandle, TS_TST_INFO_new_procname);
  FuncLoadError := not assigned(TS_TST_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_new_allownil)}
    TS_TST_INFO_new := ERR_TS_TST_INFO_new;
    {$ifend}
    {$if declared(TS_TST_INFO_new_introduced)}
    if LibVersion < TS_TST_INFO_new_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_new)}
      TS_TST_INFO_new := FC_TS_TST_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_new_removed)}
    if TS_TST_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_new)}
      TS_TST_INFO_new := _TS_TST_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_new');
    {$ifend}
  end;
  
  TS_TST_INFO_free := LoadLibFunction(ADllHandle, TS_TST_INFO_free_procname);
  FuncLoadError := not assigned(TS_TST_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_free_allownil)}
    TS_TST_INFO_free := ERR_TS_TST_INFO_free;
    {$ifend}
    {$if declared(TS_TST_INFO_free_introduced)}
    if LibVersion < TS_TST_INFO_free_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_free)}
      TS_TST_INFO_free := FC_TS_TST_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_free_removed)}
    if TS_TST_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_free)}
      TS_TST_INFO_free := _TS_TST_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_free');
    {$ifend}
  end;
  
  d2i_TS_TST_INFO := LoadLibFunction(ADllHandle, d2i_TS_TST_INFO_procname);
  FuncLoadError := not assigned(d2i_TS_TST_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_TST_INFO_allownil)}
    d2i_TS_TST_INFO := ERR_d2i_TS_TST_INFO;
    {$ifend}
    {$if declared(d2i_TS_TST_INFO_introduced)}
    if LibVersion < d2i_TS_TST_INFO_introduced then
    begin
      {$if declared(FC_d2i_TS_TST_INFO)}
      d2i_TS_TST_INFO := FC_d2i_TS_TST_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_TST_INFO_removed)}
    if d2i_TS_TST_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_TST_INFO)}
      d2i_TS_TST_INFO := _d2i_TS_TST_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_TST_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_TST_INFO');
    {$ifend}
  end;
  
  i2d_TS_TST_INFO := LoadLibFunction(ADllHandle, i2d_TS_TST_INFO_procname);
  FuncLoadError := not assigned(i2d_TS_TST_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_TST_INFO_allownil)}
    i2d_TS_TST_INFO := ERR_i2d_TS_TST_INFO;
    {$ifend}
    {$if declared(i2d_TS_TST_INFO_introduced)}
    if LibVersion < i2d_TS_TST_INFO_introduced then
    begin
      {$if declared(FC_i2d_TS_TST_INFO)}
      i2d_TS_TST_INFO := FC_i2d_TS_TST_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_TST_INFO_removed)}
    if i2d_TS_TST_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_TST_INFO)}
      i2d_TS_TST_INFO := _i2d_TS_TST_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_TST_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_TST_INFO');
    {$ifend}
  end;
  
  TS_TST_INFO_dup := LoadLibFunction(ADllHandle, TS_TST_INFO_dup_procname);
  FuncLoadError := not assigned(TS_TST_INFO_dup);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_dup_allownil)}
    TS_TST_INFO_dup := ERR_TS_TST_INFO_dup;
    {$ifend}
    {$if declared(TS_TST_INFO_dup_introduced)}
    if LibVersion < TS_TST_INFO_dup_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_dup)}
      TS_TST_INFO_dup := FC_TS_TST_INFO_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_dup_removed)}
    if TS_TST_INFO_dup_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_dup)}
      TS_TST_INFO_dup := _TS_TST_INFO_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_dup');
    {$ifend}
  end;
  
  PKCS7_to_TS_TST_INFO := LoadLibFunction(ADllHandle, PKCS7_to_TS_TST_INFO_procname);
  FuncLoadError := not assigned(PKCS7_to_TS_TST_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_to_TS_TST_INFO_allownil)}
    PKCS7_to_TS_TST_INFO := ERR_PKCS7_to_TS_TST_INFO;
    {$ifend}
    {$if declared(PKCS7_to_TS_TST_INFO_introduced)}
    if LibVersion < PKCS7_to_TS_TST_INFO_introduced then
    begin
      {$if declared(FC_PKCS7_to_TS_TST_INFO)}
      PKCS7_to_TS_TST_INFO := FC_PKCS7_to_TS_TST_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_to_TS_TST_INFO_removed)}
    if PKCS7_to_TS_TST_INFO_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_to_TS_TST_INFO)}
      PKCS7_to_TS_TST_INFO := _PKCS7_to_TS_TST_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_to_TS_TST_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_to_TS_TST_INFO');
    {$ifend}
  end;
  
  d2i_TS_TST_INFO_fp := LoadLibFunction(ADllHandle, d2i_TS_TST_INFO_fp_procname);
  FuncLoadError := not assigned(d2i_TS_TST_INFO_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_TST_INFO_fp_allownil)}
    d2i_TS_TST_INFO_fp := ERR_d2i_TS_TST_INFO_fp;
    {$ifend}
    {$if declared(d2i_TS_TST_INFO_fp_introduced)}
    if LibVersion < d2i_TS_TST_INFO_fp_introduced then
    begin
      {$if declared(FC_d2i_TS_TST_INFO_fp)}
      d2i_TS_TST_INFO_fp := FC_d2i_TS_TST_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_TST_INFO_fp_removed)}
    if d2i_TS_TST_INFO_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_TST_INFO_fp)}
      d2i_TS_TST_INFO_fp := _d2i_TS_TST_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_TST_INFO_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_TST_INFO_fp');
    {$ifend}
  end;
  
  i2d_TS_TST_INFO_fp := LoadLibFunction(ADllHandle, i2d_TS_TST_INFO_fp_procname);
  FuncLoadError := not assigned(i2d_TS_TST_INFO_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_TST_INFO_fp_allownil)}
    i2d_TS_TST_INFO_fp := ERR_i2d_TS_TST_INFO_fp;
    {$ifend}
    {$if declared(i2d_TS_TST_INFO_fp_introduced)}
    if LibVersion < i2d_TS_TST_INFO_fp_introduced then
    begin
      {$if declared(FC_i2d_TS_TST_INFO_fp)}
      i2d_TS_TST_INFO_fp := FC_i2d_TS_TST_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_TST_INFO_fp_removed)}
    if i2d_TS_TST_INFO_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_TST_INFO_fp)}
      i2d_TS_TST_INFO_fp := _i2d_TS_TST_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_TST_INFO_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_TST_INFO_fp');
    {$ifend}
  end;
  
  d2i_TS_TST_INFO_bio := LoadLibFunction(ADllHandle, d2i_TS_TST_INFO_bio_procname);
  FuncLoadError := not assigned(d2i_TS_TST_INFO_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_TST_INFO_bio_allownil)}
    d2i_TS_TST_INFO_bio := ERR_d2i_TS_TST_INFO_bio;
    {$ifend}
    {$if declared(d2i_TS_TST_INFO_bio_introduced)}
    if LibVersion < d2i_TS_TST_INFO_bio_introduced then
    begin
      {$if declared(FC_d2i_TS_TST_INFO_bio)}
      d2i_TS_TST_INFO_bio := FC_d2i_TS_TST_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_TST_INFO_bio_removed)}
    if d2i_TS_TST_INFO_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_TST_INFO_bio)}
      d2i_TS_TST_INFO_bio := _d2i_TS_TST_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_TST_INFO_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_TST_INFO_bio');
    {$ifend}
  end;
  
  i2d_TS_TST_INFO_bio := LoadLibFunction(ADllHandle, i2d_TS_TST_INFO_bio_procname);
  FuncLoadError := not assigned(i2d_TS_TST_INFO_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_TST_INFO_bio_allownil)}
    i2d_TS_TST_INFO_bio := ERR_i2d_TS_TST_INFO_bio;
    {$ifend}
    {$if declared(i2d_TS_TST_INFO_bio_introduced)}
    if LibVersion < i2d_TS_TST_INFO_bio_introduced then
    begin
      {$if declared(FC_i2d_TS_TST_INFO_bio)}
      i2d_TS_TST_INFO_bio := FC_i2d_TS_TST_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_TST_INFO_bio_removed)}
    if i2d_TS_TST_INFO_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_TST_INFO_bio)}
      i2d_TS_TST_INFO_bio := _i2d_TS_TST_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_TST_INFO_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_TST_INFO_bio');
    {$ifend}
  end;
  
  TS_ACCURACY_new := LoadLibFunction(ADllHandle, TS_ACCURACY_new_procname);
  FuncLoadError := not assigned(TS_ACCURACY_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_new_allownil)}
    TS_ACCURACY_new := ERR_TS_ACCURACY_new;
    {$ifend}
    {$if declared(TS_ACCURACY_new_introduced)}
    if LibVersion < TS_ACCURACY_new_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_new)}
      TS_ACCURACY_new := FC_TS_ACCURACY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_new_removed)}
    if TS_ACCURACY_new_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_new)}
      TS_ACCURACY_new := _TS_ACCURACY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_new');
    {$ifend}
  end;
  
  TS_ACCURACY_free := LoadLibFunction(ADllHandle, TS_ACCURACY_free_procname);
  FuncLoadError := not assigned(TS_ACCURACY_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_free_allownil)}
    TS_ACCURACY_free := ERR_TS_ACCURACY_free;
    {$ifend}
    {$if declared(TS_ACCURACY_free_introduced)}
    if LibVersion < TS_ACCURACY_free_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_free)}
      TS_ACCURACY_free := FC_TS_ACCURACY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_free_removed)}
    if TS_ACCURACY_free_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_free)}
      TS_ACCURACY_free := _TS_ACCURACY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_free');
    {$ifend}
  end;
  
  d2i_TS_ACCURACY := LoadLibFunction(ADllHandle, d2i_TS_ACCURACY_procname);
  FuncLoadError := not assigned(d2i_TS_ACCURACY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_TS_ACCURACY_allownil)}
    d2i_TS_ACCURACY := ERR_d2i_TS_ACCURACY;
    {$ifend}
    {$if declared(d2i_TS_ACCURACY_introduced)}
    if LibVersion < d2i_TS_ACCURACY_introduced then
    begin
      {$if declared(FC_d2i_TS_ACCURACY)}
      d2i_TS_ACCURACY := FC_d2i_TS_ACCURACY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_TS_ACCURACY_removed)}
    if d2i_TS_ACCURACY_removed <= LibVersion then
    begin
      {$if declared(_d2i_TS_ACCURACY)}
      d2i_TS_ACCURACY := _d2i_TS_ACCURACY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_TS_ACCURACY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_TS_ACCURACY');
    {$ifend}
  end;
  
  i2d_TS_ACCURACY := LoadLibFunction(ADllHandle, i2d_TS_ACCURACY_procname);
  FuncLoadError := not assigned(i2d_TS_ACCURACY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_TS_ACCURACY_allownil)}
    i2d_TS_ACCURACY := ERR_i2d_TS_ACCURACY;
    {$ifend}
    {$if declared(i2d_TS_ACCURACY_introduced)}
    if LibVersion < i2d_TS_ACCURACY_introduced then
    begin
      {$if declared(FC_i2d_TS_ACCURACY)}
      i2d_TS_ACCURACY := FC_i2d_TS_ACCURACY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_TS_ACCURACY_removed)}
    if i2d_TS_ACCURACY_removed <= LibVersion then
    begin
      {$if declared(_i2d_TS_ACCURACY)}
      i2d_TS_ACCURACY := _i2d_TS_ACCURACY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_TS_ACCURACY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_TS_ACCURACY');
    {$ifend}
  end;
  
  TS_ACCURACY_dup := LoadLibFunction(ADllHandle, TS_ACCURACY_dup_procname);
  FuncLoadError := not assigned(TS_ACCURACY_dup);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_dup_allownil)}
    TS_ACCURACY_dup := ERR_TS_ACCURACY_dup;
    {$ifend}
    {$if declared(TS_ACCURACY_dup_introduced)}
    if LibVersion < TS_ACCURACY_dup_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_dup)}
      TS_ACCURACY_dup := FC_TS_ACCURACY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_dup_removed)}
    if TS_ACCURACY_dup_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_dup)}
      TS_ACCURACY_dup := _TS_ACCURACY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_dup');
    {$ifend}
  end;
  
  TS_REQ_set_version := LoadLibFunction(ADllHandle, TS_REQ_set_version_procname);
  FuncLoadError := not assigned(TS_REQ_set_version);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_set_version_allownil)}
    TS_REQ_set_version := ERR_TS_REQ_set_version;
    {$ifend}
    {$if declared(TS_REQ_set_version_introduced)}
    if LibVersion < TS_REQ_set_version_introduced then
    begin
      {$if declared(FC_TS_REQ_set_version)}
      TS_REQ_set_version := FC_TS_REQ_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_set_version_removed)}
    if TS_REQ_set_version_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_set_version)}
      TS_REQ_set_version := _TS_REQ_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_set_version');
    {$ifend}
  end;
  
  TS_REQ_get_version := LoadLibFunction(ADllHandle, TS_REQ_get_version_procname);
  FuncLoadError := not assigned(TS_REQ_get_version);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_version_allownil)}
    TS_REQ_get_version := ERR_TS_REQ_get_version;
    {$ifend}
    {$if declared(TS_REQ_get_version_introduced)}
    if LibVersion < TS_REQ_get_version_introduced then
    begin
      {$if declared(FC_TS_REQ_get_version)}
      TS_REQ_get_version := FC_TS_REQ_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_version_removed)}
    if TS_REQ_get_version_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_version)}
      TS_REQ_get_version := _TS_REQ_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_version');
    {$ifend}
  end;
  
  TS_STATUS_INFO_set_status := LoadLibFunction(ADllHandle, TS_STATUS_INFO_set_status_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_set_status);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_set_status_allownil)}
    TS_STATUS_INFO_set_status := ERR_TS_STATUS_INFO_set_status;
    {$ifend}
    {$if declared(TS_STATUS_INFO_set_status_introduced)}
    if LibVersion < TS_STATUS_INFO_set_status_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_set_status)}
      TS_STATUS_INFO_set_status := FC_TS_STATUS_INFO_set_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_set_status_removed)}
    if TS_STATUS_INFO_set_status_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_set_status)}
      TS_STATUS_INFO_set_status := _TS_STATUS_INFO_set_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_set_status_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_set_status');
    {$ifend}
  end;
  
  TS_STATUS_INFO_get0_status := LoadLibFunction(ADllHandle, TS_STATUS_INFO_get0_status_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_get0_status);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_get0_status_allownil)}
    TS_STATUS_INFO_get0_status := ERR_TS_STATUS_INFO_get0_status;
    {$ifend}
    {$if declared(TS_STATUS_INFO_get0_status_introduced)}
    if LibVersion < TS_STATUS_INFO_get0_status_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_get0_status)}
      TS_STATUS_INFO_get0_status := FC_TS_STATUS_INFO_get0_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_get0_status_removed)}
    if TS_STATUS_INFO_get0_status_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_get0_status)}
      TS_STATUS_INFO_get0_status := _TS_STATUS_INFO_get0_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_get0_status_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_get0_status');
    {$ifend}
  end;
  
  TS_STATUS_INFO_get0_text := LoadLibFunction(ADllHandle, TS_STATUS_INFO_get0_text_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_get0_text);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_get0_text_allownil)}
    TS_STATUS_INFO_get0_text := ERR_TS_STATUS_INFO_get0_text;
    {$ifend}
    {$if declared(TS_STATUS_INFO_get0_text_introduced)}
    if LibVersion < TS_STATUS_INFO_get0_text_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_get0_text)}
      TS_STATUS_INFO_get0_text := FC_TS_STATUS_INFO_get0_text;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_get0_text_removed)}
    if TS_STATUS_INFO_get0_text_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_get0_text)}
      TS_STATUS_INFO_get0_text := _TS_STATUS_INFO_get0_text;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_get0_text_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_get0_text');
    {$ifend}
  end;
  
  TS_STATUS_INFO_get0_failure_info := LoadLibFunction(ADllHandle, TS_STATUS_INFO_get0_failure_info_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_get0_failure_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_get0_failure_info_allownil)}
    TS_STATUS_INFO_get0_failure_info := ERR_TS_STATUS_INFO_get0_failure_info;
    {$ifend}
    {$if declared(TS_STATUS_INFO_get0_failure_info_introduced)}
    if LibVersion < TS_STATUS_INFO_get0_failure_info_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_get0_failure_info)}
      TS_STATUS_INFO_get0_failure_info := FC_TS_STATUS_INFO_get0_failure_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_get0_failure_info_removed)}
    if TS_STATUS_INFO_get0_failure_info_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_get0_failure_info)}
      TS_STATUS_INFO_get0_failure_info := _TS_STATUS_INFO_get0_failure_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_get0_failure_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_get0_failure_info');
    {$ifend}
  end;
  
  TS_REQ_set_msg_imprint := LoadLibFunction(ADllHandle, TS_REQ_set_msg_imprint_procname);
  FuncLoadError := not assigned(TS_REQ_set_msg_imprint);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_set_msg_imprint_allownil)}
    TS_REQ_set_msg_imprint := ERR_TS_REQ_set_msg_imprint;
    {$ifend}
    {$if declared(TS_REQ_set_msg_imprint_introduced)}
    if LibVersion < TS_REQ_set_msg_imprint_introduced then
    begin
      {$if declared(FC_TS_REQ_set_msg_imprint)}
      TS_REQ_set_msg_imprint := FC_TS_REQ_set_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_set_msg_imprint_removed)}
    if TS_REQ_set_msg_imprint_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_set_msg_imprint)}
      TS_REQ_set_msg_imprint := _TS_REQ_set_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_set_msg_imprint_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_set_msg_imprint');
    {$ifend}
  end;
  
  TS_REQ_get_msg_imprint := LoadLibFunction(ADllHandle, TS_REQ_get_msg_imprint_procname);
  FuncLoadError := not assigned(TS_REQ_get_msg_imprint);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_msg_imprint_allownil)}
    TS_REQ_get_msg_imprint := ERR_TS_REQ_get_msg_imprint;
    {$ifend}
    {$if declared(TS_REQ_get_msg_imprint_introduced)}
    if LibVersion < TS_REQ_get_msg_imprint_introduced then
    begin
      {$if declared(FC_TS_REQ_get_msg_imprint)}
      TS_REQ_get_msg_imprint := FC_TS_REQ_get_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_msg_imprint_removed)}
    if TS_REQ_get_msg_imprint_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_msg_imprint)}
      TS_REQ_get_msg_imprint := _TS_REQ_get_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_msg_imprint_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_msg_imprint');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_set_algo := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_set_algo_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_set_algo);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_set_algo_allownil)}
    TS_MSG_IMPRINT_set_algo := ERR_TS_MSG_IMPRINT_set_algo;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_set_algo_introduced)}
    if LibVersion < TS_MSG_IMPRINT_set_algo_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_set_algo)}
      TS_MSG_IMPRINT_set_algo := FC_TS_MSG_IMPRINT_set_algo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_set_algo_removed)}
    if TS_MSG_IMPRINT_set_algo_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_set_algo)}
      TS_MSG_IMPRINT_set_algo := _TS_MSG_IMPRINT_set_algo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_set_algo_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_set_algo');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_get_algo := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_get_algo_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_get_algo);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_get_algo_allownil)}
    TS_MSG_IMPRINT_get_algo := ERR_TS_MSG_IMPRINT_get_algo;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_get_algo_introduced)}
    if LibVersion < TS_MSG_IMPRINT_get_algo_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_get_algo)}
      TS_MSG_IMPRINT_get_algo := FC_TS_MSG_IMPRINT_get_algo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_get_algo_removed)}
    if TS_MSG_IMPRINT_get_algo_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_get_algo)}
      TS_MSG_IMPRINT_get_algo := _TS_MSG_IMPRINT_get_algo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_get_algo_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_get_algo');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_set_msg := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_set_msg_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_set_msg);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_set_msg_allownil)}
    TS_MSG_IMPRINT_set_msg := ERR_TS_MSG_IMPRINT_set_msg;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_set_msg_introduced)}
    if LibVersion < TS_MSG_IMPRINT_set_msg_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_set_msg)}
      TS_MSG_IMPRINT_set_msg := FC_TS_MSG_IMPRINT_set_msg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_set_msg_removed)}
    if TS_MSG_IMPRINT_set_msg_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_set_msg)}
      TS_MSG_IMPRINT_set_msg := _TS_MSG_IMPRINT_set_msg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_set_msg_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_set_msg');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_get_msg := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_get_msg_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_get_msg);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_get_msg_allownil)}
    TS_MSG_IMPRINT_get_msg := ERR_TS_MSG_IMPRINT_get_msg;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_get_msg_introduced)}
    if LibVersion < TS_MSG_IMPRINT_get_msg_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_get_msg)}
      TS_MSG_IMPRINT_get_msg := FC_TS_MSG_IMPRINT_get_msg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_get_msg_removed)}
    if TS_MSG_IMPRINT_get_msg_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_get_msg)}
      TS_MSG_IMPRINT_get_msg := _TS_MSG_IMPRINT_get_msg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_get_msg_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_get_msg');
    {$ifend}
  end;
  
  TS_REQ_set_policy_id := LoadLibFunction(ADllHandle, TS_REQ_set_policy_id_procname);
  FuncLoadError := not assigned(TS_REQ_set_policy_id);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_set_policy_id_allownil)}
    TS_REQ_set_policy_id := ERR_TS_REQ_set_policy_id;
    {$ifend}
    {$if declared(TS_REQ_set_policy_id_introduced)}
    if LibVersion < TS_REQ_set_policy_id_introduced then
    begin
      {$if declared(FC_TS_REQ_set_policy_id)}
      TS_REQ_set_policy_id := FC_TS_REQ_set_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_set_policy_id_removed)}
    if TS_REQ_set_policy_id_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_set_policy_id)}
      TS_REQ_set_policy_id := _TS_REQ_set_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_set_policy_id_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_set_policy_id');
    {$ifend}
  end;
  
  TS_REQ_get_policy_id := LoadLibFunction(ADllHandle, TS_REQ_get_policy_id_procname);
  FuncLoadError := not assigned(TS_REQ_get_policy_id);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_policy_id_allownil)}
    TS_REQ_get_policy_id := ERR_TS_REQ_get_policy_id;
    {$ifend}
    {$if declared(TS_REQ_get_policy_id_introduced)}
    if LibVersion < TS_REQ_get_policy_id_introduced then
    begin
      {$if declared(FC_TS_REQ_get_policy_id)}
      TS_REQ_get_policy_id := FC_TS_REQ_get_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_policy_id_removed)}
    if TS_REQ_get_policy_id_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_policy_id)}
      TS_REQ_get_policy_id := _TS_REQ_get_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_policy_id_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_policy_id');
    {$ifend}
  end;
  
  TS_REQ_set_nonce := LoadLibFunction(ADllHandle, TS_REQ_set_nonce_procname);
  FuncLoadError := not assigned(TS_REQ_set_nonce);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_set_nonce_allownil)}
    TS_REQ_set_nonce := ERR_TS_REQ_set_nonce;
    {$ifend}
    {$if declared(TS_REQ_set_nonce_introduced)}
    if LibVersion < TS_REQ_set_nonce_introduced then
    begin
      {$if declared(FC_TS_REQ_set_nonce)}
      TS_REQ_set_nonce := FC_TS_REQ_set_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_set_nonce_removed)}
    if TS_REQ_set_nonce_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_set_nonce)}
      TS_REQ_set_nonce := _TS_REQ_set_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_set_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_set_nonce');
    {$ifend}
  end;
  
  TS_REQ_get_nonce := LoadLibFunction(ADllHandle, TS_REQ_get_nonce_procname);
  FuncLoadError := not assigned(TS_REQ_get_nonce);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_nonce_allownil)}
    TS_REQ_get_nonce := ERR_TS_REQ_get_nonce;
    {$ifend}
    {$if declared(TS_REQ_get_nonce_introduced)}
    if LibVersion < TS_REQ_get_nonce_introduced then
    begin
      {$if declared(FC_TS_REQ_get_nonce)}
      TS_REQ_get_nonce := FC_TS_REQ_get_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_nonce_removed)}
    if TS_REQ_get_nonce_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_nonce)}
      TS_REQ_get_nonce := _TS_REQ_get_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_nonce');
    {$ifend}
  end;
  
  TS_REQ_set_cert_req := LoadLibFunction(ADllHandle, TS_REQ_set_cert_req_procname);
  FuncLoadError := not assigned(TS_REQ_set_cert_req);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_set_cert_req_allownil)}
    TS_REQ_set_cert_req := ERR_TS_REQ_set_cert_req;
    {$ifend}
    {$if declared(TS_REQ_set_cert_req_introduced)}
    if LibVersion < TS_REQ_set_cert_req_introduced then
    begin
      {$if declared(FC_TS_REQ_set_cert_req)}
      TS_REQ_set_cert_req := FC_TS_REQ_set_cert_req;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_set_cert_req_removed)}
    if TS_REQ_set_cert_req_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_set_cert_req)}
      TS_REQ_set_cert_req := _TS_REQ_set_cert_req;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_set_cert_req_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_set_cert_req');
    {$ifend}
  end;
  
  TS_REQ_get_cert_req := LoadLibFunction(ADllHandle, TS_REQ_get_cert_req_procname);
  FuncLoadError := not assigned(TS_REQ_get_cert_req);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_cert_req_allownil)}
    TS_REQ_get_cert_req := ERR_TS_REQ_get_cert_req;
    {$ifend}
    {$if declared(TS_REQ_get_cert_req_introduced)}
    if LibVersion < TS_REQ_get_cert_req_introduced then
    begin
      {$if declared(FC_TS_REQ_get_cert_req)}
      TS_REQ_get_cert_req := FC_TS_REQ_get_cert_req;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_cert_req_removed)}
    if TS_REQ_get_cert_req_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_cert_req)}
      TS_REQ_get_cert_req := _TS_REQ_get_cert_req;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_cert_req_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_cert_req');
    {$ifend}
  end;
  
  TS_REQ_get_exts := LoadLibFunction(ADllHandle, TS_REQ_get_exts_procname);
  FuncLoadError := not assigned(TS_REQ_get_exts);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_exts_allownil)}
    TS_REQ_get_exts := ERR_TS_REQ_get_exts;
    {$ifend}
    {$if declared(TS_REQ_get_exts_introduced)}
    if LibVersion < TS_REQ_get_exts_introduced then
    begin
      {$if declared(FC_TS_REQ_get_exts)}
      TS_REQ_get_exts := FC_TS_REQ_get_exts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_exts_removed)}
    if TS_REQ_get_exts_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_exts)}
      TS_REQ_get_exts := _TS_REQ_get_exts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_exts_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_exts');
    {$ifend}
  end;
  
  TS_REQ_ext_free := LoadLibFunction(ADllHandle, TS_REQ_ext_free_procname);
  FuncLoadError := not assigned(TS_REQ_ext_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_ext_free_allownil)}
    TS_REQ_ext_free := ERR_TS_REQ_ext_free;
    {$ifend}
    {$if declared(TS_REQ_ext_free_introduced)}
    if LibVersion < TS_REQ_ext_free_introduced then
    begin
      {$if declared(FC_TS_REQ_ext_free)}
      TS_REQ_ext_free := FC_TS_REQ_ext_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_ext_free_removed)}
    if TS_REQ_ext_free_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_ext_free)}
      TS_REQ_ext_free := _TS_REQ_ext_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_ext_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_ext_free');
    {$ifend}
  end;
  
  TS_REQ_get_ext_count := LoadLibFunction(ADllHandle, TS_REQ_get_ext_count_procname);
  FuncLoadError := not assigned(TS_REQ_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_ext_count_allownil)}
    TS_REQ_get_ext_count := ERR_TS_REQ_get_ext_count;
    {$ifend}
    {$if declared(TS_REQ_get_ext_count_introduced)}
    if LibVersion < TS_REQ_get_ext_count_introduced then
    begin
      {$if declared(FC_TS_REQ_get_ext_count)}
      TS_REQ_get_ext_count := FC_TS_REQ_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_ext_count_removed)}
    if TS_REQ_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_ext_count)}
      TS_REQ_get_ext_count := _TS_REQ_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_ext_count');
    {$ifend}
  end;
  
  TS_REQ_get_ext_by_NID := LoadLibFunction(ADllHandle, TS_REQ_get_ext_by_NID_procname);
  FuncLoadError := not assigned(TS_REQ_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_ext_by_NID_allownil)}
    TS_REQ_get_ext_by_NID := ERR_TS_REQ_get_ext_by_NID;
    {$ifend}
    {$if declared(TS_REQ_get_ext_by_NID_introduced)}
    if LibVersion < TS_REQ_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_TS_REQ_get_ext_by_NID)}
      TS_REQ_get_ext_by_NID := FC_TS_REQ_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_ext_by_NID_removed)}
    if TS_REQ_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_ext_by_NID)}
      TS_REQ_get_ext_by_NID := _TS_REQ_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_ext_by_NID');
    {$ifend}
  end;
  
  TS_REQ_get_ext_by_OBJ := LoadLibFunction(ADllHandle, TS_REQ_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(TS_REQ_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_ext_by_OBJ_allownil)}
    TS_REQ_get_ext_by_OBJ := ERR_TS_REQ_get_ext_by_OBJ;
    {$ifend}
    {$if declared(TS_REQ_get_ext_by_OBJ_introduced)}
    if LibVersion < TS_REQ_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_TS_REQ_get_ext_by_OBJ)}
      TS_REQ_get_ext_by_OBJ := FC_TS_REQ_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_ext_by_OBJ_removed)}
    if TS_REQ_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_ext_by_OBJ)}
      TS_REQ_get_ext_by_OBJ := _TS_REQ_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_ext_by_OBJ');
    {$ifend}
  end;
  
  TS_REQ_get_ext_by_critical := LoadLibFunction(ADllHandle, TS_REQ_get_ext_by_critical_procname);
  FuncLoadError := not assigned(TS_REQ_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_ext_by_critical_allownil)}
    TS_REQ_get_ext_by_critical := ERR_TS_REQ_get_ext_by_critical;
    {$ifend}
    {$if declared(TS_REQ_get_ext_by_critical_introduced)}
    if LibVersion < TS_REQ_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_TS_REQ_get_ext_by_critical)}
      TS_REQ_get_ext_by_critical := FC_TS_REQ_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_ext_by_critical_removed)}
    if TS_REQ_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_ext_by_critical)}
      TS_REQ_get_ext_by_critical := _TS_REQ_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_ext_by_critical');
    {$ifend}
  end;
  
  TS_REQ_get_ext := LoadLibFunction(ADllHandle, TS_REQ_get_ext_procname);
  FuncLoadError := not assigned(TS_REQ_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_ext_allownil)}
    TS_REQ_get_ext := ERR_TS_REQ_get_ext;
    {$ifend}
    {$if declared(TS_REQ_get_ext_introduced)}
    if LibVersion < TS_REQ_get_ext_introduced then
    begin
      {$if declared(FC_TS_REQ_get_ext)}
      TS_REQ_get_ext := FC_TS_REQ_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_ext_removed)}
    if TS_REQ_get_ext_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_ext)}
      TS_REQ_get_ext := _TS_REQ_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_ext');
    {$ifend}
  end;
  
  TS_REQ_delete_ext := LoadLibFunction(ADllHandle, TS_REQ_delete_ext_procname);
  FuncLoadError := not assigned(TS_REQ_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_delete_ext_allownil)}
    TS_REQ_delete_ext := ERR_TS_REQ_delete_ext;
    {$ifend}
    {$if declared(TS_REQ_delete_ext_introduced)}
    if LibVersion < TS_REQ_delete_ext_introduced then
    begin
      {$if declared(FC_TS_REQ_delete_ext)}
      TS_REQ_delete_ext := FC_TS_REQ_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_delete_ext_removed)}
    if TS_REQ_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_delete_ext)}
      TS_REQ_delete_ext := _TS_REQ_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_delete_ext');
    {$ifend}
  end;
  
  TS_REQ_add_ext := LoadLibFunction(ADllHandle, TS_REQ_add_ext_procname);
  FuncLoadError := not assigned(TS_REQ_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_add_ext_allownil)}
    TS_REQ_add_ext := ERR_TS_REQ_add_ext;
    {$ifend}
    {$if declared(TS_REQ_add_ext_introduced)}
    if LibVersion < TS_REQ_add_ext_introduced then
    begin
      {$if declared(FC_TS_REQ_add_ext)}
      TS_REQ_add_ext := FC_TS_REQ_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_add_ext_removed)}
    if TS_REQ_add_ext_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_add_ext)}
      TS_REQ_add_ext := _TS_REQ_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_add_ext');
    {$ifend}
  end;
  
  TS_REQ_get_ext_d2i := LoadLibFunction(ADllHandle, TS_REQ_get_ext_d2i_procname);
  FuncLoadError := not assigned(TS_REQ_get_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_get_ext_d2i_allownil)}
    TS_REQ_get_ext_d2i := ERR_TS_REQ_get_ext_d2i;
    {$ifend}
    {$if declared(TS_REQ_get_ext_d2i_introduced)}
    if LibVersion < TS_REQ_get_ext_d2i_introduced then
    begin
      {$if declared(FC_TS_REQ_get_ext_d2i)}
      TS_REQ_get_ext_d2i := FC_TS_REQ_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_get_ext_d2i_removed)}
    if TS_REQ_get_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_get_ext_d2i)}
      TS_REQ_get_ext_d2i := _TS_REQ_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_get_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_get_ext_d2i');
    {$ifend}
  end;
  
  TS_REQ_print_bio := LoadLibFunction(ADllHandle, TS_REQ_print_bio_procname);
  FuncLoadError := not assigned(TS_REQ_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_print_bio_allownil)}
    TS_REQ_print_bio := ERR_TS_REQ_print_bio;
    {$ifend}
    {$if declared(TS_REQ_print_bio_introduced)}
    if LibVersion < TS_REQ_print_bio_introduced then
    begin
      {$if declared(FC_TS_REQ_print_bio)}
      TS_REQ_print_bio := FC_TS_REQ_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_print_bio_removed)}
    if TS_REQ_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_print_bio)}
      TS_REQ_print_bio := _TS_REQ_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_print_bio');
    {$ifend}
  end;
  
  TS_RESP_set_status_info := LoadLibFunction(ADllHandle, TS_RESP_set_status_info_procname);
  FuncLoadError := not assigned(TS_RESP_set_status_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_set_status_info_allownil)}
    TS_RESP_set_status_info := ERR_TS_RESP_set_status_info;
    {$ifend}
    {$if declared(TS_RESP_set_status_info_introduced)}
    if LibVersion < TS_RESP_set_status_info_introduced then
    begin
      {$if declared(FC_TS_RESP_set_status_info)}
      TS_RESP_set_status_info := FC_TS_RESP_set_status_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_set_status_info_removed)}
    if TS_RESP_set_status_info_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_set_status_info)}
      TS_RESP_set_status_info := _TS_RESP_set_status_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_set_status_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_set_status_info');
    {$ifend}
  end;
  
  TS_RESP_get_status_info := LoadLibFunction(ADllHandle, TS_RESP_get_status_info_procname);
  FuncLoadError := not assigned(TS_RESP_get_status_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_get_status_info_allownil)}
    TS_RESP_get_status_info := ERR_TS_RESP_get_status_info;
    {$ifend}
    {$if declared(TS_RESP_get_status_info_introduced)}
    if LibVersion < TS_RESP_get_status_info_introduced then
    begin
      {$if declared(FC_TS_RESP_get_status_info)}
      TS_RESP_get_status_info := FC_TS_RESP_get_status_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_get_status_info_removed)}
    if TS_RESP_get_status_info_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_get_status_info)}
      TS_RESP_get_status_info := _TS_RESP_get_status_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_get_status_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_get_status_info');
    {$ifend}
  end;
  
  TS_RESP_set_tst_info := LoadLibFunction(ADllHandle, TS_RESP_set_tst_info_procname);
  FuncLoadError := not assigned(TS_RESP_set_tst_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_set_tst_info_allownil)}
    TS_RESP_set_tst_info := ERR_TS_RESP_set_tst_info;
    {$ifend}
    {$if declared(TS_RESP_set_tst_info_introduced)}
    if LibVersion < TS_RESP_set_tst_info_introduced then
    begin
      {$if declared(FC_TS_RESP_set_tst_info)}
      TS_RESP_set_tst_info := FC_TS_RESP_set_tst_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_set_tst_info_removed)}
    if TS_RESP_set_tst_info_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_set_tst_info)}
      TS_RESP_set_tst_info := _TS_RESP_set_tst_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_set_tst_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_set_tst_info');
    {$ifend}
  end;
  
  TS_RESP_get_token := LoadLibFunction(ADllHandle, TS_RESP_get_token_procname);
  FuncLoadError := not assigned(TS_RESP_get_token);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_get_token_allownil)}
    TS_RESP_get_token := ERR_TS_RESP_get_token;
    {$ifend}
    {$if declared(TS_RESP_get_token_introduced)}
    if LibVersion < TS_RESP_get_token_introduced then
    begin
      {$if declared(FC_TS_RESP_get_token)}
      TS_RESP_get_token := FC_TS_RESP_get_token;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_get_token_removed)}
    if TS_RESP_get_token_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_get_token)}
      TS_RESP_get_token := _TS_RESP_get_token;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_get_token_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_get_token');
    {$ifend}
  end;
  
  TS_RESP_get_tst_info := LoadLibFunction(ADllHandle, TS_RESP_get_tst_info_procname);
  FuncLoadError := not assigned(TS_RESP_get_tst_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_get_tst_info_allownil)}
    TS_RESP_get_tst_info := ERR_TS_RESP_get_tst_info;
    {$ifend}
    {$if declared(TS_RESP_get_tst_info_introduced)}
    if LibVersion < TS_RESP_get_tst_info_introduced then
    begin
      {$if declared(FC_TS_RESP_get_tst_info)}
      TS_RESP_get_tst_info := FC_TS_RESP_get_tst_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_get_tst_info_removed)}
    if TS_RESP_get_tst_info_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_get_tst_info)}
      TS_RESP_get_tst_info := _TS_RESP_get_tst_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_get_tst_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_get_tst_info');
    {$ifend}
  end;
  
  TS_TST_INFO_set_version := LoadLibFunction(ADllHandle, TS_TST_INFO_set_version_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_version);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_version_allownil)}
    TS_TST_INFO_set_version := ERR_TS_TST_INFO_set_version;
    {$ifend}
    {$if declared(TS_TST_INFO_set_version_introduced)}
    if LibVersion < TS_TST_INFO_set_version_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_version)}
      TS_TST_INFO_set_version := FC_TS_TST_INFO_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_version_removed)}
    if TS_TST_INFO_set_version_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_version)}
      TS_TST_INFO_set_version := _TS_TST_INFO_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_version');
    {$ifend}
  end;
  
  TS_TST_INFO_get_version := LoadLibFunction(ADllHandle, TS_TST_INFO_get_version_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_version);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_version_allownil)}
    TS_TST_INFO_get_version := ERR_TS_TST_INFO_get_version;
    {$ifend}
    {$if declared(TS_TST_INFO_get_version_introduced)}
    if LibVersion < TS_TST_INFO_get_version_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_version)}
      TS_TST_INFO_get_version := FC_TS_TST_INFO_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_version_removed)}
    if TS_TST_INFO_get_version_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_version)}
      TS_TST_INFO_get_version := _TS_TST_INFO_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_version');
    {$ifend}
  end;
  
  TS_TST_INFO_set_policy_id := LoadLibFunction(ADllHandle, TS_TST_INFO_set_policy_id_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_policy_id);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_policy_id_allownil)}
    TS_TST_INFO_set_policy_id := ERR_TS_TST_INFO_set_policy_id;
    {$ifend}
    {$if declared(TS_TST_INFO_set_policy_id_introduced)}
    if LibVersion < TS_TST_INFO_set_policy_id_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_policy_id)}
      TS_TST_INFO_set_policy_id := FC_TS_TST_INFO_set_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_policy_id_removed)}
    if TS_TST_INFO_set_policy_id_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_policy_id)}
      TS_TST_INFO_set_policy_id := _TS_TST_INFO_set_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_policy_id_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_policy_id');
    {$ifend}
  end;
  
  TS_TST_INFO_get_policy_id := LoadLibFunction(ADllHandle, TS_TST_INFO_get_policy_id_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_policy_id);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_policy_id_allownil)}
    TS_TST_INFO_get_policy_id := ERR_TS_TST_INFO_get_policy_id;
    {$ifend}
    {$if declared(TS_TST_INFO_get_policy_id_introduced)}
    if LibVersion < TS_TST_INFO_get_policy_id_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_policy_id)}
      TS_TST_INFO_get_policy_id := FC_TS_TST_INFO_get_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_policy_id_removed)}
    if TS_TST_INFO_get_policy_id_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_policy_id)}
      TS_TST_INFO_get_policy_id := _TS_TST_INFO_get_policy_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_policy_id_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_policy_id');
    {$ifend}
  end;
  
  TS_TST_INFO_set_msg_imprint := LoadLibFunction(ADllHandle, TS_TST_INFO_set_msg_imprint_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_msg_imprint);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_msg_imprint_allownil)}
    TS_TST_INFO_set_msg_imprint := ERR_TS_TST_INFO_set_msg_imprint;
    {$ifend}
    {$if declared(TS_TST_INFO_set_msg_imprint_introduced)}
    if LibVersion < TS_TST_INFO_set_msg_imprint_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_msg_imprint)}
      TS_TST_INFO_set_msg_imprint := FC_TS_TST_INFO_set_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_msg_imprint_removed)}
    if TS_TST_INFO_set_msg_imprint_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_msg_imprint)}
      TS_TST_INFO_set_msg_imprint := _TS_TST_INFO_set_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_msg_imprint_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_msg_imprint');
    {$ifend}
  end;
  
  TS_TST_INFO_get_msg_imprint := LoadLibFunction(ADllHandle, TS_TST_INFO_get_msg_imprint_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_msg_imprint);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_msg_imprint_allownil)}
    TS_TST_INFO_get_msg_imprint := ERR_TS_TST_INFO_get_msg_imprint;
    {$ifend}
    {$if declared(TS_TST_INFO_get_msg_imprint_introduced)}
    if LibVersion < TS_TST_INFO_get_msg_imprint_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_msg_imprint)}
      TS_TST_INFO_get_msg_imprint := FC_TS_TST_INFO_get_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_msg_imprint_removed)}
    if TS_TST_INFO_get_msg_imprint_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_msg_imprint)}
      TS_TST_INFO_get_msg_imprint := _TS_TST_INFO_get_msg_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_msg_imprint_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_msg_imprint');
    {$ifend}
  end;
  
  TS_TST_INFO_set_serial := LoadLibFunction(ADllHandle, TS_TST_INFO_set_serial_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_serial);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_serial_allownil)}
    TS_TST_INFO_set_serial := ERR_TS_TST_INFO_set_serial;
    {$ifend}
    {$if declared(TS_TST_INFO_set_serial_introduced)}
    if LibVersion < TS_TST_INFO_set_serial_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_serial)}
      TS_TST_INFO_set_serial := FC_TS_TST_INFO_set_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_serial_removed)}
    if TS_TST_INFO_set_serial_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_serial)}
      TS_TST_INFO_set_serial := _TS_TST_INFO_set_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_serial');
    {$ifend}
  end;
  
  TS_TST_INFO_get_serial := LoadLibFunction(ADllHandle, TS_TST_INFO_get_serial_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_serial);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_serial_allownil)}
    TS_TST_INFO_get_serial := ERR_TS_TST_INFO_get_serial;
    {$ifend}
    {$if declared(TS_TST_INFO_get_serial_introduced)}
    if LibVersion < TS_TST_INFO_get_serial_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_serial)}
      TS_TST_INFO_get_serial := FC_TS_TST_INFO_get_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_serial_removed)}
    if TS_TST_INFO_get_serial_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_serial)}
      TS_TST_INFO_get_serial := _TS_TST_INFO_get_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_serial');
    {$ifend}
  end;
  
  TS_TST_INFO_set_time := LoadLibFunction(ADllHandle, TS_TST_INFO_set_time_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_time);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_time_allownil)}
    TS_TST_INFO_set_time := ERR_TS_TST_INFO_set_time;
    {$ifend}
    {$if declared(TS_TST_INFO_set_time_introduced)}
    if LibVersion < TS_TST_INFO_set_time_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_time)}
      TS_TST_INFO_set_time := FC_TS_TST_INFO_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_time_removed)}
    if TS_TST_INFO_set_time_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_time)}
      TS_TST_INFO_set_time := _TS_TST_INFO_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_time_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_time');
    {$ifend}
  end;
  
  TS_TST_INFO_get_time := LoadLibFunction(ADllHandle, TS_TST_INFO_get_time_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_time);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_time_allownil)}
    TS_TST_INFO_get_time := ERR_TS_TST_INFO_get_time;
    {$ifend}
    {$if declared(TS_TST_INFO_get_time_introduced)}
    if LibVersion < TS_TST_INFO_get_time_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_time)}
      TS_TST_INFO_get_time := FC_TS_TST_INFO_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_time_removed)}
    if TS_TST_INFO_get_time_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_time)}
      TS_TST_INFO_get_time := _TS_TST_INFO_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_time_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_time');
    {$ifend}
  end;
  
  TS_TST_INFO_set_accuracy := LoadLibFunction(ADllHandle, TS_TST_INFO_set_accuracy_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_accuracy);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_accuracy_allownil)}
    TS_TST_INFO_set_accuracy := ERR_TS_TST_INFO_set_accuracy;
    {$ifend}
    {$if declared(TS_TST_INFO_set_accuracy_introduced)}
    if LibVersion < TS_TST_INFO_set_accuracy_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_accuracy)}
      TS_TST_INFO_set_accuracy := FC_TS_TST_INFO_set_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_accuracy_removed)}
    if TS_TST_INFO_set_accuracy_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_accuracy)}
      TS_TST_INFO_set_accuracy := _TS_TST_INFO_set_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_accuracy_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_accuracy');
    {$ifend}
  end;
  
  TS_TST_INFO_get_accuracy := LoadLibFunction(ADllHandle, TS_TST_INFO_get_accuracy_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_accuracy);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_accuracy_allownil)}
    TS_TST_INFO_get_accuracy := ERR_TS_TST_INFO_get_accuracy;
    {$ifend}
    {$if declared(TS_TST_INFO_get_accuracy_introduced)}
    if LibVersion < TS_TST_INFO_get_accuracy_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_accuracy)}
      TS_TST_INFO_get_accuracy := FC_TS_TST_INFO_get_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_accuracy_removed)}
    if TS_TST_INFO_get_accuracy_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_accuracy)}
      TS_TST_INFO_get_accuracy := _TS_TST_INFO_get_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_accuracy_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_accuracy');
    {$ifend}
  end;
  
  TS_ACCURACY_set_seconds := LoadLibFunction(ADllHandle, TS_ACCURACY_set_seconds_procname);
  FuncLoadError := not assigned(TS_ACCURACY_set_seconds);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_set_seconds_allownil)}
    TS_ACCURACY_set_seconds := ERR_TS_ACCURACY_set_seconds;
    {$ifend}
    {$if declared(TS_ACCURACY_set_seconds_introduced)}
    if LibVersion < TS_ACCURACY_set_seconds_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_set_seconds)}
      TS_ACCURACY_set_seconds := FC_TS_ACCURACY_set_seconds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_set_seconds_removed)}
    if TS_ACCURACY_set_seconds_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_set_seconds)}
      TS_ACCURACY_set_seconds := _TS_ACCURACY_set_seconds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_set_seconds_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_set_seconds');
    {$ifend}
  end;
  
  TS_ACCURACY_get_seconds := LoadLibFunction(ADllHandle, TS_ACCURACY_get_seconds_procname);
  FuncLoadError := not assigned(TS_ACCURACY_get_seconds);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_get_seconds_allownil)}
    TS_ACCURACY_get_seconds := ERR_TS_ACCURACY_get_seconds;
    {$ifend}
    {$if declared(TS_ACCURACY_get_seconds_introduced)}
    if LibVersion < TS_ACCURACY_get_seconds_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_get_seconds)}
      TS_ACCURACY_get_seconds := FC_TS_ACCURACY_get_seconds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_get_seconds_removed)}
    if TS_ACCURACY_get_seconds_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_get_seconds)}
      TS_ACCURACY_get_seconds := _TS_ACCURACY_get_seconds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_get_seconds_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_get_seconds');
    {$ifend}
  end;
  
  TS_ACCURACY_set_millis := LoadLibFunction(ADllHandle, TS_ACCURACY_set_millis_procname);
  FuncLoadError := not assigned(TS_ACCURACY_set_millis);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_set_millis_allownil)}
    TS_ACCURACY_set_millis := ERR_TS_ACCURACY_set_millis;
    {$ifend}
    {$if declared(TS_ACCURACY_set_millis_introduced)}
    if LibVersion < TS_ACCURACY_set_millis_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_set_millis)}
      TS_ACCURACY_set_millis := FC_TS_ACCURACY_set_millis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_set_millis_removed)}
    if TS_ACCURACY_set_millis_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_set_millis)}
      TS_ACCURACY_set_millis := _TS_ACCURACY_set_millis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_set_millis_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_set_millis');
    {$ifend}
  end;
  
  TS_ACCURACY_get_millis := LoadLibFunction(ADllHandle, TS_ACCURACY_get_millis_procname);
  FuncLoadError := not assigned(TS_ACCURACY_get_millis);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_get_millis_allownil)}
    TS_ACCURACY_get_millis := ERR_TS_ACCURACY_get_millis;
    {$ifend}
    {$if declared(TS_ACCURACY_get_millis_introduced)}
    if LibVersion < TS_ACCURACY_get_millis_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_get_millis)}
      TS_ACCURACY_get_millis := FC_TS_ACCURACY_get_millis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_get_millis_removed)}
    if TS_ACCURACY_get_millis_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_get_millis)}
      TS_ACCURACY_get_millis := _TS_ACCURACY_get_millis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_get_millis_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_get_millis');
    {$ifend}
  end;
  
  TS_ACCURACY_set_micros := LoadLibFunction(ADllHandle, TS_ACCURACY_set_micros_procname);
  FuncLoadError := not assigned(TS_ACCURACY_set_micros);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_set_micros_allownil)}
    TS_ACCURACY_set_micros := ERR_TS_ACCURACY_set_micros;
    {$ifend}
    {$if declared(TS_ACCURACY_set_micros_introduced)}
    if LibVersion < TS_ACCURACY_set_micros_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_set_micros)}
      TS_ACCURACY_set_micros := FC_TS_ACCURACY_set_micros;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_set_micros_removed)}
    if TS_ACCURACY_set_micros_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_set_micros)}
      TS_ACCURACY_set_micros := _TS_ACCURACY_set_micros;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_set_micros_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_set_micros');
    {$ifend}
  end;
  
  TS_ACCURACY_get_micros := LoadLibFunction(ADllHandle, TS_ACCURACY_get_micros_procname);
  FuncLoadError := not assigned(TS_ACCURACY_get_micros);
  if FuncLoadError then
  begin
    {$if not defined(TS_ACCURACY_get_micros_allownil)}
    TS_ACCURACY_get_micros := ERR_TS_ACCURACY_get_micros;
    {$ifend}
    {$if declared(TS_ACCURACY_get_micros_introduced)}
    if LibVersion < TS_ACCURACY_get_micros_introduced then
    begin
      {$if declared(FC_TS_ACCURACY_get_micros)}
      TS_ACCURACY_get_micros := FC_TS_ACCURACY_get_micros;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ACCURACY_get_micros_removed)}
    if TS_ACCURACY_get_micros_removed <= LibVersion then
    begin
      {$if declared(_TS_ACCURACY_get_micros)}
      TS_ACCURACY_get_micros := _TS_ACCURACY_get_micros;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ACCURACY_get_micros_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ACCURACY_get_micros');
    {$ifend}
  end;
  
  TS_TST_INFO_set_ordering := LoadLibFunction(ADllHandle, TS_TST_INFO_set_ordering_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_ordering);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_ordering_allownil)}
    TS_TST_INFO_set_ordering := ERR_TS_TST_INFO_set_ordering;
    {$ifend}
    {$if declared(TS_TST_INFO_set_ordering_introduced)}
    if LibVersion < TS_TST_INFO_set_ordering_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_ordering)}
      TS_TST_INFO_set_ordering := FC_TS_TST_INFO_set_ordering;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_ordering_removed)}
    if TS_TST_INFO_set_ordering_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_ordering)}
      TS_TST_INFO_set_ordering := _TS_TST_INFO_set_ordering;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_ordering_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_ordering');
    {$ifend}
  end;
  
  TS_TST_INFO_get_ordering := LoadLibFunction(ADllHandle, TS_TST_INFO_get_ordering_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_ordering);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_ordering_allownil)}
    TS_TST_INFO_get_ordering := ERR_TS_TST_INFO_get_ordering;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ordering_introduced)}
    if LibVersion < TS_TST_INFO_get_ordering_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_ordering)}
      TS_TST_INFO_get_ordering := FC_TS_TST_INFO_get_ordering;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ordering_removed)}
    if TS_TST_INFO_get_ordering_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_ordering)}
      TS_TST_INFO_get_ordering := _TS_TST_INFO_get_ordering;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_ordering_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_ordering');
    {$ifend}
  end;
  
  TS_TST_INFO_set_nonce := LoadLibFunction(ADllHandle, TS_TST_INFO_set_nonce_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_nonce);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_nonce_allownil)}
    TS_TST_INFO_set_nonce := ERR_TS_TST_INFO_set_nonce;
    {$ifend}
    {$if declared(TS_TST_INFO_set_nonce_introduced)}
    if LibVersion < TS_TST_INFO_set_nonce_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_nonce)}
      TS_TST_INFO_set_nonce := FC_TS_TST_INFO_set_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_nonce_removed)}
    if TS_TST_INFO_set_nonce_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_nonce)}
      TS_TST_INFO_set_nonce := _TS_TST_INFO_set_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_nonce');
    {$ifend}
  end;
  
  TS_TST_INFO_get_nonce := LoadLibFunction(ADllHandle, TS_TST_INFO_get_nonce_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_nonce);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_nonce_allownil)}
    TS_TST_INFO_get_nonce := ERR_TS_TST_INFO_get_nonce;
    {$ifend}
    {$if declared(TS_TST_INFO_get_nonce_introduced)}
    if LibVersion < TS_TST_INFO_get_nonce_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_nonce)}
      TS_TST_INFO_get_nonce := FC_TS_TST_INFO_get_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_nonce_removed)}
    if TS_TST_INFO_get_nonce_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_nonce)}
      TS_TST_INFO_get_nonce := _TS_TST_INFO_get_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_nonce');
    {$ifend}
  end;
  
  TS_TST_INFO_set_tsa := LoadLibFunction(ADllHandle, TS_TST_INFO_set_tsa_procname);
  FuncLoadError := not assigned(TS_TST_INFO_set_tsa);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_set_tsa_allownil)}
    TS_TST_INFO_set_tsa := ERR_TS_TST_INFO_set_tsa;
    {$ifend}
    {$if declared(TS_TST_INFO_set_tsa_introduced)}
    if LibVersion < TS_TST_INFO_set_tsa_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_set_tsa)}
      TS_TST_INFO_set_tsa := FC_TS_TST_INFO_set_tsa;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_set_tsa_removed)}
    if TS_TST_INFO_set_tsa_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_set_tsa)}
      TS_TST_INFO_set_tsa := _TS_TST_INFO_set_tsa;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_set_tsa_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_set_tsa');
    {$ifend}
  end;
  
  TS_TST_INFO_get_tsa := LoadLibFunction(ADllHandle, TS_TST_INFO_get_tsa_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_tsa);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_tsa_allownil)}
    TS_TST_INFO_get_tsa := ERR_TS_TST_INFO_get_tsa;
    {$ifend}
    {$if declared(TS_TST_INFO_get_tsa_introduced)}
    if LibVersion < TS_TST_INFO_get_tsa_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_tsa)}
      TS_TST_INFO_get_tsa := FC_TS_TST_INFO_get_tsa;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_tsa_removed)}
    if TS_TST_INFO_get_tsa_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_tsa)}
      TS_TST_INFO_get_tsa := _TS_TST_INFO_get_tsa;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_tsa_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_tsa');
    {$ifend}
  end;
  
  TS_TST_INFO_get_exts := LoadLibFunction(ADllHandle, TS_TST_INFO_get_exts_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_exts);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_exts_allownil)}
    TS_TST_INFO_get_exts := ERR_TS_TST_INFO_get_exts;
    {$ifend}
    {$if declared(TS_TST_INFO_get_exts_introduced)}
    if LibVersion < TS_TST_INFO_get_exts_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_exts)}
      TS_TST_INFO_get_exts := FC_TS_TST_INFO_get_exts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_exts_removed)}
    if TS_TST_INFO_get_exts_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_exts)}
      TS_TST_INFO_get_exts := _TS_TST_INFO_get_exts;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_exts_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_exts');
    {$ifend}
  end;
  
  TS_TST_INFO_ext_free := LoadLibFunction(ADllHandle, TS_TST_INFO_ext_free_procname);
  FuncLoadError := not assigned(TS_TST_INFO_ext_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_ext_free_allownil)}
    TS_TST_INFO_ext_free := ERR_TS_TST_INFO_ext_free;
    {$ifend}
    {$if declared(TS_TST_INFO_ext_free_introduced)}
    if LibVersion < TS_TST_INFO_ext_free_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_ext_free)}
      TS_TST_INFO_ext_free := FC_TS_TST_INFO_ext_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_ext_free_removed)}
    if TS_TST_INFO_ext_free_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_ext_free)}
      TS_TST_INFO_ext_free := _TS_TST_INFO_ext_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_ext_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_ext_free');
    {$ifend}
  end;
  
  TS_TST_INFO_get_ext_count := LoadLibFunction(ADllHandle, TS_TST_INFO_get_ext_count_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_ext_count_allownil)}
    TS_TST_INFO_get_ext_count := ERR_TS_TST_INFO_get_ext_count;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_count_introduced)}
    if LibVersion < TS_TST_INFO_get_ext_count_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_ext_count)}
      TS_TST_INFO_get_ext_count := FC_TS_TST_INFO_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_count_removed)}
    if TS_TST_INFO_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_ext_count)}
      TS_TST_INFO_get_ext_count := _TS_TST_INFO_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_ext_count');
    {$ifend}
  end;
  
  TS_TST_INFO_get_ext_by_NID := LoadLibFunction(ADllHandle, TS_TST_INFO_get_ext_by_NID_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_ext_by_NID_allownil)}
    TS_TST_INFO_get_ext_by_NID := ERR_TS_TST_INFO_get_ext_by_NID;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_by_NID_introduced)}
    if LibVersion < TS_TST_INFO_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_ext_by_NID)}
      TS_TST_INFO_get_ext_by_NID := FC_TS_TST_INFO_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_by_NID_removed)}
    if TS_TST_INFO_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_ext_by_NID)}
      TS_TST_INFO_get_ext_by_NID := _TS_TST_INFO_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_ext_by_NID');
    {$ifend}
  end;
  
  TS_TST_INFO_get_ext_by_OBJ := LoadLibFunction(ADllHandle, TS_TST_INFO_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_ext_by_OBJ_allownil)}
    TS_TST_INFO_get_ext_by_OBJ := ERR_TS_TST_INFO_get_ext_by_OBJ;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_by_OBJ_introduced)}
    if LibVersion < TS_TST_INFO_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_ext_by_OBJ)}
      TS_TST_INFO_get_ext_by_OBJ := FC_TS_TST_INFO_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_by_OBJ_removed)}
    if TS_TST_INFO_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_ext_by_OBJ)}
      TS_TST_INFO_get_ext_by_OBJ := _TS_TST_INFO_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_ext_by_OBJ');
    {$ifend}
  end;
  
  TS_TST_INFO_get_ext_by_critical := LoadLibFunction(ADllHandle, TS_TST_INFO_get_ext_by_critical_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_ext_by_critical_allownil)}
    TS_TST_INFO_get_ext_by_critical := ERR_TS_TST_INFO_get_ext_by_critical;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_by_critical_introduced)}
    if LibVersion < TS_TST_INFO_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_ext_by_critical)}
      TS_TST_INFO_get_ext_by_critical := FC_TS_TST_INFO_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_by_critical_removed)}
    if TS_TST_INFO_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_ext_by_critical)}
      TS_TST_INFO_get_ext_by_critical := _TS_TST_INFO_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_ext_by_critical');
    {$ifend}
  end;
  
  TS_TST_INFO_get_ext := LoadLibFunction(ADllHandle, TS_TST_INFO_get_ext_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_ext_allownil)}
    TS_TST_INFO_get_ext := ERR_TS_TST_INFO_get_ext;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_introduced)}
    if LibVersion < TS_TST_INFO_get_ext_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_ext)}
      TS_TST_INFO_get_ext := FC_TS_TST_INFO_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_removed)}
    if TS_TST_INFO_get_ext_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_ext)}
      TS_TST_INFO_get_ext := _TS_TST_INFO_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_ext');
    {$ifend}
  end;
  
  TS_TST_INFO_delete_ext := LoadLibFunction(ADllHandle, TS_TST_INFO_delete_ext_procname);
  FuncLoadError := not assigned(TS_TST_INFO_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_delete_ext_allownil)}
    TS_TST_INFO_delete_ext := ERR_TS_TST_INFO_delete_ext;
    {$ifend}
    {$if declared(TS_TST_INFO_delete_ext_introduced)}
    if LibVersion < TS_TST_INFO_delete_ext_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_delete_ext)}
      TS_TST_INFO_delete_ext := FC_TS_TST_INFO_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_delete_ext_removed)}
    if TS_TST_INFO_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_delete_ext)}
      TS_TST_INFO_delete_ext := _TS_TST_INFO_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_delete_ext');
    {$ifend}
  end;
  
  TS_TST_INFO_add_ext := LoadLibFunction(ADllHandle, TS_TST_INFO_add_ext_procname);
  FuncLoadError := not assigned(TS_TST_INFO_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_add_ext_allownil)}
    TS_TST_INFO_add_ext := ERR_TS_TST_INFO_add_ext;
    {$ifend}
    {$if declared(TS_TST_INFO_add_ext_introduced)}
    if LibVersion < TS_TST_INFO_add_ext_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_add_ext)}
      TS_TST_INFO_add_ext := FC_TS_TST_INFO_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_add_ext_removed)}
    if TS_TST_INFO_add_ext_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_add_ext)}
      TS_TST_INFO_add_ext := _TS_TST_INFO_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_add_ext');
    {$ifend}
  end;
  
  TS_TST_INFO_get_ext_d2i := LoadLibFunction(ADllHandle, TS_TST_INFO_get_ext_d2i_procname);
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_get_ext_d2i_allownil)}
    TS_TST_INFO_get_ext_d2i := ERR_TS_TST_INFO_get_ext_d2i;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_d2i_introduced)}
    if LibVersion < TS_TST_INFO_get_ext_d2i_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_get_ext_d2i)}
      TS_TST_INFO_get_ext_d2i := FC_TS_TST_INFO_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_get_ext_d2i_removed)}
    if TS_TST_INFO_get_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_get_ext_d2i)}
      TS_TST_INFO_get_ext_d2i := _TS_TST_INFO_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_get_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_get_ext_d2i');
    {$ifend}
  end;
  
  TS_RESP_CTX_new := LoadLibFunction(ADllHandle, TS_RESP_CTX_new_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_new_allownil)}
    TS_RESP_CTX_new := ERR_TS_RESP_CTX_new;
    {$ifend}
    {$if declared(TS_RESP_CTX_new_introduced)}
    if LibVersion < TS_RESP_CTX_new_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_new)}
      TS_RESP_CTX_new := FC_TS_RESP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_new_removed)}
    if TS_RESP_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_new)}
      TS_RESP_CTX_new := _TS_RESP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_new');
    {$ifend}
  end;
  
  TS_RESP_CTX_new_ex := LoadLibFunction(ADllHandle, TS_RESP_CTX_new_ex_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_new_ex_allownil)}
    TS_RESP_CTX_new_ex := ERR_TS_RESP_CTX_new_ex;
    {$ifend}
    {$if declared(TS_RESP_CTX_new_ex_introduced)}
    if LibVersion < TS_RESP_CTX_new_ex_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_new_ex)}
      TS_RESP_CTX_new_ex := FC_TS_RESP_CTX_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_new_ex_removed)}
    if TS_RESP_CTX_new_ex_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_new_ex)}
      TS_RESP_CTX_new_ex := _TS_RESP_CTX_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_new_ex');
    {$ifend}
  end;
  
  TS_RESP_CTX_free := LoadLibFunction(ADllHandle, TS_RESP_CTX_free_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_free_allownil)}
    TS_RESP_CTX_free := ERR_TS_RESP_CTX_free;
    {$ifend}
    {$if declared(TS_RESP_CTX_free_introduced)}
    if LibVersion < TS_RESP_CTX_free_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_free)}
      TS_RESP_CTX_free := FC_TS_RESP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_free_removed)}
    if TS_RESP_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_free)}
      TS_RESP_CTX_free := _TS_RESP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_free');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_signer_cert := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_signer_cert_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_signer_cert);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_signer_cert_allownil)}
    TS_RESP_CTX_set_signer_cert := ERR_TS_RESP_CTX_set_signer_cert;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_signer_cert_introduced)}
    if LibVersion < TS_RESP_CTX_set_signer_cert_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_signer_cert)}
      TS_RESP_CTX_set_signer_cert := FC_TS_RESP_CTX_set_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_signer_cert_removed)}
    if TS_RESP_CTX_set_signer_cert_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_signer_cert)}
      TS_RESP_CTX_set_signer_cert := _TS_RESP_CTX_set_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_signer_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_signer_cert');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_signer_key := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_signer_key_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_signer_key);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_signer_key_allownil)}
    TS_RESP_CTX_set_signer_key := ERR_TS_RESP_CTX_set_signer_key;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_signer_key_introduced)}
    if LibVersion < TS_RESP_CTX_set_signer_key_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_signer_key)}
      TS_RESP_CTX_set_signer_key := FC_TS_RESP_CTX_set_signer_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_signer_key_removed)}
    if TS_RESP_CTX_set_signer_key_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_signer_key)}
      TS_RESP_CTX_set_signer_key := _TS_RESP_CTX_set_signer_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_signer_key_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_signer_key');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_signer_digest := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_signer_digest_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_signer_digest);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_signer_digest_allownil)}
    TS_RESP_CTX_set_signer_digest := ERR_TS_RESP_CTX_set_signer_digest;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_signer_digest_introduced)}
    if LibVersion < TS_RESP_CTX_set_signer_digest_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_signer_digest)}
      TS_RESP_CTX_set_signer_digest := FC_TS_RESP_CTX_set_signer_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_signer_digest_removed)}
    if TS_RESP_CTX_set_signer_digest_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_signer_digest)}
      TS_RESP_CTX_set_signer_digest := _TS_RESP_CTX_set_signer_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_signer_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_signer_digest');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_ess_cert_id_digest := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_ess_cert_id_digest_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_ess_cert_id_digest);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_ess_cert_id_digest_allownil)}
    TS_RESP_CTX_set_ess_cert_id_digest := ERR_TS_RESP_CTX_set_ess_cert_id_digest;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_ess_cert_id_digest_introduced)}
    if LibVersion < TS_RESP_CTX_set_ess_cert_id_digest_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_ess_cert_id_digest)}
      TS_RESP_CTX_set_ess_cert_id_digest := FC_TS_RESP_CTX_set_ess_cert_id_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_ess_cert_id_digest_removed)}
    if TS_RESP_CTX_set_ess_cert_id_digest_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_ess_cert_id_digest)}
      TS_RESP_CTX_set_ess_cert_id_digest := _TS_RESP_CTX_set_ess_cert_id_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_ess_cert_id_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_ess_cert_id_digest');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_def_policy := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_def_policy_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_def_policy);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_def_policy_allownil)}
    TS_RESP_CTX_set_def_policy := ERR_TS_RESP_CTX_set_def_policy;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_def_policy_introduced)}
    if LibVersion < TS_RESP_CTX_set_def_policy_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_def_policy)}
      TS_RESP_CTX_set_def_policy := FC_TS_RESP_CTX_set_def_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_def_policy_removed)}
    if TS_RESP_CTX_set_def_policy_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_def_policy)}
      TS_RESP_CTX_set_def_policy := _TS_RESP_CTX_set_def_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_def_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_def_policy');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_certs := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_certs_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_certs);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_certs_allownil)}
    TS_RESP_CTX_set_certs := ERR_TS_RESP_CTX_set_certs;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_certs_introduced)}
    if LibVersion < TS_RESP_CTX_set_certs_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_certs)}
      TS_RESP_CTX_set_certs := FC_TS_RESP_CTX_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_certs_removed)}
    if TS_RESP_CTX_set_certs_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_certs)}
      TS_RESP_CTX_set_certs := _TS_RESP_CTX_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_certs');
    {$ifend}
  end;
  
  TS_RESP_CTX_add_policy := LoadLibFunction(ADllHandle, TS_RESP_CTX_add_policy_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_add_policy);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_add_policy_allownil)}
    TS_RESP_CTX_add_policy := ERR_TS_RESP_CTX_add_policy;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_policy_introduced)}
    if LibVersion < TS_RESP_CTX_add_policy_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_add_policy)}
      TS_RESP_CTX_add_policy := FC_TS_RESP_CTX_add_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_policy_removed)}
    if TS_RESP_CTX_add_policy_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_add_policy)}
      TS_RESP_CTX_add_policy := _TS_RESP_CTX_add_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_add_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_add_policy');
    {$ifend}
  end;
  
  TS_RESP_CTX_add_md := LoadLibFunction(ADllHandle, TS_RESP_CTX_add_md_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_add_md);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_add_md_allownil)}
    TS_RESP_CTX_add_md := ERR_TS_RESP_CTX_add_md;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_md_introduced)}
    if LibVersion < TS_RESP_CTX_add_md_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_add_md)}
      TS_RESP_CTX_add_md := FC_TS_RESP_CTX_add_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_md_removed)}
    if TS_RESP_CTX_add_md_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_add_md)}
      TS_RESP_CTX_add_md := _TS_RESP_CTX_add_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_add_md_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_add_md');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_accuracy := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_accuracy_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_accuracy);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_accuracy_allownil)}
    TS_RESP_CTX_set_accuracy := ERR_TS_RESP_CTX_set_accuracy;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_accuracy_introduced)}
    if LibVersion < TS_RESP_CTX_set_accuracy_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_accuracy)}
      TS_RESP_CTX_set_accuracy := FC_TS_RESP_CTX_set_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_accuracy_removed)}
    if TS_RESP_CTX_set_accuracy_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_accuracy)}
      TS_RESP_CTX_set_accuracy := _TS_RESP_CTX_set_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_accuracy_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_accuracy');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_clock_precision_digits := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_clock_precision_digits_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_clock_precision_digits);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_clock_precision_digits_allownil)}
    TS_RESP_CTX_set_clock_precision_digits := ERR_TS_RESP_CTX_set_clock_precision_digits;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_clock_precision_digits_introduced)}
    if LibVersion < TS_RESP_CTX_set_clock_precision_digits_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_clock_precision_digits)}
      TS_RESP_CTX_set_clock_precision_digits := FC_TS_RESP_CTX_set_clock_precision_digits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_clock_precision_digits_removed)}
    if TS_RESP_CTX_set_clock_precision_digits_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_clock_precision_digits)}
      TS_RESP_CTX_set_clock_precision_digits := _TS_RESP_CTX_set_clock_precision_digits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_clock_precision_digits_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_clock_precision_digits');
    {$ifend}
  end;
  
  TS_RESP_CTX_add_flags := LoadLibFunction(ADllHandle, TS_RESP_CTX_add_flags_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_add_flags);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_add_flags_allownil)}
    TS_RESP_CTX_add_flags := ERR_TS_RESP_CTX_add_flags;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_flags_introduced)}
    if LibVersion < TS_RESP_CTX_add_flags_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_add_flags)}
      TS_RESP_CTX_add_flags := FC_TS_RESP_CTX_add_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_flags_removed)}
    if TS_RESP_CTX_add_flags_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_add_flags)}
      TS_RESP_CTX_add_flags := _TS_RESP_CTX_add_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_add_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_add_flags');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_serial_cb := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_serial_cb_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_serial_cb);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_serial_cb_allownil)}
    TS_RESP_CTX_set_serial_cb := ERR_TS_RESP_CTX_set_serial_cb;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_serial_cb_introduced)}
    if LibVersion < TS_RESP_CTX_set_serial_cb_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_serial_cb)}
      TS_RESP_CTX_set_serial_cb := FC_TS_RESP_CTX_set_serial_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_serial_cb_removed)}
    if TS_RESP_CTX_set_serial_cb_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_serial_cb)}
      TS_RESP_CTX_set_serial_cb := _TS_RESP_CTX_set_serial_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_serial_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_serial_cb');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_time_cb := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_time_cb_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_time_cb);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_time_cb_allownil)}
    TS_RESP_CTX_set_time_cb := ERR_TS_RESP_CTX_set_time_cb;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_time_cb_introduced)}
    if LibVersion < TS_RESP_CTX_set_time_cb_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_time_cb)}
      TS_RESP_CTX_set_time_cb := FC_TS_RESP_CTX_set_time_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_time_cb_removed)}
    if TS_RESP_CTX_set_time_cb_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_time_cb)}
      TS_RESP_CTX_set_time_cb := _TS_RESP_CTX_set_time_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_time_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_time_cb');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_extension_cb := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_extension_cb_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_extension_cb);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_extension_cb_allownil)}
    TS_RESP_CTX_set_extension_cb := ERR_TS_RESP_CTX_set_extension_cb;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_extension_cb_introduced)}
    if LibVersion < TS_RESP_CTX_set_extension_cb_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_extension_cb)}
      TS_RESP_CTX_set_extension_cb := FC_TS_RESP_CTX_set_extension_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_extension_cb_removed)}
    if TS_RESP_CTX_set_extension_cb_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_extension_cb)}
      TS_RESP_CTX_set_extension_cb := _TS_RESP_CTX_set_extension_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_extension_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_extension_cb');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_status_info := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_status_info_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_status_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_status_info_allownil)}
    TS_RESP_CTX_set_status_info := ERR_TS_RESP_CTX_set_status_info;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_status_info_introduced)}
    if LibVersion < TS_RESP_CTX_set_status_info_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_status_info)}
      TS_RESP_CTX_set_status_info := FC_TS_RESP_CTX_set_status_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_status_info_removed)}
    if TS_RESP_CTX_set_status_info_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_status_info)}
      TS_RESP_CTX_set_status_info := _TS_RESP_CTX_set_status_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_status_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_status_info');
    {$ifend}
  end;
  
  TS_RESP_CTX_set_status_info_cond := LoadLibFunction(ADllHandle, TS_RESP_CTX_set_status_info_cond_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_set_status_info_cond);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_set_status_info_cond_allownil)}
    TS_RESP_CTX_set_status_info_cond := ERR_TS_RESP_CTX_set_status_info_cond;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_status_info_cond_introduced)}
    if LibVersion < TS_RESP_CTX_set_status_info_cond_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_set_status_info_cond)}
      TS_RESP_CTX_set_status_info_cond := FC_TS_RESP_CTX_set_status_info_cond;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_set_status_info_cond_removed)}
    if TS_RESP_CTX_set_status_info_cond_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_set_status_info_cond)}
      TS_RESP_CTX_set_status_info_cond := _TS_RESP_CTX_set_status_info_cond;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_set_status_info_cond_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_set_status_info_cond');
    {$ifend}
  end;
  
  TS_RESP_CTX_add_failure_info := LoadLibFunction(ADllHandle, TS_RESP_CTX_add_failure_info_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_add_failure_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_add_failure_info_allownil)}
    TS_RESP_CTX_add_failure_info := ERR_TS_RESP_CTX_add_failure_info;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_failure_info_introduced)}
    if LibVersion < TS_RESP_CTX_add_failure_info_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_add_failure_info)}
      TS_RESP_CTX_add_failure_info := FC_TS_RESP_CTX_add_failure_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_add_failure_info_removed)}
    if TS_RESP_CTX_add_failure_info_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_add_failure_info)}
      TS_RESP_CTX_add_failure_info := _TS_RESP_CTX_add_failure_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_add_failure_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_add_failure_info');
    {$ifend}
  end;
  
  TS_RESP_CTX_get_request := LoadLibFunction(ADllHandle, TS_RESP_CTX_get_request_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_get_request);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_get_request_allownil)}
    TS_RESP_CTX_get_request := ERR_TS_RESP_CTX_get_request;
    {$ifend}
    {$if declared(TS_RESP_CTX_get_request_introduced)}
    if LibVersion < TS_RESP_CTX_get_request_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_get_request)}
      TS_RESP_CTX_get_request := FC_TS_RESP_CTX_get_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_get_request_removed)}
    if TS_RESP_CTX_get_request_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_get_request)}
      TS_RESP_CTX_get_request := _TS_RESP_CTX_get_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_get_request_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_get_request');
    {$ifend}
  end;
  
  TS_RESP_CTX_get_tst_info := LoadLibFunction(ADllHandle, TS_RESP_CTX_get_tst_info_procname);
  FuncLoadError := not assigned(TS_RESP_CTX_get_tst_info);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_CTX_get_tst_info_allownil)}
    TS_RESP_CTX_get_tst_info := ERR_TS_RESP_CTX_get_tst_info;
    {$ifend}
    {$if declared(TS_RESP_CTX_get_tst_info_introduced)}
    if LibVersion < TS_RESP_CTX_get_tst_info_introduced then
    begin
      {$if declared(FC_TS_RESP_CTX_get_tst_info)}
      TS_RESP_CTX_get_tst_info := FC_TS_RESP_CTX_get_tst_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_CTX_get_tst_info_removed)}
    if TS_RESP_CTX_get_tst_info_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_CTX_get_tst_info)}
      TS_RESP_CTX_get_tst_info := _TS_RESP_CTX_get_tst_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_CTX_get_tst_info_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_CTX_get_tst_info');
    {$ifend}
  end;
  
  TS_RESP_create_response := LoadLibFunction(ADllHandle, TS_RESP_create_response_procname);
  FuncLoadError := not assigned(TS_RESP_create_response);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_create_response_allownil)}
    TS_RESP_create_response := ERR_TS_RESP_create_response;
    {$ifend}
    {$if declared(TS_RESP_create_response_introduced)}
    if LibVersion < TS_RESP_create_response_introduced then
    begin
      {$if declared(FC_TS_RESP_create_response)}
      TS_RESP_create_response := FC_TS_RESP_create_response;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_create_response_removed)}
    if TS_RESP_create_response_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_create_response)}
      TS_RESP_create_response := _TS_RESP_create_response;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_create_response_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_create_response');
    {$ifend}
  end;
  
  TS_RESP_verify_signature := LoadLibFunction(ADllHandle, TS_RESP_verify_signature_procname);
  FuncLoadError := not assigned(TS_RESP_verify_signature);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_verify_signature_allownil)}
    TS_RESP_verify_signature := ERR_TS_RESP_verify_signature;
    {$ifend}
    {$if declared(TS_RESP_verify_signature_introduced)}
    if LibVersion < TS_RESP_verify_signature_introduced then
    begin
      {$if declared(FC_TS_RESP_verify_signature)}
      TS_RESP_verify_signature := FC_TS_RESP_verify_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_verify_signature_removed)}
    if TS_RESP_verify_signature_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_verify_signature)}
      TS_RESP_verify_signature := _TS_RESP_verify_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_verify_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_verify_signature');
    {$ifend}
  end;
  
  TS_RESP_verify_response := LoadLibFunction(ADllHandle, TS_RESP_verify_response_procname);
  FuncLoadError := not assigned(TS_RESP_verify_response);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_verify_response_allownil)}
    TS_RESP_verify_response := ERR_TS_RESP_verify_response;
    {$ifend}
    {$if declared(TS_RESP_verify_response_introduced)}
    if LibVersion < TS_RESP_verify_response_introduced then
    begin
      {$if declared(FC_TS_RESP_verify_response)}
      TS_RESP_verify_response := FC_TS_RESP_verify_response;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_verify_response_removed)}
    if TS_RESP_verify_response_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_verify_response)}
      TS_RESP_verify_response := _TS_RESP_verify_response;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_verify_response_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_verify_response');
    {$ifend}
  end;
  
  TS_RESP_verify_token := LoadLibFunction(ADllHandle, TS_RESP_verify_token_procname);
  FuncLoadError := not assigned(TS_RESP_verify_token);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_verify_token_allownil)}
    TS_RESP_verify_token := ERR_TS_RESP_verify_token;
    {$ifend}
    {$if declared(TS_RESP_verify_token_introduced)}
    if LibVersion < TS_RESP_verify_token_introduced then
    begin
      {$if declared(FC_TS_RESP_verify_token)}
      TS_RESP_verify_token := FC_TS_RESP_verify_token;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_verify_token_removed)}
    if TS_RESP_verify_token_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_verify_token)}
      TS_RESP_verify_token := _TS_RESP_verify_token;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_verify_token_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_verify_token');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_new := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_new_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_new_allownil)}
    TS_VERIFY_CTX_new := ERR_TS_VERIFY_CTX_new;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_new_introduced)}
    if LibVersion < TS_VERIFY_CTX_new_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_new)}
      TS_VERIFY_CTX_new := FC_TS_VERIFY_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_new_removed)}
    if TS_VERIFY_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_new)}
      TS_VERIFY_CTX_new := _TS_VERIFY_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_new');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_init := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_init_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_init);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_init_allownil)}
    TS_VERIFY_CTX_init := ERR_TS_VERIFY_CTX_init;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_init_introduced)}
    if LibVersion < TS_VERIFY_CTX_init_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_init)}
      TS_VERIFY_CTX_init := FC_TS_VERIFY_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_init_removed)}
    if TS_VERIFY_CTX_init_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_init)}
      TS_VERIFY_CTX_init := _TS_VERIFY_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_init_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_init');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_free := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_free_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_free_allownil)}
    TS_VERIFY_CTX_free := ERR_TS_VERIFY_CTX_free;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_free_introduced)}
    if LibVersion < TS_VERIFY_CTX_free_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_free)}
      TS_VERIFY_CTX_free := FC_TS_VERIFY_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_free_removed)}
    if TS_VERIFY_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_free)}
      TS_VERIFY_CTX_free := _TS_VERIFY_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_free');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_cleanup := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_cleanup_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_cleanup_allownil)}
    TS_VERIFY_CTX_cleanup := ERR_TS_VERIFY_CTX_cleanup;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_cleanup_introduced)}
    if LibVersion < TS_VERIFY_CTX_cleanup_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_cleanup)}
      TS_VERIFY_CTX_cleanup := FC_TS_VERIFY_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_cleanup_removed)}
    if TS_VERIFY_CTX_cleanup_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_cleanup)}
      TS_VERIFY_CTX_cleanup := _TS_VERIFY_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_cleanup');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set_flags := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set_flags_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set_flags_allownil)}
    TS_VERIFY_CTX_set_flags := ERR_TS_VERIFY_CTX_set_flags;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_flags_introduced)}
    if LibVersion < TS_VERIFY_CTX_set_flags_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set_flags)}
      TS_VERIFY_CTX_set_flags := FC_TS_VERIFY_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_flags_removed)}
    if TS_VERIFY_CTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set_flags)}
      TS_VERIFY_CTX_set_flags := _TS_VERIFY_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set_flags');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_add_flags := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_add_flags_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_add_flags);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_add_flags_allownil)}
    TS_VERIFY_CTX_add_flags := ERR_TS_VERIFY_CTX_add_flags;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_add_flags_introduced)}
    if LibVersion < TS_VERIFY_CTX_add_flags_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_add_flags)}
      TS_VERIFY_CTX_add_flags := FC_TS_VERIFY_CTX_add_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_add_flags_removed)}
    if TS_VERIFY_CTX_add_flags_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_add_flags)}
      TS_VERIFY_CTX_add_flags := _TS_VERIFY_CTX_add_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_add_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_add_flags');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set_data := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set_data_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_data);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set_data_allownil)}
    TS_VERIFY_CTX_set_data := ERR_TS_VERIFY_CTX_set_data;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_data_introduced)}
    if LibVersion < TS_VERIFY_CTX_set_data_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set_data)}
      TS_VERIFY_CTX_set_data := FC_TS_VERIFY_CTX_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_data_removed)}
    if TS_VERIFY_CTX_set_data_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set_data)}
      TS_VERIFY_CTX_set_data := _TS_VERIFY_CTX_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set_data_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set_data');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set0_data := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set0_data_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set0_data);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set0_data_allownil)}
    TS_VERIFY_CTX_set0_data := ERR_TS_VERIFY_CTX_set0_data;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_data_introduced)}
    if LibVersion < TS_VERIFY_CTX_set0_data_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set0_data)}
      TS_VERIFY_CTX_set0_data := FC_TS_VERIFY_CTX_set0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_data_removed)}
    if TS_VERIFY_CTX_set0_data_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set0_data)}
      TS_VERIFY_CTX_set0_data := _TS_VERIFY_CTX_set0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set0_data_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set0_data');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set_imprint := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set_imprint_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_imprint);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set_imprint_allownil)}
    TS_VERIFY_CTX_set_imprint := ERR_TS_VERIFY_CTX_set_imprint;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_imprint_introduced)}
    if LibVersion < TS_VERIFY_CTX_set_imprint_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set_imprint)}
      TS_VERIFY_CTX_set_imprint := FC_TS_VERIFY_CTX_set_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_imprint_removed)}
    if TS_VERIFY_CTX_set_imprint_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set_imprint)}
      TS_VERIFY_CTX_set_imprint := _TS_VERIFY_CTX_set_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set_imprint_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set_imprint');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set0_imprint := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set0_imprint_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set0_imprint);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set0_imprint_allownil)}
    TS_VERIFY_CTX_set0_imprint := ERR_TS_VERIFY_CTX_set0_imprint;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_imprint_introduced)}
    if LibVersion < TS_VERIFY_CTX_set0_imprint_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set0_imprint)}
      TS_VERIFY_CTX_set0_imprint := FC_TS_VERIFY_CTX_set0_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_imprint_removed)}
    if TS_VERIFY_CTX_set0_imprint_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set0_imprint)}
      TS_VERIFY_CTX_set0_imprint := _TS_VERIFY_CTX_set0_imprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set0_imprint_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set0_imprint');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set_store := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set_store_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_store);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set_store_allownil)}
    TS_VERIFY_CTX_set_store := ERR_TS_VERIFY_CTX_set_store;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_store_introduced)}
    if LibVersion < TS_VERIFY_CTX_set_store_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set_store)}
      TS_VERIFY_CTX_set_store := FC_TS_VERIFY_CTX_set_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_store_removed)}
    if TS_VERIFY_CTX_set_store_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set_store)}
      TS_VERIFY_CTX_set_store := _TS_VERIFY_CTX_set_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set_store_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set_store');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set0_store := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set0_store_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set0_store);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set0_store_allownil)}
    TS_VERIFY_CTX_set0_store := ERR_TS_VERIFY_CTX_set0_store;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_store_introduced)}
    if LibVersion < TS_VERIFY_CTX_set0_store_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set0_store)}
      TS_VERIFY_CTX_set0_store := FC_TS_VERIFY_CTX_set0_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_store_removed)}
    if TS_VERIFY_CTX_set0_store_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set0_store)}
      TS_VERIFY_CTX_set0_store := _TS_VERIFY_CTX_set0_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set0_store_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set0_store');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set_certs := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set_certs_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_certs);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set_certs_allownil)}
    TS_VERIFY_CTX_set_certs := ERR_TS_VERIFY_CTX_set_certs;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_certs_introduced)}
    if LibVersion < TS_VERIFY_CTX_set_certs_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set_certs)}
      TS_VERIFY_CTX_set_certs := FC_TS_VERIFY_CTX_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set_certs_removed)}
    if TS_VERIFY_CTX_set_certs_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set_certs)}
      TS_VERIFY_CTX_set_certs := _TS_VERIFY_CTX_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set_certs');
    {$ifend}
  end;
  
  TS_VERIFY_CTX_set0_certs := LoadLibFunction(ADllHandle, TS_VERIFY_CTX_set0_certs_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTX_set0_certs);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTX_set0_certs_allownil)}
    TS_VERIFY_CTX_set0_certs := ERR_TS_VERIFY_CTX_set0_certs;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_certs_introduced)}
    if LibVersion < TS_VERIFY_CTX_set0_certs_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTX_set0_certs)}
      TS_VERIFY_CTX_set0_certs := FC_TS_VERIFY_CTX_set0_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_certs_removed)}
    if TS_VERIFY_CTX_set0_certs_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTX_set0_certs)}
      TS_VERIFY_CTX_set0_certs := _TS_VERIFY_CTX_set0_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTX_set0_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTX_set0_certs');
    {$ifend}
  end;
  
  TS_REQ_to_TS_VERIFY_CTX := LoadLibFunction(ADllHandle, TS_REQ_to_TS_VERIFY_CTX_procname);
  FuncLoadError := not assigned(TS_REQ_to_TS_VERIFY_CTX);
  if FuncLoadError then
  begin
    {$if not defined(TS_REQ_to_TS_VERIFY_CTX_allownil)}
    TS_REQ_to_TS_VERIFY_CTX := ERR_TS_REQ_to_TS_VERIFY_CTX;
    {$ifend}
    {$if declared(TS_REQ_to_TS_VERIFY_CTX_introduced)}
    if LibVersion < TS_REQ_to_TS_VERIFY_CTX_introduced then
    begin
      {$if declared(FC_TS_REQ_to_TS_VERIFY_CTX)}
      TS_REQ_to_TS_VERIFY_CTX := FC_TS_REQ_to_TS_VERIFY_CTX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_REQ_to_TS_VERIFY_CTX_removed)}
    if TS_REQ_to_TS_VERIFY_CTX_removed <= LibVersion then
    begin
      {$if declared(_TS_REQ_to_TS_VERIFY_CTX)}
      TS_REQ_to_TS_VERIFY_CTX := _TS_REQ_to_TS_VERIFY_CTX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_REQ_to_TS_VERIFY_CTX_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_REQ_to_TS_VERIFY_CTX');
    {$ifend}
  end;
  
  TS_RESP_print_bio := LoadLibFunction(ADllHandle, TS_RESP_print_bio_procname);
  FuncLoadError := not assigned(TS_RESP_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_RESP_print_bio_allownil)}
    TS_RESP_print_bio := ERR_TS_RESP_print_bio;
    {$ifend}
    {$if declared(TS_RESP_print_bio_introduced)}
    if LibVersion < TS_RESP_print_bio_introduced then
    begin
      {$if declared(FC_TS_RESP_print_bio)}
      TS_RESP_print_bio := FC_TS_RESP_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_RESP_print_bio_removed)}
    if TS_RESP_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_RESP_print_bio)}
      TS_RESP_print_bio := _TS_RESP_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_RESP_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_RESP_print_bio');
    {$ifend}
  end;
  
  TS_STATUS_INFO_print_bio := LoadLibFunction(ADllHandle, TS_STATUS_INFO_print_bio_procname);
  FuncLoadError := not assigned(TS_STATUS_INFO_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_STATUS_INFO_print_bio_allownil)}
    TS_STATUS_INFO_print_bio := ERR_TS_STATUS_INFO_print_bio;
    {$ifend}
    {$if declared(TS_STATUS_INFO_print_bio_introduced)}
    if LibVersion < TS_STATUS_INFO_print_bio_introduced then
    begin
      {$if declared(FC_TS_STATUS_INFO_print_bio)}
      TS_STATUS_INFO_print_bio := FC_TS_STATUS_INFO_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_STATUS_INFO_print_bio_removed)}
    if TS_STATUS_INFO_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_STATUS_INFO_print_bio)}
      TS_STATUS_INFO_print_bio := _TS_STATUS_INFO_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_STATUS_INFO_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_STATUS_INFO_print_bio');
    {$ifend}
  end;
  
  TS_TST_INFO_print_bio := LoadLibFunction(ADllHandle, TS_TST_INFO_print_bio_procname);
  FuncLoadError := not assigned(TS_TST_INFO_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_TST_INFO_print_bio_allownil)}
    TS_TST_INFO_print_bio := ERR_TS_TST_INFO_print_bio;
    {$ifend}
    {$if declared(TS_TST_INFO_print_bio_introduced)}
    if LibVersion < TS_TST_INFO_print_bio_introduced then
    begin
      {$if declared(FC_TS_TST_INFO_print_bio)}
      TS_TST_INFO_print_bio := FC_TS_TST_INFO_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_TST_INFO_print_bio_removed)}
    if TS_TST_INFO_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_TST_INFO_print_bio)}
      TS_TST_INFO_print_bio := _TS_TST_INFO_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_TST_INFO_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_TST_INFO_print_bio');
    {$ifend}
  end;
  
  TS_ASN1_INTEGER_print_bio := LoadLibFunction(ADllHandle, TS_ASN1_INTEGER_print_bio_procname);
  FuncLoadError := not assigned(TS_ASN1_INTEGER_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_ASN1_INTEGER_print_bio_allownil)}
    TS_ASN1_INTEGER_print_bio := ERR_TS_ASN1_INTEGER_print_bio;
    {$ifend}
    {$if declared(TS_ASN1_INTEGER_print_bio_introduced)}
    if LibVersion < TS_ASN1_INTEGER_print_bio_introduced then
    begin
      {$if declared(FC_TS_ASN1_INTEGER_print_bio)}
      TS_ASN1_INTEGER_print_bio := FC_TS_ASN1_INTEGER_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ASN1_INTEGER_print_bio_removed)}
    if TS_ASN1_INTEGER_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_ASN1_INTEGER_print_bio)}
      TS_ASN1_INTEGER_print_bio := _TS_ASN1_INTEGER_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ASN1_INTEGER_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ASN1_INTEGER_print_bio');
    {$ifend}
  end;
  
  TS_OBJ_print_bio := LoadLibFunction(ADllHandle, TS_OBJ_print_bio_procname);
  FuncLoadError := not assigned(TS_OBJ_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_OBJ_print_bio_allownil)}
    TS_OBJ_print_bio := ERR_TS_OBJ_print_bio;
    {$ifend}
    {$if declared(TS_OBJ_print_bio_introduced)}
    if LibVersion < TS_OBJ_print_bio_introduced then
    begin
      {$if declared(FC_TS_OBJ_print_bio)}
      TS_OBJ_print_bio := FC_TS_OBJ_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_OBJ_print_bio_removed)}
    if TS_OBJ_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_OBJ_print_bio)}
      TS_OBJ_print_bio := _TS_OBJ_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_OBJ_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_OBJ_print_bio');
    {$ifend}
  end;
  
  TS_ext_print_bio := LoadLibFunction(ADllHandle, TS_ext_print_bio_procname);
  FuncLoadError := not assigned(TS_ext_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_ext_print_bio_allownil)}
    TS_ext_print_bio := ERR_TS_ext_print_bio;
    {$ifend}
    {$if declared(TS_ext_print_bio_introduced)}
    if LibVersion < TS_ext_print_bio_introduced then
    begin
      {$if declared(FC_TS_ext_print_bio)}
      TS_ext_print_bio := FC_TS_ext_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_ext_print_bio_removed)}
    if TS_ext_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_ext_print_bio)}
      TS_ext_print_bio := _TS_ext_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_ext_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_ext_print_bio');
    {$ifend}
  end;
  
  TS_X509_ALGOR_print_bio := LoadLibFunction(ADllHandle, TS_X509_ALGOR_print_bio_procname);
  FuncLoadError := not assigned(TS_X509_ALGOR_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_X509_ALGOR_print_bio_allownil)}
    TS_X509_ALGOR_print_bio := ERR_TS_X509_ALGOR_print_bio;
    {$ifend}
    {$if declared(TS_X509_ALGOR_print_bio_introduced)}
    if LibVersion < TS_X509_ALGOR_print_bio_introduced then
    begin
      {$if declared(FC_TS_X509_ALGOR_print_bio)}
      TS_X509_ALGOR_print_bio := FC_TS_X509_ALGOR_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_X509_ALGOR_print_bio_removed)}
    if TS_X509_ALGOR_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_X509_ALGOR_print_bio)}
      TS_X509_ALGOR_print_bio := _TS_X509_ALGOR_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_X509_ALGOR_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_X509_ALGOR_print_bio');
    {$ifend}
  end;
  
  TS_MSG_IMPRINT_print_bio := LoadLibFunction(ADllHandle, TS_MSG_IMPRINT_print_bio_procname);
  FuncLoadError := not assigned(TS_MSG_IMPRINT_print_bio);
  if FuncLoadError then
  begin
    {$if not defined(TS_MSG_IMPRINT_print_bio_allownil)}
    TS_MSG_IMPRINT_print_bio := ERR_TS_MSG_IMPRINT_print_bio;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_print_bio_introduced)}
    if LibVersion < TS_MSG_IMPRINT_print_bio_introduced then
    begin
      {$if declared(FC_TS_MSG_IMPRINT_print_bio)}
      TS_MSG_IMPRINT_print_bio := FC_TS_MSG_IMPRINT_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_MSG_IMPRINT_print_bio_removed)}
    if TS_MSG_IMPRINT_print_bio_removed <= LibVersion then
    begin
      {$if declared(_TS_MSG_IMPRINT_print_bio)}
      TS_MSG_IMPRINT_print_bio := _TS_MSG_IMPRINT_print_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_MSG_IMPRINT_print_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_MSG_IMPRINT_print_bio');
    {$ifend}
  end;
  
  TS_CONF_load_cert := LoadLibFunction(ADllHandle, TS_CONF_load_cert_procname);
  FuncLoadError := not assigned(TS_CONF_load_cert);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_load_cert_allownil)}
    TS_CONF_load_cert := ERR_TS_CONF_load_cert;
    {$ifend}
    {$if declared(TS_CONF_load_cert_introduced)}
    if LibVersion < TS_CONF_load_cert_introduced then
    begin
      {$if declared(FC_TS_CONF_load_cert)}
      TS_CONF_load_cert := FC_TS_CONF_load_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_load_cert_removed)}
    if TS_CONF_load_cert_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_load_cert)}
      TS_CONF_load_cert := _TS_CONF_load_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_load_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_load_cert');
    {$ifend}
  end;
  
  TS_CONF_load_certs := LoadLibFunction(ADllHandle, TS_CONF_load_certs_procname);
  FuncLoadError := not assigned(TS_CONF_load_certs);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_load_certs_allownil)}
    TS_CONF_load_certs := ERR_TS_CONF_load_certs;
    {$ifend}
    {$if declared(TS_CONF_load_certs_introduced)}
    if LibVersion < TS_CONF_load_certs_introduced then
    begin
      {$if declared(FC_TS_CONF_load_certs)}
      TS_CONF_load_certs := FC_TS_CONF_load_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_load_certs_removed)}
    if TS_CONF_load_certs_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_load_certs)}
      TS_CONF_load_certs := _TS_CONF_load_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_load_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_load_certs');
    {$ifend}
  end;
  
  TS_CONF_load_key := LoadLibFunction(ADllHandle, TS_CONF_load_key_procname);
  FuncLoadError := not assigned(TS_CONF_load_key);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_load_key_allownil)}
    TS_CONF_load_key := ERR_TS_CONF_load_key;
    {$ifend}
    {$if declared(TS_CONF_load_key_introduced)}
    if LibVersion < TS_CONF_load_key_introduced then
    begin
      {$if declared(FC_TS_CONF_load_key)}
      TS_CONF_load_key := FC_TS_CONF_load_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_load_key_removed)}
    if TS_CONF_load_key_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_load_key)}
      TS_CONF_load_key := _TS_CONF_load_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_load_key_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_load_key');
    {$ifend}
  end;
  
  TS_CONF_get_tsa_section := LoadLibFunction(ADllHandle, TS_CONF_get_tsa_section_procname);
  FuncLoadError := not assigned(TS_CONF_get_tsa_section);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_get_tsa_section_allownil)}
    TS_CONF_get_tsa_section := ERR_TS_CONF_get_tsa_section;
    {$ifend}
    {$if declared(TS_CONF_get_tsa_section_introduced)}
    if LibVersion < TS_CONF_get_tsa_section_introduced then
    begin
      {$if declared(FC_TS_CONF_get_tsa_section)}
      TS_CONF_get_tsa_section := FC_TS_CONF_get_tsa_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_get_tsa_section_removed)}
    if TS_CONF_get_tsa_section_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_get_tsa_section)}
      TS_CONF_get_tsa_section := _TS_CONF_get_tsa_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_get_tsa_section_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_get_tsa_section');
    {$ifend}
  end;
  
  TS_CONF_set_serial := LoadLibFunction(ADllHandle, TS_CONF_set_serial_procname);
  FuncLoadError := not assigned(TS_CONF_set_serial);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_serial_allownil)}
    TS_CONF_set_serial := ERR_TS_CONF_set_serial;
    {$ifend}
    {$if declared(TS_CONF_set_serial_introduced)}
    if LibVersion < TS_CONF_set_serial_introduced then
    begin
      {$if declared(FC_TS_CONF_set_serial)}
      TS_CONF_set_serial := FC_TS_CONF_set_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_serial_removed)}
    if TS_CONF_set_serial_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_serial)}
      TS_CONF_set_serial := _TS_CONF_set_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_serial');
    {$ifend}
  end;
  
  TS_CONF_set_crypto_device := LoadLibFunction(ADllHandle, TS_CONF_set_crypto_device_procname);
  FuncLoadError := not assigned(TS_CONF_set_crypto_device);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_crypto_device_allownil)}
    TS_CONF_set_crypto_device := ERR_TS_CONF_set_crypto_device;
    {$ifend}
    {$if declared(TS_CONF_set_crypto_device_introduced)}
    if LibVersion < TS_CONF_set_crypto_device_introduced then
    begin
      {$if declared(FC_TS_CONF_set_crypto_device)}
      TS_CONF_set_crypto_device := FC_TS_CONF_set_crypto_device;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_crypto_device_removed)}
    if TS_CONF_set_crypto_device_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_crypto_device)}
      TS_CONF_set_crypto_device := _TS_CONF_set_crypto_device;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_crypto_device_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_crypto_device');
    {$ifend}
  end;
  
  TS_CONF_set_default_engine := LoadLibFunction(ADllHandle, TS_CONF_set_default_engine_procname);
  FuncLoadError := not assigned(TS_CONF_set_default_engine);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_default_engine_allownil)}
    TS_CONF_set_default_engine := ERR_TS_CONF_set_default_engine;
    {$ifend}
    {$if declared(TS_CONF_set_default_engine_introduced)}
    if LibVersion < TS_CONF_set_default_engine_introduced then
    begin
      {$if declared(FC_TS_CONF_set_default_engine)}
      TS_CONF_set_default_engine := FC_TS_CONF_set_default_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_default_engine_removed)}
    if TS_CONF_set_default_engine_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_default_engine)}
      TS_CONF_set_default_engine := _TS_CONF_set_default_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_default_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_default_engine');
    {$ifend}
  end;
  
  TS_CONF_set_signer_cert := LoadLibFunction(ADllHandle, TS_CONF_set_signer_cert_procname);
  FuncLoadError := not assigned(TS_CONF_set_signer_cert);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_signer_cert_allownil)}
    TS_CONF_set_signer_cert := ERR_TS_CONF_set_signer_cert;
    {$ifend}
    {$if declared(TS_CONF_set_signer_cert_introduced)}
    if LibVersion < TS_CONF_set_signer_cert_introduced then
    begin
      {$if declared(FC_TS_CONF_set_signer_cert)}
      TS_CONF_set_signer_cert := FC_TS_CONF_set_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_signer_cert_removed)}
    if TS_CONF_set_signer_cert_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_signer_cert)}
      TS_CONF_set_signer_cert := _TS_CONF_set_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_signer_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_signer_cert');
    {$ifend}
  end;
  
  TS_CONF_set_certs := LoadLibFunction(ADllHandle, TS_CONF_set_certs_procname);
  FuncLoadError := not assigned(TS_CONF_set_certs);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_certs_allownil)}
    TS_CONF_set_certs := ERR_TS_CONF_set_certs;
    {$ifend}
    {$if declared(TS_CONF_set_certs_introduced)}
    if LibVersion < TS_CONF_set_certs_introduced then
    begin
      {$if declared(FC_TS_CONF_set_certs)}
      TS_CONF_set_certs := FC_TS_CONF_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_certs_removed)}
    if TS_CONF_set_certs_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_certs)}
      TS_CONF_set_certs := _TS_CONF_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_certs');
    {$ifend}
  end;
  
  TS_CONF_set_signer_key := LoadLibFunction(ADllHandle, TS_CONF_set_signer_key_procname);
  FuncLoadError := not assigned(TS_CONF_set_signer_key);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_signer_key_allownil)}
    TS_CONF_set_signer_key := ERR_TS_CONF_set_signer_key;
    {$ifend}
    {$if declared(TS_CONF_set_signer_key_introduced)}
    if LibVersion < TS_CONF_set_signer_key_introduced then
    begin
      {$if declared(FC_TS_CONF_set_signer_key)}
      TS_CONF_set_signer_key := FC_TS_CONF_set_signer_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_signer_key_removed)}
    if TS_CONF_set_signer_key_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_signer_key)}
      TS_CONF_set_signer_key := _TS_CONF_set_signer_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_signer_key_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_signer_key');
    {$ifend}
  end;
  
  TS_CONF_set_signer_digest := LoadLibFunction(ADllHandle, TS_CONF_set_signer_digest_procname);
  FuncLoadError := not assigned(TS_CONF_set_signer_digest);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_signer_digest_allownil)}
    TS_CONF_set_signer_digest := ERR_TS_CONF_set_signer_digest;
    {$ifend}
    {$if declared(TS_CONF_set_signer_digest_introduced)}
    if LibVersion < TS_CONF_set_signer_digest_introduced then
    begin
      {$if declared(FC_TS_CONF_set_signer_digest)}
      TS_CONF_set_signer_digest := FC_TS_CONF_set_signer_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_signer_digest_removed)}
    if TS_CONF_set_signer_digest_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_signer_digest)}
      TS_CONF_set_signer_digest := _TS_CONF_set_signer_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_signer_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_signer_digest');
    {$ifend}
  end;
  
  TS_CONF_set_def_policy := LoadLibFunction(ADllHandle, TS_CONF_set_def_policy_procname);
  FuncLoadError := not assigned(TS_CONF_set_def_policy);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_def_policy_allownil)}
    TS_CONF_set_def_policy := ERR_TS_CONF_set_def_policy;
    {$ifend}
    {$if declared(TS_CONF_set_def_policy_introduced)}
    if LibVersion < TS_CONF_set_def_policy_introduced then
    begin
      {$if declared(FC_TS_CONF_set_def_policy)}
      TS_CONF_set_def_policy := FC_TS_CONF_set_def_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_def_policy_removed)}
    if TS_CONF_set_def_policy_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_def_policy)}
      TS_CONF_set_def_policy := _TS_CONF_set_def_policy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_def_policy_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_def_policy');
    {$ifend}
  end;
  
  TS_CONF_set_policies := LoadLibFunction(ADllHandle, TS_CONF_set_policies_procname);
  FuncLoadError := not assigned(TS_CONF_set_policies);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_policies_allownil)}
    TS_CONF_set_policies := ERR_TS_CONF_set_policies;
    {$ifend}
    {$if declared(TS_CONF_set_policies_introduced)}
    if LibVersion < TS_CONF_set_policies_introduced then
    begin
      {$if declared(FC_TS_CONF_set_policies)}
      TS_CONF_set_policies := FC_TS_CONF_set_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_policies_removed)}
    if TS_CONF_set_policies_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_policies)}
      TS_CONF_set_policies := _TS_CONF_set_policies;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_policies_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_policies');
    {$ifend}
  end;
  
  TS_CONF_set_digests := LoadLibFunction(ADllHandle, TS_CONF_set_digests_procname);
  FuncLoadError := not assigned(TS_CONF_set_digests);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_digests_allownil)}
    TS_CONF_set_digests := ERR_TS_CONF_set_digests;
    {$ifend}
    {$if declared(TS_CONF_set_digests_introduced)}
    if LibVersion < TS_CONF_set_digests_introduced then
    begin
      {$if declared(FC_TS_CONF_set_digests)}
      TS_CONF_set_digests := FC_TS_CONF_set_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_digests_removed)}
    if TS_CONF_set_digests_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_digests)}
      TS_CONF_set_digests := _TS_CONF_set_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_digests');
    {$ifend}
  end;
  
  TS_CONF_set_accuracy := LoadLibFunction(ADllHandle, TS_CONF_set_accuracy_procname);
  FuncLoadError := not assigned(TS_CONF_set_accuracy);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_accuracy_allownil)}
    TS_CONF_set_accuracy := ERR_TS_CONF_set_accuracy;
    {$ifend}
    {$if declared(TS_CONF_set_accuracy_introduced)}
    if LibVersion < TS_CONF_set_accuracy_introduced then
    begin
      {$if declared(FC_TS_CONF_set_accuracy)}
      TS_CONF_set_accuracy := FC_TS_CONF_set_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_accuracy_removed)}
    if TS_CONF_set_accuracy_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_accuracy)}
      TS_CONF_set_accuracy := _TS_CONF_set_accuracy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_accuracy_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_accuracy');
    {$ifend}
  end;
  
  TS_CONF_set_clock_precision_digits := LoadLibFunction(ADllHandle, TS_CONF_set_clock_precision_digits_procname);
  FuncLoadError := not assigned(TS_CONF_set_clock_precision_digits);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_clock_precision_digits_allownil)}
    TS_CONF_set_clock_precision_digits := ERR_TS_CONF_set_clock_precision_digits;
    {$ifend}
    {$if declared(TS_CONF_set_clock_precision_digits_introduced)}
    if LibVersion < TS_CONF_set_clock_precision_digits_introduced then
    begin
      {$if declared(FC_TS_CONF_set_clock_precision_digits)}
      TS_CONF_set_clock_precision_digits := FC_TS_CONF_set_clock_precision_digits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_clock_precision_digits_removed)}
    if TS_CONF_set_clock_precision_digits_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_clock_precision_digits)}
      TS_CONF_set_clock_precision_digits := _TS_CONF_set_clock_precision_digits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_clock_precision_digits_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_clock_precision_digits');
    {$ifend}
  end;
  
  TS_CONF_set_ordering := LoadLibFunction(ADllHandle, TS_CONF_set_ordering_procname);
  FuncLoadError := not assigned(TS_CONF_set_ordering);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_ordering_allownil)}
    TS_CONF_set_ordering := ERR_TS_CONF_set_ordering;
    {$ifend}
    {$if declared(TS_CONF_set_ordering_introduced)}
    if LibVersion < TS_CONF_set_ordering_introduced then
    begin
      {$if declared(FC_TS_CONF_set_ordering)}
      TS_CONF_set_ordering := FC_TS_CONF_set_ordering;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_ordering_removed)}
    if TS_CONF_set_ordering_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_ordering)}
      TS_CONF_set_ordering := _TS_CONF_set_ordering;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_ordering_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_ordering');
    {$ifend}
  end;
  
  TS_CONF_set_tsa_name := LoadLibFunction(ADllHandle, TS_CONF_set_tsa_name_procname);
  FuncLoadError := not assigned(TS_CONF_set_tsa_name);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_tsa_name_allownil)}
    TS_CONF_set_tsa_name := ERR_TS_CONF_set_tsa_name;
    {$ifend}
    {$if declared(TS_CONF_set_tsa_name_introduced)}
    if LibVersion < TS_CONF_set_tsa_name_introduced then
    begin
      {$if declared(FC_TS_CONF_set_tsa_name)}
      TS_CONF_set_tsa_name := FC_TS_CONF_set_tsa_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_tsa_name_removed)}
    if TS_CONF_set_tsa_name_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_tsa_name)}
      TS_CONF_set_tsa_name := _TS_CONF_set_tsa_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_tsa_name_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_tsa_name');
    {$ifend}
  end;
  
  TS_CONF_set_ess_cert_id_chain := LoadLibFunction(ADllHandle, TS_CONF_set_ess_cert_id_chain_procname);
  FuncLoadError := not assigned(TS_CONF_set_ess_cert_id_chain);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_ess_cert_id_chain_allownil)}
    TS_CONF_set_ess_cert_id_chain := ERR_TS_CONF_set_ess_cert_id_chain;
    {$ifend}
    {$if declared(TS_CONF_set_ess_cert_id_chain_introduced)}
    if LibVersion < TS_CONF_set_ess_cert_id_chain_introduced then
    begin
      {$if declared(FC_TS_CONF_set_ess_cert_id_chain)}
      TS_CONF_set_ess_cert_id_chain := FC_TS_CONF_set_ess_cert_id_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_ess_cert_id_chain_removed)}
    if TS_CONF_set_ess_cert_id_chain_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_ess_cert_id_chain)}
      TS_CONF_set_ess_cert_id_chain := _TS_CONF_set_ess_cert_id_chain;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_ess_cert_id_chain_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_ess_cert_id_chain');
    {$ifend}
  end;
  
  TS_CONF_set_ess_cert_id_digest := LoadLibFunction(ADllHandle, TS_CONF_set_ess_cert_id_digest_procname);
  FuncLoadError := not assigned(TS_CONF_set_ess_cert_id_digest);
  if FuncLoadError then
  begin
    {$if not defined(TS_CONF_set_ess_cert_id_digest_allownil)}
    TS_CONF_set_ess_cert_id_digest := ERR_TS_CONF_set_ess_cert_id_digest;
    {$ifend}
    {$if declared(TS_CONF_set_ess_cert_id_digest_introduced)}
    if LibVersion < TS_CONF_set_ess_cert_id_digest_introduced then
    begin
      {$if declared(FC_TS_CONF_set_ess_cert_id_digest)}
      TS_CONF_set_ess_cert_id_digest := FC_TS_CONF_set_ess_cert_id_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_CONF_set_ess_cert_id_digest_removed)}
    if TS_CONF_set_ess_cert_id_digest_removed <= LibVersion then
    begin
      {$if declared(_TS_CONF_set_ess_cert_id_digest)}
      TS_CONF_set_ess_cert_id_digest := _TS_CONF_set_ess_cert_id_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_CONF_set_ess_cert_id_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_CONF_set_ess_cert_id_digest');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  TS_REQ_new := nil;
  TS_REQ_free := nil;
  d2i_TS_REQ := nil;
  i2d_TS_REQ := nil;
  TS_REQ_dup := nil;
  d2i_TS_REQ_fp := nil;
  i2d_TS_REQ_fp := nil;
  d2i_TS_REQ_bio := nil;
  i2d_TS_REQ_bio := nil;
  TS_MSG_IMPRINT_new := nil;
  TS_MSG_IMPRINT_free := nil;
  d2i_TS_MSG_IMPRINT := nil;
  i2d_TS_MSG_IMPRINT := nil;
  TS_MSG_IMPRINT_dup := nil;
  d2i_TS_MSG_IMPRINT_fp := nil;
  i2d_TS_MSG_IMPRINT_fp := nil;
  d2i_TS_MSG_IMPRINT_bio := nil;
  i2d_TS_MSG_IMPRINT_bio := nil;
  TS_RESP_new := nil;
  TS_RESP_free := nil;
  d2i_TS_RESP := nil;
  i2d_TS_RESP := nil;
  TS_RESP_dup := nil;
  d2i_TS_RESP_fp := nil;
  i2d_TS_RESP_fp := nil;
  d2i_TS_RESP_bio := nil;
  i2d_TS_RESP_bio := nil;
  TS_STATUS_INFO_new := nil;
  TS_STATUS_INFO_free := nil;
  d2i_TS_STATUS_INFO := nil;
  i2d_TS_STATUS_INFO := nil;
  TS_STATUS_INFO_dup := nil;
  TS_TST_INFO_new := nil;
  TS_TST_INFO_free := nil;
  d2i_TS_TST_INFO := nil;
  i2d_TS_TST_INFO := nil;
  TS_TST_INFO_dup := nil;
  PKCS7_to_TS_TST_INFO := nil;
  d2i_TS_TST_INFO_fp := nil;
  i2d_TS_TST_INFO_fp := nil;
  d2i_TS_TST_INFO_bio := nil;
  i2d_TS_TST_INFO_bio := nil;
  TS_ACCURACY_new := nil;
  TS_ACCURACY_free := nil;
  d2i_TS_ACCURACY := nil;
  i2d_TS_ACCURACY := nil;
  TS_ACCURACY_dup := nil;
  TS_REQ_set_version := nil;
  TS_REQ_get_version := nil;
  TS_STATUS_INFO_set_status := nil;
  TS_STATUS_INFO_get0_status := nil;
  TS_STATUS_INFO_get0_text := nil;
  TS_STATUS_INFO_get0_failure_info := nil;
  TS_REQ_set_msg_imprint := nil;
  TS_REQ_get_msg_imprint := nil;
  TS_MSG_IMPRINT_set_algo := nil;
  TS_MSG_IMPRINT_get_algo := nil;
  TS_MSG_IMPRINT_set_msg := nil;
  TS_MSG_IMPRINT_get_msg := nil;
  TS_REQ_set_policy_id := nil;
  TS_REQ_get_policy_id := nil;
  TS_REQ_set_nonce := nil;
  TS_REQ_get_nonce := nil;
  TS_REQ_set_cert_req := nil;
  TS_REQ_get_cert_req := nil;
  TS_REQ_get_exts := nil;
  TS_REQ_ext_free := nil;
  TS_REQ_get_ext_count := nil;
  TS_REQ_get_ext_by_NID := nil;
  TS_REQ_get_ext_by_OBJ := nil;
  TS_REQ_get_ext_by_critical := nil;
  TS_REQ_get_ext := nil;
  TS_REQ_delete_ext := nil;
  TS_REQ_add_ext := nil;
  TS_REQ_get_ext_d2i := nil;
  TS_REQ_print_bio := nil;
  TS_RESP_set_status_info := nil;
  TS_RESP_get_status_info := nil;
  TS_RESP_set_tst_info := nil;
  TS_RESP_get_token := nil;
  TS_RESP_get_tst_info := nil;
  TS_TST_INFO_set_version := nil;
  TS_TST_INFO_get_version := nil;
  TS_TST_INFO_set_policy_id := nil;
  TS_TST_INFO_get_policy_id := nil;
  TS_TST_INFO_set_msg_imprint := nil;
  TS_TST_INFO_get_msg_imprint := nil;
  TS_TST_INFO_set_serial := nil;
  TS_TST_INFO_get_serial := nil;
  TS_TST_INFO_set_time := nil;
  TS_TST_INFO_get_time := nil;
  TS_TST_INFO_set_accuracy := nil;
  TS_TST_INFO_get_accuracy := nil;
  TS_ACCURACY_set_seconds := nil;
  TS_ACCURACY_get_seconds := nil;
  TS_ACCURACY_set_millis := nil;
  TS_ACCURACY_get_millis := nil;
  TS_ACCURACY_set_micros := nil;
  TS_ACCURACY_get_micros := nil;
  TS_TST_INFO_set_ordering := nil;
  TS_TST_INFO_get_ordering := nil;
  TS_TST_INFO_set_nonce := nil;
  TS_TST_INFO_get_nonce := nil;
  TS_TST_INFO_set_tsa := nil;
  TS_TST_INFO_get_tsa := nil;
  TS_TST_INFO_get_exts := nil;
  TS_TST_INFO_ext_free := nil;
  TS_TST_INFO_get_ext_count := nil;
  TS_TST_INFO_get_ext_by_NID := nil;
  TS_TST_INFO_get_ext_by_OBJ := nil;
  TS_TST_INFO_get_ext_by_critical := nil;
  TS_TST_INFO_get_ext := nil;
  TS_TST_INFO_delete_ext := nil;
  TS_TST_INFO_add_ext := nil;
  TS_TST_INFO_get_ext_d2i := nil;
  TS_RESP_CTX_new := nil;
  TS_RESP_CTX_new_ex := nil;
  TS_RESP_CTX_free := nil;
  TS_RESP_CTX_set_signer_cert := nil;
  TS_RESP_CTX_set_signer_key := nil;
  TS_RESP_CTX_set_signer_digest := nil;
  TS_RESP_CTX_set_ess_cert_id_digest := nil;
  TS_RESP_CTX_set_def_policy := nil;
  TS_RESP_CTX_set_certs := nil;
  TS_RESP_CTX_add_policy := nil;
  TS_RESP_CTX_add_md := nil;
  TS_RESP_CTX_set_accuracy := nil;
  TS_RESP_CTX_set_clock_precision_digits := nil;
  TS_RESP_CTX_add_flags := nil;
  TS_RESP_CTX_set_serial_cb := nil;
  TS_RESP_CTX_set_time_cb := nil;
  TS_RESP_CTX_set_extension_cb := nil;
  TS_RESP_CTX_set_status_info := nil;
  TS_RESP_CTX_set_status_info_cond := nil;
  TS_RESP_CTX_add_failure_info := nil;
  TS_RESP_CTX_get_request := nil;
  TS_RESP_CTX_get_tst_info := nil;
  TS_RESP_create_response := nil;
  TS_RESP_verify_signature := nil;
  TS_RESP_verify_response := nil;
  TS_RESP_verify_token := nil;
  TS_VERIFY_CTX_new := nil;
  TS_VERIFY_CTX_init := nil;
  TS_VERIFY_CTX_free := nil;
  TS_VERIFY_CTX_cleanup := nil;
  TS_VERIFY_CTX_set_flags := nil;
  TS_VERIFY_CTX_add_flags := nil;
  TS_VERIFY_CTX_set_data := nil;
  TS_VERIFY_CTX_set0_data := nil;
  TS_VERIFY_CTX_set_imprint := nil;
  TS_VERIFY_CTX_set0_imprint := nil;
  TS_VERIFY_CTX_set_store := nil;
  TS_VERIFY_CTX_set0_store := nil;
  TS_VERIFY_CTX_set_certs := nil;
  TS_VERIFY_CTX_set0_certs := nil;
  TS_REQ_to_TS_VERIFY_CTX := nil;
  TS_RESP_print_bio := nil;
  TS_STATUS_INFO_print_bio := nil;
  TS_TST_INFO_print_bio := nil;
  TS_ASN1_INTEGER_print_bio := nil;
  TS_OBJ_print_bio := nil;
  TS_ext_print_bio := nil;
  TS_X509_ALGOR_print_bio := nil;
  TS_MSG_IMPRINT_print_bio := nil;
  TS_CONF_load_cert := nil;
  TS_CONF_load_certs := nil;
  TS_CONF_load_key := nil;
  TS_CONF_get_tsa_section := nil;
  TS_CONF_set_serial := nil;
  TS_CONF_set_crypto_device := nil;
  TS_CONF_set_default_engine := nil;
  TS_CONF_set_signer_cert := nil;
  TS_CONF_set_certs := nil;
  TS_CONF_set_signer_key := nil;
  TS_CONF_set_signer_digest := nil;
  TS_CONF_set_def_policy := nil;
  TS_CONF_set_policies := nil;
  TS_CONF_set_digests := nil;
  TS_CONF_set_accuracy := nil;
  TS_CONF_set_clock_precision_digits := nil;
  TS_CONF_set_ordering := nil;
  TS_CONF_set_tsa_name := nil;
  TS_CONF_set_ess_cert_id_chain := nil;
  TS_CONF_set_ess_cert_id_digest := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.