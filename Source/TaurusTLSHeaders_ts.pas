/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_ts.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_ts.h2pas
     and this file regenerated. TaurusTLSHeaders_ts.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_ts;

interface

// Headers for OpenSSL 1.1.1
// ts.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_pkcs7,
  TaurusTLSHeaders_rsa,
  TaurusTLSHeaders_tserr,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_x509v3;

const
  (* Possible values for status. *)
  {$EXTERNALSYM TS_STATUS_GRANTED}
  TS_STATUS_GRANTED = 0;
  {$EXTERNALSYM TS_STATUS_GRANTED_WITH_MODS}
  TS_STATUS_GRANTED_WITH_MODS = 1;
  {$EXTERNALSYM TS_STATUS_REJECTION}
  TS_STATUS_REJECTION = 2;
  {$EXTERNALSYM TS_STATUS_WAITING}
  TS_STATUS_WAITING = 3;
  {$EXTERNALSYM TS_STATUS_REVOCATION_WARNING}
  TS_STATUS_REVOCATION_WARNING = 4;
  {$EXTERNALSYM TS_STATUS_REVOCATION_NOTIFICATION}
  TS_STATUS_REVOCATION_NOTIFICATION = 5;


  (* Possible values for failure_info. *)
  {$EXTERNALSYM TS_INFO_BAD_ALG}
  TS_INFO_BAD_ALG = 0;
  {$EXTERNALSYM TS_INFO_BAD_REQUEST}
  TS_INFO_BAD_REQUEST = 2;
  {$EXTERNALSYM TS_INFO_BAD_DATA_FORMAT}
  TS_INFO_BAD_DATA_FORMAT = 5;
  {$EXTERNALSYM TS_INFO_TIME_NOT_AVAILABLE}
  TS_INFO_TIME_NOT_AVAILABLE = 14;
  {$EXTERNALSYM TS_INFO_UNACCEPTED_POLICY}
  TS_INFO_UNACCEPTED_POLICY = 15;
  {$EXTERNALSYM TS_INFO_UNACCEPTED_EXTENSION}
  TS_INFO_UNACCEPTED_EXTENSION = 16;
  {$EXTERNALSYM TS_INFO_ADD_INFO_NOT_AVAILABLE}
  TS_INFO_ADD_INFO_NOT_AVAILABLE = 17;
  {$EXTERNALSYM TS_INFO_SYSTEM_FAILURE}
  TS_INFO_SYSTEM_FAILURE = 25;

  (* Optional flags for response generation. *)

  (* Don't include the TSA name in response. *)
  {$EXTERNALSYM TS_TSA_NAME}
  TS_TSA_NAME = $01;

  (* Set ordering to true in response. *)
  {$EXTERNALSYM TS_ORDERING}
  TS_ORDERING = $02;

  (*
   * Include the signer certificate and the other specified certificates in
   * the ESS signing certificate attribute beside the PKCS7 signed data.
   * Only the signer certificates is included by default.
   *)
  {$EXTERNALSYM TS_ESS_CERT_ID_CHAIN}
  TS_ESS_CERT_ID_CHAIN = $04;

  (* At most we accept usec precision. *)
  {$EXTERNALSYM TS_MAX_CLOCK_PRECISION_DIGITS}
  TS_MAX_CLOCK_PRECISION_DIGITS = 6;

  (* Maximum status message length *)
  {$EXTERNALSYM TS_MAX_STATUS_LENGTH}
  TS_MAX_STATUS_LENGTH = 1024 * 1024;

  (* Verify the signer's certificate and the signature of the response. *)
  {$EXTERNALSYM TS_VFY_SIGNATURE}
  TS_VFY_SIGNATURE = TIdC_UINT(1) shl 0;
  (* Verify the version number of the response. *)
  {$EXTERNALSYM TS_VFY_VERSION}
  TS_VFY_VERSION = TIdC_UINT(1) shl 1;
  (* Verify if the policy supplied by the user matches the policy of the TSA. *)
  {$EXTERNALSYM TS_VFY_POLICY}
  TS_VFY_POLICY = TIdC_UINT(1) shl 2;
  (*
   * Verify the message imprint provided by the user. This flag should not be
   * specified with TS_VFY_DATA.
   *)
  {$EXTERNALSYM TS_VFY_IMPRINT}
  TS_VFY_IMPRINT = TIdC_UINT(1) shl 3;
  (*
   * Verify the message imprint computed by the verify method from the user
   * provided data and the MD algorithm of the response. This flag should not
   * be specified with TS_VFY_IMPRINT.
   *)
  {$EXTERNALSYM TS_VFY_DATA}
  TS_VFY_DATA = TIdC_UINT(1) shl 4;
  (* Verify the nonce value. *)
  {$EXTERNALSYM TS_VFY_NONCE}
  TS_VFY_NONCE = TIdC_UINT(1) shl 5;
  (* Verify if the TSA name field matches the signer certificate. *)
  {$EXTERNALSYM TS_VFY_SIGNER}
  TS_VFY_SIGNER = TIdC_UINT(1) shl 6;
  (* Verify if the TSA name field equals to the user provided name. *)
  {$EXTERNALSYM TS_VFY_TSA_NAME}
  TS_VFY_TSA_NAME = TIdC_UINT(1) shl 7;

  (* You can use the following convenience constants. *)
  {$EXTERNALSYM TS_VFY_ALL_IMPRINT}
  TS_VFY_ALL_IMPRINT = TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY
    or TS_VFY_IMPRINT or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME;

  {$EXTERNALSYM TS_VFY_ALL_DATA}
  TS_VFY_ALL_DATA = TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY
    or TS_VFY_DATA or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME;

type
  {$EXTERNALSYM TS_msg_imprint_st}
  TS_msg_imprint_st = record end;
  {$EXTERNALSYM TS_req_st}
  TS_req_st = record end;
  {$EXTERNALSYM TS_accuracy_st}
  TS_accuracy_st = record end;
  {$EXTERNALSYM TS_tst_info_st}
  TS_tst_info_st = record end;

  {$EXTERNALSYM TS_MSG_IMPRINT}
  TS_MSG_IMPRINT = TS_msg_imprint_st;
  {$EXTERNALSYM PTS_MSG_IMPRINT}
  PTS_MSG_IMPRINT = ^TS_MSG_IMPRINT;
  {$EXTERNALSYM PPTS_MSG_IMPRINT}
  PPTS_MSG_IMPRINT = ^PTS_MSG_IMPRINT;

  {$EXTERNALSYM TS_REQ}
  TS_REQ = TS_req_st;
  {$EXTERNALSYM PTS_REQ}
  PTS_REQ = ^TS_REQ;
  {$EXTERNALSYM PPTS_REQ}
  PPTS_REQ = ^PTS_REQ;

  {$EXTERNALSYM TS_ACCURACY}
  TS_ACCURACY = TS_accuracy_st;
  {$EXTERNALSYM PTS_ACCURACY}
  PTS_ACCURACY = ^TS_ACCURACY;
  {$EXTERNALSYM PPTS_ACCURACY}
  PPTS_ACCURACY = ^PTS_ACCURACY;

  {$EXTERNALSYM TS_TST_INFO}
  TS_TST_INFO = TS_tst_info_st;
  {$EXTERNALSYM PTS_TST_INFO}
  PTS_TST_INFO = ^TS_TST_INFO;
  {$EXTERNALSYM PPTS_TST_INFO}
  PPTS_TST_INFO = ^PTS_TST_INFO;

  {$EXTERNALSYM TS_status_info_st}
  TS_status_info_st = record end;
  {$EXTERNALSYM ESS_issuer_serial_st}
  ESS_issuer_serial_st = record end;
  {$EXTERNALSYM ESS_cert_id_st}
  ESS_cert_id_st = record end;
  {$EXTERNALSYM ESS_signing_cert_st}
  ESS_signing_cert_st = record end;
  {$EXTERNALSYM ESS_cert_id_v2_st}
  ESS_cert_id_v2_st = record end;
  {$EXTERNALSYM ESS_signing_cert_v2_st}
  ESS_signing_cert_v2_st = record end;

  {$EXTERNALSYM TS_STATUS_INFO}
  TS_STATUS_INFO = TS_status_info_st;
  {$EXTERNALSYM PTS_STATUS_INFO}
  PTS_STATUS_INFO = ^TS_STATUS_INFO;
  {$EXTERNALSYM PPTS_STATUS_INFO}
  PPTS_STATUS_INFO = ^PTS_STATUS_INFO;

  {$EXTERNALSYM ESS_ISSUER_SERIAL}
  ESS_ISSUER_SERIAL = ESS_issuer_serial_st;
  {$EXTERNALSYM PESS_ISSUER_SERIAL}
  PESS_ISSUER_SERIAL = ^ESS_ISSUER_SERIAL;
  {$EXTERNALSYM PPESS_ISSUER_SERIAL}
  PPESS_ISSUER_SERIAL = ^PESS_ISSUER_SERIAL;

  {$EXTERNALSYM ESS_CERT_ID}
  ESS_CERT_ID = ESS_cert_id_st;
  {$EXTERNALSYM PESS_CERT_ID}
  PESS_CERT_ID = ^ESS_CERT_ID;
  {$EXTERNALSYM PPESS_CERT_ID}
  PPESS_CERT_ID = ^PESS_CERT_ID;

  {$EXTERNALSYM ESS_SIGNING_CERT}
  ESS_SIGNING_CERT = ESS_signing_cert_st;
  {$EXTERNALSYM PESS_SIGNING_CERT}
  PESS_SIGNING_CERT = ^ESS_SIGNING_CERT;
  {$EXTERNALSYM PPESS_SIGNING_CERT}
  PPESS_SIGNING_CERT = ^PESS_SIGNING_CERT;

// DEFINE_STACK_OF(ESS_CERT_ID)

  {$EXTERNALSYM ESS_CERT_ID_V2}
  ESS_CERT_ID_V2 = ESS_cert_id_v2_st;
  {$EXTERNALSYM PESS_CERT_ID_V2}
  PESS_CERT_ID_V2 = ^ESS_CERT_ID_V2;
  {$EXTERNALSYM PPESS_CERT_ID_V2}
  PPESS_CERT_ID_V2 = ^PESS_CERT_ID_V2;

  {$EXTERNALSYM ESS_SIGNING_CERT_V2}
  ESS_SIGNING_CERT_V2 = ESS_signing_cert_v2_st;
  {$EXTERNALSYM PESS_SIGNING_CERT_V2}
  PESS_SIGNING_CERT_V2 = ^ESS_SIGNING_CERT_V2;
  {$EXTERNALSYM PPESS_SIGNING_CERT_V2}
  PPESS_SIGNING_CERT_V2 = ^PESS_SIGNING_CERT_V2;

// DEFINE_STACK_OF(ESS_CERT_ID_V2)
  {$EXTERNALSYM TS_resp_st}
  TS_resp_st = record end;
  {$EXTERNALSYM TS_RESP}
  TS_RESP = TS_resp_st;
  {$EXTERNALSYM PTS_RESP}
  PTS_RESP = ^TS_RESP;
  {$EXTERNALSYM PPTS_RESP}
  PPTS_RESP = ^PTS_RESP;

  (* Forward declaration. *)
  {$EXTERNALSYM TS_resp_ctx}
  TS_resp_ctx = record end;
  {$EXTERNALSYM PTS_resp_ctx}
  PTS_resp_ctx = ^TS_resp_ctx;
  {$EXTERNALSYM PPTS_resp_ctx}
  PPTS_resp_ctx = ^PTS_resp_ctx;

  (* This must return a unique number less than 160 bits long. *)
  {$EXTERNALSYM TS_serial_cb}
  TS_serial_cb = function({struct} v1: PTS_resp_ctx; v2: Pointer): PASN1_INTEGER;

  (*
   * This must return the seconds and microseconds since Jan 1, 1970 in the sec
   * and usec variables allocated by the caller. Return non-zero for success
   * and zero for failure.
   *)
  {$EXTERNALSYM TS_time_cb}
  TS_time_cb = function({struct} v1: PTS_resp_ctx; v2: Pointer; sec: PIdC_LONG; usec: PIdC_LONG): TIdC_INT;

  (*
   * This must process the given extension. It can modify the TS_TST_INFO
   * object of the context. Return values: !0 (processed), 0 (error, it must
   * set the status info/failure info of the response).
   *)
  {$EXTERNALSYM TS_extension_cb}
  TS_extension_cb = function({struct} v1: PTS_resp_ctx; v2: PX509_Extension; v3: Pointer): TIdC_INT;

//  TS_VERIFY_CTX = TS_verify_ctx;
  {$EXTERNALSYM TS_VERIFY_CTX}
  TS_VERIFY_CTX = record end;
  {$EXTERNALSYM PTS_VERIFY_CTX}
  PTS_VERIFY_CTX = ^TS_VERIFY_CTX;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM TS_REQ_new}
  TS_REQ_new: function : PTS_REQ; cdecl = nil;
  {$EXTERNALSYM TS_REQ_free}
  TS_REQ_free: procedure (a: PTS_REQ); cdecl = nil;
  {$EXTERNALSYM i2d_TS_REQ}
  i2d_TS_REQ: function (a: PTS_REQ; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_REQ}
  d2i_TS_REQ: function (a: PPTS_REQ; pp: PPByte; _length: TIdC_LONG): PTS_REQ; cdecl = nil;

  {$EXTERNALSYM TS_REQ_dup}
  TS_REQ_dup: function (a: PTS_REQ): PTS_REQ; cdecl = nil;

  {$EXTERNALSYM d2i_TS_REQ_bio}
  d2i_TS_REQ_bio: function (fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl = nil;
  {$EXTERNALSYM i2d_TS_REQ_bio}
  i2d_TS_REQ_bio: function (fp: PBIO; a: PTS_REQ): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM TS_MSG_IMPRINT_new}
  TS_MSG_IMPRINT_new: function : PTS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_free}
  TS_MSG_IMPRINT_free: procedure (a: PTS_MSG_IMPRINT); cdecl = nil;
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT}
  i2d_TS_MSG_IMPRINT: function (a: PTS_MSG_IMPRINT; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT}
  d2i_TS_MSG_IMPRINT: function (a: PPTS_MSG_IMPRINT; pp: PPByte; _length: TIdC_LONG): PTS_MSG_IMPRINT; cdecl = nil;

  {$EXTERNALSYM TS_MSG_IMPRINT_dup}
  TS_MSG_IMPRINT_dup: function (a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = nil;

  {$EXTERNALSYM d2i_TS_MSG_IMPRINT_bio}
  d2i_TS_MSG_IMPRINT_bio: function (bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = nil;
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT_bio}
  i2d_TS_MSG_IMPRINT_bio: function (bio: PBIO; a: PTS_MSG_IMPRINT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM TS_RESP_new}
  TS_RESP_new: function : PTS_RESP; cdecl = nil;
  {$EXTERNALSYM TS_RESP_free}
  TS_RESP_free: procedure (a: PTS_RESP); cdecl = nil;
  {$EXTERNALSYM i2d_TS_RESP}
  i2d_TS_RESP: function (a: PTS_RESP; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_RESP}
  d2i_TS_RESP: function (a: PPTS_RESP; pp: PPByte; _length: TIdC_LONG): PTS_RESP; cdecl = nil;
  {$EXTERNALSYM PKCS7_to_TS_TST_INFO}
  PKCS7_to_TS_TST_INFO: function (token: PPKCS7): PTS_TST_Info; cdecl = nil;
  {$EXTERNALSYM TS_RESP_dup}
  TS_RESP_dup: function (a: PTS_RESP): PTS_RESP; cdecl = nil;

  {$EXTERNALSYM d2i_TS_RESP_bio}
  d2i_TS_RESP_bio: function (bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl = nil;
  {$EXTERNALSYM i2d_TS_RESP_bio}
  i2d_TS_RESP_bio: function (bio: PBIO; a: PTS_RESP): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM TS_STATUS_INFO_new}
  TS_STATUS_INFO_new: function : PTS_STATUS_INFO; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_free}
  TS_STATUS_INFO_free: procedure (a: PTS_STATUS_INFO); cdecl = nil;
  {$EXTERNALSYM i2d_TS_STATUS_INFO}
  i2d_TS_STATUS_INFO: function (a: PTS_STATUS_INFO; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_STATUS_INFO}
  d2i_TS_STATUS_INFO: function (a: PPTS_STATUS_INFO; pp: PPByte; _length: TIdC_LONG): PTS_STATUS_INFO; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_dup}
  TS_STATUS_INFO_dup: function (a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_new}
  TS_TST_INFO_new: function : PTS_TST_Info; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_free}
  TS_TST_INFO_free: procedure (a: PTS_TST_Info); cdecl = nil;
  {$EXTERNALSYM i2d_TS_TST_INFO}
  i2d_TS_TST_INFO: function (a: PTS_TST_Info; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_TST_INFO}
  d2i_TS_TST_INFO: function (a: PPTS_TST_Info; pp: PPByte; _length: TIdC_LONG): PTS_TST_Info; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_dup}
  TS_TST_INFO_dup: function (a: PTS_TST_Info): PTS_TST_Info; cdecl = nil;

  {$EXTERNALSYM d2i_TS_TST_INFO_bio}
  d2i_TS_TST_INFO_bio: function (bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl = nil;
  {$EXTERNALSYM i2d_TS_TST_INFO_bio}
  i2d_TS_TST_INFO_bio: function (bio: PBIO; a: PTS_TST_Info): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM TS_ACCURACY_new}
  TS_ACCURACY_new: function : PTS_ACCURACY; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_free}
  TS_ACCURACY_free: procedure (a: PTS_ACCURACY); cdecl = nil;
  {$EXTERNALSYM i2d_TS_ACCURACY}
  i2d_TS_ACCURACY: function (a: PTS_ACCURACY; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_TS_ACCURACY}
  d2i_TS_ACCURACY: function (a: PPTS_ACCURACY; pp: PPByte; _length: TIdC_LONG): PTS_ACCURACY; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_dup}
  TS_ACCURACY_dup: function (a: PTS_ACCURACY): PTS_ACCURACY; cdecl = nil;

  {$EXTERNALSYM ESS_ISSUER_SERIAL_new}
  ESS_ISSUER_SERIAL_new: function : PESS_ISSUER_SERIAL; cdecl = nil;
  {$EXTERNALSYM ESS_ISSUER_SERIAL_free}
  ESS_ISSUER_SERIAL_free: procedure (a: PESS_ISSUER_SERIAL); cdecl = nil;
  {$EXTERNALSYM i2d_ESS_ISSUER_SERIAL}
  i2d_ESS_ISSUER_SERIAL: function ( a: PESS_ISSUER_SERIAL; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_ISSUER_SERIAL}
  d2i_ESS_ISSUER_SERIAL: function (a: PPESS_ISSUER_SERIAL; pp: PPByte; _length: TIdC_LONG): PESS_ISSUER_SERIAL; cdecl = nil;
  {$EXTERNALSYM ESS_ISSUER_SERIAL_dup}
  ESS_ISSUER_SERIAL_dup: function (a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl = nil;

  {$EXTERNALSYM ESS_CERT_ID_new}
  ESS_CERT_ID_new: function : PESS_CERT_ID; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_free}
  ESS_CERT_ID_free: procedure (a: PESS_CERT_ID); cdecl = nil;
  {$EXTERNALSYM i2d_ESS_CERT_ID}
  i2d_ESS_CERT_ID: function (a: PESS_CERT_ID; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_CERT_ID}
  d2i_ESS_CERT_ID: function (a: PPESS_CERT_ID; pp: PPByte; _length: TIdC_LONG): PESS_CERT_ID; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_dup}
  ESS_CERT_ID_dup: function (a: PESS_CERT_ID): PESS_CERT_ID; cdecl = nil;

  {$EXTERNALSYM ESS_SIGNING_CERT_new}
  ESS_SIGNING_CERT_new: function : PESS_SIGNING_Cert; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_free}
  ESS_SIGNING_CERT_free: procedure (a: PESS_SIGNING_Cert); cdecl = nil;
  {$EXTERNALSYM i2d_ESS_SIGNING_CERT}
  i2d_ESS_SIGNING_CERT: function ( a: PESS_SIGNING_Cert; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_SIGNING_CERT}
  d2i_ESS_SIGNING_CERT: function (a: PPESS_SIGNING_Cert; pp: PPByte; _length: TIdC_LONG): PESS_SIGNING_Cert; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_dup}
  ESS_SIGNING_CERT_dup: function (a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl = nil;

  {$EXTERNALSYM ESS_CERT_ID_V2_new}
  ESS_CERT_ID_V2_new: function : PESS_CERT_ID_V2; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_V2_free}
  ESS_CERT_ID_V2_free: procedure (a: PESS_CERT_ID_V2); cdecl = nil;
  {$EXTERNALSYM i2d_ESS_CERT_ID_V2}
  i2d_ESS_CERT_ID_V2: function ( a: PESS_CERT_ID_V2; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_CERT_ID_V2}
  d2i_ESS_CERT_ID_V2: function (a: PPESS_CERT_ID_V2; pp: PPByte; _length: TIdC_LONG): PESS_CERT_ID_V2; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_V2_dup}
  ESS_CERT_ID_V2_dup: function (a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl = nil;

  {$EXTERNALSYM ESS_SIGNING_CERT_V2_new}
  ESS_SIGNING_CERT_V2_new: function : PESS_SIGNING_CERT_V2; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_free}
  ESS_SIGNING_CERT_V2_free: procedure (a: PESS_SIGNING_CERT_V2); cdecl = nil;
  {$EXTERNALSYM i2d_ESS_SIGNING_CERT_V2}
  i2d_ESS_SIGNING_CERT_V2: function (a: PESS_SIGNING_CERT_V2; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_SIGNING_CERT_V2}
  d2i_ESS_SIGNING_CERT_V2: function (a: PPESS_SIGNING_CERT_V2; pp: PPByte; _length: TIdC_LONG): PESS_SIGNING_CERT_V2; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_dup}
  ESS_SIGNING_CERT_V2_dup: function (a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl = nil;

  {$EXTERNALSYM TS_REQ_set_version}
  TS_REQ_set_version: function (a: PTS_REQ; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_version}
  TS_REQ_get_version: function (a: PTS_REQ): TIdC_LONG; cdecl = nil;

  {$EXTERNALSYM TS_STATUS_INFO_set_status}
  TS_STATUS_INFO_set_status: function (a: PTS_STATUS_INFO; i: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_get0_status}
  TS_STATUS_INFO_get0_status: function (const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl = nil;

  // const STACK_OF(ASN1_UTF8STRING) *TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a);

  // const ASN1_BIT_STRING *TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a);

  {$EXTERNALSYM TS_REQ_set_msg_imprint}
  TS_REQ_set_msg_imprint: function (a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_msg_imprint}
  TS_REQ_get_msg_imprint: function (a: PTS_REQ): PTS_MSG_IMPRINT; cdecl = nil;

  {$EXTERNALSYM TS_MSG_IMPRINT_set_algo}
  TS_MSG_IMPRINT_set_algo: function (a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_get_algo}
  TS_MSG_IMPRINT_get_algo: function (a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl = nil;

  {$EXTERNALSYM TS_MSG_IMPRINT_set_msg}
  TS_MSG_IMPRINT_set_msg: function (a: PTS_MSG_IMPRINT; d: PByte; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_get_msg}
  TS_MSG_IMPRINT_get_msg: function (a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl = nil;

  {$EXTERNALSYM TS_REQ_set_policy_id}
  TS_REQ_set_policy_id: function (a: PTS_REQ; policy: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_policy_id}
  TS_REQ_get_policy_id: function (a: PTS_REQ): PASN1_OBJECT; cdecl = nil;

  {$EXTERNALSYM TS_REQ_set_nonce}
  TS_REQ_set_nonce: function (a: PTS_REQ; nonce: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_nonce}
  TS_REQ_get_nonce: function (const a: PTS_REQ): PASN1_INTEGER; cdecl = nil;

  {$EXTERNALSYM TS_REQ_set_cert_req}
  TS_REQ_set_cert_req: function (a: PTS_REQ; cert_req: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_cert_req}
  TS_REQ_get_cert_req: function (a: PTS_REQ): TIdC_INT; cdecl = nil;

  //STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a);
  {$EXTERNALSYM TS_REQ_ext_free}
  TS_REQ_ext_free: procedure (a: PTS_REQ); cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_count}
  TS_REQ_get_ext_count: function (a: PTS_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_by_NID}
  TS_REQ_get_ext_by_NID: function (a: PTS_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_by_OBJ}
  TS_REQ_get_ext_by_OBJ: function (a: PTS_REQ; obj: PASN1_Object; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_by_critical}
  TS_REQ_get_ext_by_critical: function (a: PTS_REQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext}
  TS_REQ_get_ext: function (a: PTS_REQ; loc: TIdC_INT): PX509_Extension; cdecl = nil;
  {$EXTERNALSYM TS_REQ_delete_ext}
  TS_REQ_delete_ext: function (a: PTS_REQ; loc: TIdC_INT): PX509_Extension; cdecl = nil;
  {$EXTERNALSYM TS_REQ_add_ext}
  TS_REQ_add_ext: function (a: PTS_REQ; ex: PX509_Extension; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_REQ_get_ext_d2i}
  TS_REQ_get_ext_d2i: function (a: PTS_REQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;

  //* Function declarations for TS_REQ defined in ts/ts_req_print.c */

  {$EXTERNALSYM TS_REQ_print_bio}
  TS_REQ_print_bio: function (bio: PBIO; a: PTS_REQ): TIdC_INT; cdecl = nil;

  //* Function declarations for TS_RESP defined in ts/ts_resp_utils.c */

  {$EXTERNALSYM TS_RESP_set_status_info}
  TS_RESP_set_status_info: function (a: PTS_RESP; info: PTS_STATUS_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_get_status_info}
  TS_RESP_get_status_info: function (a: PTS_RESP): PTS_STATUS_INFO; cdecl = nil;

  //* Caller loses ownership of PKCS7 and TS_TST_INFO objects. */
  {$EXTERNALSYM TS_RESP_set_tst_info}
  TS_RESP_set_tst_info: procedure (a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl = nil;
  {$EXTERNALSYM TS_RESP_get_token}
  TS_RESP_get_token: function (a: PTS_RESP): PPKCS7; cdecl = nil;
  {$EXTERNALSYM TS_RESP_get_tst_info}
  TS_RESP_get_tst_info: function (a: PTS_RESP): PTS_TST_Info; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_version}
  TS_TST_INFO_set_version: function (a: PTS_TST_Info; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_version}
  TS_TST_INFO_get_version: function (const a: PTS_TST_Info): TIdC_LONG; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_policy_id}
  TS_TST_INFO_set_policy_id: function (a: PTS_TST_Info; policy_id: PASN1_Object): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_policy_id}
  TS_TST_INFO_get_policy_id: function (a: PTS_TST_Info): PASN1_Object; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_msg_imprint}
  TS_TST_INFO_set_msg_imprint: function (a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_msg_imprint}
  TS_TST_INFO_get_msg_imprint: function (a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_serial}
  TS_TST_INFO_set_serial: function (a: PTS_TST_Info; const serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_serial}
  TS_TST_INFO_get_serial: function (const a: PTS_TST_INFO): PASN1_INTEGER; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_time}
  TS_TST_INFO_set_time: function (a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_time}
  TS_TST_INFO_get_time: function (const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_accuracy}
  TS_TST_INFO_set_accuracy: function (a: PTS_TST_Info; accuracy: PTS_ACCURACY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_accuracy}
  TS_TST_INFO_get_accuracy: function (a: PTS_TST_Info): PTS_ACCURACY; cdecl = nil;

  {$EXTERNALSYM TS_ACCURACY_set_seconds}
  TS_ACCURACY_set_seconds: function (a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_get_seconds}
  TS_ACCURACY_get_seconds: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = nil;

  {$EXTERNALSYM TS_ACCURACY_set_millis}
  TS_ACCURACY_set_millis: function (a: PTS_ACCURACY; const millis: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_get_millis}
  TS_ACCURACY_get_millis: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = nil;

  {$EXTERNALSYM TS_ACCURACY_set_micros}
  TS_ACCURACY_set_micros: function (a: PTS_ACCURACY; const micros: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_ACCURACY_get_micros}
  TS_ACCURACY_get_micros: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_ordering}
  TS_TST_INFO_set_ordering: function (a: PTS_TST_Info; ordering: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ordering}
  TS_TST_INFO_get_ordering: function (const a: PTS_TST_Info): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_nonce}
  TS_TST_INFO_set_nonce: function (a: PTS_TST_Info; const nonce: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_nonce}
  TS_TST_INFO_get_nonce: function (const a: PTS_TST_INFO): PASN1_INTEGER; cdecl = nil;

  {$EXTERNALSYM TS_TST_INFO_set_tsa}
  TS_TST_INFO_set_tsa: function (a: PTS_TST_Info; tsa: PGENERAL_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_tsa}
  TS_TST_INFO_get_tsa: function (a: PTS_TST_Info): PGENERAL_NAME; cdecl = nil;

  //STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a);
  {$EXTERNALSYM TS_TST_INFO_ext_free}
  TS_TST_INFO_ext_free: procedure (a: PTS_TST_Info); cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_count}
  TS_TST_INFO_get_ext_count: function (a: PTS_TST_Info): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_NID}
  TS_TST_INFO_get_ext_by_NID: function (a: PTS_TST_Info; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_OBJ}
  TS_TST_INFO_get_ext_by_OBJ: function (a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_critical}
  TS_TST_INFO_get_ext_by_critical: function (a: PTS_TST_Info; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext}
  TS_TST_INFO_get_ext: function (a: PTS_TST_Info; loc: TIdC_INT): PX509_Extension; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_delete_ext}
  TS_TST_INFO_delete_ext: function (a: PTS_TST_Info; loc: TIdC_INT): PX509_Extension; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_add_ext}
  TS_TST_INFO_add_ext: function (a: PTS_TST_Info; ex: PX509_Extension; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_get_ext_d2i}
  TS_TST_INFO_get_ext_d2i: function (a: PTS_TST_Info; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;

  (*
   * Declarations related to response generation, defined in ts/ts_resp_sign.c.
   *)

  //DEFINE_STACK_OF_CONST(EVP_MD)

  (* Creates a response context that can be used for generating responses. *)
  {$EXTERNALSYM TS_RESP_CTX_new}
  TS_RESP_CTX_new: function : PTS_RESP_CTX; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_free}
  TS_RESP_CTX_free: procedure (ctx: PTS_RESP_CTX); cdecl = nil;

  (* This parameter must be set. *)
  {$EXTERNALSYM TS_RESP_CTX_set_signer_cert}
  TS_RESP_CTX_set_signer_cert: function (ctx: PTS_RESP_CTX; signer: PX509): TIdC_INT; cdecl = nil;

  (* This parameter must be set. *)
  {$EXTERNALSYM TS_RESP_CTX_set_signer_key}
  TS_RESP_CTX_set_signer_key: function (ctx: PTS_RESP_CTX; key: PEVP_PKEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM TS_RESP_CTX_set_signer_digest}
  TS_RESP_CTX_set_signer_digest: function (ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_CTX_set_ess_cert_id_digest}
  TS_RESP_CTX_set_ess_cert_id_digest: function (ctx: PTS_RESP_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;

  (* This parameter must be set. *)
  {$EXTERNALSYM TS_RESP_CTX_set_def_policy}
  TS_RESP_CTX_set_def_policy: function (ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TIdC_INT; cdecl = nil;

  (* No additional certs are included in the response by default. *)
  // int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);

  (*
   * Adds a new acceptable policy, only the default policy is accepted by
   * default.
   *)
  {$EXTERNALSYM TS_RESP_CTX_add_policy}
  TS_RESP_CTX_add_policy: function (ctx: PTS_RESP_CTX; const policy: PASN1_Object): TIdC_INT; cdecl = nil;

  (*
   * Adds a new acceptable message digest. Note that no message digests are
   * accepted by default. The md argument is shared with the caller.
   *)
  {$EXTERNALSYM TS_RESP_CTX_add_md}
  TS_RESP_CTX_add_md: function (ctx: PTS_RESP_CTX; const md: PEVP_MD): TIdC_INT; cdecl = nil;

  (* Accuracy is not included by default. *)
  {$EXTERNALSYM TS_RESP_CTX_set_accuracy}
  TS_RESP_CTX_set_accuracy: function (ctx: PTS_RESP_CTX; secs: TIdC_INT; millis: TIdC_INT; micros: TIdC_INT): TIdC_INT; cdecl = nil;

  (*
   * Clock precision digits, i.e. the number of decimal digits: '0' means sec,
   * '3' msec, '6' usec, and so on. Default is 0.
   *)
  {$EXTERNALSYM TS_RESP_CTX_set_clock_precision_digits}
  TS_RESP_CTX_set_clock_precision_digits: function (ctx: PTS_RESP_CTX; clock_precision_digits: TIdC_UINT): TIdC_INT; cdecl = nil;

  (* No flags are set by default. *)
  {$EXTERNALSYM TS_RESP_CTX_add_flags}
  TS_RESP_CTX_add_flags: procedure (ctx: PTS_RESP_CTX; flags: TIdC_INT); cdecl = nil;

  (* Default callback always returns a constant. *)
  {$EXTERNALSYM TS_RESP_CTX_set_serial_cb}
  TS_RESP_CTX_set_serial_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl = nil;

  (* Default callback uses the gettimeofday() and gmtime() system calls. *)
  {$EXTERNALSYM TS_RESP_CTX_set_time_cb}
  TS_RESP_CTX_set_time_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl = nil;

  (*
   * Default callback rejects all extensions. The extension callback is called
   * when the TS_TST_INFO object is already set up and not signed yet.
   *)
  (* FIXME: extension handling is not tested yet. *)
  {$EXTERNALSYM TS_RESP_CTX_set_extension_cb}
  TS_RESP_CTX_set_extension_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl = nil;

  (* The following methods can be used in the callbacks. *)
  {$EXTERNALSYM TS_RESP_CTX_set_status_info}
  TS_RESP_CTX_set_status_info: function (ctx: PTS_RESP_CTX; status: TIdC_INT; _text: PIdAnsiChar): TIdC_INT; cdecl = nil;

  (* Sets the status info only if it is still TS_STATUS_GRANTED. *)
  {$EXTERNALSYM TS_RESP_CTX_set_status_info_cond}
  TS_RESP_CTX_set_status_info_cond: function (ctx: PTS_RESP_CTX; status: TIdC_INT; _text: PIdAnsiChar): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM TS_RESP_CTX_add_failure_info}
  TS_RESP_CTX_add_failure_info: function (ctx: PTS_RESP_CTX; failure: TIdC_INT): TIdC_INT; cdecl = nil;

  (* The get methods below can be used in the extension callback. *)
  {$EXTERNALSYM TS_RESP_CTX_get_request}
  TS_RESP_CTX_get_request: function (ctx: PTS_RESP_CTX): PTS_REQ; cdecl = nil;

  {$EXTERNALSYM TS_RESP_CTX_get_tst_info}
  TS_RESP_CTX_get_tst_info: function (ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl = nil;

  (*
   * Creates the signed TS_TST_INFO and puts it in TS_RESP.
   * In case of errors it sets the status info properly.
   * Returns NULL only in case of memory allocation/fatal error.
   *)
  {$EXTERNALSYM TS_RESP_create_response}
  TS_RESP_create_response: function (ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl = nil;

  (*
   * Declarations related to response verification,
   * they are defined in ts/ts_resp_verify.c.
   *)

  //int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs,
  //                             X509_STORE *store, X509 **signer_out);

  (* Context structure for the generic verify method. *)

  {$EXTERNALSYM TS_RESP_verify_response}
  TS_RESP_verify_response: function (ctx: PTS_VERIFY_CTX; response: PTS_RESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_RESP_verify_token}
  TS_RESP_verify_token: function (ctx: PTS_VERIFY_CTX; token: PPKCS7): TIdC_INT; cdecl = nil;

  (*
   * Declarations related to response verification context,
   *)
  {$EXTERNALSYM TS_VERIFY_CTX_new}
  TS_VERIFY_CTX_new: function : PTS_VERIFY_CTX; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_init}
  TS_VERIFY_CTX_init: procedure (ctx: PTS_VERIFY_CTX); cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_free}
  TS_VERIFY_CTX_free: procedure (ctx: PTS_VERIFY_CTX); cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_cleanup}
  TS_VERIFY_CTX_cleanup: procedure (ctx: PTS_VERIFY_CTX); cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set_flags}
  TS_VERIFY_CTX_set_flags: function (ctx: PTS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_add_flags}
  TS_VERIFY_CTX_add_flags: function (ctx: PTS_VERIFY_CTX; f: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set_data}
  TS_VERIFY_CTX_set_data: function (ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_data}
  TS_VERIFY_CTX_set0_data: function (ctx: PTS_VERIFY_CTX; b: PBIO) : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set_imprint}
  TS_VERIFY_CTX_set_imprint: function (ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TIdC_LONG): PByte; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_imprint}
  TS_VERIFY_CTX_set0_imprint : function(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set_store}
  TS_VERIFY_CTX_set_store: function (ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_store}
  TS_VERIFY_CTX_set0_store: function (ctx: PTS_VERIFY_CTX; s: PX509_Store): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTS_set_certs}
  TS_VERIFY_CTS_set_certs: function(ctx : PTS_VERIFY_CTX; certs : PSTACK_OF_X509) : PSTACK_OF_X509; cdecl = nil;
  {$EXTERNALSYM TS_VERIFY_CTS_set0_certs}
  TS_VERIFY_CTS_set0_certs: function(ctx : PTS_VERIFY_CTX; certs : PSTACK_OF_X509) : TIdC_INT; cdecl = nil;

  (*-
   * If ctx is NULL, it allocates and returns a new object, otherwise
   * it returns ctx. It initialises all the members as follows:
   * flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE)
   * certs = NULL
   * store = NULL
   * policy = policy from the request or NULL if absent (in this case
   *      TS_VFY_POLICY is cleared from flags as well)
   * md_alg = MD algorithm from request
   * imprint, imprint_len = imprint from request
   * data = NULL
   * nonce, nonce_len = nonce from the request or NULL if absent (in this case
   *      TS_VFY_NONCE is cleared from flags as well)
   * tsa_name = NULL
   * Important: after calling this method TS_VFY_SIGNATURE should be added!
   *)
  {$EXTERNALSYM TS_REQ_to_TS_VERIFY_CTX}
  TS_REQ_to_TS_VERIFY_CTX: function (req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl = nil;

  (* Function declarations for TS_RESP defined in ts/ts_resp_print.c *)

  {$EXTERNALSYM TS_RESP_print_bio}
  TS_RESP_print_bio: function (bio: PBIO; a: PTS_RESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_STATUS_INFO_print_bio}
  TS_STATUS_INFO_print_bio: function (bio: PBIO; a: PTS_STATUS_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_TST_INFO_print_bio}
  TS_TST_INFO_print_bio: function (bio: PBIO; a: PTS_TST_Info): TIdC_INT; cdecl = nil;

  (* Common utility functions defined in ts/ts_lib.c *)

  {$EXTERNALSYM TS_ASN1_INTEGER_print_bio}
  TS_ASN1_INTEGER_print_bio: function (bio: PBIO; const num: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_OBJ_print_bio}
  TS_OBJ_print_bio: function (bio: PBIO; const obj: PASN1_Object): TIdC_INT; cdecl = nil;
  //function TS_ext_print_bio(bio: PBIO; const STACK_OF(): X509_Extension * extensions): TIdC_INT;
  {$EXTERNALSYM TS_X509_ALGOR_print_bio}
  TS_X509_ALGOR_print_bio: function (bio: PBIO; const alg: PX509_ALGOr): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_MSG_IMPRINT_print_bio}
  TS_MSG_IMPRINT_print_bio: function (bio: PBIO; msg: PTS_MSG_IMPRINT): TIdC_INT; cdecl = nil;

  (*
   * Function declarations for handling configuration options, defined in
   * ts/ts_conf.c
   *)

  {$EXTERNALSYM TS_CONF_load_cert}
  TS_CONF_load_cert: function (file_: PIdAnsiChar): PX509; cdecl = nil;
  {$EXTERNALSYM TS_CONF_load_key}
  TS_CONF_load_key: function ( file_: PIdAnsiChar; pass: PIdAnsiChar): PEVP_PKey; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_serial}
  TS_CONF_set_serial: function (conf: PCONF; section: PIdAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  //STACK_OF(X509) *TS_CONF_load_certs(const char *file);
  {$EXTERNALSYM TS_CONF_get_tsa_section}
  TS_CONF_get_tsa_section: function (conf: PCONF; const section: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_crypto_device}
  TS_CONF_set_crypto_device: function (conf: PCONF; section: PIdAnsiChar; device: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_default_engine}
  TS_CONF_set_default_engine: function (name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_signer_cert}
  TS_CONF_set_signer_cert: function (conf: PCONF; section: PIdAnsiChar; cert: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_certs}
  TS_CONF_set_certs: function (conf: PCONF; section: PIdAnsiChar; certs: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_signer_key}
  TS_CONF_set_signer_key: function (conf: PCONF; const section: PIdAnsiChar; key: PIdAnsiChar; pass: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_signer_digest}
  TS_CONF_set_signer_digest: function (conf: PCONF; section: PIdAnsiChar; md: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_def_policy}
  TS_CONF_set_def_policy: function (conf: PCONF; section: PIdAnsiChar; policy: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_policies}
  TS_CONF_set_policies: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_digests}
  TS_CONF_set_digests: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_accuracy}
  TS_CONF_set_accuracy: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_clock_precision_digits}
  TS_CONF_set_clock_precision_digits: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_ordering}
  TS_CONF_set_ordering: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_tsa_name}
  TS_CONF_set_tsa_name: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_chain}
  TS_CONF_set_ess_cert_id_chain: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_digest}
  TS_CONF_set_ess_cert_id_digest: function (conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM TS_REQ_new}
  function TS_REQ_new: PTS_REQ cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_free}
  procedure TS_REQ_free(a: PTS_REQ) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_REQ}
  function i2d_TS_REQ(a: PTS_REQ; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_TS_REQ}
  function d2i_TS_REQ(a: PPTS_REQ; pp: PPByte; _length: TIdC_LONG): PTS_REQ cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_REQ_dup}
  function TS_REQ_dup(a: PTS_REQ): PTS_REQ cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_TS_REQ_bio}
  function d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_REQ_bio}
  function i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_MSG_IMPRINT_new}
  function TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_MSG_IMPRINT_free}
  procedure TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT}
  function i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT}
  function d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; pp: PPByte; _length: TIdC_LONG): PTS_MSG_IMPRINT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_MSG_IMPRINT_dup}
  function TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_TS_MSG_IMPRINT_bio}
  function d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT_bio}
  function i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_RESP_new}
  function TS_RESP_new: PTS_RESP cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_free}
  procedure TS_RESP_free(a: PTS_RESP) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_RESP}
  function i2d_TS_RESP(a: PTS_RESP; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_TS_RESP}
  function d2i_TS_RESP(a: PPTS_RESP; pp: PPByte; _length: TIdC_LONG): PTS_RESP cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS7_to_TS_TST_INFO}
  function PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_Info cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_dup}
  function TS_RESP_dup(a: PTS_RESP): PTS_RESP cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_TS_RESP_bio}
  function d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_RESP_bio}
  function i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_STATUS_INFO_new}
  function TS_STATUS_INFO_new: PTS_STATUS_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_STATUS_INFO_free}
  procedure TS_STATUS_INFO_free(a: PTS_STATUS_INFO) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_STATUS_INFO}
  function i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_TS_STATUS_INFO}
  function d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; pp: PPByte; _length: TIdC_LONG): PTS_STATUS_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_STATUS_INFO_dup}
  function TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_new}
  function TS_TST_INFO_new: PTS_TST_Info cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_free}
  procedure TS_TST_INFO_free(a: PTS_TST_Info) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_TST_INFO}
  function i2d_TS_TST_INFO(a: PTS_TST_Info; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_TS_TST_INFO}
  function d2i_TS_TST_INFO(a: PPTS_TST_Info; pp: PPByte; _length: TIdC_LONG): PTS_TST_Info cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_dup}
  function TS_TST_INFO_dup(a: PTS_TST_Info): PTS_TST_Info cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_TS_TST_INFO_bio}
  function d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_TST_INFO_bio}
  function i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_Info): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_ACCURACY_new}
  function TS_ACCURACY_new: PTS_ACCURACY cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_ACCURACY_free}
  procedure TS_ACCURACY_free(a: PTS_ACCURACY) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_TS_ACCURACY}
  function i2d_TS_ACCURACY(a: PTS_ACCURACY; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_TS_ACCURACY}
  function d2i_TS_ACCURACY(a: PPTS_ACCURACY; pp: PPByte; _length: TIdC_LONG): PTS_ACCURACY cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_ACCURACY_dup}
  function TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY cdecl; external CLibCrypto;

  {$EXTERNALSYM ESS_ISSUER_SERIAL_new}
  function ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_ISSUER_SERIAL_free}
  procedure ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ESS_ISSUER_SERIAL}
  function i2d_ESS_ISSUER_SERIAL( a: PESS_ISSUER_SERIAL; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ESS_ISSUER_SERIAL}
  function d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; pp: PPByte; _length: TIdC_LONG): PESS_ISSUER_SERIAL cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_ISSUER_SERIAL_dup}
  function ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL cdecl; external CLibCrypto;

  {$EXTERNALSYM ESS_CERT_ID_new}
  function ESS_CERT_ID_new: PESS_CERT_ID cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_CERT_ID_free}
  procedure ESS_CERT_ID_free(a: PESS_CERT_ID) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ESS_CERT_ID}
  function i2d_ESS_CERT_ID(a: PESS_CERT_ID; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ESS_CERT_ID}
  function d2i_ESS_CERT_ID(a: PPESS_CERT_ID; pp: PPByte; _length: TIdC_LONG): PESS_CERT_ID cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_CERT_ID_dup}
  function ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID cdecl; external CLibCrypto;

  {$EXTERNALSYM ESS_SIGNING_CERT_new}
  function ESS_SIGNING_CERT_new: PESS_SIGNING_Cert cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_SIGNING_CERT_free}
  procedure ESS_SIGNING_CERT_free(a: PESS_SIGNING_Cert) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ESS_SIGNING_CERT}
  function i2d_ESS_SIGNING_CERT( a: PESS_SIGNING_Cert; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ESS_SIGNING_CERT}
  function d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_Cert; pp: PPByte; _length: TIdC_LONG): PESS_SIGNING_Cert cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_SIGNING_CERT_dup}
  function ESS_SIGNING_CERT_dup(a: PESS_SIGNING_Cert): PESS_SIGNING_Cert cdecl; external CLibCrypto;

  {$EXTERNALSYM ESS_CERT_ID_V2_new}
  function ESS_CERT_ID_V2_new: PESS_CERT_ID_V2 cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_CERT_ID_V2_free}
  procedure ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ESS_CERT_ID_V2}
  function i2d_ESS_CERT_ID_V2( a: PESS_CERT_ID_V2; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ESS_CERT_ID_V2}
  function d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; pp: PPByte; _length: TIdC_LONG): PESS_CERT_ID_V2 cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_CERT_ID_V2_dup}
  function ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2 cdecl; external CLibCrypto;

  {$EXTERNALSYM ESS_SIGNING_CERT_V2_new}
  function ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2 cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_free}
  procedure ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ESS_SIGNING_CERT_V2}
  function i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ESS_SIGNING_CERT_V2}
  function d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; pp: PPByte; _length: TIdC_LONG): PESS_SIGNING_CERT_V2 cdecl; external CLibCrypto;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_dup}
  function ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2 cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_REQ_set_version}
  function TS_REQ_set_version(a: PTS_REQ; version: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_version}
  function TS_REQ_get_version(a: PTS_REQ): TIdC_LONG cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_STATUS_INFO_set_status}
  function TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_STATUS_INFO_get0_status}
  function TS_STATUS_INFO_get0_status(const a: PTS_STATUS_INFO): PASN1_INTEGER cdecl; external CLibCrypto;

  // const STACK_OF(ASN1_UTF8STRING) *TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a);

  // const ASN1_BIT_STRING *TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a);

  {$EXTERNALSYM TS_REQ_set_msg_imprint}
  function TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_msg_imprint}
  function TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_MSG_IMPRINT_set_algo}
  function TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_MSG_IMPRINT_get_algo}
  function TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOr cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_MSG_IMPRINT_set_msg}
  function TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: PByte; len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_MSG_IMPRINT_get_msg}
  function TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_REQ_set_policy_id}
  function TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_policy_id}
  function TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_REQ_set_nonce}
  function TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_nonce}
  function TS_REQ_get_nonce(const a: PTS_REQ): PASN1_INTEGER cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_REQ_set_cert_req}
  function TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_cert_req}
  function TS_REQ_get_cert_req(a: PTS_REQ): TIdC_INT cdecl; external CLibCrypto;

  //STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a);
  {$EXTERNALSYM TS_REQ_ext_free}
  procedure TS_REQ_ext_free(a: PTS_REQ) cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_ext_count}
  function TS_REQ_get_ext_count(a: PTS_REQ): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_ext_by_NID}
  function TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_ext_by_OBJ}
  function TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_Object; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_ext_by_critical}
  function TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_ext}
  function TS_REQ_get_ext(a: PTS_REQ; loc: TIdC_INT): PX509_Extension cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_delete_ext}
  function TS_REQ_delete_ext(a: PTS_REQ; loc: TIdC_INT): PX509_Extension cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_add_ext}
  function TS_REQ_add_ext(a: PTS_REQ; ex: PX509_Extension; loc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_REQ_get_ext_d2i}
  function TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer cdecl; external CLibCrypto;

  //* Function declarations for TS_REQ defined in ts/ts_req_print.c */

  {$EXTERNALSYM TS_REQ_print_bio}
  function TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TIdC_INT cdecl; external CLibCrypto;

  //* Function declarations for TS_RESP defined in ts/ts_resp_utils.c */

  {$EXTERNALSYM TS_RESP_set_status_info}
  function TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_get_status_info}
  function TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO cdecl; external CLibCrypto;

  //* Caller loses ownership of PKCS7 and TS_TST_INFO objects. */
  {$EXTERNALSYM TS_RESP_set_tst_info}
  procedure TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info) cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_get_token}
  function TS_RESP_get_token(a: PTS_RESP): PPKCS7 cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_get_tst_info}
  function TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_Info cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_version}
  function TS_TST_INFO_set_version(a: PTS_TST_Info; version: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_version}
  function TS_TST_INFO_get_version(const a: PTS_TST_Info): TIdC_LONG cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_policy_id}
  function TS_TST_INFO_set_policy_id(a: PTS_TST_Info; policy_id: PASN1_Object): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_policy_id}
  function TS_TST_INFO_get_policy_id(a: PTS_TST_Info): PASN1_Object cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_msg_imprint}
  function TS_TST_INFO_set_msg_imprint(a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_msg_imprint}
  function TS_TST_INFO_get_msg_imprint(a: PTS_TST_Info): PTS_MSG_IMPRINT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_serial}
  function TS_TST_INFO_set_serial(a: PTS_TST_Info; const serial: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_serial}
  function TS_TST_INFO_get_serial(const a: PTS_TST_INFO): PASN1_INTEGER cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_time}
  function TS_TST_INFO_set_time(a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_time}
  function TS_TST_INFO_get_time(const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_accuracy}
  function TS_TST_INFO_set_accuracy(a: PTS_TST_Info; accuracy: PTS_ACCURACY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_accuracy}
  function TS_TST_INFO_get_accuracy(a: PTS_TST_Info): PTS_ACCURACY cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_ACCURACY_set_seconds}
  function TS_ACCURACY_set_seconds(a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_ACCURACY_get_seconds}
  function TS_ACCURACY_get_seconds(const a: PTS_ACCURACY): PASN1_INTEGER cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_ACCURACY_set_millis}
  function TS_ACCURACY_set_millis(a: PTS_ACCURACY; const millis: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_ACCURACY_get_millis}
  function TS_ACCURACY_get_millis(const a: PTS_ACCURACY): PASN1_INTEGER cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_ACCURACY_set_micros}
  function TS_ACCURACY_set_micros(a: PTS_ACCURACY; const micros: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_ACCURACY_get_micros}
  function TS_ACCURACY_get_micros(const a: PTS_ACCURACY): PASN1_INTEGER cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_ordering}
  function TS_TST_INFO_set_ordering(a: PTS_TST_Info; ordering: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_ordering}
  function TS_TST_INFO_get_ordering(const a: PTS_TST_Info): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_nonce}
  function TS_TST_INFO_set_nonce(a: PTS_TST_Info; const nonce: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_nonce}
  function TS_TST_INFO_get_nonce(const a: PTS_TST_INFO): PASN1_INTEGER cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_TST_INFO_set_tsa}
  function TS_TST_INFO_set_tsa(a: PTS_TST_Info; tsa: PGENERAL_NAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_tsa}
  function TS_TST_INFO_get_tsa(a: PTS_TST_Info): PGENERAL_NAME cdecl; external CLibCrypto;

  //STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a);
  {$EXTERNALSYM TS_TST_INFO_ext_free}
  procedure TS_TST_INFO_ext_free(a: PTS_TST_Info) cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_ext_count}
  function TS_TST_INFO_get_ext_count(a: PTS_TST_Info): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_NID}
  function TS_TST_INFO_get_ext_by_NID(a: PTS_TST_Info; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_OBJ}
  function TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_critical}
  function TS_TST_INFO_get_ext_by_critical(a: PTS_TST_Info; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_ext}
  function TS_TST_INFO_get_ext(a: PTS_TST_Info; loc: TIdC_INT): PX509_Extension cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_delete_ext}
  function TS_TST_INFO_delete_ext(a: PTS_TST_Info; loc: TIdC_INT): PX509_Extension cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_add_ext}
  function TS_TST_INFO_add_ext(a: PTS_TST_Info; ex: PX509_Extension; loc: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_get_ext_d2i}
  function TS_TST_INFO_get_ext_d2i(a: PTS_TST_Info; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer cdecl; external CLibCrypto;

  (*
   * Declarations related to response generation, defined in ts/ts_resp_sign.c.
   *)

  //DEFINE_STACK_OF_CONST(EVP_MD)

  (* Creates a response context that can be used for generating responses. *)
  {$EXTERNALSYM TS_RESP_CTX_new}
  function TS_RESP_CTX_new: PTS_RESP_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_CTX_free}
  procedure TS_RESP_CTX_free(ctx: PTS_RESP_CTX) cdecl; external CLibCrypto;

  (* This parameter must be set. *)
  {$EXTERNALSYM TS_RESP_CTX_set_signer_cert}
  function TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TIdC_INT cdecl; external CLibCrypto;

  (* This parameter must be set. *)
  {$EXTERNALSYM TS_RESP_CTX_set_signer_key}
  function TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_RESP_CTX_set_signer_digest}
  function TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_CTX_set_ess_cert_id_digest}
  function TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;

  (* This parameter must be set. *)
  {$EXTERNALSYM TS_RESP_CTX_set_def_policy}
  function TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TIdC_INT cdecl; external CLibCrypto;

  (* No additional certs are included in the response by default. *)
  // int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);

  (*
   * Adds a new acceptable policy, only the default policy is accepted by
   * default.
   *)
  {$EXTERNALSYM TS_RESP_CTX_add_policy}
  function TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; const policy: PASN1_Object): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Adds a new acceptable message digest. Note that no message digests are
   * accepted by default. The md argument is shared with the caller.
   *)
  {$EXTERNALSYM TS_RESP_CTX_add_md}
  function TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;

  (* Accuracy is not included by default. *)
  {$EXTERNALSYM TS_RESP_CTX_set_accuracy}
  function TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TIdC_INT; millis: TIdC_INT; micros: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Clock precision digits, i.e. the number of decimal digits: '0' means sec,
   * '3' msec, '6' usec, and so on. Default is 0.
   *)
  {$EXTERNALSYM TS_RESP_CTX_set_clock_precision_digits}
  function TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  (* No flags are set by default. *)
  {$EXTERNALSYM TS_RESP_CTX_add_flags}
  procedure TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TIdC_INT) cdecl; external CLibCrypto;

  (* Default callback always returns a constant. *)
  {$EXTERNALSYM TS_RESP_CTX_set_serial_cb}
  procedure TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer) cdecl; external CLibCrypto;

  (* Default callback uses the gettimeofday() and gmtime() system calls. *)
  {$EXTERNALSYM TS_RESP_CTX_set_time_cb}
  procedure TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer) cdecl; external CLibCrypto;

  (*
   * Default callback rejects all extensions. The extension callback is called
   * when the TS_TST_INFO object is already set up and not signed yet.
   *)
  (* FIXME: extension handling is not tested yet. *)
  {$EXTERNALSYM TS_RESP_CTX_set_extension_cb}
  procedure TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer) cdecl; external CLibCrypto;

  (* The following methods can be used in the callbacks. *)
  {$EXTERNALSYM TS_RESP_CTX_set_status_info}
  function TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TIdC_INT; _text: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  (* Sets the status info only if it is still TS_STATUS_GRANTED. *)
  {$EXTERNALSYM TS_RESP_CTX_set_status_info_cond}
  function TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TIdC_INT; _text: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_RESP_CTX_add_failure_info}
  function TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (* The get methods below can be used in the extension callback. *)
  {$EXTERNALSYM TS_RESP_CTX_get_request}
  function TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ cdecl; external CLibCrypto;

  {$EXTERNALSYM TS_RESP_CTX_get_tst_info}
  function TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_Info cdecl; external CLibCrypto;

  (*
   * Creates the signed TS_TST_INFO and puts it in TS_RESP.
   * In case of errors it sets the status info properly.
   * Returns NULL only in case of memory allocation/fatal error.
   *)
  {$EXTERNALSYM TS_RESP_create_response}
  function TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP cdecl; external CLibCrypto;

  (*
   * Declarations related to response verification,
   * they are defined in ts/ts_resp_verify.c.
   *)

  //int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs,
  //                             X509_STORE *store, X509 **signer_out);

  (* Context structure for the generic verify method. *)

  {$EXTERNALSYM TS_RESP_verify_response}
  function TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_RESP_verify_token}
  function TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Declarations related to response verification context,
   *)
  {$EXTERNALSYM TS_VERIFY_CTX_new}
  function TS_VERIFY_CTX_new: PTS_VERIFY_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_init}
  procedure TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_free}
  procedure TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_cleanup}
  procedure TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX) cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_set_flags}
  function TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_add_flags}
  function TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_set_data}
  function TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_data}
  function TS_VERIFY_CTX_set0_data(ctx : PTS_VERIFY_CTX; b: PBIO): TIdC_INT cdecl;  external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_set_imprint}
  function TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TIdC_LONG): PByte cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_imprint}
  function TS_VERIFY_CTX_set0_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_set_store}
  function TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTX_set0_store}
  function TS_VERIFY_CTX_set0_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): TIdC_INT; cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTS_set_certs}
  function TS_VERIFY_CTS_set_certs(ctx : PTS_VERIFY_CTX; certs : PSTACK_OF_X509) : PSTACK_OF_X509; cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_VERIFY_CTS_set0_certs}
  function TS_VERIFY_CTS_set0_certs(ctx : PTS_VERIFY_CTX; certs : PSTACK_OF_X509) : TIdC_INT; cdecl; external CLibCrypto;

  (*-
   * If ctx is NULL, it allocates and returns a new object, otherwise
   * it returns ctx. It initialises all the members as follows:
   * flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE)
   * certs = NULL
   * store = NULL
   * policy = policy from the request or NULL if absent (in this case
   *      TS_VFY_POLICY is cleared from flags as well)
   * md_alg = MD algorithm from request
   * imprint, imprint_len = imprint from request
   * data = NULL
   * nonce, nonce_len = nonce from the request or NULL if absent (in this case
   *      TS_VFY_NONCE is cleared from flags as well)
   * tsa_name = NULL
   * Important: after calling this method TS_VFY_SIGNATURE should be added!
   *)
  {$EXTERNALSYM TS_REQ_to_TS_VERIFY_CTX}
  function TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX cdecl; external CLibCrypto;

  (* Function declarations for TS_RESP defined in ts/ts_resp_print.c *)

  {$EXTERNALSYM TS_RESP_print_bio}
  function TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_STATUS_INFO_print_bio}
  function TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_TST_INFO_print_bio}
  function TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_Info): TIdC_INT cdecl; external CLibCrypto;

  (* Common utility functions defined in ts/ts_lib.c *)

  {$EXTERNALSYM TS_ASN1_INTEGER_print_bio}
  function TS_ASN1_INTEGER_print_bio(bio: PBIO; const num: PASN1_INTEGER): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_OBJ_print_bio}
  function TS_OBJ_print_bio(bio: PBIO; const obj: PASN1_Object): TIdC_INT cdecl; external CLibCrypto;
  //function TS_ext_print_bio(bio: PBIO; const STACK_OF(): X509_Extension * extensions): TIdC_INT;
  {$EXTERNALSYM TS_X509_ALGOR_print_bio}
  function TS_X509_ALGOR_print_bio(bio: PBIO; const alg: PX509_ALGOr): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_MSG_IMPRINT_print_bio}
  function TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Function declarations for handling configuration options, defined in
   * ts/ts_conf.c
   *)

  {$EXTERNALSYM TS_CONF_load_cert}
  function TS_CONF_load_cert(file_: PIdAnsiChar): PX509 cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_load_key}
  function TS_CONF_load_key( file_: PIdAnsiChar; pass: PIdAnsiChar): PEVP_PKey cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_serial}
  function TS_CONF_set_serial(conf: PCONF; section: PIdAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  //STACK_OF(X509) *TS_CONF_load_certs(const char *file);
  {$EXTERNALSYM TS_CONF_get_tsa_section}
  function TS_CONF_get_tsa_section(conf: PCONF; const section: PIdAnsiChar): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_crypto_device}
  function TS_CONF_set_crypto_device(conf: PCONF; section: PIdAnsiChar; device: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_default_engine}
  function TS_CONF_set_default_engine(name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_signer_cert}
  function TS_CONF_set_signer_cert(conf: PCONF; section: PIdAnsiChar; cert: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_certs}
  function TS_CONF_set_certs(conf: PCONF; section: PIdAnsiChar; certs: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_signer_key}
  function TS_CONF_set_signer_key(conf: PCONF; const section: PIdAnsiChar; key: PIdAnsiChar; pass: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_signer_digest}
  function TS_CONF_set_signer_digest(conf: PCONF; section: PIdAnsiChar; md: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_def_policy}
  function TS_CONF_set_def_policy(conf: PCONF; section: PIdAnsiChar; policy: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_policies}
  function TS_CONF_set_policies(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_digests}
  function TS_CONF_set_digests(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_accuracy}
  function TS_CONF_set_accuracy(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_clock_precision_digits}
  function TS_CONF_set_clock_precision_digits(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_ordering}
  function TS_CONF_set_ordering(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_tsa_name}
  function TS_CONF_set_tsa_name(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_chain}
  function TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_digest}
  function TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

const
  TS_VERIFY_CTX_set0_data_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);
  TS_VERIFY_CTX_set0_imprint_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);
  TS_VERIFY_CTX_set0_store_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);
  TS_VERIFY_CTX_set0_certs_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  TS_REQ_new_procname = 'TS_REQ_new';
  TS_REQ_free_procname = 'TS_REQ_free';
  i2d_TS_REQ_procname = 'i2d_TS_REQ';
  d2i_TS_REQ_procname = 'd2i_TS_REQ';

  TS_REQ_dup_procname = 'TS_REQ_dup';

  d2i_TS_REQ_bio_procname = 'd2i_TS_REQ_bio';
  i2d_TS_REQ_bio_procname = 'i2d_TS_REQ_bio';

  TS_MSG_IMPRINT_new_procname = 'TS_MSG_IMPRINT_new';
  TS_MSG_IMPRINT_free_procname = 'TS_MSG_IMPRINT_free';
  i2d_TS_MSG_IMPRINT_procname = 'i2d_TS_MSG_IMPRINT';
  d2i_TS_MSG_IMPRINT_procname = 'd2i_TS_MSG_IMPRINT';

  TS_MSG_IMPRINT_dup_procname = 'TS_MSG_IMPRINT_dup';

  d2i_TS_MSG_IMPRINT_bio_procname = 'd2i_TS_MSG_IMPRINT_bio';
  i2d_TS_MSG_IMPRINT_bio_procname = 'i2d_TS_MSG_IMPRINT_bio';

  TS_RESP_new_procname = 'TS_RESP_new';
  TS_RESP_free_procname = 'TS_RESP_free';
  i2d_TS_RESP_procname = 'i2d_TS_RESP';
  d2i_TS_RESP_procname = 'd2i_TS_RESP';
  PKCS7_to_TS_TST_INFO_procname = 'PKCS7_to_TS_TST_INFO';
  TS_RESP_dup_procname = 'TS_RESP_dup';

  d2i_TS_RESP_bio_procname = 'd2i_TS_RESP_bio';
  i2d_TS_RESP_bio_procname = 'i2d_TS_RESP_bio';

  TS_STATUS_INFO_new_procname = 'TS_STATUS_INFO_new';
  TS_STATUS_INFO_free_procname = 'TS_STATUS_INFO_free';
  i2d_TS_STATUS_INFO_procname = 'i2d_TS_STATUS_INFO';
  d2i_TS_STATUS_INFO_procname = 'd2i_TS_STATUS_INFO';
  TS_STATUS_INFO_dup_procname = 'TS_STATUS_INFO_dup';

  TS_TST_INFO_new_procname = 'TS_TST_INFO_new';
  TS_TST_INFO_free_procname = 'TS_TST_INFO_free';
  i2d_TS_TST_INFO_procname = 'i2d_TS_TST_INFO';
  d2i_TS_TST_INFO_procname = 'd2i_TS_TST_INFO';
  TS_TST_INFO_dup_procname = 'TS_TST_INFO_dup';

  d2i_TS_TST_INFO_bio_procname = 'd2i_TS_TST_INFO_bio';
  i2d_TS_TST_INFO_bio_procname = 'i2d_TS_TST_INFO_bio';

  TS_ACCURACY_new_procname = 'TS_ACCURACY_new';
  TS_ACCURACY_free_procname = 'TS_ACCURACY_free';
  i2d_TS_ACCURACY_procname = 'i2d_TS_ACCURACY';
  d2i_TS_ACCURACY_procname = 'd2i_TS_ACCURACY';
  TS_ACCURACY_dup_procname = 'TS_ACCURACY_dup';

  ESS_ISSUER_SERIAL_new_procname = 'ESS_ISSUER_SERIAL_new';
  ESS_ISSUER_SERIAL_free_procname = 'ESS_ISSUER_SERIAL_free';
  i2d_ESS_ISSUER_SERIAL_procname = 'i2d_ESS_ISSUER_SERIAL';
  d2i_ESS_ISSUER_SERIAL_procname = 'd2i_ESS_ISSUER_SERIAL';
  ESS_ISSUER_SERIAL_dup_procname = 'ESS_ISSUER_SERIAL_dup';

  ESS_CERT_ID_new_procname = 'ESS_CERT_ID_new';
  ESS_CERT_ID_free_procname = 'ESS_CERT_ID_free';
  i2d_ESS_CERT_ID_procname = 'i2d_ESS_CERT_ID';
  d2i_ESS_CERT_ID_procname = 'd2i_ESS_CERT_ID';
  ESS_CERT_ID_dup_procname = 'ESS_CERT_ID_dup';

  ESS_SIGNING_CERT_new_procname = 'ESS_SIGNING_CERT_new';
  ESS_SIGNING_CERT_free_procname = 'ESS_SIGNING_CERT_free';
  i2d_ESS_SIGNING_CERT_procname = 'i2d_ESS_SIGNING_CERT';
  d2i_ESS_SIGNING_CERT_procname = 'd2i_ESS_SIGNING_CERT';
  ESS_SIGNING_CERT_dup_procname = 'ESS_SIGNING_CERT_dup';

  ESS_CERT_ID_V2_new_procname = 'ESS_CERT_ID_V2_new';
  ESS_CERT_ID_V2_free_procname = 'ESS_CERT_ID_V2_free';
  i2d_ESS_CERT_ID_V2_procname = 'i2d_ESS_CERT_ID_V2';
  d2i_ESS_CERT_ID_V2_procname = 'd2i_ESS_CERT_ID_V2';
  ESS_CERT_ID_V2_dup_procname = 'ESS_CERT_ID_V2_dup';

  ESS_SIGNING_CERT_V2_new_procname = 'ESS_SIGNING_CERT_V2_new';
  ESS_SIGNING_CERT_V2_free_procname = 'ESS_SIGNING_CERT_V2_free';
  i2d_ESS_SIGNING_CERT_V2_procname = 'i2d_ESS_SIGNING_CERT_V2';
  d2i_ESS_SIGNING_CERT_V2_procname = 'd2i_ESS_SIGNING_CERT_V2';
  ESS_SIGNING_CERT_V2_dup_procname = 'ESS_SIGNING_CERT_V2_dup';

  TS_REQ_set_version_procname = 'TS_REQ_set_version';
  TS_REQ_get_version_procname = 'TS_REQ_get_version';

  TS_STATUS_INFO_set_status_procname = 'TS_STATUS_INFO_set_status';
  TS_STATUS_INFO_get0_status_procname = 'TS_STATUS_INFO_get0_status';

  // const STACK_OF(ASN1_UTF8STRING) *TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a);

  // const ASN1_BIT_STRING *TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a);

  TS_REQ_set_msg_imprint_procname = 'TS_REQ_set_msg_imprint';
  TS_REQ_get_msg_imprint_procname = 'TS_REQ_get_msg_imprint';

  TS_MSG_IMPRINT_set_algo_procname = 'TS_MSG_IMPRINT_set_algo';
  TS_MSG_IMPRINT_get_algo_procname = 'TS_MSG_IMPRINT_get_algo';

  TS_MSG_IMPRINT_set_msg_procname = 'TS_MSG_IMPRINT_set_msg';
  TS_MSG_IMPRINT_get_msg_procname = 'TS_MSG_IMPRINT_get_msg';

  TS_REQ_set_policy_id_procname = 'TS_REQ_set_policy_id';
  TS_REQ_get_policy_id_procname = 'TS_REQ_get_policy_id';

  TS_REQ_set_nonce_procname = 'TS_REQ_set_nonce';
  TS_REQ_get_nonce_procname = 'TS_REQ_get_nonce';

  TS_REQ_set_cert_req_procname = 'TS_REQ_set_cert_req';
  TS_REQ_get_cert_req_procname = 'TS_REQ_get_cert_req';

  //STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a);
  TS_REQ_ext_free_procname = 'TS_REQ_ext_free';
  TS_REQ_get_ext_count_procname = 'TS_REQ_get_ext_count';
  TS_REQ_get_ext_by_NID_procname = 'TS_REQ_get_ext_by_NID';
  TS_REQ_get_ext_by_OBJ_procname = 'TS_REQ_get_ext_by_OBJ';
  TS_REQ_get_ext_by_critical_procname = 'TS_REQ_get_ext_by_critical';
  TS_REQ_get_ext_procname = 'TS_REQ_get_ext';
  TS_REQ_delete_ext_procname = 'TS_REQ_delete_ext';
  TS_REQ_add_ext_procname = 'TS_REQ_add_ext';
  TS_REQ_get_ext_d2i_procname = 'TS_REQ_get_ext_d2i';

  //* Function declarations for TS_REQ defined in ts/ts_req_print.c */

  TS_REQ_print_bio_procname = 'TS_REQ_print_bio';

  //* Function declarations for TS_RESP defined in ts/ts_resp_utils.c */

  TS_RESP_set_status_info_procname = 'TS_RESP_set_status_info';
  TS_RESP_get_status_info_procname = 'TS_RESP_get_status_info';

  //* Caller loses ownership of PKCS7 and TS_TST_INFO objects. */
  TS_RESP_set_tst_info_procname = 'TS_RESP_set_tst_info';
  TS_RESP_get_token_procname = 'TS_RESP_get_token';
  TS_RESP_get_tst_info_procname = 'TS_RESP_get_tst_info';

  TS_TST_INFO_set_version_procname = 'TS_TST_INFO_set_version';
  TS_TST_INFO_get_version_procname = 'TS_TST_INFO_get_version';

  TS_TST_INFO_set_policy_id_procname = 'TS_TST_INFO_set_policy_id';
  TS_TST_INFO_get_policy_id_procname = 'TS_TST_INFO_get_policy_id';

  TS_TST_INFO_set_msg_imprint_procname = 'TS_TST_INFO_set_msg_imprint';
  TS_TST_INFO_get_msg_imprint_procname = 'TS_TST_INFO_get_msg_imprint';

  TS_TST_INFO_set_serial_procname = 'TS_TST_INFO_set_serial';
  TS_TST_INFO_get_serial_procname = 'TS_TST_INFO_get_serial';

  TS_TST_INFO_set_time_procname = 'TS_TST_INFO_set_time';
  TS_TST_INFO_get_time_procname = 'TS_TST_INFO_get_time';

  TS_TST_INFO_set_accuracy_procname = 'TS_TST_INFO_set_accuracy';
  TS_TST_INFO_get_accuracy_procname = 'TS_TST_INFO_get_accuracy';

  TS_ACCURACY_set_seconds_procname = 'TS_ACCURACY_set_seconds';
  TS_ACCURACY_get_seconds_procname = 'TS_ACCURACY_get_seconds';

  TS_ACCURACY_set_millis_procname = 'TS_ACCURACY_set_millis';
  TS_ACCURACY_get_millis_procname = 'TS_ACCURACY_get_millis';

  TS_ACCURACY_set_micros_procname = 'TS_ACCURACY_set_micros';
  TS_ACCURACY_get_micros_procname = 'TS_ACCURACY_get_micros';

  TS_TST_INFO_set_ordering_procname = 'TS_TST_INFO_set_ordering';
  TS_TST_INFO_get_ordering_procname = 'TS_TST_INFO_get_ordering';

  TS_TST_INFO_set_nonce_procname = 'TS_TST_INFO_set_nonce';
  TS_TST_INFO_get_nonce_procname = 'TS_TST_INFO_get_nonce';

  TS_TST_INFO_set_tsa_procname = 'TS_TST_INFO_set_tsa';
  TS_TST_INFO_get_tsa_procname = 'TS_TST_INFO_get_tsa';

  //STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a);
  TS_TST_INFO_ext_free_procname = 'TS_TST_INFO_ext_free';
  TS_TST_INFO_get_ext_count_procname = 'TS_TST_INFO_get_ext_count';
  TS_TST_INFO_get_ext_by_NID_procname = 'TS_TST_INFO_get_ext_by_NID';
  TS_TST_INFO_get_ext_by_OBJ_procname = 'TS_TST_INFO_get_ext_by_OBJ';
  TS_TST_INFO_get_ext_by_critical_procname = 'TS_TST_INFO_get_ext_by_critical';
  TS_TST_INFO_get_ext_procname = 'TS_TST_INFO_get_ext';
  TS_TST_INFO_delete_ext_procname = 'TS_TST_INFO_delete_ext';
  TS_TST_INFO_add_ext_procname = 'TS_TST_INFO_add_ext';
  TS_TST_INFO_get_ext_d2i_procname = 'TS_TST_INFO_get_ext_d2i';

  (*
   * Declarations related to response generation, defined in ts/ts_resp_sign.c.
   *)

  //DEFINE_STACK_OF_CONST(EVP_MD)

  (* Creates a response context that can be used for generating responses. *)
  TS_RESP_CTX_new_procname = 'TS_RESP_CTX_new';
  TS_RESP_CTX_free_procname = 'TS_RESP_CTX_free';

  (* This parameter must be set. *)
  TS_RESP_CTX_set_signer_cert_procname = 'TS_RESP_CTX_set_signer_cert';

  (* This parameter must be set. *)
  TS_RESP_CTX_set_signer_key_procname = 'TS_RESP_CTX_set_signer_key';

  TS_RESP_CTX_set_signer_digest_procname = 'TS_RESP_CTX_set_signer_digest';
  TS_RESP_CTX_set_ess_cert_id_digest_procname = 'TS_RESP_CTX_set_ess_cert_id_digest';

  (* This parameter must be set. *)
  TS_RESP_CTX_set_def_policy_procname = 'TS_RESP_CTX_set_def_policy';

  (* No additional certs are included in the response by default. *)
  // int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);

  (*
   * Adds a new acceptable policy, only the default policy is accepted by
   * default.
   *)
  TS_RESP_CTX_add_policy_procname = 'TS_RESP_CTX_add_policy';

  (*
   * Adds a new acceptable message digest. Note that no message digests are
   * accepted by default. The md argument is shared with the caller.
   *)
  TS_RESP_CTX_add_md_procname = 'TS_RESP_CTX_add_md';

  (* Accuracy is not included by default. *)
  TS_RESP_CTX_set_accuracy_procname = 'TS_RESP_CTX_set_accuracy';

  (*
   * Clock precision digits, i.e. the number of decimal digits: '0' means sec,
   * '3' msec, '6' usec, and so on. Default is 0.
   *)
  TS_RESP_CTX_set_clock_precision_digits_procname = 'TS_RESP_CTX_set_clock_precision_digits';

  (* No flags are set by default. *)
  TS_RESP_CTX_add_flags_procname = 'TS_RESP_CTX_add_flags';

  (* Default callback always returns a constant. *)
  TS_RESP_CTX_set_serial_cb_procname = 'TS_RESP_CTX_set_serial_cb';

  (* Default callback uses the gettimeofday() and gmtime() system calls. *)
  TS_RESP_CTX_set_time_cb_procname = 'TS_RESP_CTX_set_time_cb';

  (*
   * Default callback rejects all extensions. The extension callback is called
   * when the TS_TST_INFO object is already set up and not signed yet.
   *)
  (* FIXME: extension handling is not tested yet. *)
  TS_RESP_CTX_set_extension_cb_procname = 'TS_RESP_CTX_set_extension_cb';

  (* The following methods can be used in the callbacks. *)
  TS_RESP_CTX_set_status_info_procname = 'TS_RESP_CTX_set_status_info';

  (* Sets the status info only if it is still TS_STATUS_GRANTED. *)
  TS_RESP_CTX_set_status_info_cond_procname = 'TS_RESP_CTX_set_status_info_cond';

  TS_RESP_CTX_add_failure_info_procname = 'TS_RESP_CTX_add_failure_info';

  (* The get methods below can be used in the extension callback. *)
  TS_RESP_CTX_get_request_procname = 'TS_RESP_CTX_get_request';

  TS_RESP_CTX_get_tst_info_procname = 'TS_RESP_CTX_get_tst_info';

  (*
   * Creates the signed TS_TST_INFO and puts it in TS_RESP.
   * In case of errors it sets the status info properly.
   * Returns NULL only in case of memory allocation/fatal error.
   *)
  TS_RESP_create_response_procname = 'TS_RESP_create_response';

  (*
   * Declarations related to response verification,
   * they are defined in ts/ts_resp_verify.c.
   *)

  //int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs,
  //                             X509_STORE *store, X509 **signer_out);

  (* Context structure for the generic verify method. *)

  TS_RESP_verify_response_procname = 'TS_RESP_verify_response';
  TS_RESP_verify_token_procname = 'TS_RESP_verify_token';

  (*
   * Declarations related to response verification context,
   *)
  TS_VERIFY_CTX_new_procname = 'TS_VERIFY_CTX_new';
  TS_VERIFY_CTX_init_procname = 'TS_VERIFY_CTX_init';
  TS_VERIFY_CTX_free_procname = 'TS_VERIFY_CTX_free';
  TS_VERIFY_CTX_cleanup_procname = 'TS_VERIFY_CTX_cleanup';
  TS_VERIFY_CTX_set_flags_procname = 'TS_VERIFY_CTX_set_flags';
  TS_VERIFY_CTX_add_flags_procname = 'TS_VERIFY_CTX_add_flags';
  TS_VERIFY_CTX_set_data_procname = 'TS_VERIFY_CTX_set_data';
  TS_VERIFY_CTX_set0_data_procname = 'TS_VERIFY_CTX_set0_data';
  TS_VERIFY_CTX_set_imprint_procname = 'TS_VERIFY_CTX_set_imprint';
  TS_VERIFY_CTX_set0_imprint_procname = 'TS_VERIFY_CTX_set0_imprint';
  TS_VERIFY_CTX_set_store_procname = 'TS_VERIFY_CTX_set_store';
  TS_VERIFY_CTX_set0_store_procname = 'TS_VERIFY_CTX_set0_store';
  TS_VERIFY_CTS_set_certs_procname = 'TS_VERIFY_CTS_set_certs';
  TS_VERIFY_CTS_set0_certs_procname = 'TS_VERIFY_CTS_set0_certs';
  (*-
   * If ctx is NULL, it allocates and returns a new object, otherwise
   * it returns ctx. It initialises all the members as follows:
   * flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE)
   * certs = NULL
   * store = NULL
   * policy = policy from the request or NULL if absent (in this case
   *      TS_VFY_POLICY is cleared from flags as well)
   * md_alg = MD algorithm from request
   * imprint, imprint_len = imprint from request
   * data = NULL
   * nonce, nonce_len = nonce from the request or NULL if absent (in this case
   *      TS_VFY_NONCE is cleared from flags as well)
   * tsa_name = NULL
   * Important: after calling this method TS_VFY_SIGNATURE should be added!
   *)
  TS_REQ_to_TS_VERIFY_CTX_procname = 'TS_REQ_to_TS_VERIFY_CTX';

  (* Function declarations for TS_RESP defined in ts/ts_resp_print.c *)

  TS_RESP_print_bio_procname = 'TS_RESP_print_bio';
  TS_STATUS_INFO_print_bio_procname = 'TS_STATUS_INFO_print_bio';
  TS_TST_INFO_print_bio_procname = 'TS_TST_INFO_print_bio';

  (* Common utility functions defined in ts/ts_lib.c *)

  TS_ASN1_INTEGER_print_bio_procname = 'TS_ASN1_INTEGER_print_bio';
  TS_OBJ_print_bio_procname = 'TS_OBJ_print_bio';
  //function TS_ext_print_bio(bio: PBIO; const STACK_OF(): X509_Extension * extensions): TIdC_INT;
  TS_X509_ALGOR_print_bio_procname = 'TS_X509_ALGOR_print_bio';
  TS_MSG_IMPRINT_print_bio_procname = 'TS_MSG_IMPRINT_print_bio';

  (*
   * Function declarations for handling configuration options, defined in
   * ts/ts_conf.c
   *)

  TS_CONF_load_cert_procname = 'TS_CONF_load_cert';
  TS_CONF_load_key_procname = 'TS_CONF_load_key';
  TS_CONF_set_serial_procname = 'TS_CONF_set_serial';
  //STACK_OF(X509) *TS_CONF_load_certs(const char *file);
  TS_CONF_get_tsa_section_procname = 'TS_CONF_get_tsa_section';
  TS_CONF_set_crypto_device_procname = 'TS_CONF_set_crypto_device';
  TS_CONF_set_default_engine_procname = 'TS_CONF_set_default_engine';
  TS_CONF_set_signer_cert_procname = 'TS_CONF_set_signer_cert';
  TS_CONF_set_certs_procname = 'TS_CONF_set_certs';
  TS_CONF_set_signer_key_procname = 'TS_CONF_set_signer_key';
  TS_CONF_set_signer_digest_procname = 'TS_CONF_set_signer_digest';
  TS_CONF_set_def_policy_procname = 'TS_CONF_set_def_policy';
  TS_CONF_set_policies_procname = 'TS_CONF_set_policies';
  TS_CONF_set_digests_procname = 'TS_CONF_set_digests';
  TS_CONF_set_accuracy_procname = 'TS_CONF_set_accuracy';
  TS_CONF_set_clock_precision_digits_procname = 'TS_CONF_set_clock_precision_digits';
  TS_CONF_set_ordering_procname = 'TS_CONF_set_ordering';
  TS_CONF_set_tsa_name_procname = 'TS_CONF_set_tsa_name';
  TS_CONF_set_ess_cert_id_chain_procname = 'TS_CONF_set_ess_cert_id_chain';
  TS_CONF_set_ess_cert_id_digest_procname = 'TS_CONF_set_ess_cert_id_digest';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 

function  ERR_TS_REQ_new: PTS_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_new_procname);
end;


procedure  ERR_TS_REQ_free(a: PTS_REQ);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_free_procname);
end;


function  ERR_i2d_TS_REQ(a: PTS_REQ; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_REQ_procname);
end;


function  ERR_d2i_TS_REQ(a: PPTS_REQ; pp: PPByte; _length: TIdC_LONG): PTS_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_REQ_procname);
end;



function  ERR_TS_REQ_dup(a: PTS_REQ): PTS_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_dup_procname);
end;



function  ERR_d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_REQ_bio_procname);
end;


function  ERR_i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_REQ_bio_procname);
end;



function  ERR_TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_new_procname);
end;


procedure  ERR_TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_free_procname);
end;


function  ERR_i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_MSG_IMPRINT_procname);
end;


function  ERR_d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; pp: PPByte; _length: TIdC_LONG): PTS_MSG_IMPRINT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_MSG_IMPRINT_procname);
end;


function  ERR_TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_dup_procname);
end;



function  ERR_d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_MSG_IMPRINT_bio_procname);
end;


function  ERR_i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_MSG_IMPRINT_bio_procname);
end;



function  ERR_TS_RESP_new: PTS_RESP;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_new_procname);
end;


procedure  ERR_TS_RESP_free(a: PTS_RESP);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_free_procname);
end;


function  ERR_i2d_TS_RESP(a: PTS_RESP; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_RESP_procname);
end;


function  ERR_d2i_TS_RESP(a: PPTS_RESP; pp: PPByte; _length: TIdC_LONG): PTS_RESP;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_RESP_procname);
end;


function  ERR_PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_Info;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_to_TS_TST_INFO_procname);
end;


function  ERR_TS_RESP_dup(a: PTS_RESP): PTS_RESP;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_dup_procname);
end;



function  ERR_d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_RESP_bio_procname);
end;


function  ERR_i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_RESP_bio_procname);
end;



function  ERR_TS_STATUS_INFO_new: PTS_STATUS_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_new_procname);
end;


procedure  ERR_TS_STATUS_INFO_free(a: PTS_STATUS_INFO);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_free_procname);
end;


function  ERR_i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_STATUS_INFO_procname);
end;


function  ERR_d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; pp: PPByte; _length: TIdC_LONG): PTS_STATUS_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_STATUS_INFO_procname);
end;


function  ERR_TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_dup_procname);
end;



function  ERR_TS_TST_INFO_new: PTS_TST_Info;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_new_procname);
end;


procedure  ERR_TS_TST_INFO_free(a: PTS_TST_Info);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_free_procname);
end;


function  ERR_i2d_TS_TST_INFO(a: PTS_TST_Info; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_TST_INFO_procname);
end;


function  ERR_d2i_TS_TST_INFO(a: PPTS_TST_Info; pp: PPByte; _length: TIdC_LONG): PTS_TST_Info;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_TST_INFO_procname);
end;


function  ERR_TS_TST_INFO_dup(a: PTS_TST_Info): PTS_TST_Info;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_dup_procname);
end;



function  ERR_d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_TST_INFO_bio_procname);
end;


function  ERR_i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_Info): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_TST_INFO_bio_procname);
end;



function  ERR_TS_ACCURACY_new: PTS_ACCURACY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_new_procname);
end;


procedure  ERR_TS_ACCURACY_free(a: PTS_ACCURACY);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_free_procname);
end;


function  ERR_i2d_TS_ACCURACY(a: PTS_ACCURACY; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_TS_ACCURACY_procname);
end;


function  ERR_d2i_TS_ACCURACY(a: PPTS_ACCURACY; pp: PPByte; _length: TIdC_LONG): PTS_ACCURACY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_TS_ACCURACY_procname);
end;


function  ERR_TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_dup_procname);
end;



function  ERR_ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_ISSUER_SERIAL_new_procname);
end;


procedure  ERR_ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_ISSUER_SERIAL_free_procname);
end;


function  ERR_i2d_ESS_ISSUER_SERIAL( a: PESS_ISSUER_SERIAL; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_ISSUER_SERIAL_procname);
end;


function  ERR_d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; pp: PPByte; _length: TIdC_LONG): PESS_ISSUER_SERIAL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_ISSUER_SERIAL_procname);
end;


function  ERR_ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_ISSUER_SERIAL_dup_procname);
end;



function  ERR_ESS_CERT_ID_new: PESS_CERT_ID;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_new_procname);
end;


procedure  ERR_ESS_CERT_ID_free(a: PESS_CERT_ID);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_free_procname);
end;


function  ERR_i2d_ESS_CERT_ID(a: PESS_CERT_ID; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_CERT_ID_procname);
end;


function  ERR_d2i_ESS_CERT_ID(a: PPESS_CERT_ID; pp: PPByte; _length: TIdC_LONG): PESS_CERT_ID;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_CERT_ID_procname);
end;


function  ERR_ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_dup_procname);
end;



function  ERR_ESS_SIGNING_CERT_new: PESS_SIGNING_Cert;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_new_procname);
end;


procedure  ERR_ESS_SIGNING_CERT_free(a: PESS_SIGNING_Cert);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_free_procname);
end;


function  ERR_i2d_ESS_SIGNING_CERT( a: PESS_SIGNING_Cert; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_SIGNING_CERT_procname);
end;


function  ERR_d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_Cert; pp: PPByte; _length: TIdC_LONG): PESS_SIGNING_Cert;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_SIGNING_CERT_procname);
end;


function  ERR_ESS_SIGNING_CERT_dup(a: PESS_SIGNING_Cert): PESS_SIGNING_Cert;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_dup_procname);
end;



function  ERR_ESS_CERT_ID_V2_new: PESS_CERT_ID_V2;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_V2_new_procname);
end;


procedure  ERR_ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_V2_free_procname);
end;


function  ERR_i2d_ESS_CERT_ID_V2( a: PESS_CERT_ID_V2; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_CERT_ID_V2_procname);
end;


function  ERR_d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; pp: PPByte; _length: TIdC_LONG): PESS_CERT_ID_V2;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_CERT_ID_V2_procname);
end;


function  ERR_ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_V2_dup_procname);
end;



function  ERR_ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_V2_new_procname);
end;


procedure  ERR_ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_V2_free_procname);
end;


function  ERR_i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; pp: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_SIGNING_CERT_V2_procname);
end;


function  ERR_d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; pp: PPByte; _length: TIdC_LONG): PESS_SIGNING_CERT_V2;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_SIGNING_CERT_V2_procname);
end;


function  ERR_ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_V2_dup_procname);
end;



function  ERR_TS_REQ_set_version(a: PTS_REQ; version: TIdC_LONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_version_procname);
end;


function  ERR_TS_REQ_get_version(a: PTS_REQ): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_version_procname);
end;



function  ERR_TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_set_status_procname);
end;


function  ERR_TS_STATUS_INFO_get0_status(const a: PTS_STATUS_INFO): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_get0_status_procname);
end;



  // const STACK_OF(ASN1_UTF8STRING) *TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a);

  // const ASN1_BIT_STRING *TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a);

function  ERR_TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_msg_imprint_procname);
end;


function  ERR_TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_msg_imprint_procname);
end;



function  ERR_TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_set_algo_procname);
end;


function  ERR_TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOr;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_get_algo_procname);
end;



function  ERR_TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: PByte; len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_set_msg_procname);
end;


function  ERR_TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_get_msg_procname);
end;



function  ERR_TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_policy_id_procname);
end;


function  ERR_TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_policy_id_procname);
end;



function  ERR_TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_nonce_procname);
end;


function  ERR_TS_REQ_get_nonce(const a: PTS_REQ): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_nonce_procname);
end;



function  ERR_TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_set_cert_req_procname);
end;


function  ERR_TS_REQ_get_cert_req(a: PTS_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_cert_req_procname);
end;



  //STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a);
procedure  ERR_TS_REQ_ext_free(a: PTS_REQ);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_ext_free_procname);
end;


function  ERR_TS_REQ_get_ext_count(a: PTS_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_count_procname);
end;


function  ERR_TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_by_NID_procname);
end;


function  ERR_TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_Object; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_by_OBJ_procname);
end;


function  ERR_TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_by_critical_procname);
end;


function  ERR_TS_REQ_get_ext(a: PTS_REQ; loc: TIdC_INT): PX509_Extension;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_procname);
end;


function  ERR_TS_REQ_delete_ext(a: PTS_REQ; loc: TIdC_INT): PX509_Extension;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_delete_ext_procname);
end;


function  ERR_TS_REQ_add_ext(a: PTS_REQ; ex: PX509_Extension; loc: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_add_ext_procname);
end;


function  ERR_TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_get_ext_d2i_procname);
end;



  //* Function declarations for TS_REQ defined in ts/ts_req_print.c */

function  ERR_TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_print_bio_procname);
end;



  //* Function declarations for TS_RESP defined in ts/ts_resp_utils.c */

function  ERR_TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_set_status_info_procname);
end;


function  ERR_TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_get_status_info_procname);
end;



  //* Caller loses ownership of PKCS7 and TS_TST_INFO objects. */
procedure  ERR_TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_set_tst_info_procname);
end;


function  ERR_TS_RESP_get_token(a: PTS_RESP): PPKCS7;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_get_token_procname);
end;


function  ERR_TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_Info;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_get_tst_info_procname);
end;



function  ERR_TS_TST_INFO_set_version(a: PTS_TST_Info; version: TIdC_LONG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_version_procname);
end;


function  ERR_TS_TST_INFO_get_version(const a: PTS_TST_Info): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_version_procname);
end;



function  ERR_TS_TST_INFO_set_policy_id(a: PTS_TST_Info; policy_id: PASN1_Object): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_policy_id_procname);
end;


function  ERR_TS_TST_INFO_get_policy_id(a: PTS_TST_Info): PASN1_Object;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_policy_id_procname);
end;



function  ERR_TS_TST_INFO_set_msg_imprint(a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_msg_imprint_procname);
end;


function  ERR_TS_TST_INFO_get_msg_imprint(a: PTS_TST_Info): PTS_MSG_IMPRINT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_msg_imprint_procname);
end;



function  ERR_TS_TST_INFO_set_serial(a: PTS_TST_Info; const serial: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_serial_procname);
end;


function  ERR_TS_TST_INFO_get_serial(const a: PTS_TST_INFO): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_serial_procname);
end;



function  ERR_TS_TST_INFO_set_time(a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_time_procname);
end;


function  ERR_TS_TST_INFO_get_time(const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_time_procname);
end;



function  ERR_TS_TST_INFO_set_accuracy(a: PTS_TST_Info; accuracy: PTS_ACCURACY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_accuracy_procname);
end;


function  ERR_TS_TST_INFO_get_accuracy(a: PTS_TST_Info): PTS_ACCURACY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_accuracy_procname);
end;



function  ERR_TS_ACCURACY_set_seconds(a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_set_seconds_procname);
end;


function  ERR_TS_ACCURACY_get_seconds(const a: PTS_ACCURACY): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_get_seconds_procname);
end;



function  ERR_TS_ACCURACY_set_millis(a: PTS_ACCURACY; const millis: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_set_millis_procname);
end;


function  ERR_TS_ACCURACY_get_millis(const a: PTS_ACCURACY): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_get_millis_procname);
end;



function  ERR_TS_ACCURACY_set_micros(a: PTS_ACCURACY; const micros: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_set_micros_procname);
end;


function  ERR_TS_ACCURACY_get_micros(const a: PTS_ACCURACY): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ACCURACY_get_micros_procname);
end;



function  ERR_TS_TST_INFO_set_ordering(a: PTS_TST_Info; ordering: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_ordering_procname);
end;


function  ERR_TS_TST_INFO_get_ordering(const a: PTS_TST_Info): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ordering_procname);
end;



function  ERR_TS_TST_INFO_set_nonce(a: PTS_TST_Info; const nonce: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_nonce_procname);
end;


function  ERR_TS_TST_INFO_get_nonce(const a: PTS_TST_INFO): PASN1_INTEGER;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_nonce_procname);
end;



function  ERR_TS_TST_INFO_set_tsa(a: PTS_TST_Info; tsa: PGENERAL_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_set_tsa_procname);
end;


function  ERR_TS_TST_INFO_get_tsa(a: PTS_TST_Info): PGENERAL_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_tsa_procname);
end;



  //STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a);
procedure  ERR_TS_TST_INFO_ext_free(a: PTS_TST_Info);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_ext_free_procname);
end;


function  ERR_TS_TST_INFO_get_ext_count(a: PTS_TST_Info): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_count_procname);
end;


function  ERR_TS_TST_INFO_get_ext_by_NID(a: PTS_TST_Info; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_by_NID_procname);
end;


function  ERR_TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_by_OBJ_procname);
end;


function  ERR_TS_TST_INFO_get_ext_by_critical(a: PTS_TST_Info; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_by_critical_procname);
end;


function  ERR_TS_TST_INFO_get_ext(a: PTS_TST_Info; loc: TIdC_INT): PX509_Extension;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_procname);
end;


function  ERR_TS_TST_INFO_delete_ext(a: PTS_TST_Info; loc: TIdC_INT): PX509_Extension;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_delete_ext_procname);
end;


function  ERR_TS_TST_INFO_add_ext(a: PTS_TST_Info; ex: PX509_Extension; loc: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_add_ext_procname);
end;


function  ERR_TS_TST_INFO_get_ext_d2i(a: PTS_TST_Info; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_get_ext_d2i_procname);
end;



  (*
   * Declarations related to response generation, defined in ts/ts_resp_sign.c.
   *)

  //DEFINE_STACK_OF_CONST(EVP_MD)

  (* Creates a response context that can be used for generating responses. *)
function  ERR_TS_RESP_CTX_new: PTS_RESP_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_new_procname);
end;


procedure  ERR_TS_RESP_CTX_free(ctx: PTS_RESP_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_free_procname);
end;



  (* This parameter must be set. *)
function  ERR_TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_signer_cert_procname);
end;



  (* This parameter must be set. *)
function  ERR_TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_signer_key_procname);
end;



function  ERR_TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_signer_digest_procname);
end;


function  ERR_TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_ess_cert_id_digest_procname);
end;



  (* This parameter must be set. *)
function  ERR_TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_def_policy_procname);
end;



  (* No additional certs are included in the response by default. *)
  // int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs);

  (*
   * Adds a new acceptable policy, only the default policy is accepted by
   * default.
   *)
function  ERR_TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; const policy: PASN1_Object): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_policy_procname);
end;



  (*
   * Adds a new acceptable message digest. Note that no message digests are
   * accepted by default. The md argument is shared with the caller.
   *)
function  ERR_TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; const md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_md_procname);
end;



  (* Accuracy is not included by default. *)
function  ERR_TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TIdC_INT; millis: TIdC_INT; micros: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_accuracy_procname);
end;



  (*
   * Clock precision digits, i.e. the number of decimal digits: '0' means sec,
   * '3' msec, '6' usec, and so on. Default is 0.
   *)
function  ERR_TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_clock_precision_digits_procname);
end;



  (* No flags are set by default. *)
procedure  ERR_TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_flags_procname);
end;



  (* Default callback always returns a constant. *)
procedure  ERR_TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_serial_cb_procname);
end;



  (* Default callback uses the gettimeofday() and gmtime() system calls. *)
procedure  ERR_TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_time_cb_procname);
end;



  (*
   * Default callback rejects all extensions. The extension callback is called
   * when the TS_TST_INFO object is already set up and not signed yet.
   *)
  (* FIXME: extension handling is not tested yet. *)
procedure  ERR_TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_extension_cb_procname);
end;



  (* The following methods can be used in the callbacks. *)
function  ERR_TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TIdC_INT; _text: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_status_info_procname);
end;



  (* Sets the status info only if it is still TS_STATUS_GRANTED. *)
function  ERR_TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TIdC_INT; _text: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_set_status_info_cond_procname);
end;



function  ERR_TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_add_failure_info_procname);
end;



  (* The get methods below can be used in the extension callback. *)
function  ERR_TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_get_request_procname);
end;



function  ERR_TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_Info;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_CTX_get_tst_info_procname);
end;



  (*
   * Creates the signed TS_TST_INFO and puts it in TS_RESP.
   * In case of errors it sets the status info properly.
   * Returns NULL only in case of memory allocation/fatal error.
   *)
function  ERR_TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_create_response_procname);
end;



  (*
   * Declarations related to response verification,
   * they are defined in ts/ts_resp_verify.c.
   *)

  //int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs,
  //                             X509_STORE *store, X509 **signer_out);

  (* Context structure for the generic verify method. *)

function  ERR_TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_verify_response_procname);
end;


function  ERR_TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_verify_token_procname);
end;



  (*
   * Declarations related to response verification context,
   *)
function  ERR_TS_VERIFY_CTX_new: PTS_VERIFY_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_new_procname);
end;


procedure  ERR_TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_init_procname);
end;


procedure  ERR_TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_free_procname);
end;


procedure  ERR_TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_cleanup_procname);
end;


function  ERR_TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_flags_procname);
end;


function  ERR_TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_add_flags_procname);
end;


function  ERR_TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_data_procname);
end;


function ERR_TS_VERIFY_CTX_set0_data(ctx : PTS_VERIFY_CTX; b : PBIO) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set0_data_procname);
end;


function  ERR_TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TIdC_LONG): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_imprint_procname);
end;


function  ERR_TS_VERIFY_CTX_set0_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set0_imprint_procname);
end;


function  ERR_TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set_store_procname);
end;


function ERR_TS_VERIFY_CTX_set0_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTX_set0_store_procname);
end;


function ERR_TS_VERIFY_CTS_set_certs(ctx : PTS_VERIFY_CTX; certs : PSTACK_OF_X509) : PSTACK_OF_X509; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTS_set_certs_procname);
end;

function ERR_TS_VERIFY_CTS_set0_certs(ctx : PTS_VERIFY_CTX; certs : PSTACK_OF_X509) : TIdC_INT; cdecl;
begin
   ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_VERIFY_CTS_set_certs_procname);
end;

  (*-
   * If ctx is NULL, it allocates and returns a new object, otherwise
   * it returns ctx. It initialises all the members as follows:
   * flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE)
   * certs = NULL
   * store = NULL
   * policy = policy from the request or NULL if absent (in this case
   *      TS_VFY_POLICY is cleared from flags as well)
   * md_alg = MD algorithm from request
   * imprint, imprint_len = imprint from request
   * data = NULL
   * nonce, nonce_len = nonce from the request or NULL if absent (in this case
   *      TS_VFY_NONCE is cleared from flags as well)
   * tsa_name = NULL
   * Important: after calling this method TS_VFY_SIGNATURE should be added!
   *)
function  ERR_TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_REQ_to_TS_VERIFY_CTX_procname);
end;



  (* Function declarations for TS_RESP defined in ts/ts_resp_print.c *)

function  ERR_TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_RESP_print_bio_procname);
end;


function  ERR_TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_STATUS_INFO_print_bio_procname);
end;


function  ERR_TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_Info): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_TST_INFO_print_bio_procname);
end;



  (* Common utility functions defined in ts/ts_lib.c *)

function  ERR_TS_ASN1_INTEGER_print_bio(bio: PBIO; const num: PASN1_INTEGER): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_ASN1_INTEGER_print_bio_procname);
end;


function  ERR_TS_OBJ_print_bio(bio: PBIO; const obj: PASN1_Object): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_OBJ_print_bio_procname);
end;


  //function TS_ext_print_bio(bio: PBIO; const STACK_OF(): X509_Extension * extensions): TIdC_INT;
function  ERR_TS_X509_ALGOR_print_bio(bio: PBIO; const alg: PX509_ALGOr): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_X509_ALGOR_print_bio_procname);
end;


function  ERR_TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_MSG_IMPRINT_print_bio_procname);
end;



  (*
   * Function declarations for handling configuration options, defined in
   * ts/ts_conf.c
   *)

function  ERR_TS_CONF_load_cert(file_: PIdAnsiChar): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_load_cert_procname);
end;


function  ERR_TS_CONF_load_key( file_: PIdAnsiChar; pass: PIdAnsiChar): PEVP_PKey;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_load_key_procname);
end;


function  ERR_TS_CONF_set_serial(conf: PCONF; section: PIdAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_serial_procname);
end;


  //STACK_OF(X509) *TS_CONF_load_certs(const char *file);
function  ERR_TS_CONF_get_tsa_section(conf: PCONF; const section: PIdAnsiChar): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_get_tsa_section_procname);
end;


function  ERR_TS_CONF_set_crypto_device(conf: PCONF; section: PIdAnsiChar; device: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_crypto_device_procname);
end;


function  ERR_TS_CONF_set_default_engine(name: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_default_engine_procname);
end;


function  ERR_TS_CONF_set_signer_cert(conf: PCONF; section: PIdAnsiChar; cert: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_signer_cert_procname);
end;


function  ERR_TS_CONF_set_certs(conf: PCONF; section: PIdAnsiChar; certs: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_certs_procname);
end;


function  ERR_TS_CONF_set_signer_key(conf: PCONF; const section: PIdAnsiChar; key: PIdAnsiChar; pass: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_signer_key_procname);
end;


function  ERR_TS_CONF_set_signer_digest(conf: PCONF; section: PIdAnsiChar; md: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_signer_digest_procname);
end;


function  ERR_TS_CONF_set_def_policy(conf: PCONF; section: PIdAnsiChar; policy: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_def_policy_procname);
end;


function  ERR_TS_CONF_set_policies(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_policies_procname);
end;


function  ERR_TS_CONF_set_digests(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_digests_procname);
end;


function  ERR_TS_CONF_set_accuracy(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_accuracy_procname);
end;


function  ERR_TS_CONF_set_clock_precision_digits(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_clock_precision_digits_procname);
end;


function  ERR_TS_CONF_set_ordering(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_ordering_procname);
end;


function  ERR_TS_CONF_set_tsa_name(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_tsa_name_procname);
end;


function  ERR_TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_ess_cert_id_chain_procname);
end;


function  ERR_TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PIdAnsiChar; ctx: PTS_RESP_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TS_CONF_set_ess_cert_id_digest_procname);
end;


  {$I TaurusTLSNoRetValOn.inc} 

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

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


  ESS_ISSUER_SERIAL_new := LoadLibFunction(ADllHandle, ESS_ISSUER_SERIAL_new_procname);
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_ISSUER_SERIAL_new_allownil)}
    ESS_ISSUER_SERIAL_new := ERR_ESS_ISSUER_SERIAL_new;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_new_introduced)}
    if LibVersion < ESS_ISSUER_SERIAL_new_introduced then
    begin
      {$if declared(FC_ESS_ISSUER_SERIAL_new)}
      ESS_ISSUER_SERIAL_new := FC_ESS_ISSUER_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_new_removed)}
    if ESS_ISSUER_SERIAL_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_ISSUER_SERIAL_new)}
      ESS_ISSUER_SERIAL_new := _ESS_ISSUER_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_ISSUER_SERIAL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_ISSUER_SERIAL_new');
    {$ifend}
  end;


  ESS_ISSUER_SERIAL_free := LoadLibFunction(ADllHandle, ESS_ISSUER_SERIAL_free_procname);
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_ISSUER_SERIAL_free_allownil)}
    ESS_ISSUER_SERIAL_free := ERR_ESS_ISSUER_SERIAL_free;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_free_introduced)}
    if LibVersion < ESS_ISSUER_SERIAL_free_introduced then
    begin
      {$if declared(FC_ESS_ISSUER_SERIAL_free)}
      ESS_ISSUER_SERIAL_free := FC_ESS_ISSUER_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_free_removed)}
    if ESS_ISSUER_SERIAL_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_ISSUER_SERIAL_free)}
      ESS_ISSUER_SERIAL_free := _ESS_ISSUER_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_ISSUER_SERIAL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_ISSUER_SERIAL_free');
    {$ifend}
  end;


  i2d_ESS_ISSUER_SERIAL := LoadLibFunction(ADllHandle, i2d_ESS_ISSUER_SERIAL_procname);
  FuncLoadError := not assigned(i2d_ESS_ISSUER_SERIAL);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_ISSUER_SERIAL_allownil)}
    i2d_ESS_ISSUER_SERIAL := ERR_i2d_ESS_ISSUER_SERIAL;
    {$ifend}
    {$if declared(i2d_ESS_ISSUER_SERIAL_introduced)}
    if LibVersion < i2d_ESS_ISSUER_SERIAL_introduced then
    begin
      {$if declared(FC_i2d_ESS_ISSUER_SERIAL)}
      i2d_ESS_ISSUER_SERIAL := FC_i2d_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_ISSUER_SERIAL_removed)}
    if i2d_ESS_ISSUER_SERIAL_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_ISSUER_SERIAL)}
      i2d_ESS_ISSUER_SERIAL := _i2d_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_ISSUER_SERIAL_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_ISSUER_SERIAL');
    {$ifend}
  end;


  d2i_ESS_ISSUER_SERIAL := LoadLibFunction(ADllHandle, d2i_ESS_ISSUER_SERIAL_procname);
  FuncLoadError := not assigned(d2i_ESS_ISSUER_SERIAL);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_ISSUER_SERIAL_allownil)}
    d2i_ESS_ISSUER_SERIAL := ERR_d2i_ESS_ISSUER_SERIAL;
    {$ifend}
    {$if declared(d2i_ESS_ISSUER_SERIAL_introduced)}
    if LibVersion < d2i_ESS_ISSUER_SERIAL_introduced then
    begin
      {$if declared(FC_d2i_ESS_ISSUER_SERIAL)}
      d2i_ESS_ISSUER_SERIAL := FC_d2i_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_ISSUER_SERIAL_removed)}
    if d2i_ESS_ISSUER_SERIAL_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_ISSUER_SERIAL)}
      d2i_ESS_ISSUER_SERIAL := _d2i_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_ISSUER_SERIAL_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_ISSUER_SERIAL');
    {$ifend}
  end;


  ESS_ISSUER_SERIAL_dup := LoadLibFunction(ADllHandle, ESS_ISSUER_SERIAL_dup_procname);
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_ISSUER_SERIAL_dup_allownil)}
    ESS_ISSUER_SERIAL_dup := ERR_ESS_ISSUER_SERIAL_dup;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_dup_introduced)}
    if LibVersion < ESS_ISSUER_SERIAL_dup_introduced then
    begin
      {$if declared(FC_ESS_ISSUER_SERIAL_dup)}
      ESS_ISSUER_SERIAL_dup := FC_ESS_ISSUER_SERIAL_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_dup_removed)}
    if ESS_ISSUER_SERIAL_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_ISSUER_SERIAL_dup)}
      ESS_ISSUER_SERIAL_dup := _ESS_ISSUER_SERIAL_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_ISSUER_SERIAL_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_ISSUER_SERIAL_dup');
    {$ifend}
  end;


  ESS_CERT_ID_new := LoadLibFunction(ADllHandle, ESS_CERT_ID_new_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_new_allownil)}
    ESS_CERT_ID_new := ERR_ESS_CERT_ID_new;
    {$ifend}
    {$if declared(ESS_CERT_ID_new_introduced)}
    if LibVersion < ESS_CERT_ID_new_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_new)}
      ESS_CERT_ID_new := FC_ESS_CERT_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_new_removed)}
    if ESS_CERT_ID_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_new)}
      ESS_CERT_ID_new := _ESS_CERT_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_new');
    {$ifend}
  end;


  ESS_CERT_ID_free := LoadLibFunction(ADllHandle, ESS_CERT_ID_free_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_free_allownil)}
    ESS_CERT_ID_free := ERR_ESS_CERT_ID_free;
    {$ifend}
    {$if declared(ESS_CERT_ID_free_introduced)}
    if LibVersion < ESS_CERT_ID_free_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_free)}
      ESS_CERT_ID_free := FC_ESS_CERT_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_free_removed)}
    if ESS_CERT_ID_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_free)}
      ESS_CERT_ID_free := _ESS_CERT_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_free');
    {$ifend}
  end;


  i2d_ESS_CERT_ID := LoadLibFunction(ADllHandle, i2d_ESS_CERT_ID_procname);
  FuncLoadError := not assigned(i2d_ESS_CERT_ID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_CERT_ID_allownil)}
    i2d_ESS_CERT_ID := ERR_i2d_ESS_CERT_ID;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_introduced)}
    if LibVersion < i2d_ESS_CERT_ID_introduced then
    begin
      {$if declared(FC_i2d_ESS_CERT_ID)}
      i2d_ESS_CERT_ID := FC_i2d_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_removed)}
    if i2d_ESS_CERT_ID_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_CERT_ID)}
      i2d_ESS_CERT_ID := _i2d_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_CERT_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_CERT_ID');
    {$ifend}
  end;


  d2i_ESS_CERT_ID := LoadLibFunction(ADllHandle, d2i_ESS_CERT_ID_procname);
  FuncLoadError := not assigned(d2i_ESS_CERT_ID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_CERT_ID_allownil)}
    d2i_ESS_CERT_ID := ERR_d2i_ESS_CERT_ID;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_introduced)}
    if LibVersion < d2i_ESS_CERT_ID_introduced then
    begin
      {$if declared(FC_d2i_ESS_CERT_ID)}
      d2i_ESS_CERT_ID := FC_d2i_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_removed)}
    if d2i_ESS_CERT_ID_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_CERT_ID)}
      d2i_ESS_CERT_ID := _d2i_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_CERT_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_CERT_ID');
    {$ifend}
  end;


  ESS_CERT_ID_dup := LoadLibFunction(ADllHandle, ESS_CERT_ID_dup_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_dup_allownil)}
    ESS_CERT_ID_dup := ERR_ESS_CERT_ID_dup;
    {$ifend}
    {$if declared(ESS_CERT_ID_dup_introduced)}
    if LibVersion < ESS_CERT_ID_dup_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_dup)}
      ESS_CERT_ID_dup := FC_ESS_CERT_ID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_dup_removed)}
    if ESS_CERT_ID_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_dup)}
      ESS_CERT_ID_dup := _ESS_CERT_ID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_dup');
    {$ifend}
  end;


  ESS_SIGNING_CERT_new := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_new_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_new_allownil)}
    ESS_SIGNING_CERT_new := ERR_ESS_SIGNING_CERT_new;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_new_introduced)}
    if LibVersion < ESS_SIGNING_CERT_new_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_new)}
      ESS_SIGNING_CERT_new := FC_ESS_SIGNING_CERT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_new_removed)}
    if ESS_SIGNING_CERT_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_new)}
      ESS_SIGNING_CERT_new := _ESS_SIGNING_CERT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_new');
    {$ifend}
  end;


  ESS_SIGNING_CERT_free := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_free_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_free_allownil)}
    ESS_SIGNING_CERT_free := ERR_ESS_SIGNING_CERT_free;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_free_introduced)}
    if LibVersion < ESS_SIGNING_CERT_free_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_free)}
      ESS_SIGNING_CERT_free := FC_ESS_SIGNING_CERT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_free_removed)}
    if ESS_SIGNING_CERT_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_free)}
      ESS_SIGNING_CERT_free := _ESS_SIGNING_CERT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_free');
    {$ifend}
  end;


  i2d_ESS_SIGNING_CERT := LoadLibFunction(ADllHandle, i2d_ESS_SIGNING_CERT_procname);
  FuncLoadError := not assigned(i2d_ESS_SIGNING_CERT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_SIGNING_CERT_allownil)}
    i2d_ESS_SIGNING_CERT := ERR_i2d_ESS_SIGNING_CERT;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_introduced)}
    if LibVersion < i2d_ESS_SIGNING_CERT_introduced then
    begin
      {$if declared(FC_i2d_ESS_SIGNING_CERT)}
      i2d_ESS_SIGNING_CERT := FC_i2d_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_removed)}
    if i2d_ESS_SIGNING_CERT_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_SIGNING_CERT)}
      i2d_ESS_SIGNING_CERT := _i2d_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_SIGNING_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_SIGNING_CERT');
    {$ifend}
  end;


  d2i_ESS_SIGNING_CERT := LoadLibFunction(ADllHandle, d2i_ESS_SIGNING_CERT_procname);
  FuncLoadError := not assigned(d2i_ESS_SIGNING_CERT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_SIGNING_CERT_allownil)}
    d2i_ESS_SIGNING_CERT := ERR_d2i_ESS_SIGNING_CERT;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_introduced)}
    if LibVersion < d2i_ESS_SIGNING_CERT_introduced then
    begin
      {$if declared(FC_d2i_ESS_SIGNING_CERT)}
      d2i_ESS_SIGNING_CERT := FC_d2i_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_removed)}
    if d2i_ESS_SIGNING_CERT_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_SIGNING_CERT)}
      d2i_ESS_SIGNING_CERT := _d2i_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_SIGNING_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_SIGNING_CERT');
    {$ifend}
  end;


  ESS_SIGNING_CERT_dup := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_dup_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_dup_allownil)}
    ESS_SIGNING_CERT_dup := ERR_ESS_SIGNING_CERT_dup;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_dup_introduced)}
    if LibVersion < ESS_SIGNING_CERT_dup_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_dup)}
      ESS_SIGNING_CERT_dup := FC_ESS_SIGNING_CERT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_dup_removed)}
    if ESS_SIGNING_CERT_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_dup)}
      ESS_SIGNING_CERT_dup := _ESS_SIGNING_CERT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_dup');
    {$ifend}
  end;


  ESS_CERT_ID_V2_new := LoadLibFunction(ADllHandle, ESS_CERT_ID_V2_new_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_V2_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_V2_new_allownil)}
    ESS_CERT_ID_V2_new := ERR_ESS_CERT_ID_V2_new;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_new_introduced)}
    if LibVersion < ESS_CERT_ID_V2_new_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_V2_new)}
      ESS_CERT_ID_V2_new := FC_ESS_CERT_ID_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_new_removed)}
    if ESS_CERT_ID_V2_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_V2_new)}
      ESS_CERT_ID_V2_new := _ESS_CERT_ID_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_V2_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_V2_new');
    {$ifend}
  end;


  ESS_CERT_ID_V2_free := LoadLibFunction(ADllHandle, ESS_CERT_ID_V2_free_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_V2_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_V2_free_allownil)}
    ESS_CERT_ID_V2_free := ERR_ESS_CERT_ID_V2_free;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_free_introduced)}
    if LibVersion < ESS_CERT_ID_V2_free_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_V2_free)}
      ESS_CERT_ID_V2_free := FC_ESS_CERT_ID_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_free_removed)}
    if ESS_CERT_ID_V2_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_V2_free)}
      ESS_CERT_ID_V2_free := _ESS_CERT_ID_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_V2_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_V2_free');
    {$ifend}
  end;


  i2d_ESS_CERT_ID_V2 := LoadLibFunction(ADllHandle, i2d_ESS_CERT_ID_V2_procname);
  FuncLoadError := not assigned(i2d_ESS_CERT_ID_V2);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_CERT_ID_V2_allownil)}
    i2d_ESS_CERT_ID_V2 := ERR_i2d_ESS_CERT_ID_V2;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_V2_introduced)}
    if LibVersion < i2d_ESS_CERT_ID_V2_introduced then
    begin
      {$if declared(FC_i2d_ESS_CERT_ID_V2)}
      i2d_ESS_CERT_ID_V2 := FC_i2d_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_V2_removed)}
    if i2d_ESS_CERT_ID_V2_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_CERT_ID_V2)}
      i2d_ESS_CERT_ID_V2 := _i2d_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_CERT_ID_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_CERT_ID_V2');
    {$ifend}
  end;


  d2i_ESS_CERT_ID_V2 := LoadLibFunction(ADllHandle, d2i_ESS_CERT_ID_V2_procname);
  FuncLoadError := not assigned(d2i_ESS_CERT_ID_V2);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_CERT_ID_V2_allownil)}
    d2i_ESS_CERT_ID_V2 := ERR_d2i_ESS_CERT_ID_V2;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_V2_introduced)}
    if LibVersion < d2i_ESS_CERT_ID_V2_introduced then
    begin
      {$if declared(FC_d2i_ESS_CERT_ID_V2)}
      d2i_ESS_CERT_ID_V2 := FC_d2i_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_V2_removed)}
    if d2i_ESS_CERT_ID_V2_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_CERT_ID_V2)}
      d2i_ESS_CERT_ID_V2 := _d2i_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_CERT_ID_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_CERT_ID_V2');
    {$ifend}
  end;


  ESS_CERT_ID_V2_dup := LoadLibFunction(ADllHandle, ESS_CERT_ID_V2_dup_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_V2_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_V2_dup_allownil)}
    ESS_CERT_ID_V2_dup := ERR_ESS_CERT_ID_V2_dup;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_dup_introduced)}
    if LibVersion < ESS_CERT_ID_V2_dup_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_V2_dup)}
      ESS_CERT_ID_V2_dup := FC_ESS_CERT_ID_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_dup_removed)}
    if ESS_CERT_ID_V2_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_V2_dup)}
      ESS_CERT_ID_V2_dup := _ESS_CERT_ID_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_V2_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_V2_dup');
    {$ifend}
  end;


  ESS_SIGNING_CERT_V2_new := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_V2_new_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_V2_new_allownil)}
    ESS_SIGNING_CERT_V2_new := ERR_ESS_SIGNING_CERT_V2_new;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_new_introduced)}
    if LibVersion < ESS_SIGNING_CERT_V2_new_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_V2_new)}
      ESS_SIGNING_CERT_V2_new := FC_ESS_SIGNING_CERT_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_new_removed)}
    if ESS_SIGNING_CERT_V2_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_V2_new)}
      ESS_SIGNING_CERT_V2_new := _ESS_SIGNING_CERT_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_V2_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_V2_new');
    {$ifend}
  end;


  ESS_SIGNING_CERT_V2_free := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_V2_free_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_V2_free_allownil)}
    ESS_SIGNING_CERT_V2_free := ERR_ESS_SIGNING_CERT_V2_free;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_free_introduced)}
    if LibVersion < ESS_SIGNING_CERT_V2_free_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_V2_free)}
      ESS_SIGNING_CERT_V2_free := FC_ESS_SIGNING_CERT_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_free_removed)}
    if ESS_SIGNING_CERT_V2_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_V2_free)}
      ESS_SIGNING_CERT_V2_free := _ESS_SIGNING_CERT_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_V2_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_V2_free');
    {$ifend}
  end;


  i2d_ESS_SIGNING_CERT_V2 := LoadLibFunction(ADllHandle, i2d_ESS_SIGNING_CERT_V2_procname);
  FuncLoadError := not assigned(i2d_ESS_SIGNING_CERT_V2);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_SIGNING_CERT_V2_allownil)}
    i2d_ESS_SIGNING_CERT_V2 := ERR_i2d_ESS_SIGNING_CERT_V2;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_V2_introduced)}
    if LibVersion < i2d_ESS_SIGNING_CERT_V2_introduced then
    begin
      {$if declared(FC_i2d_ESS_SIGNING_CERT_V2)}
      i2d_ESS_SIGNING_CERT_V2 := FC_i2d_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_V2_removed)}
    if i2d_ESS_SIGNING_CERT_V2_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_SIGNING_CERT_V2)}
      i2d_ESS_SIGNING_CERT_V2 := _i2d_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_SIGNING_CERT_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_SIGNING_CERT_V2');
    {$ifend}
  end;


  d2i_ESS_SIGNING_CERT_V2 := LoadLibFunction(ADllHandle, d2i_ESS_SIGNING_CERT_V2_procname);
  FuncLoadError := not assigned(d2i_ESS_SIGNING_CERT_V2);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_SIGNING_CERT_V2_allownil)}
    d2i_ESS_SIGNING_CERT_V2 := ERR_d2i_ESS_SIGNING_CERT_V2;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_V2_introduced)}
    if LibVersion < d2i_ESS_SIGNING_CERT_V2_introduced then
    begin
      {$if declared(FC_d2i_ESS_SIGNING_CERT_V2)}
      d2i_ESS_SIGNING_CERT_V2 := FC_d2i_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_V2_removed)}
    if d2i_ESS_SIGNING_CERT_V2_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_SIGNING_CERT_V2)}
      d2i_ESS_SIGNING_CERT_V2 := _d2i_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_SIGNING_CERT_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_SIGNING_CERT_V2');
    {$ifend}
  end;


  ESS_SIGNING_CERT_V2_dup := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_V2_dup_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_V2_dup_allownil)}
    ESS_SIGNING_CERT_V2_dup := ERR_ESS_SIGNING_CERT_V2_dup;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_dup_introduced)}
    if LibVersion < ESS_SIGNING_CERT_V2_dup_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_V2_dup)}
      ESS_SIGNING_CERT_V2_dup := FC_ESS_SIGNING_CERT_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_dup_removed)}
    if ESS_SIGNING_CERT_V2_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_V2_dup)}
      ESS_SIGNING_CERT_V2_dup := _ESS_SIGNING_CERT_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_V2_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_V2_dup');
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


  TS_VERIFY_CTS_set_certs := LoadLibFunction(ADllHandle,TS_VERIFY_CTS_set_certs_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTS_set_certs);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTS_set_certs_allownil)}
   TS_VERIFY_CTS_set_certs := ERR_TS_VERIFY_CTS_set_certs;
    {$ifend}
    {$if declared(TS_VERIFY_CTS_set_certsintroduced)}
    if LibVersion < TS_VERIFY_CTS_set_certs_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTS_set_certs)}
      TS_VERIFY_CTS_set_certs := FC_TS_VERIFY_CTS_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTS_set_certs_removed)}
    ifTS_VERIFY_CTS_set_certs_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTS_set_certs)}
     TS_VERIFY_CTS_set_certs := _TS_VERIFY_CTS_set_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTS_set_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTS_set_certs');
    {$ifend}
  end;


  TS_VERIFY_CTS_set0_certs := LoadLibFunction(ADllHandle,TS_VERIFY_CTS_set0_certs_procname);
  FuncLoadError := not assigned(TS_VERIFY_CTS_set0_certs);
  if FuncLoadError then
  begin
    {$if not defined(TS_VERIFY_CTS_set0_certs_allownil)}
    TS_VERIFY_CTS_set0_certs := ERR_TS_VERIFY_CTS_set0_certs;
    {$ifend}
    {$if declared(TS_VERIFY_CTX_set0_certs_introduced)}
    if LibVersion < TS_VERIFY_CTX_set0_certs_introduced then
    begin
      {$if declared(FC_TS_VERIFY_CTS_set0_certs)}
      TS_VERIFY_CTS_set0_certs := FC_TS_VERIFY_CTS_set0_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TS_VERIFY_CTS_set0_certs_removed)}
    ifTS_VERIFY_CTS_set0_certs_removed <= LibVersion then
    begin
      {$if declared(_TS_VERIFY_CTS_set0_certs)}
     TS_VERIFY_CTS_set0_certs := _TS_VERIFY_CTS_set0_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TS_VERIFY_CTS_set0_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('TS_VERIFY_CTS_set0_certs');
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
  i2d_TS_REQ := nil;
  d2i_TS_REQ := nil;
  TS_REQ_dup := nil;
  d2i_TS_REQ_bio := nil;
  i2d_TS_REQ_bio := nil;
  TS_MSG_IMPRINT_new := nil;
  TS_MSG_IMPRINT_free := nil;
  i2d_TS_MSG_IMPRINT := nil;
  d2i_TS_MSG_IMPRINT := nil;
  TS_MSG_IMPRINT_dup := nil;
  d2i_TS_MSG_IMPRINT_bio := nil;
  i2d_TS_MSG_IMPRINT_bio := nil;
  TS_RESP_new := nil;
  TS_RESP_free := nil;
  i2d_TS_RESP := nil;
  d2i_TS_RESP := nil;
  PKCS7_to_TS_TST_INFO := nil;
  TS_RESP_dup := nil;
  d2i_TS_RESP_bio := nil;
  i2d_TS_RESP_bio := nil;
  TS_STATUS_INFO_new := nil;
  TS_STATUS_INFO_free := nil;
  i2d_TS_STATUS_INFO := nil;
  d2i_TS_STATUS_INFO := nil;
  TS_STATUS_INFO_dup := nil;
  TS_TST_INFO_new := nil;
  TS_TST_INFO_free := nil;
  i2d_TS_TST_INFO := nil;
  d2i_TS_TST_INFO := nil;
  TS_TST_INFO_dup := nil;
  d2i_TS_TST_INFO_bio := nil;
  i2d_TS_TST_INFO_bio := nil;
  TS_ACCURACY_new := nil;
  TS_ACCURACY_free := nil;
  i2d_TS_ACCURACY := nil;
  d2i_TS_ACCURACY := nil;
  TS_ACCURACY_dup := nil;
  ESS_ISSUER_SERIAL_new := nil;
  ESS_ISSUER_SERIAL_free := nil;
  i2d_ESS_ISSUER_SERIAL := nil;
  d2i_ESS_ISSUER_SERIAL := nil;
  ESS_ISSUER_SERIAL_dup := nil;
  ESS_CERT_ID_new := nil;
  ESS_CERT_ID_free := nil;
  i2d_ESS_CERT_ID := nil;
  d2i_ESS_CERT_ID := nil;
  ESS_CERT_ID_dup := nil;
  ESS_SIGNING_CERT_new := nil;
  ESS_SIGNING_CERT_free := nil;
  i2d_ESS_SIGNING_CERT := nil;
  d2i_ESS_SIGNING_CERT := nil;
  ESS_SIGNING_CERT_dup := nil;
  ESS_CERT_ID_V2_new := nil;
  ESS_CERT_ID_V2_free := nil;
  i2d_ESS_CERT_ID_V2 := nil;
  d2i_ESS_CERT_ID_V2 := nil;
  ESS_CERT_ID_V2_dup := nil;
  ESS_SIGNING_CERT_V2_new := nil;
  ESS_SIGNING_CERT_V2_free := nil;
  i2d_ESS_SIGNING_CERT_V2 := nil;
  d2i_ESS_SIGNING_CERT_V2 := nil;
  ESS_SIGNING_CERT_V2_dup := nil;
  TS_REQ_set_version := nil;
  TS_REQ_get_version := nil;
  TS_STATUS_INFO_set_status := nil;
  TS_STATUS_INFO_get0_status := nil;
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
  TS_RESP_CTX_free := nil;
  TS_RESP_CTX_set_signer_cert := nil;
  TS_RESP_CTX_set_signer_key := nil;
  TS_RESP_CTX_set_signer_digest := nil;
  TS_RESP_CTX_set_ess_cert_id_digest := nil;
  TS_RESP_CTX_set_def_policy := nil;
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
  TS_VERIFY_CTS_set_certs := nil;
  TS_VERIFY_CTS_set0_certs := nil;
  TS_REQ_to_TS_VERIFY_CTX := nil;
  TS_RESP_print_bio := nil;
  TS_STATUS_INFO_print_bio := nil;
  TS_TST_INFO_print_bio := nil;
  TS_ASN1_INTEGER_print_bio := nil;
  TS_OBJ_print_bio := nil;
  TS_X509_ALGOR_print_bio := nil;
  TS_MSG_IMPRINT_print_bio := nil;
  TS_CONF_load_cert := nil;
  TS_CONF_load_key := nil;
  TS_CONF_set_serial := nil;
  TS_CONF_get_tsa_section := nil;
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
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
