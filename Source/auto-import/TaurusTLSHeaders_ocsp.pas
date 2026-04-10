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

unit TaurusTLSHeaders_ocsp;

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
  Pocsp_cert_id_st = ^Tocsp_cert_id_st;
  Tocsp_cert_id_st =   record end;
  {$EXTERNALSYM Pocsp_cert_id_st}

  Pocsp_one_request_st = ^Tocsp_one_request_st;
  Tocsp_one_request_st =   record end;
  {$EXTERNALSYM Pocsp_one_request_st}

  Pocsp_req_info_st = ^Tocsp_req_info_st;
  Tocsp_req_info_st =   record end;
  {$EXTERNALSYM Pocsp_req_info_st}

  Pocsp_signature_st = ^Tocsp_signature_st;
  Tocsp_signature_st =   record end;
  {$EXTERNALSYM Pocsp_signature_st}

  Pocsp_request_st = ^Tocsp_request_st;
  Tocsp_request_st =   record end;
  {$EXTERNALSYM Pocsp_request_st}

  Pocsp_resp_bytes_st = ^Tocsp_resp_bytes_st;
  Tocsp_resp_bytes_st =   record end;
  {$EXTERNALSYM Pocsp_resp_bytes_st}

  Pocsp_revoked_info_st = ^Tocsp_revoked_info_st;
  Tocsp_revoked_info_st =   record end;
  {$EXTERNALSYM Pocsp_revoked_info_st}

  Pocsp_cert_status_st = ^Tocsp_cert_status_st;
  Tocsp_cert_status_st =   record end;
  {$EXTERNALSYM Pocsp_cert_status_st}

  Pocsp_single_response_st = ^Tocsp_single_response_st;
  Tocsp_single_response_st =   record end;
  {$EXTERNALSYM Pocsp_single_response_st}

  Pocsp_response_data_st = ^Tocsp_response_data_st;
  Tocsp_response_data_st =   record end;
  {$EXTERNALSYM Pocsp_response_data_st}

  Pocsp_basic_response_st = ^Tocsp_basic_response_st;
  Tocsp_basic_response_st =   record end;
  {$EXTERNALSYM Pocsp_basic_response_st}

  Pocsp_crl_id_st = ^Tocsp_crl_id_st;
  Tocsp_crl_id_st =   record end;
  {$EXTERNALSYM Pocsp_crl_id_st}

  Pocsp_service_locator_st = ^Tocsp_service_locator_st;
  Tocsp_service_locator_st =   record end;
  {$EXTERNALSYM Pocsp_service_locator_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OCSP_REVOKED_STATUS_NOSTATUS = -1;
  OCSP_REVOKED_STATUS_UNSPECIFIED = 0;
  OCSP_REVOKED_STATUS_KEYCOMPROMISE = 1;
  OCSP_REVOKED_STATUS_CACOMPROMISE = 2;
  OCSP_REVOKED_STATUS_AFFILIATIONCHANGED = 3;
  OCSP_REVOKED_STATUS_SUPERSEDED = 4;
  OCSP_REVOKED_STATUS_CESSATIONOFOPERATION = 5;
  OCSP_REVOKED_STATUS_CERTIFICATEHOLD = 6;
  OCSP_REVOKED_STATUS_REMOVEFROMCRL = 8;
  OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN = 9;
  OCSP_REVOKED_STATUS_AACOMPROMISE = 10;
  OCSP_DEFAULT_NONCE_LENGTH = 16;
  OCSP_NOCERTS = $1;
  OCSP_NOINTERN = $2;
  OCSP_NOSIGS = $4;
  OCSP_NOCHAIN = $8;
  OCSP_NOVERIFY = $10;
  OCSP_NOEXPLICIT = $20;
  OCSP_NOCASIGN = $40;
  OCSP_NODELEGATED = $80;
  OCSP_NOCHECKS = $100;
  OCSP_TRUSTOTHER = $200;
  OCSP_RESPID_KEY = $400;
  OCSP_NOTIME = $800;
  OCSP_PARTIAL_CHAIN = $1000;
  OCSP_RESPONSE_STATUS_SUCCESSFUL = 0;
  OCSP_RESPONSE_STATUS_MALFORMEDREQUEST = 1;
  OCSP_RESPONSE_STATUS_INTERNALERROR = 2;
  OCSP_RESPONSE_STATUS_TRYLATER = 3;
  OCSP_RESPONSE_STATUS_SIGREQUIRED = 5;
  OCSP_RESPONSE_STATUS_UNAUTHORIZED = 6;
  V_OCSP_RESPID_NAME = 0;
  V_OCSP_RESPID_KEY = 1;
  V_OCSP_CERTSTATUS_GOOD = 0;
  V_OCSP_CERTSTATUS_REVOKED = 1;
  V_OCSP_CERTSTATUS_UNKNOWN = 2;
  PEM_STRING_OCSP_REQUEST = 'OCSP REQUEST';
  PEM_STRING_OCSP_RESPONSE = 'OCSP RESPONSE';
  OCSP_REQ_CTX_free = OSSL_HTTP_REQ_CTX_free;
  OCSP_REQ_CTX_add1_header = OSSL_HTTP_REQ_CTX_add1_header;
  OCSP_REQ_CTX_nbio = OSSL_HTTP_REQ_CTX_nbio;
  OCSP_REQ_CTX_nbio_d2i = OSSL_HTTP_REQ_CTX_nbio_d2i;
  OCSP_REQ_CTX_get0_mem_bio = OSSL_HTTP_REQ_CTX_get0_mem_bio;
  OCSP_set_max_response_length = OSSL_HTTP_REQ_CTX_set_max_response_length;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OCSP_CERTID_dup: function(a: POCSP_CERTID): POCSP_CERTID; cdecl = nil;
  {$EXTERNALSYM OCSP_CERTID_dup}

  OCSP_sendreq_new: function(io: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl = nil;
  {$EXTERNALSYM OCSP_sendreq_new}

  OCSP_sendreq_bio: function(b: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST): POCSP_RESPONSE; cdecl = nil;
  {$EXTERNALSYM OCSP_sendreq_bio}

  OCSP_cert_to_id: function(dgst: PEVP_MD; subject: PX509; issuer: PX509): POCSP_CERTID; cdecl = nil;
  {$EXTERNALSYM OCSP_cert_to_id}

  OCSP_cert_id_new: function(dgst: PEVP_MD; issuerName: PX509_NAME; issuerKey: PASN1_BIT_STRING; serialNumber: PASN1_INTEGER): POCSP_CERTID; cdecl = nil;
  {$EXTERNALSYM OCSP_cert_id_new}

  OCSP_request_add0_id: function(req: POCSP_REQUEST; cid: POCSP_CERTID): POCSP_ONEREQ; cdecl = nil;
  {$EXTERNALSYM OCSP_request_add0_id}

  OCSP_request_add1_nonce: function(req: POCSP_REQUEST; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_request_add1_nonce}

  OCSP_basic_add1_nonce: function(resp: POCSP_BASICRESP; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_basic_add1_nonce}

  OCSP_check_nonce: function(req: POCSP_REQUEST; bs: POCSP_BASICRESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_check_nonce}

  OCSP_copy_nonce: function(resp: POCSP_BASICRESP; req: POCSP_REQUEST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_copy_nonce}

  OCSP_request_set1_name: function(req: POCSP_REQUEST; nm: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_request_set1_name}

  OCSP_request_add1_cert: function(req: POCSP_REQUEST; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_request_add1_cert}

  OCSP_request_sign: function(req: POCSP_REQUEST; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_request_sign}

  OCSP_response_status: function(resp: POCSP_RESPONSE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_response_status}

  OCSP_response_get1_basic: function(resp: POCSP_RESPONSE): POCSP_BASICRESP; cdecl = nil;
  {$EXTERNALSYM OCSP_response_get1_basic}

  OCSP_resp_get0_signature: function(bs: POCSP_BASICRESP): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0_signature}

  OCSP_resp_get0_tbs_sigalg: function(bs: POCSP_BASICRESP): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0_tbs_sigalg}

  OCSP_resp_get0_respdata: function(bs: POCSP_BASICRESP): POCSP_RESPDATA; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0_respdata}

  OCSP_resp_get0_signer: function(bs: POCSP_BASICRESP; signer: PPX509; extra_certs: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0_signer}

  OCSP_resp_count: function(bs: POCSP_BASICRESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_count}

  OCSP_resp_get0: function(bs: POCSP_BASICRESP; idx: TIdC_INT): POCSP_SINGLERESP; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0}

  OCSP_resp_get0_produced_at: function(bs: POCSP_BASICRESP): PASN1_GENERALIZEDTIME; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0_produced_at}

  OCSP_resp_get0_certs: function(bs: POCSP_BASICRESP): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0_certs}

  OCSP_resp_get0_id: function(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get0_id}

  OCSP_resp_get1_id: function(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_get1_id}

  OCSP_resp_find: function(bs: POCSP_BASICRESP; id: POCSP_CERTID; last: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_find}

  OCSP_single_get0_status: function(single: POCSP_SINGLERESP; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_single_get0_status}

  OCSP_resp_find_status: function(bs: POCSP_BASICRESP; id: POCSP_CERTID; status: PIdC_INT; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_resp_find_status}

  OCSP_check_validity: function(thisupd: PASN1_GENERALIZEDTIME; nextupd: PASN1_GENERALIZEDTIME; sec: TIdC_LONG; maxsec: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_check_validity}

  OCSP_request_verify: function(req: POCSP_REQUEST; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_request_verify}

  OCSP_id_issuer_cmp: function(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_id_issuer_cmp}

  OCSP_id_cmp: function(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_id_cmp}

  OCSP_request_onereq_count: function(req: POCSP_REQUEST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_request_onereq_count}

  OCSP_request_onereq_get0: function(req: POCSP_REQUEST; i: TIdC_INT): POCSP_ONEREQ; cdecl = nil;
  {$EXTERNALSYM OCSP_request_onereq_get0}

  OCSP_onereq_get0_id: function(one: POCSP_ONEREQ): POCSP_CERTID; cdecl = nil;
  {$EXTERNALSYM OCSP_onereq_get0_id}

  OCSP_id_get0_info: function(piNameHash: PPASN1_OCTET_STRING; pmd: PPASN1_OBJECT; pikeyHash: PPASN1_OCTET_STRING; pserial: PPASN1_INTEGER; cid: POCSP_CERTID): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_id_get0_info}

  OCSP_request_is_signed: function(req: POCSP_REQUEST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_request_is_signed}

  OCSP_response_create: function(status: TIdC_INT; bs: POCSP_BASICRESP): POCSP_RESPONSE; cdecl = nil;
  {$EXTERNALSYM OCSP_response_create}

  OCSP_basic_add1_status: function(rsp: POCSP_BASICRESP; cid: POCSP_CERTID; status: TIdC_INT; reason: TIdC_INT; revtime: PASN1_TIME; thisupd: PASN1_TIME; nextupd: PASN1_TIME): POCSP_SINGLERESP; cdecl = nil;
  {$EXTERNALSYM OCSP_basic_add1_status}

  OCSP_basic_add1_cert: function(resp: POCSP_BASICRESP; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_basic_add1_cert}

  OCSP_basic_sign: function(brsp: POCSP_BASICRESP; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_basic_sign}

  OCSP_basic_sign_ctx: function(brsp: POCSP_BASICRESP; signer: PX509; ctx: PEVP_MD_CTX; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_basic_sign_ctx}

  OCSP_RESPID_set_by_name: function(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_set_by_name}

  OCSP_RESPID_set_by_key_ex: function(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_set_by_key_ex}

  OCSP_RESPID_set_by_key: function(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_set_by_key}

  OCSP_RESPID_match_ex: function(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_match_ex}

  OCSP_RESPID_match: function(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_match}

  OCSP_crlID_new: function(url: PIdAnsiChar; n: PIdC_LONG; tim: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_crlID_new}

  OCSP_accept_responses_new: function(oids: PPIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_accept_responses_new}

  OCSP_archive_cutoff_new: function(tim: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_archive_cutoff_new}

  OCSP_url_svcloc_new: function(issuer: PX509_NAME; urls: PPIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_url_svcloc_new}

  OCSP_REQUEST_get_ext_count: function(x: POCSP_REQUEST): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_get_ext_count}

  OCSP_REQUEST_get_ext_by_NID: function(x: POCSP_REQUEST; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_get_ext_by_NID}

  OCSP_REQUEST_get_ext_by_OBJ: function(x: POCSP_REQUEST; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_get_ext_by_OBJ}

  OCSP_REQUEST_get_ext_by_critical: function(x: POCSP_REQUEST; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_get_ext_by_critical}

  OCSP_REQUEST_get_ext: function(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_get_ext}

  OCSP_REQUEST_delete_ext: function(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_delete_ext}

  OCSP_REQUEST_get1_ext_d2i: function(x: POCSP_REQUEST; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_get1_ext_d2i}

  OCSP_REQUEST_add1_ext_i2d: function(x: POCSP_REQUEST; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_add1_ext_i2d}

  OCSP_REQUEST_add_ext: function(x: POCSP_REQUEST; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_add_ext}

  OCSP_ONEREQ_get_ext_count: function(x: POCSP_ONEREQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_get_ext_count}

  OCSP_ONEREQ_get_ext_by_NID: function(x: POCSP_ONEREQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_get_ext_by_NID}

  OCSP_ONEREQ_get_ext_by_OBJ: function(x: POCSP_ONEREQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_get_ext_by_OBJ}

  OCSP_ONEREQ_get_ext_by_critical: function(x: POCSP_ONEREQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_get_ext_by_critical}

  OCSP_ONEREQ_get_ext: function(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_get_ext}

  OCSP_ONEREQ_delete_ext: function(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_delete_ext}

  OCSP_ONEREQ_get1_ext_d2i: function(x: POCSP_ONEREQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_get1_ext_d2i}

  OCSP_ONEREQ_add1_ext_i2d: function(x: POCSP_ONEREQ; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_add1_ext_i2d}

  OCSP_ONEREQ_add_ext: function(x: POCSP_ONEREQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_add_ext}

  OCSP_BASICRESP_get_ext_count: function(x: POCSP_BASICRESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_get_ext_count}

  OCSP_BASICRESP_get_ext_by_NID: function(x: POCSP_BASICRESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_get_ext_by_NID}

  OCSP_BASICRESP_get_ext_by_OBJ: function(x: POCSP_BASICRESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_get_ext_by_OBJ}

  OCSP_BASICRESP_get_ext_by_critical: function(x: POCSP_BASICRESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_get_ext_by_critical}

  OCSP_BASICRESP_get_ext: function(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_get_ext}

  OCSP_BASICRESP_delete_ext: function(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_delete_ext}

  OCSP_BASICRESP_get1_ext_d2i: function(x: POCSP_BASICRESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_get1_ext_d2i}

  OCSP_BASICRESP_add1_ext_i2d: function(x: POCSP_BASICRESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_add1_ext_i2d}

  OCSP_BASICRESP_add_ext: function(x: POCSP_BASICRESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_add_ext}

  OCSP_SINGLERESP_get_ext_count: function(x: POCSP_SINGLERESP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_get_ext_count}

  OCSP_SINGLERESP_get_ext_by_NID: function(x: POCSP_SINGLERESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_get_ext_by_NID}

  OCSP_SINGLERESP_get_ext_by_OBJ: function(x: POCSP_SINGLERESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_get_ext_by_OBJ}

  OCSP_SINGLERESP_get_ext_by_critical: function(x: POCSP_SINGLERESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_get_ext_by_critical}

  OCSP_SINGLERESP_get_ext: function(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_get_ext}

  OCSP_SINGLERESP_delete_ext: function(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_delete_ext}

  OCSP_SINGLERESP_get1_ext_d2i: function(x: POCSP_SINGLERESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_get1_ext_d2i}

  OCSP_SINGLERESP_add1_ext_i2d: function(x: POCSP_SINGLERESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_add1_ext_i2d}

  OCSP_SINGLERESP_add_ext: function(x: POCSP_SINGLERESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_add_ext}

  OCSP_SINGLERESP_get0_id: function(x: POCSP_SINGLERESP): POCSP_CERTID; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_get0_id}

  OCSP_SINGLERESP_new: function: POCSP_SINGLERESP; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_new}

  OCSP_SINGLERESP_free: function(a: POCSP_SINGLERESP): void; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_free}

  d2i_OCSP_SINGLERESP: function(a: PPOCSP_SINGLERESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SINGLERESP; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_SINGLERESP}

  i2d_OCSP_SINGLERESP: function(a: POCSP_SINGLERESP; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_SINGLERESP}

  OCSP_SINGLERESP_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_SINGLERESP_it}

  OCSP_CERTSTATUS_new: function: POCSP_CERTSTATUS; cdecl = nil;
  {$EXTERNALSYM OCSP_CERTSTATUS_new}

  OCSP_CERTSTATUS_free: function(a: POCSP_CERTSTATUS): void; cdecl = nil;
  {$EXTERNALSYM OCSP_CERTSTATUS_free}

  d2i_OCSP_CERTSTATUS: function(a: PPOCSP_CERTSTATUS; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTSTATUS; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_CERTSTATUS}

  i2d_OCSP_CERTSTATUS: function(a: POCSP_CERTSTATUS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_CERTSTATUS}

  OCSP_CERTSTATUS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_CERTSTATUS_it}

  OCSP_REVOKEDINFO_new: function: POCSP_REVOKEDINFO; cdecl = nil;
  {$EXTERNALSYM OCSP_REVOKEDINFO_new}

  OCSP_REVOKEDINFO_free: function(a: POCSP_REVOKEDINFO): void; cdecl = nil;
  {$EXTERNALSYM OCSP_REVOKEDINFO_free}

  d2i_OCSP_REVOKEDINFO: function(a: PPOCSP_REVOKEDINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REVOKEDINFO; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_REVOKEDINFO}

  i2d_OCSP_REVOKEDINFO: function(a: POCSP_REVOKEDINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_REVOKEDINFO}

  OCSP_REVOKEDINFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_REVOKEDINFO_it}

  OCSP_BASICRESP_new: function: POCSP_BASICRESP; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_new}

  OCSP_BASICRESP_free: function(a: POCSP_BASICRESP): void; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_free}

  d2i_OCSP_BASICRESP: function(a: PPOCSP_BASICRESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_BASICRESP; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_BASICRESP}

  i2d_OCSP_BASICRESP: function(a: POCSP_BASICRESP; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_BASICRESP}

  OCSP_BASICRESP_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_BASICRESP_it}

  OCSP_RESPDATA_new: function: POCSP_RESPDATA; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPDATA_new}

  OCSP_RESPDATA_free: function(a: POCSP_RESPDATA): void; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPDATA_free}

  d2i_OCSP_RESPDATA: function(a: PPOCSP_RESPDATA; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPDATA; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_RESPDATA}

  i2d_OCSP_RESPDATA: function(a: POCSP_RESPDATA; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_RESPDATA}

  OCSP_RESPDATA_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPDATA_it}

  OCSP_RESPID_new: function: POCSP_RESPID; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_new}

  OCSP_RESPID_free: function(a: POCSP_RESPID): void; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_free}

  d2i_OCSP_RESPID: function(a: PPOCSP_RESPID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPID; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_RESPID}

  i2d_OCSP_RESPID: function(a: POCSP_RESPID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_RESPID}

  OCSP_RESPID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPID_it}

  OCSP_RESPONSE_new: function: POCSP_RESPONSE; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPONSE_new}

  OCSP_RESPONSE_free: function(a: POCSP_RESPONSE): void; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPONSE_free}

  d2i_OCSP_RESPONSE: function(a: PPOCSP_RESPONSE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPONSE; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_RESPONSE}

  i2d_OCSP_RESPONSE: function(a: POCSP_RESPONSE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_RESPONSE}

  OCSP_RESPONSE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPONSE_it}

  OCSP_RESPBYTES_new: function: POCSP_RESPBYTES; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPBYTES_new}

  OCSP_RESPBYTES_free: function(a: POCSP_RESPBYTES): void; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPBYTES_free}

  d2i_OCSP_RESPBYTES: function(a: PPOCSP_RESPBYTES; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPBYTES; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_RESPBYTES}

  i2d_OCSP_RESPBYTES: function(a: POCSP_RESPBYTES; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_RESPBYTES}

  OCSP_RESPBYTES_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPBYTES_it}

  OCSP_ONEREQ_new: function: POCSP_ONEREQ; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_new}

  OCSP_ONEREQ_free: function(a: POCSP_ONEREQ): void; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_free}

  d2i_OCSP_ONEREQ: function(a: PPOCSP_ONEREQ; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_ONEREQ; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_ONEREQ}

  i2d_OCSP_ONEREQ: function(a: POCSP_ONEREQ; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_ONEREQ}

  OCSP_ONEREQ_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_ONEREQ_it}

  OCSP_CERTID_new: function: POCSP_CERTID; cdecl = nil;
  {$EXTERNALSYM OCSP_CERTID_new}

  OCSP_CERTID_free: function(a: POCSP_CERTID): void; cdecl = nil;
  {$EXTERNALSYM OCSP_CERTID_free}

  d2i_OCSP_CERTID: function(a: PPOCSP_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTID; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_CERTID}

  i2d_OCSP_CERTID: function(a: POCSP_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_CERTID}

  OCSP_CERTID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_CERTID_it}

  OCSP_REQUEST_new: function: POCSP_REQUEST; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_new}

  OCSP_REQUEST_free: function(a: POCSP_REQUEST): void; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_free}

  d2i_OCSP_REQUEST: function(a: PPOCSP_REQUEST; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQUEST; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_REQUEST}

  i2d_OCSP_REQUEST: function(a: POCSP_REQUEST; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_REQUEST}

  OCSP_REQUEST_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_it}

  OCSP_SIGNATURE_new: function: POCSP_SIGNATURE; cdecl = nil;
  {$EXTERNALSYM OCSP_SIGNATURE_new}

  OCSP_SIGNATURE_free: function(a: POCSP_SIGNATURE): void; cdecl = nil;
  {$EXTERNALSYM OCSP_SIGNATURE_free}

  d2i_OCSP_SIGNATURE: function(a: PPOCSP_SIGNATURE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SIGNATURE; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_SIGNATURE}

  i2d_OCSP_SIGNATURE: function(a: POCSP_SIGNATURE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_SIGNATURE}

  OCSP_SIGNATURE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_SIGNATURE_it}

  OCSP_REQINFO_new: function: POCSP_REQINFO; cdecl = nil;
  {$EXTERNALSYM OCSP_REQINFO_new}

  OCSP_REQINFO_free: function(a: POCSP_REQINFO): void; cdecl = nil;
  {$EXTERNALSYM OCSP_REQINFO_free}

  d2i_OCSP_REQINFO: function(a: PPOCSP_REQINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQINFO; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_REQINFO}

  i2d_OCSP_REQINFO: function(a: POCSP_REQINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_REQINFO}

  OCSP_REQINFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_REQINFO_it}

  OCSP_CRLID_new: function: POCSP_CRLID; cdecl = nil;
  {$EXTERNALSYM OCSP_CRLID_new}

  OCSP_CRLID_free: function(a: POCSP_CRLID): void; cdecl = nil;
  {$EXTERNALSYM OCSP_CRLID_free}

  d2i_OCSP_CRLID: function(a: PPOCSP_CRLID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CRLID; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_CRLID}

  i2d_OCSP_CRLID: function(a: POCSP_CRLID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_CRLID}

  OCSP_CRLID_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_CRLID_it}

  OCSP_SERVICELOC_new: function: POCSP_SERVICELOC; cdecl = nil;
  {$EXTERNALSYM OCSP_SERVICELOC_new}

  OCSP_SERVICELOC_free: function(a: POCSP_SERVICELOC): void; cdecl = nil;
  {$EXTERNALSYM OCSP_SERVICELOC_free}

  d2i_OCSP_SERVICELOC: function(a: PPOCSP_SERVICELOC; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SERVICELOC; cdecl = nil;
  {$EXTERNALSYM d2i_OCSP_SERVICELOC}

  i2d_OCSP_SERVICELOC: function(a: POCSP_SERVICELOC; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OCSP_SERVICELOC}

  OCSP_SERVICELOC_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OCSP_SERVICELOC_it}

  OCSP_response_status_str: function(s: TIdC_LONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OCSP_response_status_str}

  OCSP_cert_status_str: function(s: TIdC_LONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OCSP_cert_status_str}

  OCSP_crl_reason_str: function(s: TIdC_LONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OCSP_crl_reason_str}

  OCSP_REQUEST_print: function(bp: PBIO; a: POCSP_REQUEST; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_REQUEST_print}

  OCSP_RESPONSE_print: function(bp: PBIO; o: POCSP_RESPONSE; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_RESPONSE_print}

  OCSP_basic_verify: function(bs: POCSP_BASICRESP; certs: Pstack_st_X509; st: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OCSP_basic_verify}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OCSP_CERTID_dup(a: POCSP_CERTID): POCSP_CERTID; cdecl;
function OCSP_sendreq_new(io: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl;
function OCSP_sendreq_bio(b: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST): POCSP_RESPONSE; cdecl;
function OCSP_cert_to_id(dgst: PEVP_MD; subject: PX509; issuer: PX509): POCSP_CERTID; cdecl;
function OCSP_cert_id_new(dgst: PEVP_MD; issuerName: PX509_NAME; issuerKey: PASN1_BIT_STRING; serialNumber: PASN1_INTEGER): POCSP_CERTID; cdecl;
function OCSP_request_add0_id(req: POCSP_REQUEST; cid: POCSP_CERTID): POCSP_ONEREQ; cdecl;
function OCSP_request_add1_nonce(req: POCSP_REQUEST; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function OCSP_basic_add1_nonce(resp: POCSP_BASICRESP; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function OCSP_check_nonce(req: POCSP_REQUEST; bs: POCSP_BASICRESP): TIdC_INT; cdecl;
function OCSP_copy_nonce(resp: POCSP_BASICRESP; req: POCSP_REQUEST): TIdC_INT; cdecl;
function OCSP_request_set1_name(req: POCSP_REQUEST; nm: PX509_NAME): TIdC_INT; cdecl;
function OCSP_request_add1_cert(req: POCSP_REQUEST; cert: PX509): TIdC_INT; cdecl;
function OCSP_request_sign(req: POCSP_REQUEST; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_response_status(resp: POCSP_RESPONSE): TIdC_INT; cdecl;
function OCSP_response_get1_basic(resp: POCSP_RESPONSE): POCSP_BASICRESP; cdecl;
function OCSP_resp_get0_signature(bs: POCSP_BASICRESP): PASN1_OCTET_STRING; cdecl;
function OCSP_resp_get0_tbs_sigalg(bs: POCSP_BASICRESP): PX509_ALGOR; cdecl;
function OCSP_resp_get0_respdata(bs: POCSP_BASICRESP): POCSP_RESPDATA; cdecl;
function OCSP_resp_get0_signer(bs: POCSP_BASICRESP; signer: PPX509; extra_certs: Pstack_st_X509): TIdC_INT; cdecl;
function OCSP_resp_count(bs: POCSP_BASICRESP): TIdC_INT; cdecl;
function OCSP_resp_get0(bs: POCSP_BASICRESP; idx: TIdC_INT): POCSP_SINGLERESP; cdecl;
function OCSP_resp_get0_produced_at(bs: POCSP_BASICRESP): PASN1_GENERALIZEDTIME; cdecl;
function OCSP_resp_get0_certs(bs: POCSP_BASICRESP): Pstack_st_X509; cdecl;
function OCSP_resp_get0_id(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl;
function OCSP_resp_get1_id(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl;
function OCSP_resp_find(bs: POCSP_BASICRESP; id: POCSP_CERTID; last: TIdC_INT): TIdC_INT; cdecl;
function OCSP_single_get0_status(single: POCSP_SINGLERESP; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
function OCSP_resp_find_status(bs: POCSP_BASICRESP; id: POCSP_CERTID; status: PIdC_INT; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
function OCSP_check_validity(thisupd: PASN1_GENERALIZEDTIME; nextupd: PASN1_GENERALIZEDTIME; sec: TIdC_LONG; maxsec: TIdC_LONG): TIdC_INT; cdecl;
function OCSP_request_verify(req: POCSP_REQUEST; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_id_issuer_cmp(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl;
function OCSP_id_cmp(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl;
function OCSP_request_onereq_count(req: POCSP_REQUEST): TIdC_INT; cdecl;
function OCSP_request_onereq_get0(req: POCSP_REQUEST; i: TIdC_INT): POCSP_ONEREQ; cdecl;
function OCSP_onereq_get0_id(one: POCSP_ONEREQ): POCSP_CERTID; cdecl;
function OCSP_id_get0_info(piNameHash: PPASN1_OCTET_STRING; pmd: PPASN1_OBJECT; pikeyHash: PPASN1_OCTET_STRING; pserial: PPASN1_INTEGER; cid: POCSP_CERTID): TIdC_INT; cdecl;
function OCSP_request_is_signed(req: POCSP_REQUEST): TIdC_INT; cdecl;
function OCSP_response_create(status: TIdC_INT; bs: POCSP_BASICRESP): POCSP_RESPONSE; cdecl;
function OCSP_basic_add1_status(rsp: POCSP_BASICRESP; cid: POCSP_CERTID; status: TIdC_INT; reason: TIdC_INT; revtime: PASN1_TIME; thisupd: PASN1_TIME; nextupd: PASN1_TIME): POCSP_SINGLERESP; cdecl;
function OCSP_basic_add1_cert(resp: POCSP_BASICRESP; cert: PX509): TIdC_INT; cdecl;
function OCSP_basic_sign(brsp: POCSP_BASICRESP; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_basic_sign_ctx(brsp: POCSP_BASICRESP; signer: PX509; ctx: PEVP_MD_CTX; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_RESPID_set_by_name(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl;
function OCSP_RESPID_set_by_key_ex(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function OCSP_RESPID_set_by_key(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl;
function OCSP_RESPID_match_ex(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function OCSP_RESPID_match(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl;
function OCSP_crlID_new(url: PIdAnsiChar; n: PIdC_LONG; tim: PIdAnsiChar): PX509_EXTENSION; cdecl;
function OCSP_accept_responses_new(oids: PPIdAnsiChar): PX509_EXTENSION; cdecl;
function OCSP_archive_cutoff_new(tim: PIdAnsiChar): PX509_EXTENSION; cdecl;
function OCSP_url_svcloc_new(issuer: PX509_NAME; urls: PPIdAnsiChar): PX509_EXTENSION; cdecl;
function OCSP_REQUEST_get_ext_count(x: POCSP_REQUEST): TIdC_INT; cdecl;
function OCSP_REQUEST_get_ext_by_NID(x: POCSP_REQUEST; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_REQUEST_get_ext_by_OBJ(x: POCSP_REQUEST; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_REQUEST_get_ext_by_critical(x: POCSP_REQUEST; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_REQUEST_get_ext(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_REQUEST_delete_ext(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_REQUEST_get1_ext_d2i(x: POCSP_REQUEST; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function OCSP_REQUEST_add1_ext_i2d(x: POCSP_REQUEST; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_REQUEST_add_ext(x: POCSP_REQUEST; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function OCSP_ONEREQ_get_ext_count(x: POCSP_ONEREQ): TIdC_INT; cdecl;
function OCSP_ONEREQ_get_ext_by_NID(x: POCSP_ONEREQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_ONEREQ_get_ext_by_OBJ(x: POCSP_ONEREQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_ONEREQ_get_ext_by_critical(x: POCSP_ONEREQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_ONEREQ_get_ext(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_ONEREQ_delete_ext(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_ONEREQ_get1_ext_d2i(x: POCSP_ONEREQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function OCSP_ONEREQ_add1_ext_i2d(x: POCSP_ONEREQ; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_ONEREQ_add_ext(x: POCSP_ONEREQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function OCSP_BASICRESP_get_ext_count(x: POCSP_BASICRESP): TIdC_INT; cdecl;
function OCSP_BASICRESP_get_ext_by_NID(x: POCSP_BASICRESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_BASICRESP_get_ext_by_OBJ(x: POCSP_BASICRESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_BASICRESP_get_ext_by_critical(x: POCSP_BASICRESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_BASICRESP_get_ext(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_BASICRESP_delete_ext(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_BASICRESP_get1_ext_d2i(x: POCSP_BASICRESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function OCSP_BASICRESP_add1_ext_i2d(x: POCSP_BASICRESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_BASICRESP_add_ext(x: POCSP_BASICRESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function OCSP_SINGLERESP_get_ext_count(x: POCSP_SINGLERESP): TIdC_INT; cdecl;
function OCSP_SINGLERESP_get_ext_by_NID(x: POCSP_SINGLERESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_SINGLERESP_get_ext_by_OBJ(x: POCSP_SINGLERESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_SINGLERESP_get_ext_by_critical(x: POCSP_SINGLERESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function OCSP_SINGLERESP_get_ext(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_SINGLERESP_delete_ext(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function OCSP_SINGLERESP_get1_ext_d2i(x: POCSP_SINGLERESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function OCSP_SINGLERESP_add1_ext_i2d(x: POCSP_SINGLERESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_SINGLERESP_add_ext(x: POCSP_SINGLERESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function OCSP_SINGLERESP_get0_id(x: POCSP_SINGLERESP): POCSP_CERTID; cdecl;
function OCSP_SINGLERESP_new: POCSP_SINGLERESP; cdecl;
function OCSP_SINGLERESP_free(a: POCSP_SINGLERESP): void; cdecl;
function d2i_OCSP_SINGLERESP(a: PPOCSP_SINGLERESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SINGLERESP; cdecl;
function i2d_OCSP_SINGLERESP(a: POCSP_SINGLERESP; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_SINGLERESP_it: PASN1_ITEM; cdecl;
function OCSP_CERTSTATUS_new: POCSP_CERTSTATUS; cdecl;
function OCSP_CERTSTATUS_free(a: POCSP_CERTSTATUS): void; cdecl;
function d2i_OCSP_CERTSTATUS(a: PPOCSP_CERTSTATUS; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTSTATUS; cdecl;
function i2d_OCSP_CERTSTATUS(a: POCSP_CERTSTATUS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_CERTSTATUS_it: PASN1_ITEM; cdecl;
function OCSP_REVOKEDINFO_new: POCSP_REVOKEDINFO; cdecl;
function OCSP_REVOKEDINFO_free(a: POCSP_REVOKEDINFO): void; cdecl;
function d2i_OCSP_REVOKEDINFO(a: PPOCSP_REVOKEDINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REVOKEDINFO; cdecl;
function i2d_OCSP_REVOKEDINFO(a: POCSP_REVOKEDINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_REVOKEDINFO_it: PASN1_ITEM; cdecl;
function OCSP_BASICRESP_new: POCSP_BASICRESP; cdecl;
function OCSP_BASICRESP_free(a: POCSP_BASICRESP): void; cdecl;
function d2i_OCSP_BASICRESP(a: PPOCSP_BASICRESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_BASICRESP; cdecl;
function i2d_OCSP_BASICRESP(a: POCSP_BASICRESP; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_BASICRESP_it: PASN1_ITEM; cdecl;
function OCSP_RESPDATA_new: POCSP_RESPDATA; cdecl;
function OCSP_RESPDATA_free(a: POCSP_RESPDATA): void; cdecl;
function d2i_OCSP_RESPDATA(a: PPOCSP_RESPDATA; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPDATA; cdecl;
function i2d_OCSP_RESPDATA(a: POCSP_RESPDATA; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_RESPDATA_it: PASN1_ITEM; cdecl;
function OCSP_RESPID_new: POCSP_RESPID; cdecl;
function OCSP_RESPID_free(a: POCSP_RESPID): void; cdecl;
function d2i_OCSP_RESPID(a: PPOCSP_RESPID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPID; cdecl;
function i2d_OCSP_RESPID(a: POCSP_RESPID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_RESPID_it: PASN1_ITEM; cdecl;
function OCSP_RESPONSE_new: POCSP_RESPONSE; cdecl;
function OCSP_RESPONSE_free(a: POCSP_RESPONSE): void; cdecl;
function d2i_OCSP_RESPONSE(a: PPOCSP_RESPONSE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPONSE; cdecl;
function i2d_OCSP_RESPONSE(a: POCSP_RESPONSE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_RESPONSE_it: PASN1_ITEM; cdecl;
function OCSP_RESPBYTES_new: POCSP_RESPBYTES; cdecl;
function OCSP_RESPBYTES_free(a: POCSP_RESPBYTES): void; cdecl;
function d2i_OCSP_RESPBYTES(a: PPOCSP_RESPBYTES; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPBYTES; cdecl;
function i2d_OCSP_RESPBYTES(a: POCSP_RESPBYTES; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_RESPBYTES_it: PASN1_ITEM; cdecl;
function OCSP_ONEREQ_new: POCSP_ONEREQ; cdecl;
function OCSP_ONEREQ_free(a: POCSP_ONEREQ): void; cdecl;
function d2i_OCSP_ONEREQ(a: PPOCSP_ONEREQ; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_ONEREQ; cdecl;
function i2d_OCSP_ONEREQ(a: POCSP_ONEREQ; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_ONEREQ_it: PASN1_ITEM; cdecl;
function OCSP_CERTID_new: POCSP_CERTID; cdecl;
function OCSP_CERTID_free(a: POCSP_CERTID): void; cdecl;
function d2i_OCSP_CERTID(a: PPOCSP_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTID; cdecl;
function i2d_OCSP_CERTID(a: POCSP_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_CERTID_it: PASN1_ITEM; cdecl;
function OCSP_REQUEST_new: POCSP_REQUEST; cdecl;
function OCSP_REQUEST_free(a: POCSP_REQUEST): void; cdecl;
function d2i_OCSP_REQUEST(a: PPOCSP_REQUEST; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQUEST; cdecl;
function i2d_OCSP_REQUEST(a: POCSP_REQUEST; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_REQUEST_it: PASN1_ITEM; cdecl;
function OCSP_SIGNATURE_new: POCSP_SIGNATURE; cdecl;
function OCSP_SIGNATURE_free(a: POCSP_SIGNATURE): void; cdecl;
function d2i_OCSP_SIGNATURE(a: PPOCSP_SIGNATURE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SIGNATURE; cdecl;
function i2d_OCSP_SIGNATURE(a: POCSP_SIGNATURE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_SIGNATURE_it: PASN1_ITEM; cdecl;
function OCSP_REQINFO_new: POCSP_REQINFO; cdecl;
function OCSP_REQINFO_free(a: POCSP_REQINFO): void; cdecl;
function d2i_OCSP_REQINFO(a: PPOCSP_REQINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQINFO; cdecl;
function i2d_OCSP_REQINFO(a: POCSP_REQINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_REQINFO_it: PASN1_ITEM; cdecl;
function OCSP_CRLID_new: POCSP_CRLID; cdecl;
function OCSP_CRLID_free(a: POCSP_CRLID): void; cdecl;
function d2i_OCSP_CRLID(a: PPOCSP_CRLID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CRLID; cdecl;
function i2d_OCSP_CRLID(a: POCSP_CRLID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_CRLID_it: PASN1_ITEM; cdecl;
function OCSP_SERVICELOC_new: POCSP_SERVICELOC; cdecl;
function OCSP_SERVICELOC_free(a: POCSP_SERVICELOC): void; cdecl;
function d2i_OCSP_SERVICELOC(a: PPOCSP_SERVICELOC; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SERVICELOC; cdecl;
function i2d_OCSP_SERVICELOC(a: POCSP_SERVICELOC; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OCSP_SERVICELOC_it: PASN1_ITEM; cdecl;
function OCSP_response_status_str(s: TIdC_LONG): PIdAnsiChar; cdecl;
function OCSP_cert_status_str(s: TIdC_LONG): PIdAnsiChar; cdecl;
function OCSP_crl_reason_str(s: TIdC_LONG): PIdAnsiChar; cdecl;
function OCSP_REQUEST_print(bp: PBIO; a: POCSP_REQUEST; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_RESPONSE_print(bp: PBIO; o: POCSP_RESPONSE; flags: TIdC_ULONG): TIdC_INT; cdecl;
function OCSP_basic_verify(bs: POCSP_BASICRESP; certs: Pstack_st_X509; st: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function ASN1_BIT_STRING_digest(data: Pointer; _type: Pointer; md: Pointer; len: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OCSP_REQ_CTX_i2d(r: Pointer; it: Pointer; req: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OCSP_REQ_CTX_set1_req(r: Pointer; req: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OCSP_sendreq_nbio(p: Pointer; r: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OCSP_parse_url(url: Pointer; host: Pointer; port: Pointer; path: Pointer; ssl: Pointer): TIdC_INT; cdecl;


// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack OCSP_CERTID definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OCSP_CERTID = Pointer;
  {$EXTERNALSYM PSTACK_OF_OCSP_CERTID}

  { Original Stack Macros for OCSP_CERTID:
    SKM_DEFINE_STACK_OF_INTERNAL(OCSP_CERTID, OCSP_CERTID, OCSP_CERTID)
    sk_OCSP_CERTID_num(sk) OPENSSL_sk_num(ossl_check_const_OCSP_CERTID_sk_type(sk))
    sk_OCSP_CERTID_value(sk, idx) ((OCSP_CERTID *)OPENSSL_sk_value(ossl_check_const_OCSP_CERTID_sk_type(sk), (idx)))
    sk_OCSP_CERTID_new(cmp) ((STACK_OF(OCSP_CERTID) *)OPENSSL_sk_new(ossl_check_OCSP_CERTID_compfunc_type(cmp)))
    sk_OCSP_CERTID_new_null() ((STACK_OF(OCSP_CERTID) *)OPENSSL_sk_new_null())
    sk_OCSP_CERTID_new_reserve(cmp, n) ((STACK_OF(OCSP_CERTID) *)OPENSSL_sk_new_reserve(ossl_check_OCSP_CERTID_compfunc_type(cmp), (n)))
    sk_OCSP_CERTID_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OCSP_CERTID_sk_type(sk), (n))
    sk_OCSP_CERTID_free(sk) OPENSSL_sk_free(ossl_check_OCSP_CERTID_sk_type(sk))
    sk_OCSP_CERTID_zero(sk) OPENSSL_sk_zero(ossl_check_OCSP_CERTID_sk_type(sk))
    sk_OCSP_CERTID_delete(sk, i) ((OCSP_CERTID *)OPENSSL_sk_delete(ossl_check_OCSP_CERTID_sk_type(sk), (i)))
    sk_OCSP_CERTID_delete_ptr(sk, ptr) ((OCSP_CERTID *)OPENSSL_sk_delete_ptr(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_type(ptr)))
    sk_OCSP_CERTID_push(sk, ptr) OPENSSL_sk_push(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_type(ptr))
    sk_OCSP_CERTID_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_type(ptr))
    sk_OCSP_CERTID_pop(sk) ((OCSP_CERTID *)OPENSSL_sk_pop(ossl_check_OCSP_CERTID_sk_type(sk)))
    sk_OCSP_CERTID_shift(sk) ((OCSP_CERTID *)OPENSSL_sk_shift(ossl_check_OCSP_CERTID_sk_type(sk)))
    sk_OCSP_CERTID_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_freefunc_type(freefunc))
    sk_OCSP_CERTID_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_type(ptr), (idx))
    sk_OCSP_CERTID_set(sk, idx, ptr) ((OCSP_CERTID *)OPENSSL_sk_set(ossl_check_OCSP_CERTID_sk_type(sk), (idx), ossl_check_OCSP_CERTID_type(ptr)))
    sk_OCSP_CERTID_find(sk, ptr) OPENSSL_sk_find(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_type(ptr))
    sk_OCSP_CERTID_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_type(ptr))
    sk_OCSP_CERTID_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_type(ptr), pnum)
    sk_OCSP_CERTID_sort(sk) OPENSSL_sk_sort(ossl_check_OCSP_CERTID_sk_type(sk))
    sk_OCSP_CERTID_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OCSP_CERTID_sk_type(sk))
    sk_OCSP_CERTID_dup(sk) ((STACK_OF(OCSP_CERTID) *)OPENSSL_sk_dup(ossl_check_const_OCSP_CERTID_sk_type(sk)))
    sk_OCSP_CERTID_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OCSP_CERTID) *)OPENSSL_sk_deep_copy(ossl_check_const_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_copyfunc_type(copyfunc), ossl_check_OCSP_CERTID_freefunc_type(freefunc)))
    sk_OCSP_CERTID_set_cmp_func(sk, cmp) ((sk_OCSP_CERTID_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OCSP_CERTID_sk_type(sk), ossl_check_OCSP_CERTID_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OCSP_ONEREQ definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OCSP_ONEREQ = Pointer;
  {$EXTERNALSYM PSTACK_OF_OCSP_ONEREQ}

  { Original Stack Macros for OCSP_ONEREQ:
    SKM_DEFINE_STACK_OF_INTERNAL(OCSP_ONEREQ, OCSP_ONEREQ, OCSP_ONEREQ)
    sk_OCSP_ONEREQ_num(sk) OPENSSL_sk_num(ossl_check_const_OCSP_ONEREQ_sk_type(sk))
    sk_OCSP_ONEREQ_value(sk, idx) ((OCSP_ONEREQ *)OPENSSL_sk_value(ossl_check_const_OCSP_ONEREQ_sk_type(sk), (idx)))
    sk_OCSP_ONEREQ_new(cmp) ((STACK_OF(OCSP_ONEREQ) *)OPENSSL_sk_new(ossl_check_OCSP_ONEREQ_compfunc_type(cmp)))
    sk_OCSP_ONEREQ_new_null() ((STACK_OF(OCSP_ONEREQ) *)OPENSSL_sk_new_null())
    sk_OCSP_ONEREQ_new_reserve(cmp, n) ((STACK_OF(OCSP_ONEREQ) *)OPENSSL_sk_new_reserve(ossl_check_OCSP_ONEREQ_compfunc_type(cmp), (n)))
    sk_OCSP_ONEREQ_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OCSP_ONEREQ_sk_type(sk), (n))
    sk_OCSP_ONEREQ_free(sk) OPENSSL_sk_free(ossl_check_OCSP_ONEREQ_sk_type(sk))
    sk_OCSP_ONEREQ_zero(sk) OPENSSL_sk_zero(ossl_check_OCSP_ONEREQ_sk_type(sk))
    sk_OCSP_ONEREQ_delete(sk, i) ((OCSP_ONEREQ *)OPENSSL_sk_delete(ossl_check_OCSP_ONEREQ_sk_type(sk), (i)))
    sk_OCSP_ONEREQ_delete_ptr(sk, ptr) ((OCSP_ONEREQ *)OPENSSL_sk_delete_ptr(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_type(ptr)))
    sk_OCSP_ONEREQ_push(sk, ptr) OPENSSL_sk_push(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_type(ptr))
    sk_OCSP_ONEREQ_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_type(ptr))
    sk_OCSP_ONEREQ_pop(sk) ((OCSP_ONEREQ *)OPENSSL_sk_pop(ossl_check_OCSP_ONEREQ_sk_type(sk)))
    sk_OCSP_ONEREQ_shift(sk) ((OCSP_ONEREQ *)OPENSSL_sk_shift(ossl_check_OCSP_ONEREQ_sk_type(sk)))
    sk_OCSP_ONEREQ_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_freefunc_type(freefunc))
    sk_OCSP_ONEREQ_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_type(ptr), (idx))
    sk_OCSP_ONEREQ_set(sk, idx, ptr) ((OCSP_ONEREQ *)OPENSSL_sk_set(ossl_check_OCSP_ONEREQ_sk_type(sk), (idx), ossl_check_OCSP_ONEREQ_type(ptr)))
    sk_OCSP_ONEREQ_find(sk, ptr) OPENSSL_sk_find(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_type(ptr))
    sk_OCSP_ONEREQ_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_type(ptr))
    sk_OCSP_ONEREQ_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_type(ptr), pnum)
    sk_OCSP_ONEREQ_sort(sk) OPENSSL_sk_sort(ossl_check_OCSP_ONEREQ_sk_type(sk))
    sk_OCSP_ONEREQ_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OCSP_ONEREQ_sk_type(sk))
    sk_OCSP_ONEREQ_dup(sk) ((STACK_OF(OCSP_ONEREQ) *)OPENSSL_sk_dup(ossl_check_const_OCSP_ONEREQ_sk_type(sk)))
    sk_OCSP_ONEREQ_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OCSP_ONEREQ) *)OPENSSL_sk_deep_copy(ossl_check_const_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_copyfunc_type(copyfunc), ossl_check_OCSP_ONEREQ_freefunc_type(freefunc)))
    sk_OCSP_ONEREQ_set_cmp_func(sk, cmp) ((sk_OCSP_ONEREQ_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OCSP_ONEREQ_sk_type(sk), ossl_check_OCSP_ONEREQ_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OCSP_RESPID definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OCSP_RESPID = Pointer;
  {$EXTERNALSYM PSTACK_OF_OCSP_RESPID}

  { Original Stack Macros for OCSP_RESPID:
    SKM_DEFINE_STACK_OF_INTERNAL(OCSP_RESPID, OCSP_RESPID, OCSP_RESPID)
    sk_OCSP_RESPID_num(sk) OPENSSL_sk_num(ossl_check_const_OCSP_RESPID_sk_type(sk))
    sk_OCSP_RESPID_value(sk, idx) ((OCSP_RESPID *)OPENSSL_sk_value(ossl_check_const_OCSP_RESPID_sk_type(sk), (idx)))
    sk_OCSP_RESPID_new(cmp) ((STACK_OF(OCSP_RESPID) *)OPENSSL_sk_new(ossl_check_OCSP_RESPID_compfunc_type(cmp)))
    sk_OCSP_RESPID_new_null() ((STACK_OF(OCSP_RESPID) *)OPENSSL_sk_new_null())
    sk_OCSP_RESPID_new_reserve(cmp, n) ((STACK_OF(OCSP_RESPID) *)OPENSSL_sk_new_reserve(ossl_check_OCSP_RESPID_compfunc_type(cmp), (n)))
    sk_OCSP_RESPID_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OCSP_RESPID_sk_type(sk), (n))
    sk_OCSP_RESPID_free(sk) OPENSSL_sk_free(ossl_check_OCSP_RESPID_sk_type(sk))
    sk_OCSP_RESPID_zero(sk) OPENSSL_sk_zero(ossl_check_OCSP_RESPID_sk_type(sk))
    sk_OCSP_RESPID_delete(sk, i) ((OCSP_RESPID *)OPENSSL_sk_delete(ossl_check_OCSP_RESPID_sk_type(sk), (i)))
    sk_OCSP_RESPID_delete_ptr(sk, ptr) ((OCSP_RESPID *)OPENSSL_sk_delete_ptr(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_type(ptr)))
    sk_OCSP_RESPID_push(sk, ptr) OPENSSL_sk_push(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_type(ptr))
    sk_OCSP_RESPID_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_type(ptr))
    sk_OCSP_RESPID_pop(sk) ((OCSP_RESPID *)OPENSSL_sk_pop(ossl_check_OCSP_RESPID_sk_type(sk)))
    sk_OCSP_RESPID_shift(sk) ((OCSP_RESPID *)OPENSSL_sk_shift(ossl_check_OCSP_RESPID_sk_type(sk)))
    sk_OCSP_RESPID_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_freefunc_type(freefunc))
    sk_OCSP_RESPID_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_type(ptr), (idx))
    sk_OCSP_RESPID_set(sk, idx, ptr) ((OCSP_RESPID *)OPENSSL_sk_set(ossl_check_OCSP_RESPID_sk_type(sk), (idx), ossl_check_OCSP_RESPID_type(ptr)))
    sk_OCSP_RESPID_find(sk, ptr) OPENSSL_sk_find(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_type(ptr))
    sk_OCSP_RESPID_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_type(ptr))
    sk_OCSP_RESPID_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_type(ptr), pnum)
    sk_OCSP_RESPID_sort(sk) OPENSSL_sk_sort(ossl_check_OCSP_RESPID_sk_type(sk))
    sk_OCSP_RESPID_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OCSP_RESPID_sk_type(sk))
    sk_OCSP_RESPID_dup(sk) ((STACK_OF(OCSP_RESPID) *)OPENSSL_sk_dup(ossl_check_const_OCSP_RESPID_sk_type(sk)))
    sk_OCSP_RESPID_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OCSP_RESPID) *)OPENSSL_sk_deep_copy(ossl_check_const_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_copyfunc_type(copyfunc), ossl_check_OCSP_RESPID_freefunc_type(freefunc)))
    sk_OCSP_RESPID_set_cmp_func(sk, cmp) ((sk_OCSP_RESPID_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OCSP_RESPID_sk_type(sk), ossl_check_OCSP_RESPID_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OCSP_SINGLERESP definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OCSP_SINGLERESP = Pointer;
  {$EXTERNALSYM PSTACK_OF_OCSP_SINGLERESP}

  { Original Stack Macros for OCSP_SINGLERESP:
    SKM_DEFINE_STACK_OF_INTERNAL(OCSP_SINGLERESP, OCSP_SINGLERESP, OCSP_SINGLERESP)
    sk_OCSP_SINGLERESP_num(sk) OPENSSL_sk_num(ossl_check_const_OCSP_SINGLERESP_sk_type(sk))
    sk_OCSP_SINGLERESP_value(sk, idx) ((OCSP_SINGLERESP *)OPENSSL_sk_value(ossl_check_const_OCSP_SINGLERESP_sk_type(sk), (idx)))
    sk_OCSP_SINGLERESP_new(cmp) ((STACK_OF(OCSP_SINGLERESP) *)OPENSSL_sk_new(ossl_check_OCSP_SINGLERESP_compfunc_type(cmp)))
    sk_OCSP_SINGLERESP_new_null() ((STACK_OF(OCSP_SINGLERESP) *)OPENSSL_sk_new_null())
    sk_OCSP_SINGLERESP_new_reserve(cmp, n) ((STACK_OF(OCSP_SINGLERESP) *)OPENSSL_sk_new_reserve(ossl_check_OCSP_SINGLERESP_compfunc_type(cmp), (n)))
    sk_OCSP_SINGLERESP_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OCSP_SINGLERESP_sk_type(sk), (n))
    sk_OCSP_SINGLERESP_free(sk) OPENSSL_sk_free(ossl_check_OCSP_SINGLERESP_sk_type(sk))
    sk_OCSP_SINGLERESP_zero(sk) OPENSSL_sk_zero(ossl_check_OCSP_SINGLERESP_sk_type(sk))
    sk_OCSP_SINGLERESP_delete(sk, i) ((OCSP_SINGLERESP *)OPENSSL_sk_delete(ossl_check_OCSP_SINGLERESP_sk_type(sk), (i)))
    sk_OCSP_SINGLERESP_delete_ptr(sk, ptr) ((OCSP_SINGLERESP *)OPENSSL_sk_delete_ptr(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_type(ptr)))
    sk_OCSP_SINGLERESP_push(sk, ptr) OPENSSL_sk_push(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_type(ptr))
    sk_OCSP_SINGLERESP_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_type(ptr))
    sk_OCSP_SINGLERESP_pop(sk) ((OCSP_SINGLERESP *)OPENSSL_sk_pop(ossl_check_OCSP_SINGLERESP_sk_type(sk)))
    sk_OCSP_SINGLERESP_shift(sk) ((OCSP_SINGLERESP *)OPENSSL_sk_shift(ossl_check_OCSP_SINGLERESP_sk_type(sk)))
    sk_OCSP_SINGLERESP_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_freefunc_type(freefunc))
    sk_OCSP_SINGLERESP_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_type(ptr), (idx))
    sk_OCSP_SINGLERESP_set(sk, idx, ptr) ((OCSP_SINGLERESP *)OPENSSL_sk_set(ossl_check_OCSP_SINGLERESP_sk_type(sk), (idx), ossl_check_OCSP_SINGLERESP_type(ptr)))
    sk_OCSP_SINGLERESP_find(sk, ptr) OPENSSL_sk_find(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_type(ptr))
    sk_OCSP_SINGLERESP_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_type(ptr))
    sk_OCSP_SINGLERESP_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_type(ptr), pnum)
    sk_OCSP_SINGLERESP_sort(sk) OPENSSL_sk_sort(ossl_check_OCSP_SINGLERESP_sk_type(sk))
    sk_OCSP_SINGLERESP_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OCSP_SINGLERESP_sk_type(sk))
    sk_OCSP_SINGLERESP_dup(sk) ((STACK_OF(OCSP_SINGLERESP) *)OPENSSL_sk_dup(ossl_check_const_OCSP_SINGLERESP_sk_type(sk)))
    sk_OCSP_SINGLERESP_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OCSP_SINGLERESP) *)OPENSSL_sk_deep_copy(ossl_check_const_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_copyfunc_type(copyfunc), ossl_check_OCSP_SINGLERESP_freefunc_type(freefunc)))
    sk_OCSP_SINGLERESP_set_cmp_func(sk, cmp) ((sk_OCSP_SINGLERESP_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OCSP_SINGLERESP_sk_type(sk), ossl_check_OCSP_SINGLERESP_compfunc_type(cmp)))
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

function OCSP_CERTID_dup(a: POCSP_CERTID): POCSP_CERTID; cdecl external CLibCrypto name 'OCSP_CERTID_dup';
function OCSP_sendreq_new(io: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl external CLibCrypto name 'OCSP_sendreq_new';
function OCSP_sendreq_bio(b: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST): POCSP_RESPONSE; cdecl external CLibCrypto name 'OCSP_sendreq_bio';
function OCSP_cert_to_id(dgst: PEVP_MD; subject: PX509; issuer: PX509): POCSP_CERTID; cdecl external CLibCrypto name 'OCSP_cert_to_id';
function OCSP_cert_id_new(dgst: PEVP_MD; issuerName: PX509_NAME; issuerKey: PASN1_BIT_STRING; serialNumber: PASN1_INTEGER): POCSP_CERTID; cdecl external CLibCrypto name 'OCSP_cert_id_new';
function OCSP_request_add0_id(req: POCSP_REQUEST; cid: POCSP_CERTID): POCSP_ONEREQ; cdecl external CLibCrypto name 'OCSP_request_add0_id';
function OCSP_request_add1_nonce(req: POCSP_REQUEST; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_request_add1_nonce';
function OCSP_basic_add1_nonce(resp: POCSP_BASICRESP; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_basic_add1_nonce';
function OCSP_check_nonce(req: POCSP_REQUEST; bs: POCSP_BASICRESP): TIdC_INT; cdecl external CLibCrypto name 'OCSP_check_nonce';
function OCSP_copy_nonce(resp: POCSP_BASICRESP; req: POCSP_REQUEST): TIdC_INT; cdecl external CLibCrypto name 'OCSP_copy_nonce';
function OCSP_request_set1_name(req: POCSP_REQUEST; nm: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OCSP_request_set1_name';
function OCSP_request_add1_cert(req: POCSP_REQUEST; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OCSP_request_add1_cert';
function OCSP_request_sign(req: POCSP_REQUEST; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_request_sign';
function OCSP_response_status(resp: POCSP_RESPONSE): TIdC_INT; cdecl external CLibCrypto name 'OCSP_response_status';
function OCSP_response_get1_basic(resp: POCSP_RESPONSE): POCSP_BASICRESP; cdecl external CLibCrypto name 'OCSP_response_get1_basic';
function OCSP_resp_get0_signature(bs: POCSP_BASICRESP): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'OCSP_resp_get0_signature';
function OCSP_resp_get0_tbs_sigalg(bs: POCSP_BASICRESP): PX509_ALGOR; cdecl external CLibCrypto name 'OCSP_resp_get0_tbs_sigalg';
function OCSP_resp_get0_respdata(bs: POCSP_BASICRESP): POCSP_RESPDATA; cdecl external CLibCrypto name 'OCSP_resp_get0_respdata';
function OCSP_resp_get0_signer(bs: POCSP_BASICRESP; signer: PPX509; extra_certs: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'OCSP_resp_get0_signer';
function OCSP_resp_count(bs: POCSP_BASICRESP): TIdC_INT; cdecl external CLibCrypto name 'OCSP_resp_count';
function OCSP_resp_get0(bs: POCSP_BASICRESP; idx: TIdC_INT): POCSP_SINGLERESP; cdecl external CLibCrypto name 'OCSP_resp_get0';
function OCSP_resp_get0_produced_at(bs: POCSP_BASICRESP): PASN1_GENERALIZEDTIME; cdecl external CLibCrypto name 'OCSP_resp_get0_produced_at';
function OCSP_resp_get0_certs(bs: POCSP_BASICRESP): Pstack_st_X509; cdecl external CLibCrypto name 'OCSP_resp_get0_certs';
function OCSP_resp_get0_id(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OCSP_resp_get0_id';
function OCSP_resp_get1_id(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OCSP_resp_get1_id';
function OCSP_resp_find(bs: POCSP_BASICRESP; id: POCSP_CERTID; last: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_resp_find';
function OCSP_single_get0_status(single: POCSP_SINGLERESP; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl external CLibCrypto name 'OCSP_single_get0_status';
function OCSP_resp_find_status(bs: POCSP_BASICRESP; id: POCSP_CERTID; status: PIdC_INT; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl external CLibCrypto name 'OCSP_resp_find_status';
function OCSP_check_validity(thisupd: PASN1_GENERALIZEDTIME; nextupd: PASN1_GENERALIZEDTIME; sec: TIdC_LONG; maxsec: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_check_validity';
function OCSP_request_verify(req: POCSP_REQUEST; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_request_verify';
function OCSP_id_issuer_cmp(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl external CLibCrypto name 'OCSP_id_issuer_cmp';
function OCSP_id_cmp(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl external CLibCrypto name 'OCSP_id_cmp';
function OCSP_request_onereq_count(req: POCSP_REQUEST): TIdC_INT; cdecl external CLibCrypto name 'OCSP_request_onereq_count';
function OCSP_request_onereq_get0(req: POCSP_REQUEST; i: TIdC_INT): POCSP_ONEREQ; cdecl external CLibCrypto name 'OCSP_request_onereq_get0';
function OCSP_onereq_get0_id(one: POCSP_ONEREQ): POCSP_CERTID; cdecl external CLibCrypto name 'OCSP_onereq_get0_id';
function OCSP_id_get0_info(piNameHash: PPASN1_OCTET_STRING; pmd: PPASN1_OBJECT; pikeyHash: PPASN1_OCTET_STRING; pserial: PPASN1_INTEGER; cid: POCSP_CERTID): TIdC_INT; cdecl external CLibCrypto name 'OCSP_id_get0_info';
function OCSP_request_is_signed(req: POCSP_REQUEST): TIdC_INT; cdecl external CLibCrypto name 'OCSP_request_is_signed';
function OCSP_response_create(status: TIdC_INT; bs: POCSP_BASICRESP): POCSP_RESPONSE; cdecl external CLibCrypto name 'OCSP_response_create';
function OCSP_basic_add1_status(rsp: POCSP_BASICRESP; cid: POCSP_CERTID; status: TIdC_INT; reason: TIdC_INT; revtime: PASN1_TIME; thisupd: PASN1_TIME; nextupd: PASN1_TIME): POCSP_SINGLERESP; cdecl external CLibCrypto name 'OCSP_basic_add1_status';
function OCSP_basic_add1_cert(resp: POCSP_BASICRESP; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OCSP_basic_add1_cert';
function OCSP_basic_sign(brsp: POCSP_BASICRESP; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_basic_sign';
function OCSP_basic_sign_ctx(brsp: POCSP_BASICRESP; signer: PX509; ctx: PEVP_MD_CTX; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_basic_sign_ctx';
function OCSP_RESPID_set_by_name(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OCSP_RESPID_set_by_name';
function OCSP_RESPID_set_by_key_ex(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OCSP_RESPID_set_by_key_ex';
function OCSP_RESPID_set_by_key(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OCSP_RESPID_set_by_key';
function OCSP_RESPID_match_ex(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OCSP_RESPID_match_ex';
function OCSP_RESPID_match(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'OCSP_RESPID_match';
function OCSP_crlID_new(url: PIdAnsiChar; n: PIdC_LONG; tim: PIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_crlID_new';
function OCSP_accept_responses_new(oids: PPIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_accept_responses_new';
function OCSP_archive_cutoff_new(tim: PIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_archive_cutoff_new';
function OCSP_url_svcloc_new(issuer: PX509_NAME; urls: PPIdAnsiChar): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_url_svcloc_new';
function OCSP_REQUEST_get_ext_count(x: POCSP_REQUEST): TIdC_INT; cdecl external CLibCrypto name 'OCSP_REQUEST_get_ext_count';
function OCSP_REQUEST_get_ext_by_NID(x: POCSP_REQUEST; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_REQUEST_get_ext_by_NID';
function OCSP_REQUEST_get_ext_by_OBJ(x: POCSP_REQUEST; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_REQUEST_get_ext_by_OBJ';
function OCSP_REQUEST_get_ext_by_critical(x: POCSP_REQUEST; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_REQUEST_get_ext_by_critical';
function OCSP_REQUEST_get_ext(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_REQUEST_get_ext';
function OCSP_REQUEST_delete_ext(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_REQUEST_delete_ext';
function OCSP_REQUEST_get1_ext_d2i(x: POCSP_REQUEST; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'OCSP_REQUEST_get1_ext_d2i';
function OCSP_REQUEST_add1_ext_i2d(x: POCSP_REQUEST; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_REQUEST_add1_ext_i2d';
function OCSP_REQUEST_add_ext(x: POCSP_REQUEST; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_REQUEST_add_ext';
function OCSP_ONEREQ_get_ext_count(x: POCSP_ONEREQ): TIdC_INT; cdecl external CLibCrypto name 'OCSP_ONEREQ_get_ext_count';
function OCSP_ONEREQ_get_ext_by_NID(x: POCSP_ONEREQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_ONEREQ_get_ext_by_NID';
function OCSP_ONEREQ_get_ext_by_OBJ(x: POCSP_ONEREQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_ONEREQ_get_ext_by_OBJ';
function OCSP_ONEREQ_get_ext_by_critical(x: POCSP_ONEREQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_ONEREQ_get_ext_by_critical';
function OCSP_ONEREQ_get_ext(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_ONEREQ_get_ext';
function OCSP_ONEREQ_delete_ext(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_ONEREQ_delete_ext';
function OCSP_ONEREQ_get1_ext_d2i(x: POCSP_ONEREQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'OCSP_ONEREQ_get1_ext_d2i';
function OCSP_ONEREQ_add1_ext_i2d(x: POCSP_ONEREQ; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_ONEREQ_add1_ext_i2d';
function OCSP_ONEREQ_add_ext(x: POCSP_ONEREQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_ONEREQ_add_ext';
function OCSP_BASICRESP_get_ext_count(x: POCSP_BASICRESP): TIdC_INT; cdecl external CLibCrypto name 'OCSP_BASICRESP_get_ext_count';
function OCSP_BASICRESP_get_ext_by_NID(x: POCSP_BASICRESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_BASICRESP_get_ext_by_NID';
function OCSP_BASICRESP_get_ext_by_OBJ(x: POCSP_BASICRESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_BASICRESP_get_ext_by_OBJ';
function OCSP_BASICRESP_get_ext_by_critical(x: POCSP_BASICRESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_BASICRESP_get_ext_by_critical';
function OCSP_BASICRESP_get_ext(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_BASICRESP_get_ext';
function OCSP_BASICRESP_delete_ext(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_BASICRESP_delete_ext';
function OCSP_BASICRESP_get1_ext_d2i(x: POCSP_BASICRESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'OCSP_BASICRESP_get1_ext_d2i';
function OCSP_BASICRESP_add1_ext_i2d(x: POCSP_BASICRESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_BASICRESP_add1_ext_i2d';
function OCSP_BASICRESP_add_ext(x: POCSP_BASICRESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_BASICRESP_add_ext';
function OCSP_SINGLERESP_get_ext_count(x: POCSP_SINGLERESP): TIdC_INT; cdecl external CLibCrypto name 'OCSP_SINGLERESP_get_ext_count';
function OCSP_SINGLERESP_get_ext_by_NID(x: POCSP_SINGLERESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_SINGLERESP_get_ext_by_NID';
function OCSP_SINGLERESP_get_ext_by_OBJ(x: POCSP_SINGLERESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_SINGLERESP_get_ext_by_OBJ';
function OCSP_SINGLERESP_get_ext_by_critical(x: POCSP_SINGLERESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_SINGLERESP_get_ext_by_critical';
function OCSP_SINGLERESP_get_ext(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_SINGLERESP_get_ext';
function OCSP_SINGLERESP_delete_ext(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'OCSP_SINGLERESP_delete_ext';
function OCSP_SINGLERESP_get1_ext_d2i(x: POCSP_SINGLERESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'OCSP_SINGLERESP_get1_ext_d2i';
function OCSP_SINGLERESP_add1_ext_i2d(x: POCSP_SINGLERESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_SINGLERESP_add1_ext_i2d';
function OCSP_SINGLERESP_add_ext(x: POCSP_SINGLERESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OCSP_SINGLERESP_add_ext';
function OCSP_SINGLERESP_get0_id(x: POCSP_SINGLERESP): POCSP_CERTID; cdecl external CLibCrypto name 'OCSP_SINGLERESP_get0_id';
function OCSP_SINGLERESP_new: POCSP_SINGLERESP; cdecl external CLibCrypto name 'OCSP_SINGLERESP_new';
function OCSP_SINGLERESP_free(a: POCSP_SINGLERESP): void; cdecl external CLibCrypto name 'OCSP_SINGLERESP_free';
function d2i_OCSP_SINGLERESP(a: PPOCSP_SINGLERESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SINGLERESP; cdecl external CLibCrypto name 'd2i_OCSP_SINGLERESP';
function i2d_OCSP_SINGLERESP(a: POCSP_SINGLERESP; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_SINGLERESP';
function OCSP_SINGLERESP_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_SINGLERESP_it';
function OCSP_CERTSTATUS_new: POCSP_CERTSTATUS; cdecl external CLibCrypto name 'OCSP_CERTSTATUS_new';
function OCSP_CERTSTATUS_free(a: POCSP_CERTSTATUS): void; cdecl external CLibCrypto name 'OCSP_CERTSTATUS_free';
function d2i_OCSP_CERTSTATUS(a: PPOCSP_CERTSTATUS; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTSTATUS; cdecl external CLibCrypto name 'd2i_OCSP_CERTSTATUS';
function i2d_OCSP_CERTSTATUS(a: POCSP_CERTSTATUS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_CERTSTATUS';
function OCSP_CERTSTATUS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_CERTSTATUS_it';
function OCSP_REVOKEDINFO_new: POCSP_REVOKEDINFO; cdecl external CLibCrypto name 'OCSP_REVOKEDINFO_new';
function OCSP_REVOKEDINFO_free(a: POCSP_REVOKEDINFO): void; cdecl external CLibCrypto name 'OCSP_REVOKEDINFO_free';
function d2i_OCSP_REVOKEDINFO(a: PPOCSP_REVOKEDINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REVOKEDINFO; cdecl external CLibCrypto name 'd2i_OCSP_REVOKEDINFO';
function i2d_OCSP_REVOKEDINFO(a: POCSP_REVOKEDINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_REVOKEDINFO';
function OCSP_REVOKEDINFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_REVOKEDINFO_it';
function OCSP_BASICRESP_new: POCSP_BASICRESP; cdecl external CLibCrypto name 'OCSP_BASICRESP_new';
function OCSP_BASICRESP_free(a: POCSP_BASICRESP): void; cdecl external CLibCrypto name 'OCSP_BASICRESP_free';
function d2i_OCSP_BASICRESP(a: PPOCSP_BASICRESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_BASICRESP; cdecl external CLibCrypto name 'd2i_OCSP_BASICRESP';
function i2d_OCSP_BASICRESP(a: POCSP_BASICRESP; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_BASICRESP';
function OCSP_BASICRESP_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_BASICRESP_it';
function OCSP_RESPDATA_new: POCSP_RESPDATA; cdecl external CLibCrypto name 'OCSP_RESPDATA_new';
function OCSP_RESPDATA_free(a: POCSP_RESPDATA): void; cdecl external CLibCrypto name 'OCSP_RESPDATA_free';
function d2i_OCSP_RESPDATA(a: PPOCSP_RESPDATA; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPDATA; cdecl external CLibCrypto name 'd2i_OCSP_RESPDATA';
function i2d_OCSP_RESPDATA(a: POCSP_RESPDATA; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_RESPDATA';
function OCSP_RESPDATA_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_RESPDATA_it';
function OCSP_RESPID_new: POCSP_RESPID; cdecl external CLibCrypto name 'OCSP_RESPID_new';
function OCSP_RESPID_free(a: POCSP_RESPID): void; cdecl external CLibCrypto name 'OCSP_RESPID_free';
function d2i_OCSP_RESPID(a: PPOCSP_RESPID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPID; cdecl external CLibCrypto name 'd2i_OCSP_RESPID';
function i2d_OCSP_RESPID(a: POCSP_RESPID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_RESPID';
function OCSP_RESPID_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_RESPID_it';
function OCSP_RESPONSE_new: POCSP_RESPONSE; cdecl external CLibCrypto name 'OCSP_RESPONSE_new';
function OCSP_RESPONSE_free(a: POCSP_RESPONSE): void; cdecl external CLibCrypto name 'OCSP_RESPONSE_free';
function d2i_OCSP_RESPONSE(a: PPOCSP_RESPONSE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPONSE; cdecl external CLibCrypto name 'd2i_OCSP_RESPONSE';
function i2d_OCSP_RESPONSE(a: POCSP_RESPONSE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_RESPONSE';
function OCSP_RESPONSE_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_RESPONSE_it';
function OCSP_RESPBYTES_new: POCSP_RESPBYTES; cdecl external CLibCrypto name 'OCSP_RESPBYTES_new';
function OCSP_RESPBYTES_free(a: POCSP_RESPBYTES): void; cdecl external CLibCrypto name 'OCSP_RESPBYTES_free';
function d2i_OCSP_RESPBYTES(a: PPOCSP_RESPBYTES; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPBYTES; cdecl external CLibCrypto name 'd2i_OCSP_RESPBYTES';
function i2d_OCSP_RESPBYTES(a: POCSP_RESPBYTES; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_RESPBYTES';
function OCSP_RESPBYTES_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_RESPBYTES_it';
function OCSP_ONEREQ_new: POCSP_ONEREQ; cdecl external CLibCrypto name 'OCSP_ONEREQ_new';
function OCSP_ONEREQ_free(a: POCSP_ONEREQ): void; cdecl external CLibCrypto name 'OCSP_ONEREQ_free';
function d2i_OCSP_ONEREQ(a: PPOCSP_ONEREQ; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_ONEREQ; cdecl external CLibCrypto name 'd2i_OCSP_ONEREQ';
function i2d_OCSP_ONEREQ(a: POCSP_ONEREQ; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_ONEREQ';
function OCSP_ONEREQ_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_ONEREQ_it';
function OCSP_CERTID_new: POCSP_CERTID; cdecl external CLibCrypto name 'OCSP_CERTID_new';
function OCSP_CERTID_free(a: POCSP_CERTID): void; cdecl external CLibCrypto name 'OCSP_CERTID_free';
function d2i_OCSP_CERTID(a: PPOCSP_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTID; cdecl external CLibCrypto name 'd2i_OCSP_CERTID';
function i2d_OCSP_CERTID(a: POCSP_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_CERTID';
function OCSP_CERTID_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_CERTID_it';
function OCSP_REQUEST_new: POCSP_REQUEST; cdecl external CLibCrypto name 'OCSP_REQUEST_new';
function OCSP_REQUEST_free(a: POCSP_REQUEST): void; cdecl external CLibCrypto name 'OCSP_REQUEST_free';
function d2i_OCSP_REQUEST(a: PPOCSP_REQUEST; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQUEST; cdecl external CLibCrypto name 'd2i_OCSP_REQUEST';
function i2d_OCSP_REQUEST(a: POCSP_REQUEST; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_REQUEST';
function OCSP_REQUEST_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_REQUEST_it';
function OCSP_SIGNATURE_new: POCSP_SIGNATURE; cdecl external CLibCrypto name 'OCSP_SIGNATURE_new';
function OCSP_SIGNATURE_free(a: POCSP_SIGNATURE): void; cdecl external CLibCrypto name 'OCSP_SIGNATURE_free';
function d2i_OCSP_SIGNATURE(a: PPOCSP_SIGNATURE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SIGNATURE; cdecl external CLibCrypto name 'd2i_OCSP_SIGNATURE';
function i2d_OCSP_SIGNATURE(a: POCSP_SIGNATURE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_SIGNATURE';
function OCSP_SIGNATURE_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_SIGNATURE_it';
function OCSP_REQINFO_new: POCSP_REQINFO; cdecl external CLibCrypto name 'OCSP_REQINFO_new';
function OCSP_REQINFO_free(a: POCSP_REQINFO): void; cdecl external CLibCrypto name 'OCSP_REQINFO_free';
function d2i_OCSP_REQINFO(a: PPOCSP_REQINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQINFO; cdecl external CLibCrypto name 'd2i_OCSP_REQINFO';
function i2d_OCSP_REQINFO(a: POCSP_REQINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_REQINFO';
function OCSP_REQINFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_REQINFO_it';
function OCSP_CRLID_new: POCSP_CRLID; cdecl external CLibCrypto name 'OCSP_CRLID_new';
function OCSP_CRLID_free(a: POCSP_CRLID): void; cdecl external CLibCrypto name 'OCSP_CRLID_free';
function d2i_OCSP_CRLID(a: PPOCSP_CRLID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CRLID; cdecl external CLibCrypto name 'd2i_OCSP_CRLID';
function i2d_OCSP_CRLID(a: POCSP_CRLID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_CRLID';
function OCSP_CRLID_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_CRLID_it';
function OCSP_SERVICELOC_new: POCSP_SERVICELOC; cdecl external CLibCrypto name 'OCSP_SERVICELOC_new';
function OCSP_SERVICELOC_free(a: POCSP_SERVICELOC): void; cdecl external CLibCrypto name 'OCSP_SERVICELOC_free';
function d2i_OCSP_SERVICELOC(a: PPOCSP_SERVICELOC; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SERVICELOC; cdecl external CLibCrypto name 'd2i_OCSP_SERVICELOC';
function i2d_OCSP_SERVICELOC(a: POCSP_SERVICELOC; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OCSP_SERVICELOC';
function OCSP_SERVICELOC_it: PASN1_ITEM; cdecl external CLibCrypto name 'OCSP_SERVICELOC_it';
function OCSP_response_status_str(s: TIdC_LONG): PIdAnsiChar; cdecl external CLibCrypto name 'OCSP_response_status_str';
function OCSP_cert_status_str(s: TIdC_LONG): PIdAnsiChar; cdecl external CLibCrypto name 'OCSP_cert_status_str';
function OCSP_crl_reason_str(s: TIdC_LONG): PIdAnsiChar; cdecl external CLibCrypto name 'OCSP_crl_reason_str';
function OCSP_REQUEST_print(bp: PBIO; a: POCSP_REQUEST; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_REQUEST_print';
function OCSP_RESPONSE_print(bp: PBIO; o: POCSP_RESPONSE; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_RESPONSE_print';
function OCSP_basic_verify(bs: POCSP_BASICRESP; certs: Pstack_st_X509; st: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OCSP_basic_verify';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OCSP_CERTID_dup_procname = 'OCSP_CERTID_dup';
  OCSP_CERTID_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_sendreq_new_procname = 'OCSP_sendreq_new';
  OCSP_sendreq_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_sendreq_bio_procname = 'OCSP_sendreq_bio';
  OCSP_sendreq_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_cert_to_id_procname = 'OCSP_cert_to_id';
  OCSP_cert_to_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_cert_id_new_procname = 'OCSP_cert_id_new';
  OCSP_cert_id_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_add0_id_procname = 'OCSP_request_add0_id';
  OCSP_request_add0_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_add1_nonce_procname = 'OCSP_request_add1_nonce';
  OCSP_request_add1_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_basic_add1_nonce_procname = 'OCSP_basic_add1_nonce';
  OCSP_basic_add1_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_check_nonce_procname = 'OCSP_check_nonce';
  OCSP_check_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_copy_nonce_procname = 'OCSP_copy_nonce';
  OCSP_copy_nonce_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_set1_name_procname = 'OCSP_request_set1_name';
  OCSP_request_set1_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_add1_cert_procname = 'OCSP_request_add1_cert';
  OCSP_request_add1_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_sign_procname = 'OCSP_request_sign';
  OCSP_request_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_response_status_procname = 'OCSP_response_status';
  OCSP_response_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_response_get1_basic_procname = 'OCSP_response_get1_basic';
  OCSP_response_get1_basic_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_get0_signature_procname = 'OCSP_resp_get0_signature';
  OCSP_resp_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_get0_tbs_sigalg_procname = 'OCSP_resp_get0_tbs_sigalg';
  OCSP_resp_get0_tbs_sigalg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0j);

  OCSP_resp_get0_respdata_procname = 'OCSP_resp_get0_respdata';
  OCSP_resp_get0_respdata_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0j);

  OCSP_resp_get0_signer_procname = 'OCSP_resp_get0_signer';
  OCSP_resp_get0_signer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0h);

  OCSP_resp_count_procname = 'OCSP_resp_count';
  OCSP_resp_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_get0_procname = 'OCSP_resp_get0';
  OCSP_resp_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_get0_produced_at_procname = 'OCSP_resp_get0_produced_at';
  OCSP_resp_get0_produced_at_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_get0_certs_procname = 'OCSP_resp_get0_certs';
  OCSP_resp_get0_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_get0_id_procname = 'OCSP_resp_get0_id';
  OCSP_resp_get0_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_get1_id_procname = 'OCSP_resp_get1_id';
  OCSP_resp_get1_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OCSP_resp_find_procname = 'OCSP_resp_find';
  OCSP_resp_find_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_single_get0_status_procname = 'OCSP_single_get0_status';
  OCSP_single_get0_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_resp_find_status_procname = 'OCSP_resp_find_status';
  OCSP_resp_find_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_check_validity_procname = 'OCSP_check_validity';
  OCSP_check_validity_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_verify_procname = 'OCSP_request_verify';
  OCSP_request_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_id_issuer_cmp_procname = 'OCSP_id_issuer_cmp';
  OCSP_id_issuer_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_id_cmp_procname = 'OCSP_id_cmp';
  OCSP_id_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_onereq_count_procname = 'OCSP_request_onereq_count';
  OCSP_request_onereq_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_onereq_get0_procname = 'OCSP_request_onereq_get0';
  OCSP_request_onereq_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_onereq_get0_id_procname = 'OCSP_onereq_get0_id';
  OCSP_onereq_get0_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_id_get0_info_procname = 'OCSP_id_get0_info';
  OCSP_id_get0_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_request_is_signed_procname = 'OCSP_request_is_signed';
  OCSP_request_is_signed_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_response_create_procname = 'OCSP_response_create';
  OCSP_response_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_basic_add1_status_procname = 'OCSP_basic_add1_status';
  OCSP_basic_add1_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_basic_add1_cert_procname = 'OCSP_basic_add1_cert';
  OCSP_basic_add1_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_basic_sign_procname = 'OCSP_basic_sign';
  OCSP_basic_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_basic_sign_ctx_procname = 'OCSP_basic_sign_ctx';
  OCSP_basic_sign_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OCSP_RESPID_set_by_name_procname = 'OCSP_RESPID_set_by_name';
  OCSP_RESPID_set_by_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0a);

  OCSP_RESPID_set_by_key_ex_procname = 'OCSP_RESPID_set_by_key_ex';
  OCSP_RESPID_set_by_key_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OCSP_RESPID_set_by_key_procname = 'OCSP_RESPID_set_by_key';
  OCSP_RESPID_set_by_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0a);

  OCSP_RESPID_match_ex_procname = 'OCSP_RESPID_match_ex';
  OCSP_RESPID_match_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OCSP_RESPID_match_procname = 'OCSP_RESPID_match';
  OCSP_RESPID_match_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0a);

  OCSP_crlID_new_procname = 'OCSP_crlID_new';
  OCSP_crlID_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_accept_responses_new_procname = 'OCSP_accept_responses_new';
  OCSP_accept_responses_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_archive_cutoff_new_procname = 'OCSP_archive_cutoff_new';
  OCSP_archive_cutoff_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_url_svcloc_new_procname = 'OCSP_url_svcloc_new';
  OCSP_url_svcloc_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_get_ext_count_procname = 'OCSP_REQUEST_get_ext_count';
  OCSP_REQUEST_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_get_ext_by_NID_procname = 'OCSP_REQUEST_get_ext_by_NID';
  OCSP_REQUEST_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_get_ext_by_OBJ_procname = 'OCSP_REQUEST_get_ext_by_OBJ';
  OCSP_REQUEST_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_get_ext_by_critical_procname = 'OCSP_REQUEST_get_ext_by_critical';
  OCSP_REQUEST_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_get_ext_procname = 'OCSP_REQUEST_get_ext';
  OCSP_REQUEST_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_delete_ext_procname = 'OCSP_REQUEST_delete_ext';
  OCSP_REQUEST_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_get1_ext_d2i_procname = 'OCSP_REQUEST_get1_ext_d2i';
  OCSP_REQUEST_get1_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_add1_ext_i2d_procname = 'OCSP_REQUEST_add1_ext_i2d';
  OCSP_REQUEST_add1_ext_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_add_ext_procname = 'OCSP_REQUEST_add_ext';
  OCSP_REQUEST_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_get_ext_count_procname = 'OCSP_ONEREQ_get_ext_count';
  OCSP_ONEREQ_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_get_ext_by_NID_procname = 'OCSP_ONEREQ_get_ext_by_NID';
  OCSP_ONEREQ_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_get_ext_by_OBJ_procname = 'OCSP_ONEREQ_get_ext_by_OBJ';
  OCSP_ONEREQ_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_get_ext_by_critical_procname = 'OCSP_ONEREQ_get_ext_by_critical';
  OCSP_ONEREQ_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_get_ext_procname = 'OCSP_ONEREQ_get_ext';
  OCSP_ONEREQ_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_delete_ext_procname = 'OCSP_ONEREQ_delete_ext';
  OCSP_ONEREQ_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_get1_ext_d2i_procname = 'OCSP_ONEREQ_get1_ext_d2i';
  OCSP_ONEREQ_get1_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_add1_ext_i2d_procname = 'OCSP_ONEREQ_add1_ext_i2d';
  OCSP_ONEREQ_add1_ext_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_add_ext_procname = 'OCSP_ONEREQ_add_ext';
  OCSP_ONEREQ_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_get_ext_count_procname = 'OCSP_BASICRESP_get_ext_count';
  OCSP_BASICRESP_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_get_ext_by_NID_procname = 'OCSP_BASICRESP_get_ext_by_NID';
  OCSP_BASICRESP_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_get_ext_by_OBJ_procname = 'OCSP_BASICRESP_get_ext_by_OBJ';
  OCSP_BASICRESP_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_get_ext_by_critical_procname = 'OCSP_BASICRESP_get_ext_by_critical';
  OCSP_BASICRESP_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_get_ext_procname = 'OCSP_BASICRESP_get_ext';
  OCSP_BASICRESP_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_delete_ext_procname = 'OCSP_BASICRESP_delete_ext';
  OCSP_BASICRESP_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_get1_ext_d2i_procname = 'OCSP_BASICRESP_get1_ext_d2i';
  OCSP_BASICRESP_get1_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_add1_ext_i2d_procname = 'OCSP_BASICRESP_add1_ext_i2d';
  OCSP_BASICRESP_add1_ext_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_add_ext_procname = 'OCSP_BASICRESP_add_ext';
  OCSP_BASICRESP_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_get_ext_count_procname = 'OCSP_SINGLERESP_get_ext_count';
  OCSP_SINGLERESP_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_get_ext_by_NID_procname = 'OCSP_SINGLERESP_get_ext_by_NID';
  OCSP_SINGLERESP_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_get_ext_by_OBJ_procname = 'OCSP_SINGLERESP_get_ext_by_OBJ';
  OCSP_SINGLERESP_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_get_ext_by_critical_procname = 'OCSP_SINGLERESP_get_ext_by_critical';
  OCSP_SINGLERESP_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_get_ext_procname = 'OCSP_SINGLERESP_get_ext';
  OCSP_SINGLERESP_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_delete_ext_procname = 'OCSP_SINGLERESP_delete_ext';
  OCSP_SINGLERESP_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_get1_ext_d2i_procname = 'OCSP_SINGLERESP_get1_ext_d2i';
  OCSP_SINGLERESP_get1_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_add1_ext_i2d_procname = 'OCSP_SINGLERESP_add1_ext_i2d';
  OCSP_SINGLERESP_add1_ext_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_add_ext_procname = 'OCSP_SINGLERESP_add_ext';
  OCSP_SINGLERESP_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_get0_id_procname = 'OCSP_SINGLERESP_get0_id';
  OCSP_SINGLERESP_get0_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_new_procname = 'OCSP_SINGLERESP_new';
  OCSP_SINGLERESP_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_free_procname = 'OCSP_SINGLERESP_free';
  OCSP_SINGLERESP_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_SINGLERESP_procname = 'd2i_OCSP_SINGLERESP';
  d2i_OCSP_SINGLERESP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_SINGLERESP_procname = 'i2d_OCSP_SINGLERESP';
  i2d_OCSP_SINGLERESP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SINGLERESP_it_procname = 'OCSP_SINGLERESP_it';
  OCSP_SINGLERESP_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CERTSTATUS_new_procname = 'OCSP_CERTSTATUS_new';
  OCSP_CERTSTATUS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CERTSTATUS_free_procname = 'OCSP_CERTSTATUS_free';
  OCSP_CERTSTATUS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_CERTSTATUS_procname = 'd2i_OCSP_CERTSTATUS';
  d2i_OCSP_CERTSTATUS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_CERTSTATUS_procname = 'i2d_OCSP_CERTSTATUS';
  i2d_OCSP_CERTSTATUS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CERTSTATUS_it_procname = 'OCSP_CERTSTATUS_it';
  OCSP_CERTSTATUS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REVOKEDINFO_new_procname = 'OCSP_REVOKEDINFO_new';
  OCSP_REVOKEDINFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REVOKEDINFO_free_procname = 'OCSP_REVOKEDINFO_free';
  OCSP_REVOKEDINFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_REVOKEDINFO_procname = 'd2i_OCSP_REVOKEDINFO';
  d2i_OCSP_REVOKEDINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_REVOKEDINFO_procname = 'i2d_OCSP_REVOKEDINFO';
  i2d_OCSP_REVOKEDINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REVOKEDINFO_it_procname = 'OCSP_REVOKEDINFO_it';
  OCSP_REVOKEDINFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_new_procname = 'OCSP_BASICRESP_new';
  OCSP_BASICRESP_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_free_procname = 'OCSP_BASICRESP_free';
  OCSP_BASICRESP_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_BASICRESP_procname = 'd2i_OCSP_BASICRESP';
  d2i_OCSP_BASICRESP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_BASICRESP_procname = 'i2d_OCSP_BASICRESP';
  i2d_OCSP_BASICRESP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_BASICRESP_it_procname = 'OCSP_BASICRESP_it';
  OCSP_BASICRESP_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPDATA_new_procname = 'OCSP_RESPDATA_new';
  OCSP_RESPDATA_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPDATA_free_procname = 'OCSP_RESPDATA_free';
  OCSP_RESPDATA_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_RESPDATA_procname = 'd2i_OCSP_RESPDATA';
  d2i_OCSP_RESPDATA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_RESPDATA_procname = 'i2d_OCSP_RESPDATA';
  i2d_OCSP_RESPDATA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPDATA_it_procname = 'OCSP_RESPDATA_it';
  OCSP_RESPDATA_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPID_new_procname = 'OCSP_RESPID_new';
  OCSP_RESPID_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPID_free_procname = 'OCSP_RESPID_free';
  OCSP_RESPID_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_RESPID_procname = 'd2i_OCSP_RESPID';
  d2i_OCSP_RESPID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_RESPID_procname = 'i2d_OCSP_RESPID';
  i2d_OCSP_RESPID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPID_it_procname = 'OCSP_RESPID_it';
  OCSP_RESPID_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPONSE_new_procname = 'OCSP_RESPONSE_new';
  OCSP_RESPONSE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPONSE_free_procname = 'OCSP_RESPONSE_free';
  OCSP_RESPONSE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_RESPONSE_procname = 'd2i_OCSP_RESPONSE';
  d2i_OCSP_RESPONSE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_RESPONSE_procname = 'i2d_OCSP_RESPONSE';
  i2d_OCSP_RESPONSE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPONSE_it_procname = 'OCSP_RESPONSE_it';
  OCSP_RESPONSE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPBYTES_new_procname = 'OCSP_RESPBYTES_new';
  OCSP_RESPBYTES_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPBYTES_free_procname = 'OCSP_RESPBYTES_free';
  OCSP_RESPBYTES_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_RESPBYTES_procname = 'd2i_OCSP_RESPBYTES';
  d2i_OCSP_RESPBYTES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_RESPBYTES_procname = 'i2d_OCSP_RESPBYTES';
  i2d_OCSP_RESPBYTES_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPBYTES_it_procname = 'OCSP_RESPBYTES_it';
  OCSP_RESPBYTES_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_new_procname = 'OCSP_ONEREQ_new';
  OCSP_ONEREQ_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_free_procname = 'OCSP_ONEREQ_free';
  OCSP_ONEREQ_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_ONEREQ_procname = 'd2i_OCSP_ONEREQ';
  d2i_OCSP_ONEREQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_ONEREQ_procname = 'i2d_OCSP_ONEREQ';
  i2d_OCSP_ONEREQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_ONEREQ_it_procname = 'OCSP_ONEREQ_it';
  OCSP_ONEREQ_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CERTID_new_procname = 'OCSP_CERTID_new';
  OCSP_CERTID_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CERTID_free_procname = 'OCSP_CERTID_free';
  OCSP_CERTID_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_CERTID_procname = 'd2i_OCSP_CERTID';
  d2i_OCSP_CERTID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_CERTID_procname = 'i2d_OCSP_CERTID';
  i2d_OCSP_CERTID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CERTID_it_procname = 'OCSP_CERTID_it';
  OCSP_CERTID_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_new_procname = 'OCSP_REQUEST_new';
  OCSP_REQUEST_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_free_procname = 'OCSP_REQUEST_free';
  OCSP_REQUEST_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_REQUEST_procname = 'd2i_OCSP_REQUEST';
  d2i_OCSP_REQUEST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_REQUEST_procname = 'i2d_OCSP_REQUEST';
  i2d_OCSP_REQUEST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_it_procname = 'OCSP_REQUEST_it';
  OCSP_REQUEST_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SIGNATURE_new_procname = 'OCSP_SIGNATURE_new';
  OCSP_SIGNATURE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SIGNATURE_free_procname = 'OCSP_SIGNATURE_free';
  OCSP_SIGNATURE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_SIGNATURE_procname = 'd2i_OCSP_SIGNATURE';
  d2i_OCSP_SIGNATURE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_SIGNATURE_procname = 'i2d_OCSP_SIGNATURE';
  i2d_OCSP_SIGNATURE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SIGNATURE_it_procname = 'OCSP_SIGNATURE_it';
  OCSP_SIGNATURE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQINFO_new_procname = 'OCSP_REQINFO_new';
  OCSP_REQINFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQINFO_free_procname = 'OCSP_REQINFO_free';
  OCSP_REQINFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_REQINFO_procname = 'd2i_OCSP_REQINFO';
  d2i_OCSP_REQINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_REQINFO_procname = 'i2d_OCSP_REQINFO';
  i2d_OCSP_REQINFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQINFO_it_procname = 'OCSP_REQINFO_it';
  OCSP_REQINFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CRLID_new_procname = 'OCSP_CRLID_new';
  OCSP_CRLID_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CRLID_free_procname = 'OCSP_CRLID_free';
  OCSP_CRLID_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_CRLID_procname = 'd2i_OCSP_CRLID';
  d2i_OCSP_CRLID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_CRLID_procname = 'i2d_OCSP_CRLID';
  i2d_OCSP_CRLID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_CRLID_it_procname = 'OCSP_CRLID_it';
  OCSP_CRLID_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SERVICELOC_new_procname = 'OCSP_SERVICELOC_new';
  OCSP_SERVICELOC_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SERVICELOC_free_procname = 'OCSP_SERVICELOC_free';
  OCSP_SERVICELOC_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_OCSP_SERVICELOC_procname = 'd2i_OCSP_SERVICELOC';
  d2i_OCSP_SERVICELOC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_OCSP_SERVICELOC_procname = 'i2d_OCSP_SERVICELOC';
  i2d_OCSP_SERVICELOC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_SERVICELOC_it_procname = 'OCSP_SERVICELOC_it';
  OCSP_SERVICELOC_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_response_status_str_procname = 'OCSP_response_status_str';
  OCSP_response_status_str_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_cert_status_str_procname = 'OCSP_cert_status_str';
  OCSP_cert_status_str_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_crl_reason_str_procname = 'OCSP_crl_reason_str';
  OCSP_crl_reason_str_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_REQUEST_print_procname = 'OCSP_REQUEST_print';
  OCSP_REQUEST_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_RESPONSE_print_procname = 'OCSP_RESPONSE_print';
  OCSP_RESPONSE_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OCSP_basic_verify_procname = 'OCSP_basic_verify';
  OCSP_basic_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function ASN1_BIT_STRING_digest(data: Pointer; _type: Pointer; md: Pointer; len: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    ASN1_BIT_STRING_digest(data, type, md, len) \
    ASN1_item_digest(ASN1_ITEM_rptr(ASN1_BIT_STRING), type, data, md, len)
  }
end;

function OCSP_REQ_CTX_i2d(r: Pointer; it: Pointer; req: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OCSP_REQ_CTX_i2d(r, it, req) \
    OSSL_HTTP_REQ_CTX_set1_req(r, "application/ocsp-request", it, req)
  }
end;

function OCSP_REQ_CTX_set1_req(r: Pointer; req: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OCSP_REQ_CTX_set1_req(r, req) \
    OCSP_REQ_CTX_i2d(r, ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)(req))
  }
end;

function OCSP_sendreq_nbio(p: Pointer; r: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OCSP_sendreq_nbio(p, r)                       \
    OSSL_HTTP_REQ_CTX_nbio_d2i(r, (ASN1_VALUE **)(p), \
        ASN1_ITEM_rptr(OCSP_RESPONSE))
  }
end;

function OCSP_parse_url(url: Pointer; host: Pointer; port: Pointer; path: Pointer; ssl: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OCSP_parse_url(url, host, port, path, ssl) \
    OSSL_HTTP_parse_url(url, ssl, NULL, host, port, NULL, path, NULL, NULL)
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OCSP_CERTID_dup(a: POCSP_CERTID): POCSP_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CERTID_dup_procname);
end;

function ERR_OCSP_sendreq_new(io: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_sendreq_new_procname);
end;

function ERR_OCSP_sendreq_bio(b: PBIO; path: PIdAnsiChar; req: POCSP_REQUEST): POCSP_RESPONSE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_sendreq_bio_procname);
end;

function ERR_OCSP_cert_to_id(dgst: PEVP_MD; subject: PX509; issuer: PX509): POCSP_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_cert_to_id_procname);
end;

function ERR_OCSP_cert_id_new(dgst: PEVP_MD; issuerName: PX509_NAME; issuerKey: PASN1_BIT_STRING; serialNumber: PASN1_INTEGER): POCSP_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_cert_id_new_procname);
end;

function ERR_OCSP_request_add0_id(req: POCSP_REQUEST; cid: POCSP_CERTID): POCSP_ONEREQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_add0_id_procname);
end;

function ERR_OCSP_request_add1_nonce(req: POCSP_REQUEST; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_add1_nonce_procname);
end;

function ERR_OCSP_basic_add1_nonce(resp: POCSP_BASICRESP; val: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_basic_add1_nonce_procname);
end;

function ERR_OCSP_check_nonce(req: POCSP_REQUEST; bs: POCSP_BASICRESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_check_nonce_procname);
end;

function ERR_OCSP_copy_nonce(resp: POCSP_BASICRESP; req: POCSP_REQUEST): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_copy_nonce_procname);
end;

function ERR_OCSP_request_set1_name(req: POCSP_REQUEST; nm: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_set1_name_procname);
end;

function ERR_OCSP_request_add1_cert(req: POCSP_REQUEST; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_add1_cert_procname);
end;

function ERR_OCSP_request_sign(req: POCSP_REQUEST; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_sign_procname);
end;

function ERR_OCSP_response_status(resp: POCSP_RESPONSE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_response_status_procname);
end;

function ERR_OCSP_response_get1_basic(resp: POCSP_RESPONSE): POCSP_BASICRESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_response_get1_basic_procname);
end;

function ERR_OCSP_resp_get0_signature(bs: POCSP_BASICRESP): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_signature_procname);
end;

function ERR_OCSP_resp_get0_tbs_sigalg(bs: POCSP_BASICRESP): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_tbs_sigalg_procname);
end;

function ERR_OCSP_resp_get0_respdata(bs: POCSP_BASICRESP): POCSP_RESPDATA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_respdata_procname);
end;

function ERR_OCSP_resp_get0_signer(bs: POCSP_BASICRESP; signer: PPX509; extra_certs: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_signer_procname);
end;

function ERR_OCSP_resp_count(bs: POCSP_BASICRESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_count_procname);
end;

function ERR_OCSP_resp_get0(bs: POCSP_BASICRESP; idx: TIdC_INT): POCSP_SINGLERESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_procname);
end;

function ERR_OCSP_resp_get0_produced_at(bs: POCSP_BASICRESP): PASN1_GENERALIZEDTIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_produced_at_procname);
end;

function ERR_OCSP_resp_get0_certs(bs: POCSP_BASICRESP): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_certs_procname);
end;

function ERR_OCSP_resp_get0_id(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get0_id_procname);
end;

function ERR_OCSP_resp_get1_id(bs: POCSP_BASICRESP; pid: PPASN1_OCTET_STRING; pname: PPX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_get1_id_procname);
end;

function ERR_OCSP_resp_find(bs: POCSP_BASICRESP; id: POCSP_CERTID; last: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_find_procname);
end;

function ERR_OCSP_single_get0_status(single: POCSP_SINGLERESP; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_single_get0_status_procname);
end;

function ERR_OCSP_resp_find_status(bs: POCSP_BASICRESP; id: POCSP_CERTID; status: PIdC_INT; reason: PIdC_INT; revtime: PPASN1_GENERALIZEDTIME; thisupd: PPASN1_GENERALIZEDTIME; nextupd: PPASN1_GENERALIZEDTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_resp_find_status_procname);
end;

function ERR_OCSP_check_validity(thisupd: PASN1_GENERALIZEDTIME; nextupd: PASN1_GENERALIZEDTIME; sec: TIdC_LONG; maxsec: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_check_validity_procname);
end;

function ERR_OCSP_request_verify(req: POCSP_REQUEST; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_verify_procname);
end;

function ERR_OCSP_id_issuer_cmp(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_id_issuer_cmp_procname);
end;

function ERR_OCSP_id_cmp(a: POCSP_CERTID; b: POCSP_CERTID): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_id_cmp_procname);
end;

function ERR_OCSP_request_onereq_count(req: POCSP_REQUEST): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_onereq_count_procname);
end;

function ERR_OCSP_request_onereq_get0(req: POCSP_REQUEST; i: TIdC_INT): POCSP_ONEREQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_onereq_get0_procname);
end;

function ERR_OCSP_onereq_get0_id(one: POCSP_ONEREQ): POCSP_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_onereq_get0_id_procname);
end;

function ERR_OCSP_id_get0_info(piNameHash: PPASN1_OCTET_STRING; pmd: PPASN1_OBJECT; pikeyHash: PPASN1_OCTET_STRING; pserial: PPASN1_INTEGER; cid: POCSP_CERTID): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_id_get0_info_procname);
end;

function ERR_OCSP_request_is_signed(req: POCSP_REQUEST): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_request_is_signed_procname);
end;

function ERR_OCSP_response_create(status: TIdC_INT; bs: POCSP_BASICRESP): POCSP_RESPONSE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_response_create_procname);
end;

function ERR_OCSP_basic_add1_status(rsp: POCSP_BASICRESP; cid: POCSP_CERTID; status: TIdC_INT; reason: TIdC_INT; revtime: PASN1_TIME; thisupd: PASN1_TIME; nextupd: PASN1_TIME): POCSP_SINGLERESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_basic_add1_status_procname);
end;

function ERR_OCSP_basic_add1_cert(resp: POCSP_BASICRESP; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_basic_add1_cert_procname);
end;

function ERR_OCSP_basic_sign(brsp: POCSP_BASICRESP; signer: PX509; key: PEVP_PKEY; dgst: PEVP_MD; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_basic_sign_procname);
end;

function ERR_OCSP_basic_sign_ctx(brsp: POCSP_BASICRESP; signer: PX509; ctx: PEVP_MD_CTX; certs: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_basic_sign_ctx_procname);
end;

function ERR_OCSP_RESPID_set_by_name(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_set_by_name_procname);
end;

function ERR_OCSP_RESPID_set_by_key_ex(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_set_by_key_ex_procname);
end;

function ERR_OCSP_RESPID_set_by_key(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_set_by_key_procname);
end;

function ERR_OCSP_RESPID_match_ex(respid: POCSP_RESPID; cert: PX509; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_match_ex_procname);
end;

function ERR_OCSP_RESPID_match(respid: POCSP_RESPID; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_match_procname);
end;

function ERR_OCSP_crlID_new(url: PIdAnsiChar; n: PIdC_LONG; tim: PIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_crlID_new_procname);
end;

function ERR_OCSP_accept_responses_new(oids: PPIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_accept_responses_new_procname);
end;

function ERR_OCSP_archive_cutoff_new(tim: PIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_archive_cutoff_new_procname);
end;

function ERR_OCSP_url_svcloc_new(issuer: PX509_NAME; urls: PPIdAnsiChar): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_url_svcloc_new_procname);
end;

function ERR_OCSP_REQUEST_get_ext_count(x: POCSP_REQUEST): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_get_ext_count_procname);
end;

function ERR_OCSP_REQUEST_get_ext_by_NID(x: POCSP_REQUEST; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_get_ext_by_NID_procname);
end;

function ERR_OCSP_REQUEST_get_ext_by_OBJ(x: POCSP_REQUEST; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_get_ext_by_OBJ_procname);
end;

function ERR_OCSP_REQUEST_get_ext_by_critical(x: POCSP_REQUEST; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_get_ext_by_critical_procname);
end;

function ERR_OCSP_REQUEST_get_ext(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_get_ext_procname);
end;

function ERR_OCSP_REQUEST_delete_ext(x: POCSP_REQUEST; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_delete_ext_procname);
end;

function ERR_OCSP_REQUEST_get1_ext_d2i(x: POCSP_REQUEST; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_get1_ext_d2i_procname);
end;

function ERR_OCSP_REQUEST_add1_ext_i2d(x: POCSP_REQUEST; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_add1_ext_i2d_procname);
end;

function ERR_OCSP_REQUEST_add_ext(x: POCSP_REQUEST; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_add_ext_procname);
end;

function ERR_OCSP_ONEREQ_get_ext_count(x: POCSP_ONEREQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_get_ext_count_procname);
end;

function ERR_OCSP_ONEREQ_get_ext_by_NID(x: POCSP_ONEREQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_get_ext_by_NID_procname);
end;

function ERR_OCSP_ONEREQ_get_ext_by_OBJ(x: POCSP_ONEREQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_get_ext_by_OBJ_procname);
end;

function ERR_OCSP_ONEREQ_get_ext_by_critical(x: POCSP_ONEREQ; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_get_ext_by_critical_procname);
end;

function ERR_OCSP_ONEREQ_get_ext(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_get_ext_procname);
end;

function ERR_OCSP_ONEREQ_delete_ext(x: POCSP_ONEREQ; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_delete_ext_procname);
end;

function ERR_OCSP_ONEREQ_get1_ext_d2i(x: POCSP_ONEREQ; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_get1_ext_d2i_procname);
end;

function ERR_OCSP_ONEREQ_add1_ext_i2d(x: POCSP_ONEREQ; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_add1_ext_i2d_procname);
end;

function ERR_OCSP_ONEREQ_add_ext(x: POCSP_ONEREQ; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_add_ext_procname);
end;

function ERR_OCSP_BASICRESP_get_ext_count(x: POCSP_BASICRESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_get_ext_count_procname);
end;

function ERR_OCSP_BASICRESP_get_ext_by_NID(x: POCSP_BASICRESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_get_ext_by_NID_procname);
end;

function ERR_OCSP_BASICRESP_get_ext_by_OBJ(x: POCSP_BASICRESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_get_ext_by_OBJ_procname);
end;

function ERR_OCSP_BASICRESP_get_ext_by_critical(x: POCSP_BASICRESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_get_ext_by_critical_procname);
end;

function ERR_OCSP_BASICRESP_get_ext(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_get_ext_procname);
end;

function ERR_OCSP_BASICRESP_delete_ext(x: POCSP_BASICRESP; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_delete_ext_procname);
end;

function ERR_OCSP_BASICRESP_get1_ext_d2i(x: POCSP_BASICRESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_get1_ext_d2i_procname);
end;

function ERR_OCSP_BASICRESP_add1_ext_i2d(x: POCSP_BASICRESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_add1_ext_i2d_procname);
end;

function ERR_OCSP_BASICRESP_add_ext(x: POCSP_BASICRESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_add_ext_procname);
end;

function ERR_OCSP_SINGLERESP_get_ext_count(x: POCSP_SINGLERESP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_get_ext_count_procname);
end;

function ERR_OCSP_SINGLERESP_get_ext_by_NID(x: POCSP_SINGLERESP; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_get_ext_by_NID_procname);
end;

function ERR_OCSP_SINGLERESP_get_ext_by_OBJ(x: POCSP_SINGLERESP; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_get_ext_by_OBJ_procname);
end;

function ERR_OCSP_SINGLERESP_get_ext_by_critical(x: POCSP_SINGLERESP; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_get_ext_by_critical_procname);
end;

function ERR_OCSP_SINGLERESP_get_ext(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_get_ext_procname);
end;

function ERR_OCSP_SINGLERESP_delete_ext(x: POCSP_SINGLERESP; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_delete_ext_procname);
end;

function ERR_OCSP_SINGLERESP_get1_ext_d2i(x: POCSP_SINGLERESP; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_get1_ext_d2i_procname);
end;

function ERR_OCSP_SINGLERESP_add1_ext_i2d(x: POCSP_SINGLERESP; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_add1_ext_i2d_procname);
end;

function ERR_OCSP_SINGLERESP_add_ext(x: POCSP_SINGLERESP; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_add_ext_procname);
end;

function ERR_OCSP_SINGLERESP_get0_id(x: POCSP_SINGLERESP): POCSP_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_get0_id_procname);
end;

function ERR_OCSP_SINGLERESP_new: POCSP_SINGLERESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_new_procname);
end;

function ERR_OCSP_SINGLERESP_free(a: POCSP_SINGLERESP): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_free_procname);
end;

function ERR_d2i_OCSP_SINGLERESP(a: PPOCSP_SINGLERESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SINGLERESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_SINGLERESP_procname);
end;

function ERR_i2d_OCSP_SINGLERESP(a: POCSP_SINGLERESP; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_SINGLERESP_procname);
end;

function ERR_OCSP_SINGLERESP_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SINGLERESP_it_procname);
end;

function ERR_OCSP_CERTSTATUS_new: POCSP_CERTSTATUS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CERTSTATUS_new_procname);
end;

function ERR_OCSP_CERTSTATUS_free(a: POCSP_CERTSTATUS): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CERTSTATUS_free_procname);
end;

function ERR_d2i_OCSP_CERTSTATUS(a: PPOCSP_CERTSTATUS; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTSTATUS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_CERTSTATUS_procname);
end;

function ERR_i2d_OCSP_CERTSTATUS(a: POCSP_CERTSTATUS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_CERTSTATUS_procname);
end;

function ERR_OCSP_CERTSTATUS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CERTSTATUS_it_procname);
end;

function ERR_OCSP_REVOKEDINFO_new: POCSP_REVOKEDINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REVOKEDINFO_new_procname);
end;

function ERR_OCSP_REVOKEDINFO_free(a: POCSP_REVOKEDINFO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REVOKEDINFO_free_procname);
end;

function ERR_d2i_OCSP_REVOKEDINFO(a: PPOCSP_REVOKEDINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REVOKEDINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_REVOKEDINFO_procname);
end;

function ERR_i2d_OCSP_REVOKEDINFO(a: POCSP_REVOKEDINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_REVOKEDINFO_procname);
end;

function ERR_OCSP_REVOKEDINFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REVOKEDINFO_it_procname);
end;

function ERR_OCSP_BASICRESP_new: POCSP_BASICRESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_new_procname);
end;

function ERR_OCSP_BASICRESP_free(a: POCSP_BASICRESP): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_free_procname);
end;

function ERR_d2i_OCSP_BASICRESP(a: PPOCSP_BASICRESP; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_BASICRESP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_BASICRESP_procname);
end;

function ERR_i2d_OCSP_BASICRESP(a: POCSP_BASICRESP; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_BASICRESP_procname);
end;

function ERR_OCSP_BASICRESP_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_BASICRESP_it_procname);
end;

function ERR_OCSP_RESPDATA_new: POCSP_RESPDATA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPDATA_new_procname);
end;

function ERR_OCSP_RESPDATA_free(a: POCSP_RESPDATA): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPDATA_free_procname);
end;

function ERR_d2i_OCSP_RESPDATA(a: PPOCSP_RESPDATA; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPDATA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_RESPDATA_procname);
end;

function ERR_i2d_OCSP_RESPDATA(a: POCSP_RESPDATA; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_RESPDATA_procname);
end;

function ERR_OCSP_RESPDATA_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPDATA_it_procname);
end;

function ERR_OCSP_RESPID_new: POCSP_RESPID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_new_procname);
end;

function ERR_OCSP_RESPID_free(a: POCSP_RESPID): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_free_procname);
end;

function ERR_d2i_OCSP_RESPID(a: PPOCSP_RESPID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_RESPID_procname);
end;

function ERR_i2d_OCSP_RESPID(a: POCSP_RESPID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_RESPID_procname);
end;

function ERR_OCSP_RESPID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPID_it_procname);
end;

function ERR_OCSP_RESPONSE_new: POCSP_RESPONSE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPONSE_new_procname);
end;

function ERR_OCSP_RESPONSE_free(a: POCSP_RESPONSE): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPONSE_free_procname);
end;

function ERR_d2i_OCSP_RESPONSE(a: PPOCSP_RESPONSE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPONSE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_RESPONSE_procname);
end;

function ERR_i2d_OCSP_RESPONSE(a: POCSP_RESPONSE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_RESPONSE_procname);
end;

function ERR_OCSP_RESPONSE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPONSE_it_procname);
end;

function ERR_OCSP_RESPBYTES_new: POCSP_RESPBYTES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPBYTES_new_procname);
end;

function ERR_OCSP_RESPBYTES_free(a: POCSP_RESPBYTES): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPBYTES_free_procname);
end;

function ERR_d2i_OCSP_RESPBYTES(a: PPOCSP_RESPBYTES; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_RESPBYTES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_RESPBYTES_procname);
end;

function ERR_i2d_OCSP_RESPBYTES(a: POCSP_RESPBYTES; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_RESPBYTES_procname);
end;

function ERR_OCSP_RESPBYTES_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPBYTES_it_procname);
end;

function ERR_OCSP_ONEREQ_new: POCSP_ONEREQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_new_procname);
end;

function ERR_OCSP_ONEREQ_free(a: POCSP_ONEREQ): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_free_procname);
end;

function ERR_d2i_OCSP_ONEREQ(a: PPOCSP_ONEREQ; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_ONEREQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_ONEREQ_procname);
end;

function ERR_i2d_OCSP_ONEREQ(a: POCSP_ONEREQ; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_ONEREQ_procname);
end;

function ERR_OCSP_ONEREQ_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_ONEREQ_it_procname);
end;

function ERR_OCSP_CERTID_new: POCSP_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CERTID_new_procname);
end;

function ERR_OCSP_CERTID_free(a: POCSP_CERTID): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CERTID_free_procname);
end;

function ERR_d2i_OCSP_CERTID(a: PPOCSP_CERTID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CERTID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_CERTID_procname);
end;

function ERR_i2d_OCSP_CERTID(a: POCSP_CERTID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_CERTID_procname);
end;

function ERR_OCSP_CERTID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CERTID_it_procname);
end;

function ERR_OCSP_REQUEST_new: POCSP_REQUEST; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_new_procname);
end;

function ERR_OCSP_REQUEST_free(a: POCSP_REQUEST): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_free_procname);
end;

function ERR_d2i_OCSP_REQUEST(a: PPOCSP_REQUEST; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQUEST; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_REQUEST_procname);
end;

function ERR_i2d_OCSP_REQUEST(a: POCSP_REQUEST; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_REQUEST_procname);
end;

function ERR_OCSP_REQUEST_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_it_procname);
end;

function ERR_OCSP_SIGNATURE_new: POCSP_SIGNATURE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SIGNATURE_new_procname);
end;

function ERR_OCSP_SIGNATURE_free(a: POCSP_SIGNATURE): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SIGNATURE_free_procname);
end;

function ERR_d2i_OCSP_SIGNATURE(a: PPOCSP_SIGNATURE; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SIGNATURE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_SIGNATURE_procname);
end;

function ERR_i2d_OCSP_SIGNATURE(a: POCSP_SIGNATURE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_SIGNATURE_procname);
end;

function ERR_OCSP_SIGNATURE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SIGNATURE_it_procname);
end;

function ERR_OCSP_REQINFO_new: POCSP_REQINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQINFO_new_procname);
end;

function ERR_OCSP_REQINFO_free(a: POCSP_REQINFO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQINFO_free_procname);
end;

function ERR_d2i_OCSP_REQINFO(a: PPOCSP_REQINFO; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_REQINFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_REQINFO_procname);
end;

function ERR_i2d_OCSP_REQINFO(a: POCSP_REQINFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_REQINFO_procname);
end;

function ERR_OCSP_REQINFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQINFO_it_procname);
end;

function ERR_OCSP_CRLID_new: POCSP_CRLID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CRLID_new_procname);
end;

function ERR_OCSP_CRLID_free(a: POCSP_CRLID): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CRLID_free_procname);
end;

function ERR_d2i_OCSP_CRLID(a: PPOCSP_CRLID; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_CRLID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_CRLID_procname);
end;

function ERR_i2d_OCSP_CRLID(a: POCSP_CRLID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_CRLID_procname);
end;

function ERR_OCSP_CRLID_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_CRLID_it_procname);
end;

function ERR_OCSP_SERVICELOC_new: POCSP_SERVICELOC; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SERVICELOC_new_procname);
end;

function ERR_OCSP_SERVICELOC_free(a: POCSP_SERVICELOC): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SERVICELOC_free_procname);
end;

function ERR_d2i_OCSP_SERVICELOC(a: PPOCSP_SERVICELOC; _in: PPIdAnsiChar; len: TIdC_LONG): POCSP_SERVICELOC; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OCSP_SERVICELOC_procname);
end;

function ERR_i2d_OCSP_SERVICELOC(a: POCSP_SERVICELOC; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OCSP_SERVICELOC_procname);
end;

function ERR_OCSP_SERVICELOC_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_SERVICELOC_it_procname);
end;

function ERR_OCSP_response_status_str(s: TIdC_LONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_response_status_str_procname);
end;

function ERR_OCSP_cert_status_str(s: TIdC_LONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_cert_status_str_procname);
end;

function ERR_OCSP_crl_reason_str(s: TIdC_LONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_crl_reason_str_procname);
end;

function ERR_OCSP_REQUEST_print(bp: PBIO; a: POCSP_REQUEST; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_REQUEST_print_procname);
end;

function ERR_OCSP_RESPONSE_print(bp: PBIO; o: POCSP_RESPONSE; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_RESPONSE_print_procname);
end;

function ERR_OCSP_basic_verify(bs: POCSP_BASICRESP; certs: Pstack_st_X509; st: PX509_STORE; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OCSP_basic_verify_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OCSP_CERTID_dup := LoadLibFunction(ADllHandle, OCSP_CERTID_dup_procname);
  FuncLoadError := not assigned(OCSP_CERTID_dup);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CERTID_dup_allownil)}
    OCSP_CERTID_dup := ERR_OCSP_CERTID_dup;
    {$ifend}
    {$if declared(OCSP_CERTID_dup_introduced)}
    if LibVersion < OCSP_CERTID_dup_introduced then
    begin
      {$if declared(FC_OCSP_CERTID_dup)}
      OCSP_CERTID_dup := FC_OCSP_CERTID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CERTID_dup_removed)}
    if OCSP_CERTID_dup_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CERTID_dup)}
      OCSP_CERTID_dup := _OCSP_CERTID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CERTID_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CERTID_dup');
    {$ifend}
  end;
  
  OCSP_sendreq_new := LoadLibFunction(ADllHandle, OCSP_sendreq_new_procname);
  FuncLoadError := not assigned(OCSP_sendreq_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_sendreq_new_allownil)}
    OCSP_sendreq_new := ERR_OCSP_sendreq_new;
    {$ifend}
    {$if declared(OCSP_sendreq_new_introduced)}
    if LibVersion < OCSP_sendreq_new_introduced then
    begin
      {$if declared(FC_OCSP_sendreq_new)}
      OCSP_sendreq_new := FC_OCSP_sendreq_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_sendreq_new_removed)}
    if OCSP_sendreq_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_sendreq_new)}
      OCSP_sendreq_new := _OCSP_sendreq_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_sendreq_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_sendreq_new');
    {$ifend}
  end;
  
  OCSP_sendreq_bio := LoadLibFunction(ADllHandle, OCSP_sendreq_bio_procname);
  FuncLoadError := not assigned(OCSP_sendreq_bio);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_sendreq_bio_allownil)}
    OCSP_sendreq_bio := ERR_OCSP_sendreq_bio;
    {$ifend}
    {$if declared(OCSP_sendreq_bio_introduced)}
    if LibVersion < OCSP_sendreq_bio_introduced then
    begin
      {$if declared(FC_OCSP_sendreq_bio)}
      OCSP_sendreq_bio := FC_OCSP_sendreq_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_sendreq_bio_removed)}
    if OCSP_sendreq_bio_removed <= LibVersion then
    begin
      {$if declared(_OCSP_sendreq_bio)}
      OCSP_sendreq_bio := _OCSP_sendreq_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_sendreq_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_sendreq_bio');
    {$ifend}
  end;
  
  OCSP_cert_to_id := LoadLibFunction(ADllHandle, OCSP_cert_to_id_procname);
  FuncLoadError := not assigned(OCSP_cert_to_id);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_cert_to_id_allownil)}
    OCSP_cert_to_id := ERR_OCSP_cert_to_id;
    {$ifend}
    {$if declared(OCSP_cert_to_id_introduced)}
    if LibVersion < OCSP_cert_to_id_introduced then
    begin
      {$if declared(FC_OCSP_cert_to_id)}
      OCSP_cert_to_id := FC_OCSP_cert_to_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_cert_to_id_removed)}
    if OCSP_cert_to_id_removed <= LibVersion then
    begin
      {$if declared(_OCSP_cert_to_id)}
      OCSP_cert_to_id := _OCSP_cert_to_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_cert_to_id_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_cert_to_id');
    {$ifend}
  end;
  
  OCSP_cert_id_new := LoadLibFunction(ADllHandle, OCSP_cert_id_new_procname);
  FuncLoadError := not assigned(OCSP_cert_id_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_cert_id_new_allownil)}
    OCSP_cert_id_new := ERR_OCSP_cert_id_new;
    {$ifend}
    {$if declared(OCSP_cert_id_new_introduced)}
    if LibVersion < OCSP_cert_id_new_introduced then
    begin
      {$if declared(FC_OCSP_cert_id_new)}
      OCSP_cert_id_new := FC_OCSP_cert_id_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_cert_id_new_removed)}
    if OCSP_cert_id_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_cert_id_new)}
      OCSP_cert_id_new := _OCSP_cert_id_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_cert_id_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_cert_id_new');
    {$ifend}
  end;
  
  OCSP_request_add0_id := LoadLibFunction(ADllHandle, OCSP_request_add0_id_procname);
  FuncLoadError := not assigned(OCSP_request_add0_id);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_add0_id_allownil)}
    OCSP_request_add0_id := ERR_OCSP_request_add0_id;
    {$ifend}
    {$if declared(OCSP_request_add0_id_introduced)}
    if LibVersion < OCSP_request_add0_id_introduced then
    begin
      {$if declared(FC_OCSP_request_add0_id)}
      OCSP_request_add0_id := FC_OCSP_request_add0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_add0_id_removed)}
    if OCSP_request_add0_id_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_add0_id)}
      OCSP_request_add0_id := _OCSP_request_add0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_add0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_add0_id');
    {$ifend}
  end;
  
  OCSP_request_add1_nonce := LoadLibFunction(ADllHandle, OCSP_request_add1_nonce_procname);
  FuncLoadError := not assigned(OCSP_request_add1_nonce);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_add1_nonce_allownil)}
    OCSP_request_add1_nonce := ERR_OCSP_request_add1_nonce;
    {$ifend}
    {$if declared(OCSP_request_add1_nonce_introduced)}
    if LibVersion < OCSP_request_add1_nonce_introduced then
    begin
      {$if declared(FC_OCSP_request_add1_nonce)}
      OCSP_request_add1_nonce := FC_OCSP_request_add1_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_add1_nonce_removed)}
    if OCSP_request_add1_nonce_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_add1_nonce)}
      OCSP_request_add1_nonce := _OCSP_request_add1_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_add1_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_add1_nonce');
    {$ifend}
  end;
  
  OCSP_basic_add1_nonce := LoadLibFunction(ADllHandle, OCSP_basic_add1_nonce_procname);
  FuncLoadError := not assigned(OCSP_basic_add1_nonce);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_basic_add1_nonce_allownil)}
    OCSP_basic_add1_nonce := ERR_OCSP_basic_add1_nonce;
    {$ifend}
    {$if declared(OCSP_basic_add1_nonce_introduced)}
    if LibVersion < OCSP_basic_add1_nonce_introduced then
    begin
      {$if declared(FC_OCSP_basic_add1_nonce)}
      OCSP_basic_add1_nonce := FC_OCSP_basic_add1_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_basic_add1_nonce_removed)}
    if OCSP_basic_add1_nonce_removed <= LibVersion then
    begin
      {$if declared(_OCSP_basic_add1_nonce)}
      OCSP_basic_add1_nonce := _OCSP_basic_add1_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_basic_add1_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_basic_add1_nonce');
    {$ifend}
  end;
  
  OCSP_check_nonce := LoadLibFunction(ADllHandle, OCSP_check_nonce_procname);
  FuncLoadError := not assigned(OCSP_check_nonce);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_check_nonce_allownil)}
    OCSP_check_nonce := ERR_OCSP_check_nonce;
    {$ifend}
    {$if declared(OCSP_check_nonce_introduced)}
    if LibVersion < OCSP_check_nonce_introduced then
    begin
      {$if declared(FC_OCSP_check_nonce)}
      OCSP_check_nonce := FC_OCSP_check_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_check_nonce_removed)}
    if OCSP_check_nonce_removed <= LibVersion then
    begin
      {$if declared(_OCSP_check_nonce)}
      OCSP_check_nonce := _OCSP_check_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_check_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_check_nonce');
    {$ifend}
  end;
  
  OCSP_copy_nonce := LoadLibFunction(ADllHandle, OCSP_copy_nonce_procname);
  FuncLoadError := not assigned(OCSP_copy_nonce);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_copy_nonce_allownil)}
    OCSP_copy_nonce := ERR_OCSP_copy_nonce;
    {$ifend}
    {$if declared(OCSP_copy_nonce_introduced)}
    if LibVersion < OCSP_copy_nonce_introduced then
    begin
      {$if declared(FC_OCSP_copy_nonce)}
      OCSP_copy_nonce := FC_OCSP_copy_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_copy_nonce_removed)}
    if OCSP_copy_nonce_removed <= LibVersion then
    begin
      {$if declared(_OCSP_copy_nonce)}
      OCSP_copy_nonce := _OCSP_copy_nonce;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_copy_nonce_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_copy_nonce');
    {$ifend}
  end;
  
  OCSP_request_set1_name := LoadLibFunction(ADllHandle, OCSP_request_set1_name_procname);
  FuncLoadError := not assigned(OCSP_request_set1_name);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_set1_name_allownil)}
    OCSP_request_set1_name := ERR_OCSP_request_set1_name;
    {$ifend}
    {$if declared(OCSP_request_set1_name_introduced)}
    if LibVersion < OCSP_request_set1_name_introduced then
    begin
      {$if declared(FC_OCSP_request_set1_name)}
      OCSP_request_set1_name := FC_OCSP_request_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_set1_name_removed)}
    if OCSP_request_set1_name_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_set1_name)}
      OCSP_request_set1_name := _OCSP_request_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_set1_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_set1_name');
    {$ifend}
  end;
  
  OCSP_request_add1_cert := LoadLibFunction(ADllHandle, OCSP_request_add1_cert_procname);
  FuncLoadError := not assigned(OCSP_request_add1_cert);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_add1_cert_allownil)}
    OCSP_request_add1_cert := ERR_OCSP_request_add1_cert;
    {$ifend}
    {$if declared(OCSP_request_add1_cert_introduced)}
    if LibVersion < OCSP_request_add1_cert_introduced then
    begin
      {$if declared(FC_OCSP_request_add1_cert)}
      OCSP_request_add1_cert := FC_OCSP_request_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_add1_cert_removed)}
    if OCSP_request_add1_cert_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_add1_cert)}
      OCSP_request_add1_cert := _OCSP_request_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_add1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_add1_cert');
    {$ifend}
  end;
  
  OCSP_request_sign := LoadLibFunction(ADllHandle, OCSP_request_sign_procname);
  FuncLoadError := not assigned(OCSP_request_sign);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_sign_allownil)}
    OCSP_request_sign := ERR_OCSP_request_sign;
    {$ifend}
    {$if declared(OCSP_request_sign_introduced)}
    if LibVersion < OCSP_request_sign_introduced then
    begin
      {$if declared(FC_OCSP_request_sign)}
      OCSP_request_sign := FC_OCSP_request_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_sign_removed)}
    if OCSP_request_sign_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_sign)}
      OCSP_request_sign := _OCSP_request_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_sign');
    {$ifend}
  end;
  
  OCSP_response_status := LoadLibFunction(ADllHandle, OCSP_response_status_procname);
  FuncLoadError := not assigned(OCSP_response_status);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_response_status_allownil)}
    OCSP_response_status := ERR_OCSP_response_status;
    {$ifend}
    {$if declared(OCSP_response_status_introduced)}
    if LibVersion < OCSP_response_status_introduced then
    begin
      {$if declared(FC_OCSP_response_status)}
      OCSP_response_status := FC_OCSP_response_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_response_status_removed)}
    if OCSP_response_status_removed <= LibVersion then
    begin
      {$if declared(_OCSP_response_status)}
      OCSP_response_status := _OCSP_response_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_response_status_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_response_status');
    {$ifend}
  end;
  
  OCSP_response_get1_basic := LoadLibFunction(ADllHandle, OCSP_response_get1_basic_procname);
  FuncLoadError := not assigned(OCSP_response_get1_basic);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_response_get1_basic_allownil)}
    OCSP_response_get1_basic := ERR_OCSP_response_get1_basic;
    {$ifend}
    {$if declared(OCSP_response_get1_basic_introduced)}
    if LibVersion < OCSP_response_get1_basic_introduced then
    begin
      {$if declared(FC_OCSP_response_get1_basic)}
      OCSP_response_get1_basic := FC_OCSP_response_get1_basic;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_response_get1_basic_removed)}
    if OCSP_response_get1_basic_removed <= LibVersion then
    begin
      {$if declared(_OCSP_response_get1_basic)}
      OCSP_response_get1_basic := _OCSP_response_get1_basic;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_response_get1_basic_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_response_get1_basic');
    {$ifend}
  end;
  
  OCSP_resp_get0_signature := LoadLibFunction(ADllHandle, OCSP_resp_get0_signature_procname);
  FuncLoadError := not assigned(OCSP_resp_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_signature_allownil)}
    OCSP_resp_get0_signature := ERR_OCSP_resp_get0_signature;
    {$ifend}
    {$if declared(OCSP_resp_get0_signature_introduced)}
    if LibVersion < OCSP_resp_get0_signature_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0_signature)}
      OCSP_resp_get0_signature := FC_OCSP_resp_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_signature_removed)}
    if OCSP_resp_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0_signature)}
      OCSP_resp_get0_signature := _OCSP_resp_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0_signature');
    {$ifend}
  end;
  
  OCSP_resp_get0_tbs_sigalg := LoadLibFunction(ADllHandle, OCSP_resp_get0_tbs_sigalg_procname);
  FuncLoadError := not assigned(OCSP_resp_get0_tbs_sigalg);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_tbs_sigalg_allownil)}
    OCSP_resp_get0_tbs_sigalg := ERR_OCSP_resp_get0_tbs_sigalg;
    {$ifend}
    {$if declared(OCSP_resp_get0_tbs_sigalg_introduced)}
    if LibVersion < OCSP_resp_get0_tbs_sigalg_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0_tbs_sigalg)}
      OCSP_resp_get0_tbs_sigalg := FC_OCSP_resp_get0_tbs_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_tbs_sigalg_removed)}
    if OCSP_resp_get0_tbs_sigalg_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0_tbs_sigalg)}
      OCSP_resp_get0_tbs_sigalg := _OCSP_resp_get0_tbs_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_tbs_sigalg_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0_tbs_sigalg');
    {$ifend}
  end;
  
  OCSP_resp_get0_respdata := LoadLibFunction(ADllHandle, OCSP_resp_get0_respdata_procname);
  FuncLoadError := not assigned(OCSP_resp_get0_respdata);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_respdata_allownil)}
    OCSP_resp_get0_respdata := ERR_OCSP_resp_get0_respdata;
    {$ifend}
    {$if declared(OCSP_resp_get0_respdata_introduced)}
    if LibVersion < OCSP_resp_get0_respdata_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0_respdata)}
      OCSP_resp_get0_respdata := FC_OCSP_resp_get0_respdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_respdata_removed)}
    if OCSP_resp_get0_respdata_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0_respdata)}
      OCSP_resp_get0_respdata := _OCSP_resp_get0_respdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_respdata_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0_respdata');
    {$ifend}
  end;
  
  OCSP_resp_get0_signer := LoadLibFunction(ADllHandle, OCSP_resp_get0_signer_procname);
  FuncLoadError := not assigned(OCSP_resp_get0_signer);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_signer_allownil)}
    OCSP_resp_get0_signer := ERR_OCSP_resp_get0_signer;
    {$ifend}
    {$if declared(OCSP_resp_get0_signer_introduced)}
    if LibVersion < OCSP_resp_get0_signer_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0_signer)}
      OCSP_resp_get0_signer := FC_OCSP_resp_get0_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_signer_removed)}
    if OCSP_resp_get0_signer_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0_signer)}
      OCSP_resp_get0_signer := _OCSP_resp_get0_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_signer_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0_signer');
    {$ifend}
  end;
  
  OCSP_resp_count := LoadLibFunction(ADllHandle, OCSP_resp_count_procname);
  FuncLoadError := not assigned(OCSP_resp_count);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_count_allownil)}
    OCSP_resp_count := ERR_OCSP_resp_count;
    {$ifend}
    {$if declared(OCSP_resp_count_introduced)}
    if LibVersion < OCSP_resp_count_introduced then
    begin
      {$if declared(FC_OCSP_resp_count)}
      OCSP_resp_count := FC_OCSP_resp_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_count_removed)}
    if OCSP_resp_count_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_count)}
      OCSP_resp_count := _OCSP_resp_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_count_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_count');
    {$ifend}
  end;
  
  OCSP_resp_get0 := LoadLibFunction(ADllHandle, OCSP_resp_get0_procname);
  FuncLoadError := not assigned(OCSP_resp_get0);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_allownil)}
    OCSP_resp_get0 := ERR_OCSP_resp_get0;
    {$ifend}
    {$if declared(OCSP_resp_get0_introduced)}
    if LibVersion < OCSP_resp_get0_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0)}
      OCSP_resp_get0 := FC_OCSP_resp_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_removed)}
    if OCSP_resp_get0_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0)}
      OCSP_resp_get0 := _OCSP_resp_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0');
    {$ifend}
  end;
  
  OCSP_resp_get0_produced_at := LoadLibFunction(ADllHandle, OCSP_resp_get0_produced_at_procname);
  FuncLoadError := not assigned(OCSP_resp_get0_produced_at);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_produced_at_allownil)}
    OCSP_resp_get0_produced_at := ERR_OCSP_resp_get0_produced_at;
    {$ifend}
    {$if declared(OCSP_resp_get0_produced_at_introduced)}
    if LibVersion < OCSP_resp_get0_produced_at_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0_produced_at)}
      OCSP_resp_get0_produced_at := FC_OCSP_resp_get0_produced_at;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_produced_at_removed)}
    if OCSP_resp_get0_produced_at_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0_produced_at)}
      OCSP_resp_get0_produced_at := _OCSP_resp_get0_produced_at;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_produced_at_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0_produced_at');
    {$ifend}
  end;
  
  OCSP_resp_get0_certs := LoadLibFunction(ADllHandle, OCSP_resp_get0_certs_procname);
  FuncLoadError := not assigned(OCSP_resp_get0_certs);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_certs_allownil)}
    OCSP_resp_get0_certs := ERR_OCSP_resp_get0_certs;
    {$ifend}
    {$if declared(OCSP_resp_get0_certs_introduced)}
    if LibVersion < OCSP_resp_get0_certs_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0_certs)}
      OCSP_resp_get0_certs := FC_OCSP_resp_get0_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_certs_removed)}
    if OCSP_resp_get0_certs_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0_certs)}
      OCSP_resp_get0_certs := _OCSP_resp_get0_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0_certs');
    {$ifend}
  end;
  
  OCSP_resp_get0_id := LoadLibFunction(ADllHandle, OCSP_resp_get0_id_procname);
  FuncLoadError := not assigned(OCSP_resp_get0_id);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get0_id_allownil)}
    OCSP_resp_get0_id := ERR_OCSP_resp_get0_id;
    {$ifend}
    {$if declared(OCSP_resp_get0_id_introduced)}
    if LibVersion < OCSP_resp_get0_id_introduced then
    begin
      {$if declared(FC_OCSP_resp_get0_id)}
      OCSP_resp_get0_id := FC_OCSP_resp_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get0_id_removed)}
    if OCSP_resp_get0_id_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get0_id)}
      OCSP_resp_get0_id := _OCSP_resp_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get0_id');
    {$ifend}
  end;
  
  OCSP_resp_get1_id := LoadLibFunction(ADllHandle, OCSP_resp_get1_id_procname);
  FuncLoadError := not assigned(OCSP_resp_get1_id);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_get1_id_allownil)}
    OCSP_resp_get1_id := ERR_OCSP_resp_get1_id;
    {$ifend}
    {$if declared(OCSP_resp_get1_id_introduced)}
    if LibVersion < OCSP_resp_get1_id_introduced then
    begin
      {$if declared(FC_OCSP_resp_get1_id)}
      OCSP_resp_get1_id := FC_OCSP_resp_get1_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_get1_id_removed)}
    if OCSP_resp_get1_id_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_get1_id)}
      OCSP_resp_get1_id := _OCSP_resp_get1_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_get1_id_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_get1_id');
    {$ifend}
  end;
  
  OCSP_resp_find := LoadLibFunction(ADllHandle, OCSP_resp_find_procname);
  FuncLoadError := not assigned(OCSP_resp_find);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_find_allownil)}
    OCSP_resp_find := ERR_OCSP_resp_find;
    {$ifend}
    {$if declared(OCSP_resp_find_introduced)}
    if LibVersion < OCSP_resp_find_introduced then
    begin
      {$if declared(FC_OCSP_resp_find)}
      OCSP_resp_find := FC_OCSP_resp_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_find_removed)}
    if OCSP_resp_find_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_find)}
      OCSP_resp_find := _OCSP_resp_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_find_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_find');
    {$ifend}
  end;
  
  OCSP_single_get0_status := LoadLibFunction(ADllHandle, OCSP_single_get0_status_procname);
  FuncLoadError := not assigned(OCSP_single_get0_status);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_single_get0_status_allownil)}
    OCSP_single_get0_status := ERR_OCSP_single_get0_status;
    {$ifend}
    {$if declared(OCSP_single_get0_status_introduced)}
    if LibVersion < OCSP_single_get0_status_introduced then
    begin
      {$if declared(FC_OCSP_single_get0_status)}
      OCSP_single_get0_status := FC_OCSP_single_get0_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_single_get0_status_removed)}
    if OCSP_single_get0_status_removed <= LibVersion then
    begin
      {$if declared(_OCSP_single_get0_status)}
      OCSP_single_get0_status := _OCSP_single_get0_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_single_get0_status_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_single_get0_status');
    {$ifend}
  end;
  
  OCSP_resp_find_status := LoadLibFunction(ADllHandle, OCSP_resp_find_status_procname);
  FuncLoadError := not assigned(OCSP_resp_find_status);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_resp_find_status_allownil)}
    OCSP_resp_find_status := ERR_OCSP_resp_find_status;
    {$ifend}
    {$if declared(OCSP_resp_find_status_introduced)}
    if LibVersion < OCSP_resp_find_status_introduced then
    begin
      {$if declared(FC_OCSP_resp_find_status)}
      OCSP_resp_find_status := FC_OCSP_resp_find_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_resp_find_status_removed)}
    if OCSP_resp_find_status_removed <= LibVersion then
    begin
      {$if declared(_OCSP_resp_find_status)}
      OCSP_resp_find_status := _OCSP_resp_find_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_resp_find_status_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_resp_find_status');
    {$ifend}
  end;
  
  OCSP_check_validity := LoadLibFunction(ADllHandle, OCSP_check_validity_procname);
  FuncLoadError := not assigned(OCSP_check_validity);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_check_validity_allownil)}
    OCSP_check_validity := ERR_OCSP_check_validity;
    {$ifend}
    {$if declared(OCSP_check_validity_introduced)}
    if LibVersion < OCSP_check_validity_introduced then
    begin
      {$if declared(FC_OCSP_check_validity)}
      OCSP_check_validity := FC_OCSP_check_validity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_check_validity_removed)}
    if OCSP_check_validity_removed <= LibVersion then
    begin
      {$if declared(_OCSP_check_validity)}
      OCSP_check_validity := _OCSP_check_validity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_check_validity_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_check_validity');
    {$ifend}
  end;
  
  OCSP_request_verify := LoadLibFunction(ADllHandle, OCSP_request_verify_procname);
  FuncLoadError := not assigned(OCSP_request_verify);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_verify_allownil)}
    OCSP_request_verify := ERR_OCSP_request_verify;
    {$ifend}
    {$if declared(OCSP_request_verify_introduced)}
    if LibVersion < OCSP_request_verify_introduced then
    begin
      {$if declared(FC_OCSP_request_verify)}
      OCSP_request_verify := FC_OCSP_request_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_verify_removed)}
    if OCSP_request_verify_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_verify)}
      OCSP_request_verify := _OCSP_request_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_verify');
    {$ifend}
  end;
  
  OCSP_id_issuer_cmp := LoadLibFunction(ADllHandle, OCSP_id_issuer_cmp_procname);
  FuncLoadError := not assigned(OCSP_id_issuer_cmp);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_id_issuer_cmp_allownil)}
    OCSP_id_issuer_cmp := ERR_OCSP_id_issuer_cmp;
    {$ifend}
    {$if declared(OCSP_id_issuer_cmp_introduced)}
    if LibVersion < OCSP_id_issuer_cmp_introduced then
    begin
      {$if declared(FC_OCSP_id_issuer_cmp)}
      OCSP_id_issuer_cmp := FC_OCSP_id_issuer_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_id_issuer_cmp_removed)}
    if OCSP_id_issuer_cmp_removed <= LibVersion then
    begin
      {$if declared(_OCSP_id_issuer_cmp)}
      OCSP_id_issuer_cmp := _OCSP_id_issuer_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_id_issuer_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_id_issuer_cmp');
    {$ifend}
  end;
  
  OCSP_id_cmp := LoadLibFunction(ADllHandle, OCSP_id_cmp_procname);
  FuncLoadError := not assigned(OCSP_id_cmp);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_id_cmp_allownil)}
    OCSP_id_cmp := ERR_OCSP_id_cmp;
    {$ifend}
    {$if declared(OCSP_id_cmp_introduced)}
    if LibVersion < OCSP_id_cmp_introduced then
    begin
      {$if declared(FC_OCSP_id_cmp)}
      OCSP_id_cmp := FC_OCSP_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_id_cmp_removed)}
    if OCSP_id_cmp_removed <= LibVersion then
    begin
      {$if declared(_OCSP_id_cmp)}
      OCSP_id_cmp := _OCSP_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_id_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_id_cmp');
    {$ifend}
  end;
  
  OCSP_request_onereq_count := LoadLibFunction(ADllHandle, OCSP_request_onereq_count_procname);
  FuncLoadError := not assigned(OCSP_request_onereq_count);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_onereq_count_allownil)}
    OCSP_request_onereq_count := ERR_OCSP_request_onereq_count;
    {$ifend}
    {$if declared(OCSP_request_onereq_count_introduced)}
    if LibVersion < OCSP_request_onereq_count_introduced then
    begin
      {$if declared(FC_OCSP_request_onereq_count)}
      OCSP_request_onereq_count := FC_OCSP_request_onereq_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_onereq_count_removed)}
    if OCSP_request_onereq_count_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_onereq_count)}
      OCSP_request_onereq_count := _OCSP_request_onereq_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_onereq_count_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_onereq_count');
    {$ifend}
  end;
  
  OCSP_request_onereq_get0 := LoadLibFunction(ADllHandle, OCSP_request_onereq_get0_procname);
  FuncLoadError := not assigned(OCSP_request_onereq_get0);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_onereq_get0_allownil)}
    OCSP_request_onereq_get0 := ERR_OCSP_request_onereq_get0;
    {$ifend}
    {$if declared(OCSP_request_onereq_get0_introduced)}
    if LibVersion < OCSP_request_onereq_get0_introduced then
    begin
      {$if declared(FC_OCSP_request_onereq_get0)}
      OCSP_request_onereq_get0 := FC_OCSP_request_onereq_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_onereq_get0_removed)}
    if OCSP_request_onereq_get0_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_onereq_get0)}
      OCSP_request_onereq_get0 := _OCSP_request_onereq_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_onereq_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_onereq_get0');
    {$ifend}
  end;
  
  OCSP_onereq_get0_id := LoadLibFunction(ADllHandle, OCSP_onereq_get0_id_procname);
  FuncLoadError := not assigned(OCSP_onereq_get0_id);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_onereq_get0_id_allownil)}
    OCSP_onereq_get0_id := ERR_OCSP_onereq_get0_id;
    {$ifend}
    {$if declared(OCSP_onereq_get0_id_introduced)}
    if LibVersion < OCSP_onereq_get0_id_introduced then
    begin
      {$if declared(FC_OCSP_onereq_get0_id)}
      OCSP_onereq_get0_id := FC_OCSP_onereq_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_onereq_get0_id_removed)}
    if OCSP_onereq_get0_id_removed <= LibVersion then
    begin
      {$if declared(_OCSP_onereq_get0_id)}
      OCSP_onereq_get0_id := _OCSP_onereq_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_onereq_get0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_onereq_get0_id');
    {$ifend}
  end;
  
  OCSP_id_get0_info := LoadLibFunction(ADllHandle, OCSP_id_get0_info_procname);
  FuncLoadError := not assigned(OCSP_id_get0_info);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_id_get0_info_allownil)}
    OCSP_id_get0_info := ERR_OCSP_id_get0_info;
    {$ifend}
    {$if declared(OCSP_id_get0_info_introduced)}
    if LibVersion < OCSP_id_get0_info_introduced then
    begin
      {$if declared(FC_OCSP_id_get0_info)}
      OCSP_id_get0_info := FC_OCSP_id_get0_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_id_get0_info_removed)}
    if OCSP_id_get0_info_removed <= LibVersion then
    begin
      {$if declared(_OCSP_id_get0_info)}
      OCSP_id_get0_info := _OCSP_id_get0_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_id_get0_info_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_id_get0_info');
    {$ifend}
  end;
  
  OCSP_request_is_signed := LoadLibFunction(ADllHandle, OCSP_request_is_signed_procname);
  FuncLoadError := not assigned(OCSP_request_is_signed);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_request_is_signed_allownil)}
    OCSP_request_is_signed := ERR_OCSP_request_is_signed;
    {$ifend}
    {$if declared(OCSP_request_is_signed_introduced)}
    if LibVersion < OCSP_request_is_signed_introduced then
    begin
      {$if declared(FC_OCSP_request_is_signed)}
      OCSP_request_is_signed := FC_OCSP_request_is_signed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_request_is_signed_removed)}
    if OCSP_request_is_signed_removed <= LibVersion then
    begin
      {$if declared(_OCSP_request_is_signed)}
      OCSP_request_is_signed := _OCSP_request_is_signed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_request_is_signed_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_request_is_signed');
    {$ifend}
  end;
  
  OCSP_response_create := LoadLibFunction(ADllHandle, OCSP_response_create_procname);
  FuncLoadError := not assigned(OCSP_response_create);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_response_create_allownil)}
    OCSP_response_create := ERR_OCSP_response_create;
    {$ifend}
    {$if declared(OCSP_response_create_introduced)}
    if LibVersion < OCSP_response_create_introduced then
    begin
      {$if declared(FC_OCSP_response_create)}
      OCSP_response_create := FC_OCSP_response_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_response_create_removed)}
    if OCSP_response_create_removed <= LibVersion then
    begin
      {$if declared(_OCSP_response_create)}
      OCSP_response_create := _OCSP_response_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_response_create_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_response_create');
    {$ifend}
  end;
  
  OCSP_basic_add1_status := LoadLibFunction(ADllHandle, OCSP_basic_add1_status_procname);
  FuncLoadError := not assigned(OCSP_basic_add1_status);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_basic_add1_status_allownil)}
    OCSP_basic_add1_status := ERR_OCSP_basic_add1_status;
    {$ifend}
    {$if declared(OCSP_basic_add1_status_introduced)}
    if LibVersion < OCSP_basic_add1_status_introduced then
    begin
      {$if declared(FC_OCSP_basic_add1_status)}
      OCSP_basic_add1_status := FC_OCSP_basic_add1_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_basic_add1_status_removed)}
    if OCSP_basic_add1_status_removed <= LibVersion then
    begin
      {$if declared(_OCSP_basic_add1_status)}
      OCSP_basic_add1_status := _OCSP_basic_add1_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_basic_add1_status_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_basic_add1_status');
    {$ifend}
  end;
  
  OCSP_basic_add1_cert := LoadLibFunction(ADllHandle, OCSP_basic_add1_cert_procname);
  FuncLoadError := not assigned(OCSP_basic_add1_cert);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_basic_add1_cert_allownil)}
    OCSP_basic_add1_cert := ERR_OCSP_basic_add1_cert;
    {$ifend}
    {$if declared(OCSP_basic_add1_cert_introduced)}
    if LibVersion < OCSP_basic_add1_cert_introduced then
    begin
      {$if declared(FC_OCSP_basic_add1_cert)}
      OCSP_basic_add1_cert := FC_OCSP_basic_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_basic_add1_cert_removed)}
    if OCSP_basic_add1_cert_removed <= LibVersion then
    begin
      {$if declared(_OCSP_basic_add1_cert)}
      OCSP_basic_add1_cert := _OCSP_basic_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_basic_add1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_basic_add1_cert');
    {$ifend}
  end;
  
  OCSP_basic_sign := LoadLibFunction(ADllHandle, OCSP_basic_sign_procname);
  FuncLoadError := not assigned(OCSP_basic_sign);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_basic_sign_allownil)}
    OCSP_basic_sign := ERR_OCSP_basic_sign;
    {$ifend}
    {$if declared(OCSP_basic_sign_introduced)}
    if LibVersion < OCSP_basic_sign_introduced then
    begin
      {$if declared(FC_OCSP_basic_sign)}
      OCSP_basic_sign := FC_OCSP_basic_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_basic_sign_removed)}
    if OCSP_basic_sign_removed <= LibVersion then
    begin
      {$if declared(_OCSP_basic_sign)}
      OCSP_basic_sign := _OCSP_basic_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_basic_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_basic_sign');
    {$ifend}
  end;
  
  OCSP_basic_sign_ctx := LoadLibFunction(ADllHandle, OCSP_basic_sign_ctx_procname);
  FuncLoadError := not assigned(OCSP_basic_sign_ctx);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_basic_sign_ctx_allownil)}
    OCSP_basic_sign_ctx := ERR_OCSP_basic_sign_ctx;
    {$ifend}
    {$if declared(OCSP_basic_sign_ctx_introduced)}
    if LibVersion < OCSP_basic_sign_ctx_introduced then
    begin
      {$if declared(FC_OCSP_basic_sign_ctx)}
      OCSP_basic_sign_ctx := FC_OCSP_basic_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_basic_sign_ctx_removed)}
    if OCSP_basic_sign_ctx_removed <= LibVersion then
    begin
      {$if declared(_OCSP_basic_sign_ctx)}
      OCSP_basic_sign_ctx := _OCSP_basic_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_basic_sign_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_basic_sign_ctx');
    {$ifend}
  end;
  
  OCSP_RESPID_set_by_name := LoadLibFunction(ADllHandle, OCSP_RESPID_set_by_name_procname);
  FuncLoadError := not assigned(OCSP_RESPID_set_by_name);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_set_by_name_allownil)}
    OCSP_RESPID_set_by_name := ERR_OCSP_RESPID_set_by_name;
    {$ifend}
    {$if declared(OCSP_RESPID_set_by_name_introduced)}
    if LibVersion < OCSP_RESPID_set_by_name_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_set_by_name)}
      OCSP_RESPID_set_by_name := FC_OCSP_RESPID_set_by_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_set_by_name_removed)}
    if OCSP_RESPID_set_by_name_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_set_by_name)}
      OCSP_RESPID_set_by_name := _OCSP_RESPID_set_by_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_set_by_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_set_by_name');
    {$ifend}
  end;
  
  OCSP_RESPID_set_by_key_ex := LoadLibFunction(ADllHandle, OCSP_RESPID_set_by_key_ex_procname);
  FuncLoadError := not assigned(OCSP_RESPID_set_by_key_ex);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_set_by_key_ex_allownil)}
    OCSP_RESPID_set_by_key_ex := ERR_OCSP_RESPID_set_by_key_ex;
    {$ifend}
    {$if declared(OCSP_RESPID_set_by_key_ex_introduced)}
    if LibVersion < OCSP_RESPID_set_by_key_ex_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_set_by_key_ex)}
      OCSP_RESPID_set_by_key_ex := FC_OCSP_RESPID_set_by_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_set_by_key_ex_removed)}
    if OCSP_RESPID_set_by_key_ex_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_set_by_key_ex)}
      OCSP_RESPID_set_by_key_ex := _OCSP_RESPID_set_by_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_set_by_key_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_set_by_key_ex');
    {$ifend}
  end;
  
  OCSP_RESPID_set_by_key := LoadLibFunction(ADllHandle, OCSP_RESPID_set_by_key_procname);
  FuncLoadError := not assigned(OCSP_RESPID_set_by_key);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_set_by_key_allownil)}
    OCSP_RESPID_set_by_key := ERR_OCSP_RESPID_set_by_key;
    {$ifend}
    {$if declared(OCSP_RESPID_set_by_key_introduced)}
    if LibVersion < OCSP_RESPID_set_by_key_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_set_by_key)}
      OCSP_RESPID_set_by_key := FC_OCSP_RESPID_set_by_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_set_by_key_removed)}
    if OCSP_RESPID_set_by_key_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_set_by_key)}
      OCSP_RESPID_set_by_key := _OCSP_RESPID_set_by_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_set_by_key_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_set_by_key');
    {$ifend}
  end;
  
  OCSP_RESPID_match_ex := LoadLibFunction(ADllHandle, OCSP_RESPID_match_ex_procname);
  FuncLoadError := not assigned(OCSP_RESPID_match_ex);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_match_ex_allownil)}
    OCSP_RESPID_match_ex := ERR_OCSP_RESPID_match_ex;
    {$ifend}
    {$if declared(OCSP_RESPID_match_ex_introduced)}
    if LibVersion < OCSP_RESPID_match_ex_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_match_ex)}
      OCSP_RESPID_match_ex := FC_OCSP_RESPID_match_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_match_ex_removed)}
    if OCSP_RESPID_match_ex_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_match_ex)}
      OCSP_RESPID_match_ex := _OCSP_RESPID_match_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_match_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_match_ex');
    {$ifend}
  end;
  
  OCSP_RESPID_match := LoadLibFunction(ADllHandle, OCSP_RESPID_match_procname);
  FuncLoadError := not assigned(OCSP_RESPID_match);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_match_allownil)}
    OCSP_RESPID_match := ERR_OCSP_RESPID_match;
    {$ifend}
    {$if declared(OCSP_RESPID_match_introduced)}
    if LibVersion < OCSP_RESPID_match_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_match)}
      OCSP_RESPID_match := FC_OCSP_RESPID_match;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_match_removed)}
    if OCSP_RESPID_match_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_match)}
      OCSP_RESPID_match := _OCSP_RESPID_match;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_match_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_match');
    {$ifend}
  end;
  
  OCSP_crlID_new := LoadLibFunction(ADllHandle, OCSP_crlID_new_procname);
  FuncLoadError := not assigned(OCSP_crlID_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_crlID_new_allownil)}
    OCSP_crlID_new := ERR_OCSP_crlID_new;
    {$ifend}
    {$if declared(OCSP_crlID_new_introduced)}
    if LibVersion < OCSP_crlID_new_introduced then
    begin
      {$if declared(FC_OCSP_crlID_new)}
      OCSP_crlID_new := FC_OCSP_crlID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_crlID_new_removed)}
    if OCSP_crlID_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_crlID_new)}
      OCSP_crlID_new := _OCSP_crlID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_crlID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_crlID_new');
    {$ifend}
  end;
  
  OCSP_accept_responses_new := LoadLibFunction(ADllHandle, OCSP_accept_responses_new_procname);
  FuncLoadError := not assigned(OCSP_accept_responses_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_accept_responses_new_allownil)}
    OCSP_accept_responses_new := ERR_OCSP_accept_responses_new;
    {$ifend}
    {$if declared(OCSP_accept_responses_new_introduced)}
    if LibVersion < OCSP_accept_responses_new_introduced then
    begin
      {$if declared(FC_OCSP_accept_responses_new)}
      OCSP_accept_responses_new := FC_OCSP_accept_responses_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_accept_responses_new_removed)}
    if OCSP_accept_responses_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_accept_responses_new)}
      OCSP_accept_responses_new := _OCSP_accept_responses_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_accept_responses_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_accept_responses_new');
    {$ifend}
  end;
  
  OCSP_archive_cutoff_new := LoadLibFunction(ADllHandle, OCSP_archive_cutoff_new_procname);
  FuncLoadError := not assigned(OCSP_archive_cutoff_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_archive_cutoff_new_allownil)}
    OCSP_archive_cutoff_new := ERR_OCSP_archive_cutoff_new;
    {$ifend}
    {$if declared(OCSP_archive_cutoff_new_introduced)}
    if LibVersion < OCSP_archive_cutoff_new_introduced then
    begin
      {$if declared(FC_OCSP_archive_cutoff_new)}
      OCSP_archive_cutoff_new := FC_OCSP_archive_cutoff_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_archive_cutoff_new_removed)}
    if OCSP_archive_cutoff_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_archive_cutoff_new)}
      OCSP_archive_cutoff_new := _OCSP_archive_cutoff_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_archive_cutoff_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_archive_cutoff_new');
    {$ifend}
  end;
  
  OCSP_url_svcloc_new := LoadLibFunction(ADllHandle, OCSP_url_svcloc_new_procname);
  FuncLoadError := not assigned(OCSP_url_svcloc_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_url_svcloc_new_allownil)}
    OCSP_url_svcloc_new := ERR_OCSP_url_svcloc_new;
    {$ifend}
    {$if declared(OCSP_url_svcloc_new_introduced)}
    if LibVersion < OCSP_url_svcloc_new_introduced then
    begin
      {$if declared(FC_OCSP_url_svcloc_new)}
      OCSP_url_svcloc_new := FC_OCSP_url_svcloc_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_url_svcloc_new_removed)}
    if OCSP_url_svcloc_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_url_svcloc_new)}
      OCSP_url_svcloc_new := _OCSP_url_svcloc_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_url_svcloc_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_url_svcloc_new');
    {$ifend}
  end;
  
  OCSP_REQUEST_get_ext_count := LoadLibFunction(ADllHandle, OCSP_REQUEST_get_ext_count_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_get_ext_count_allownil)}
    OCSP_REQUEST_get_ext_count := ERR_OCSP_REQUEST_get_ext_count;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_count_introduced)}
    if LibVersion < OCSP_REQUEST_get_ext_count_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_get_ext_count)}
      OCSP_REQUEST_get_ext_count := FC_OCSP_REQUEST_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_count_removed)}
    if OCSP_REQUEST_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_get_ext_count)}
      OCSP_REQUEST_get_ext_count := _OCSP_REQUEST_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_get_ext_count');
    {$ifend}
  end;
  
  OCSP_REQUEST_get_ext_by_NID := LoadLibFunction(ADllHandle, OCSP_REQUEST_get_ext_by_NID_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_get_ext_by_NID_allownil)}
    OCSP_REQUEST_get_ext_by_NID := ERR_OCSP_REQUEST_get_ext_by_NID;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_by_NID_introduced)}
    if LibVersion < OCSP_REQUEST_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_get_ext_by_NID)}
      OCSP_REQUEST_get_ext_by_NID := FC_OCSP_REQUEST_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_by_NID_removed)}
    if OCSP_REQUEST_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_get_ext_by_NID)}
      OCSP_REQUEST_get_ext_by_NID := _OCSP_REQUEST_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_get_ext_by_NID');
    {$ifend}
  end;
  
  OCSP_REQUEST_get_ext_by_OBJ := LoadLibFunction(ADllHandle, OCSP_REQUEST_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_get_ext_by_OBJ_allownil)}
    OCSP_REQUEST_get_ext_by_OBJ := ERR_OCSP_REQUEST_get_ext_by_OBJ;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_by_OBJ_introduced)}
    if LibVersion < OCSP_REQUEST_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_get_ext_by_OBJ)}
      OCSP_REQUEST_get_ext_by_OBJ := FC_OCSP_REQUEST_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_by_OBJ_removed)}
    if OCSP_REQUEST_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_get_ext_by_OBJ)}
      OCSP_REQUEST_get_ext_by_OBJ := _OCSP_REQUEST_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_get_ext_by_OBJ');
    {$ifend}
  end;
  
  OCSP_REQUEST_get_ext_by_critical := LoadLibFunction(ADllHandle, OCSP_REQUEST_get_ext_by_critical_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_get_ext_by_critical_allownil)}
    OCSP_REQUEST_get_ext_by_critical := ERR_OCSP_REQUEST_get_ext_by_critical;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_by_critical_introduced)}
    if LibVersion < OCSP_REQUEST_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_get_ext_by_critical)}
      OCSP_REQUEST_get_ext_by_critical := FC_OCSP_REQUEST_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_by_critical_removed)}
    if OCSP_REQUEST_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_get_ext_by_critical)}
      OCSP_REQUEST_get_ext_by_critical := _OCSP_REQUEST_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_get_ext_by_critical');
    {$ifend}
  end;
  
  OCSP_REQUEST_get_ext := LoadLibFunction(ADllHandle, OCSP_REQUEST_get_ext_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_get_ext_allownil)}
    OCSP_REQUEST_get_ext := ERR_OCSP_REQUEST_get_ext;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_introduced)}
    if LibVersion < OCSP_REQUEST_get_ext_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_get_ext)}
      OCSP_REQUEST_get_ext := FC_OCSP_REQUEST_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_get_ext_removed)}
    if OCSP_REQUEST_get_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_get_ext)}
      OCSP_REQUEST_get_ext := _OCSP_REQUEST_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_get_ext');
    {$ifend}
  end;
  
  OCSP_REQUEST_delete_ext := LoadLibFunction(ADllHandle, OCSP_REQUEST_delete_ext_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_delete_ext_allownil)}
    OCSP_REQUEST_delete_ext := ERR_OCSP_REQUEST_delete_ext;
    {$ifend}
    {$if declared(OCSP_REQUEST_delete_ext_introduced)}
    if LibVersion < OCSP_REQUEST_delete_ext_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_delete_ext)}
      OCSP_REQUEST_delete_ext := FC_OCSP_REQUEST_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_delete_ext_removed)}
    if OCSP_REQUEST_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_delete_ext)}
      OCSP_REQUEST_delete_ext := _OCSP_REQUEST_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_delete_ext');
    {$ifend}
  end;
  
  OCSP_REQUEST_get1_ext_d2i := LoadLibFunction(ADllHandle, OCSP_REQUEST_get1_ext_d2i_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_get1_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_get1_ext_d2i_allownil)}
    OCSP_REQUEST_get1_ext_d2i := ERR_OCSP_REQUEST_get1_ext_d2i;
    {$ifend}
    {$if declared(OCSP_REQUEST_get1_ext_d2i_introduced)}
    if LibVersion < OCSP_REQUEST_get1_ext_d2i_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_get1_ext_d2i)}
      OCSP_REQUEST_get1_ext_d2i := FC_OCSP_REQUEST_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_get1_ext_d2i_removed)}
    if OCSP_REQUEST_get1_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_get1_ext_d2i)}
      OCSP_REQUEST_get1_ext_d2i := _OCSP_REQUEST_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_get1_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_get1_ext_d2i');
    {$ifend}
  end;
  
  OCSP_REQUEST_add1_ext_i2d := LoadLibFunction(ADllHandle, OCSP_REQUEST_add1_ext_i2d_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_add1_ext_i2d_allownil)}
    OCSP_REQUEST_add1_ext_i2d := ERR_OCSP_REQUEST_add1_ext_i2d;
    {$ifend}
    {$if declared(OCSP_REQUEST_add1_ext_i2d_introduced)}
    if LibVersion < OCSP_REQUEST_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_add1_ext_i2d)}
      OCSP_REQUEST_add1_ext_i2d := FC_OCSP_REQUEST_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_add1_ext_i2d_removed)}
    if OCSP_REQUEST_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_add1_ext_i2d)}
      OCSP_REQUEST_add1_ext_i2d := _OCSP_REQUEST_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_add1_ext_i2d');
    {$ifend}
  end;
  
  OCSP_REQUEST_add_ext := LoadLibFunction(ADllHandle, OCSP_REQUEST_add_ext_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_add_ext_allownil)}
    OCSP_REQUEST_add_ext := ERR_OCSP_REQUEST_add_ext;
    {$ifend}
    {$if declared(OCSP_REQUEST_add_ext_introduced)}
    if LibVersion < OCSP_REQUEST_add_ext_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_add_ext)}
      OCSP_REQUEST_add_ext := FC_OCSP_REQUEST_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_add_ext_removed)}
    if OCSP_REQUEST_add_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_add_ext)}
      OCSP_REQUEST_add_ext := _OCSP_REQUEST_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_add_ext');
    {$ifend}
  end;
  
  OCSP_ONEREQ_get_ext_count := LoadLibFunction(ADllHandle, OCSP_ONEREQ_get_ext_count_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_get_ext_count_allownil)}
    OCSP_ONEREQ_get_ext_count := ERR_OCSP_ONEREQ_get_ext_count;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_count_introduced)}
    if LibVersion < OCSP_ONEREQ_get_ext_count_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_get_ext_count)}
      OCSP_ONEREQ_get_ext_count := FC_OCSP_ONEREQ_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_count_removed)}
    if OCSP_ONEREQ_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_get_ext_count)}
      OCSP_ONEREQ_get_ext_count := _OCSP_ONEREQ_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_get_ext_count');
    {$ifend}
  end;
  
  OCSP_ONEREQ_get_ext_by_NID := LoadLibFunction(ADllHandle, OCSP_ONEREQ_get_ext_by_NID_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_get_ext_by_NID_allownil)}
    OCSP_ONEREQ_get_ext_by_NID := ERR_OCSP_ONEREQ_get_ext_by_NID;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_by_NID_introduced)}
    if LibVersion < OCSP_ONEREQ_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_get_ext_by_NID)}
      OCSP_ONEREQ_get_ext_by_NID := FC_OCSP_ONEREQ_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_by_NID_removed)}
    if OCSP_ONEREQ_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_get_ext_by_NID)}
      OCSP_ONEREQ_get_ext_by_NID := _OCSP_ONEREQ_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_get_ext_by_NID');
    {$ifend}
  end;
  
  OCSP_ONEREQ_get_ext_by_OBJ := LoadLibFunction(ADllHandle, OCSP_ONEREQ_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_get_ext_by_OBJ_allownil)}
    OCSP_ONEREQ_get_ext_by_OBJ := ERR_OCSP_ONEREQ_get_ext_by_OBJ;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_by_OBJ_introduced)}
    if LibVersion < OCSP_ONEREQ_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_get_ext_by_OBJ)}
      OCSP_ONEREQ_get_ext_by_OBJ := FC_OCSP_ONEREQ_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_by_OBJ_removed)}
    if OCSP_ONEREQ_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_get_ext_by_OBJ)}
      OCSP_ONEREQ_get_ext_by_OBJ := _OCSP_ONEREQ_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_get_ext_by_OBJ');
    {$ifend}
  end;
  
  OCSP_ONEREQ_get_ext_by_critical := LoadLibFunction(ADllHandle, OCSP_ONEREQ_get_ext_by_critical_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_get_ext_by_critical_allownil)}
    OCSP_ONEREQ_get_ext_by_critical := ERR_OCSP_ONEREQ_get_ext_by_critical;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_by_critical_introduced)}
    if LibVersion < OCSP_ONEREQ_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_get_ext_by_critical)}
      OCSP_ONEREQ_get_ext_by_critical := FC_OCSP_ONEREQ_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_by_critical_removed)}
    if OCSP_ONEREQ_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_get_ext_by_critical)}
      OCSP_ONEREQ_get_ext_by_critical := _OCSP_ONEREQ_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_get_ext_by_critical');
    {$ifend}
  end;
  
  OCSP_ONEREQ_get_ext := LoadLibFunction(ADllHandle, OCSP_ONEREQ_get_ext_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_get_ext_allownil)}
    OCSP_ONEREQ_get_ext := ERR_OCSP_ONEREQ_get_ext;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_introduced)}
    if LibVersion < OCSP_ONEREQ_get_ext_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_get_ext)}
      OCSP_ONEREQ_get_ext := FC_OCSP_ONEREQ_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get_ext_removed)}
    if OCSP_ONEREQ_get_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_get_ext)}
      OCSP_ONEREQ_get_ext := _OCSP_ONEREQ_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_get_ext');
    {$ifend}
  end;
  
  OCSP_ONEREQ_delete_ext := LoadLibFunction(ADllHandle, OCSP_ONEREQ_delete_ext_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_delete_ext_allownil)}
    OCSP_ONEREQ_delete_ext := ERR_OCSP_ONEREQ_delete_ext;
    {$ifend}
    {$if declared(OCSP_ONEREQ_delete_ext_introduced)}
    if LibVersion < OCSP_ONEREQ_delete_ext_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_delete_ext)}
      OCSP_ONEREQ_delete_ext := FC_OCSP_ONEREQ_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_delete_ext_removed)}
    if OCSP_ONEREQ_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_delete_ext)}
      OCSP_ONEREQ_delete_ext := _OCSP_ONEREQ_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_delete_ext');
    {$ifend}
  end;
  
  OCSP_ONEREQ_get1_ext_d2i := LoadLibFunction(ADllHandle, OCSP_ONEREQ_get1_ext_d2i_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_get1_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_get1_ext_d2i_allownil)}
    OCSP_ONEREQ_get1_ext_d2i := ERR_OCSP_ONEREQ_get1_ext_d2i;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get1_ext_d2i_introduced)}
    if LibVersion < OCSP_ONEREQ_get1_ext_d2i_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_get1_ext_d2i)}
      OCSP_ONEREQ_get1_ext_d2i := FC_OCSP_ONEREQ_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_get1_ext_d2i_removed)}
    if OCSP_ONEREQ_get1_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_get1_ext_d2i)}
      OCSP_ONEREQ_get1_ext_d2i := _OCSP_ONEREQ_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_get1_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_get1_ext_d2i');
    {$ifend}
  end;
  
  OCSP_ONEREQ_add1_ext_i2d := LoadLibFunction(ADllHandle, OCSP_ONEREQ_add1_ext_i2d_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_add1_ext_i2d_allownil)}
    OCSP_ONEREQ_add1_ext_i2d := ERR_OCSP_ONEREQ_add1_ext_i2d;
    {$ifend}
    {$if declared(OCSP_ONEREQ_add1_ext_i2d_introduced)}
    if LibVersion < OCSP_ONEREQ_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_add1_ext_i2d)}
      OCSP_ONEREQ_add1_ext_i2d := FC_OCSP_ONEREQ_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_add1_ext_i2d_removed)}
    if OCSP_ONEREQ_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_add1_ext_i2d)}
      OCSP_ONEREQ_add1_ext_i2d := _OCSP_ONEREQ_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_add1_ext_i2d');
    {$ifend}
  end;
  
  OCSP_ONEREQ_add_ext := LoadLibFunction(ADllHandle, OCSP_ONEREQ_add_ext_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_add_ext_allownil)}
    OCSP_ONEREQ_add_ext := ERR_OCSP_ONEREQ_add_ext;
    {$ifend}
    {$if declared(OCSP_ONEREQ_add_ext_introduced)}
    if LibVersion < OCSP_ONEREQ_add_ext_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_add_ext)}
      OCSP_ONEREQ_add_ext := FC_OCSP_ONEREQ_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_add_ext_removed)}
    if OCSP_ONEREQ_add_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_add_ext)}
      OCSP_ONEREQ_add_ext := _OCSP_ONEREQ_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_add_ext');
    {$ifend}
  end;
  
  OCSP_BASICRESP_get_ext_count := LoadLibFunction(ADllHandle, OCSP_BASICRESP_get_ext_count_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_get_ext_count_allownil)}
    OCSP_BASICRESP_get_ext_count := ERR_OCSP_BASICRESP_get_ext_count;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_count_introduced)}
    if LibVersion < OCSP_BASICRESP_get_ext_count_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_get_ext_count)}
      OCSP_BASICRESP_get_ext_count := FC_OCSP_BASICRESP_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_count_removed)}
    if OCSP_BASICRESP_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_get_ext_count)}
      OCSP_BASICRESP_get_ext_count := _OCSP_BASICRESP_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_get_ext_count');
    {$ifend}
  end;
  
  OCSP_BASICRESP_get_ext_by_NID := LoadLibFunction(ADllHandle, OCSP_BASICRESP_get_ext_by_NID_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_get_ext_by_NID_allownil)}
    OCSP_BASICRESP_get_ext_by_NID := ERR_OCSP_BASICRESP_get_ext_by_NID;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_by_NID_introduced)}
    if LibVersion < OCSP_BASICRESP_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_get_ext_by_NID)}
      OCSP_BASICRESP_get_ext_by_NID := FC_OCSP_BASICRESP_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_by_NID_removed)}
    if OCSP_BASICRESP_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_get_ext_by_NID)}
      OCSP_BASICRESP_get_ext_by_NID := _OCSP_BASICRESP_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_get_ext_by_NID');
    {$ifend}
  end;
  
  OCSP_BASICRESP_get_ext_by_OBJ := LoadLibFunction(ADllHandle, OCSP_BASICRESP_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_get_ext_by_OBJ_allownil)}
    OCSP_BASICRESP_get_ext_by_OBJ := ERR_OCSP_BASICRESP_get_ext_by_OBJ;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_by_OBJ_introduced)}
    if LibVersion < OCSP_BASICRESP_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_get_ext_by_OBJ)}
      OCSP_BASICRESP_get_ext_by_OBJ := FC_OCSP_BASICRESP_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_by_OBJ_removed)}
    if OCSP_BASICRESP_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_get_ext_by_OBJ)}
      OCSP_BASICRESP_get_ext_by_OBJ := _OCSP_BASICRESP_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_get_ext_by_OBJ');
    {$ifend}
  end;
  
  OCSP_BASICRESP_get_ext_by_critical := LoadLibFunction(ADllHandle, OCSP_BASICRESP_get_ext_by_critical_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_get_ext_by_critical_allownil)}
    OCSP_BASICRESP_get_ext_by_critical := ERR_OCSP_BASICRESP_get_ext_by_critical;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_by_critical_introduced)}
    if LibVersion < OCSP_BASICRESP_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_get_ext_by_critical)}
      OCSP_BASICRESP_get_ext_by_critical := FC_OCSP_BASICRESP_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_by_critical_removed)}
    if OCSP_BASICRESP_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_get_ext_by_critical)}
      OCSP_BASICRESP_get_ext_by_critical := _OCSP_BASICRESP_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_get_ext_by_critical');
    {$ifend}
  end;
  
  OCSP_BASICRESP_get_ext := LoadLibFunction(ADllHandle, OCSP_BASICRESP_get_ext_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_get_ext_allownil)}
    OCSP_BASICRESP_get_ext := ERR_OCSP_BASICRESP_get_ext;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_introduced)}
    if LibVersion < OCSP_BASICRESP_get_ext_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_get_ext)}
      OCSP_BASICRESP_get_ext := FC_OCSP_BASICRESP_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get_ext_removed)}
    if OCSP_BASICRESP_get_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_get_ext)}
      OCSP_BASICRESP_get_ext := _OCSP_BASICRESP_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_get_ext');
    {$ifend}
  end;
  
  OCSP_BASICRESP_delete_ext := LoadLibFunction(ADllHandle, OCSP_BASICRESP_delete_ext_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_delete_ext_allownil)}
    OCSP_BASICRESP_delete_ext := ERR_OCSP_BASICRESP_delete_ext;
    {$ifend}
    {$if declared(OCSP_BASICRESP_delete_ext_introduced)}
    if LibVersion < OCSP_BASICRESP_delete_ext_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_delete_ext)}
      OCSP_BASICRESP_delete_ext := FC_OCSP_BASICRESP_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_delete_ext_removed)}
    if OCSP_BASICRESP_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_delete_ext)}
      OCSP_BASICRESP_delete_ext := _OCSP_BASICRESP_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_delete_ext');
    {$ifend}
  end;
  
  OCSP_BASICRESP_get1_ext_d2i := LoadLibFunction(ADllHandle, OCSP_BASICRESP_get1_ext_d2i_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_get1_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_get1_ext_d2i_allownil)}
    OCSP_BASICRESP_get1_ext_d2i := ERR_OCSP_BASICRESP_get1_ext_d2i;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get1_ext_d2i_introduced)}
    if LibVersion < OCSP_BASICRESP_get1_ext_d2i_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_get1_ext_d2i)}
      OCSP_BASICRESP_get1_ext_d2i := FC_OCSP_BASICRESP_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_get1_ext_d2i_removed)}
    if OCSP_BASICRESP_get1_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_get1_ext_d2i)}
      OCSP_BASICRESP_get1_ext_d2i := _OCSP_BASICRESP_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_get1_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_get1_ext_d2i');
    {$ifend}
  end;
  
  OCSP_BASICRESP_add1_ext_i2d := LoadLibFunction(ADllHandle, OCSP_BASICRESP_add1_ext_i2d_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_add1_ext_i2d_allownil)}
    OCSP_BASICRESP_add1_ext_i2d := ERR_OCSP_BASICRESP_add1_ext_i2d;
    {$ifend}
    {$if declared(OCSP_BASICRESP_add1_ext_i2d_introduced)}
    if LibVersion < OCSP_BASICRESP_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_add1_ext_i2d)}
      OCSP_BASICRESP_add1_ext_i2d := FC_OCSP_BASICRESP_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_add1_ext_i2d_removed)}
    if OCSP_BASICRESP_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_add1_ext_i2d)}
      OCSP_BASICRESP_add1_ext_i2d := _OCSP_BASICRESP_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_add1_ext_i2d');
    {$ifend}
  end;
  
  OCSP_BASICRESP_add_ext := LoadLibFunction(ADllHandle, OCSP_BASICRESP_add_ext_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_add_ext_allownil)}
    OCSP_BASICRESP_add_ext := ERR_OCSP_BASICRESP_add_ext;
    {$ifend}
    {$if declared(OCSP_BASICRESP_add_ext_introduced)}
    if LibVersion < OCSP_BASICRESP_add_ext_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_add_ext)}
      OCSP_BASICRESP_add_ext := FC_OCSP_BASICRESP_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_add_ext_removed)}
    if OCSP_BASICRESP_add_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_add_ext)}
      OCSP_BASICRESP_add_ext := _OCSP_BASICRESP_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_add_ext');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_get_ext_count := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_get_ext_count_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_get_ext_count_allownil)}
    OCSP_SINGLERESP_get_ext_count := ERR_OCSP_SINGLERESP_get_ext_count;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_count_introduced)}
    if LibVersion < OCSP_SINGLERESP_get_ext_count_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_get_ext_count)}
      OCSP_SINGLERESP_get_ext_count := FC_OCSP_SINGLERESP_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_count_removed)}
    if OCSP_SINGLERESP_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_get_ext_count)}
      OCSP_SINGLERESP_get_ext_count := _OCSP_SINGLERESP_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_get_ext_count');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_get_ext_by_NID := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_get_ext_by_NID_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_get_ext_by_NID_allownil)}
    OCSP_SINGLERESP_get_ext_by_NID := ERR_OCSP_SINGLERESP_get_ext_by_NID;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_by_NID_introduced)}
    if LibVersion < OCSP_SINGLERESP_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_get_ext_by_NID)}
      OCSP_SINGLERESP_get_ext_by_NID := FC_OCSP_SINGLERESP_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_by_NID_removed)}
    if OCSP_SINGLERESP_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_get_ext_by_NID)}
      OCSP_SINGLERESP_get_ext_by_NID := _OCSP_SINGLERESP_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_get_ext_by_NID');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_get_ext_by_OBJ := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_get_ext_by_OBJ_allownil)}
    OCSP_SINGLERESP_get_ext_by_OBJ := ERR_OCSP_SINGLERESP_get_ext_by_OBJ;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_by_OBJ_introduced)}
    if LibVersion < OCSP_SINGLERESP_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_get_ext_by_OBJ)}
      OCSP_SINGLERESP_get_ext_by_OBJ := FC_OCSP_SINGLERESP_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_by_OBJ_removed)}
    if OCSP_SINGLERESP_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_get_ext_by_OBJ)}
      OCSP_SINGLERESP_get_ext_by_OBJ := _OCSP_SINGLERESP_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_get_ext_by_OBJ');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_get_ext_by_critical := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_get_ext_by_critical_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_get_ext_by_critical_allownil)}
    OCSP_SINGLERESP_get_ext_by_critical := ERR_OCSP_SINGLERESP_get_ext_by_critical;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_by_critical_introduced)}
    if LibVersion < OCSP_SINGLERESP_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_get_ext_by_critical)}
      OCSP_SINGLERESP_get_ext_by_critical := FC_OCSP_SINGLERESP_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_by_critical_removed)}
    if OCSP_SINGLERESP_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_get_ext_by_critical)}
      OCSP_SINGLERESP_get_ext_by_critical := _OCSP_SINGLERESP_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_get_ext_by_critical');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_get_ext := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_get_ext_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_get_ext_allownil)}
    OCSP_SINGLERESP_get_ext := ERR_OCSP_SINGLERESP_get_ext;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_introduced)}
    if LibVersion < OCSP_SINGLERESP_get_ext_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_get_ext)}
      OCSP_SINGLERESP_get_ext := FC_OCSP_SINGLERESP_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get_ext_removed)}
    if OCSP_SINGLERESP_get_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_get_ext)}
      OCSP_SINGLERESP_get_ext := _OCSP_SINGLERESP_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_get_ext');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_delete_ext := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_delete_ext_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_delete_ext_allownil)}
    OCSP_SINGLERESP_delete_ext := ERR_OCSP_SINGLERESP_delete_ext;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_delete_ext_introduced)}
    if LibVersion < OCSP_SINGLERESP_delete_ext_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_delete_ext)}
      OCSP_SINGLERESP_delete_ext := FC_OCSP_SINGLERESP_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_delete_ext_removed)}
    if OCSP_SINGLERESP_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_delete_ext)}
      OCSP_SINGLERESP_delete_ext := _OCSP_SINGLERESP_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_delete_ext');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_get1_ext_d2i := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_get1_ext_d2i_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_get1_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_get1_ext_d2i_allownil)}
    OCSP_SINGLERESP_get1_ext_d2i := ERR_OCSP_SINGLERESP_get1_ext_d2i;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get1_ext_d2i_introduced)}
    if LibVersion < OCSP_SINGLERESP_get1_ext_d2i_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_get1_ext_d2i)}
      OCSP_SINGLERESP_get1_ext_d2i := FC_OCSP_SINGLERESP_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get1_ext_d2i_removed)}
    if OCSP_SINGLERESP_get1_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_get1_ext_d2i)}
      OCSP_SINGLERESP_get1_ext_d2i := _OCSP_SINGLERESP_get1_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_get1_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_get1_ext_d2i');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_add1_ext_i2d := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_add1_ext_i2d_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_add1_ext_i2d_allownil)}
    OCSP_SINGLERESP_add1_ext_i2d := ERR_OCSP_SINGLERESP_add1_ext_i2d;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_add1_ext_i2d_introduced)}
    if LibVersion < OCSP_SINGLERESP_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_add1_ext_i2d)}
      OCSP_SINGLERESP_add1_ext_i2d := FC_OCSP_SINGLERESP_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_add1_ext_i2d_removed)}
    if OCSP_SINGLERESP_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_add1_ext_i2d)}
      OCSP_SINGLERESP_add1_ext_i2d := _OCSP_SINGLERESP_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_add1_ext_i2d');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_add_ext := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_add_ext_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_add_ext_allownil)}
    OCSP_SINGLERESP_add_ext := ERR_OCSP_SINGLERESP_add_ext;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_add_ext_introduced)}
    if LibVersion < OCSP_SINGLERESP_add_ext_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_add_ext)}
      OCSP_SINGLERESP_add_ext := FC_OCSP_SINGLERESP_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_add_ext_removed)}
    if OCSP_SINGLERESP_add_ext_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_add_ext)}
      OCSP_SINGLERESP_add_ext := _OCSP_SINGLERESP_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_add_ext');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_get0_id := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_get0_id_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_get0_id);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_get0_id_allownil)}
    OCSP_SINGLERESP_get0_id := ERR_OCSP_SINGLERESP_get0_id;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get0_id_introduced)}
    if LibVersion < OCSP_SINGLERESP_get0_id_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_get0_id)}
      OCSP_SINGLERESP_get0_id := FC_OCSP_SINGLERESP_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_get0_id_removed)}
    if OCSP_SINGLERESP_get0_id_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_get0_id)}
      OCSP_SINGLERESP_get0_id := _OCSP_SINGLERESP_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_get0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_get0_id');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_new := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_new_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_new_allownil)}
    OCSP_SINGLERESP_new := ERR_OCSP_SINGLERESP_new;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_new_introduced)}
    if LibVersion < OCSP_SINGLERESP_new_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_new)}
      OCSP_SINGLERESP_new := FC_OCSP_SINGLERESP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_new_removed)}
    if OCSP_SINGLERESP_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_new)}
      OCSP_SINGLERESP_new := _OCSP_SINGLERESP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_new');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_free := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_free_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_free_allownil)}
    OCSP_SINGLERESP_free := ERR_OCSP_SINGLERESP_free;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_free_introduced)}
    if LibVersion < OCSP_SINGLERESP_free_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_free)}
      OCSP_SINGLERESP_free := FC_OCSP_SINGLERESP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_free_removed)}
    if OCSP_SINGLERESP_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_free)}
      OCSP_SINGLERESP_free := _OCSP_SINGLERESP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_free');
    {$ifend}
  end;
  
  d2i_OCSP_SINGLERESP := LoadLibFunction(ADllHandle, d2i_OCSP_SINGLERESP_procname);
  FuncLoadError := not assigned(d2i_OCSP_SINGLERESP);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_SINGLERESP_allownil)}
    d2i_OCSP_SINGLERESP := ERR_d2i_OCSP_SINGLERESP;
    {$ifend}
    {$if declared(d2i_OCSP_SINGLERESP_introduced)}
    if LibVersion < d2i_OCSP_SINGLERESP_introduced then
    begin
      {$if declared(FC_d2i_OCSP_SINGLERESP)}
      d2i_OCSP_SINGLERESP := FC_d2i_OCSP_SINGLERESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_SINGLERESP_removed)}
    if d2i_OCSP_SINGLERESP_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_SINGLERESP)}
      d2i_OCSP_SINGLERESP := _d2i_OCSP_SINGLERESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_SINGLERESP_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_SINGLERESP');
    {$ifend}
  end;
  
  i2d_OCSP_SINGLERESP := LoadLibFunction(ADllHandle, i2d_OCSP_SINGLERESP_procname);
  FuncLoadError := not assigned(i2d_OCSP_SINGLERESP);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_SINGLERESP_allownil)}
    i2d_OCSP_SINGLERESP := ERR_i2d_OCSP_SINGLERESP;
    {$ifend}
    {$if declared(i2d_OCSP_SINGLERESP_introduced)}
    if LibVersion < i2d_OCSP_SINGLERESP_introduced then
    begin
      {$if declared(FC_i2d_OCSP_SINGLERESP)}
      i2d_OCSP_SINGLERESP := FC_i2d_OCSP_SINGLERESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_SINGLERESP_removed)}
    if i2d_OCSP_SINGLERESP_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_SINGLERESP)}
      i2d_OCSP_SINGLERESP := _i2d_OCSP_SINGLERESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_SINGLERESP_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_SINGLERESP');
    {$ifend}
  end;
  
  OCSP_SINGLERESP_it := LoadLibFunction(ADllHandle, OCSP_SINGLERESP_it_procname);
  FuncLoadError := not assigned(OCSP_SINGLERESP_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SINGLERESP_it_allownil)}
    OCSP_SINGLERESP_it := ERR_OCSP_SINGLERESP_it;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_it_introduced)}
    if LibVersion < OCSP_SINGLERESP_it_introduced then
    begin
      {$if declared(FC_OCSP_SINGLERESP_it)}
      OCSP_SINGLERESP_it := FC_OCSP_SINGLERESP_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SINGLERESP_it_removed)}
    if OCSP_SINGLERESP_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SINGLERESP_it)}
      OCSP_SINGLERESP_it := _OCSP_SINGLERESP_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SINGLERESP_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SINGLERESP_it');
    {$ifend}
  end;
  
  OCSP_CERTSTATUS_new := LoadLibFunction(ADllHandle, OCSP_CERTSTATUS_new_procname);
  FuncLoadError := not assigned(OCSP_CERTSTATUS_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CERTSTATUS_new_allownil)}
    OCSP_CERTSTATUS_new := ERR_OCSP_CERTSTATUS_new;
    {$ifend}
    {$if declared(OCSP_CERTSTATUS_new_introduced)}
    if LibVersion < OCSP_CERTSTATUS_new_introduced then
    begin
      {$if declared(FC_OCSP_CERTSTATUS_new)}
      OCSP_CERTSTATUS_new := FC_OCSP_CERTSTATUS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CERTSTATUS_new_removed)}
    if OCSP_CERTSTATUS_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CERTSTATUS_new)}
      OCSP_CERTSTATUS_new := _OCSP_CERTSTATUS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CERTSTATUS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CERTSTATUS_new');
    {$ifend}
  end;
  
  OCSP_CERTSTATUS_free := LoadLibFunction(ADllHandle, OCSP_CERTSTATUS_free_procname);
  FuncLoadError := not assigned(OCSP_CERTSTATUS_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CERTSTATUS_free_allownil)}
    OCSP_CERTSTATUS_free := ERR_OCSP_CERTSTATUS_free;
    {$ifend}
    {$if declared(OCSP_CERTSTATUS_free_introduced)}
    if LibVersion < OCSP_CERTSTATUS_free_introduced then
    begin
      {$if declared(FC_OCSP_CERTSTATUS_free)}
      OCSP_CERTSTATUS_free := FC_OCSP_CERTSTATUS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CERTSTATUS_free_removed)}
    if OCSP_CERTSTATUS_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CERTSTATUS_free)}
      OCSP_CERTSTATUS_free := _OCSP_CERTSTATUS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CERTSTATUS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CERTSTATUS_free');
    {$ifend}
  end;
  
  d2i_OCSP_CERTSTATUS := LoadLibFunction(ADllHandle, d2i_OCSP_CERTSTATUS_procname);
  FuncLoadError := not assigned(d2i_OCSP_CERTSTATUS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_CERTSTATUS_allownil)}
    d2i_OCSP_CERTSTATUS := ERR_d2i_OCSP_CERTSTATUS;
    {$ifend}
    {$if declared(d2i_OCSP_CERTSTATUS_introduced)}
    if LibVersion < d2i_OCSP_CERTSTATUS_introduced then
    begin
      {$if declared(FC_d2i_OCSP_CERTSTATUS)}
      d2i_OCSP_CERTSTATUS := FC_d2i_OCSP_CERTSTATUS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_CERTSTATUS_removed)}
    if d2i_OCSP_CERTSTATUS_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_CERTSTATUS)}
      d2i_OCSP_CERTSTATUS := _d2i_OCSP_CERTSTATUS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_CERTSTATUS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_CERTSTATUS');
    {$ifend}
  end;
  
  i2d_OCSP_CERTSTATUS := LoadLibFunction(ADllHandle, i2d_OCSP_CERTSTATUS_procname);
  FuncLoadError := not assigned(i2d_OCSP_CERTSTATUS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_CERTSTATUS_allownil)}
    i2d_OCSP_CERTSTATUS := ERR_i2d_OCSP_CERTSTATUS;
    {$ifend}
    {$if declared(i2d_OCSP_CERTSTATUS_introduced)}
    if LibVersion < i2d_OCSP_CERTSTATUS_introduced then
    begin
      {$if declared(FC_i2d_OCSP_CERTSTATUS)}
      i2d_OCSP_CERTSTATUS := FC_i2d_OCSP_CERTSTATUS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_CERTSTATUS_removed)}
    if i2d_OCSP_CERTSTATUS_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_CERTSTATUS)}
      i2d_OCSP_CERTSTATUS := _i2d_OCSP_CERTSTATUS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_CERTSTATUS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_CERTSTATUS');
    {$ifend}
  end;
  
  OCSP_CERTSTATUS_it := LoadLibFunction(ADllHandle, OCSP_CERTSTATUS_it_procname);
  FuncLoadError := not assigned(OCSP_CERTSTATUS_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CERTSTATUS_it_allownil)}
    OCSP_CERTSTATUS_it := ERR_OCSP_CERTSTATUS_it;
    {$ifend}
    {$if declared(OCSP_CERTSTATUS_it_introduced)}
    if LibVersion < OCSP_CERTSTATUS_it_introduced then
    begin
      {$if declared(FC_OCSP_CERTSTATUS_it)}
      OCSP_CERTSTATUS_it := FC_OCSP_CERTSTATUS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CERTSTATUS_it_removed)}
    if OCSP_CERTSTATUS_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CERTSTATUS_it)}
      OCSP_CERTSTATUS_it := _OCSP_CERTSTATUS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CERTSTATUS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CERTSTATUS_it');
    {$ifend}
  end;
  
  OCSP_REVOKEDINFO_new := LoadLibFunction(ADllHandle, OCSP_REVOKEDINFO_new_procname);
  FuncLoadError := not assigned(OCSP_REVOKEDINFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REVOKEDINFO_new_allownil)}
    OCSP_REVOKEDINFO_new := ERR_OCSP_REVOKEDINFO_new;
    {$ifend}
    {$if declared(OCSP_REVOKEDINFO_new_introduced)}
    if LibVersion < OCSP_REVOKEDINFO_new_introduced then
    begin
      {$if declared(FC_OCSP_REVOKEDINFO_new)}
      OCSP_REVOKEDINFO_new := FC_OCSP_REVOKEDINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REVOKEDINFO_new_removed)}
    if OCSP_REVOKEDINFO_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REVOKEDINFO_new)}
      OCSP_REVOKEDINFO_new := _OCSP_REVOKEDINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REVOKEDINFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REVOKEDINFO_new');
    {$ifend}
  end;
  
  OCSP_REVOKEDINFO_free := LoadLibFunction(ADllHandle, OCSP_REVOKEDINFO_free_procname);
  FuncLoadError := not assigned(OCSP_REVOKEDINFO_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REVOKEDINFO_free_allownil)}
    OCSP_REVOKEDINFO_free := ERR_OCSP_REVOKEDINFO_free;
    {$ifend}
    {$if declared(OCSP_REVOKEDINFO_free_introduced)}
    if LibVersion < OCSP_REVOKEDINFO_free_introduced then
    begin
      {$if declared(FC_OCSP_REVOKEDINFO_free)}
      OCSP_REVOKEDINFO_free := FC_OCSP_REVOKEDINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REVOKEDINFO_free_removed)}
    if OCSP_REVOKEDINFO_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REVOKEDINFO_free)}
      OCSP_REVOKEDINFO_free := _OCSP_REVOKEDINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REVOKEDINFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REVOKEDINFO_free');
    {$ifend}
  end;
  
  d2i_OCSP_REVOKEDINFO := LoadLibFunction(ADllHandle, d2i_OCSP_REVOKEDINFO_procname);
  FuncLoadError := not assigned(d2i_OCSP_REVOKEDINFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_REVOKEDINFO_allownil)}
    d2i_OCSP_REVOKEDINFO := ERR_d2i_OCSP_REVOKEDINFO;
    {$ifend}
    {$if declared(d2i_OCSP_REVOKEDINFO_introduced)}
    if LibVersion < d2i_OCSP_REVOKEDINFO_introduced then
    begin
      {$if declared(FC_d2i_OCSP_REVOKEDINFO)}
      d2i_OCSP_REVOKEDINFO := FC_d2i_OCSP_REVOKEDINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_REVOKEDINFO_removed)}
    if d2i_OCSP_REVOKEDINFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_REVOKEDINFO)}
      d2i_OCSP_REVOKEDINFO := _d2i_OCSP_REVOKEDINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_REVOKEDINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_REVOKEDINFO');
    {$ifend}
  end;
  
  i2d_OCSP_REVOKEDINFO := LoadLibFunction(ADllHandle, i2d_OCSP_REVOKEDINFO_procname);
  FuncLoadError := not assigned(i2d_OCSP_REVOKEDINFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_REVOKEDINFO_allownil)}
    i2d_OCSP_REVOKEDINFO := ERR_i2d_OCSP_REVOKEDINFO;
    {$ifend}
    {$if declared(i2d_OCSP_REVOKEDINFO_introduced)}
    if LibVersion < i2d_OCSP_REVOKEDINFO_introduced then
    begin
      {$if declared(FC_i2d_OCSP_REVOKEDINFO)}
      i2d_OCSP_REVOKEDINFO := FC_i2d_OCSP_REVOKEDINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_REVOKEDINFO_removed)}
    if i2d_OCSP_REVOKEDINFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_REVOKEDINFO)}
      i2d_OCSP_REVOKEDINFO := _i2d_OCSP_REVOKEDINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_REVOKEDINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_REVOKEDINFO');
    {$ifend}
  end;
  
  OCSP_REVOKEDINFO_it := LoadLibFunction(ADllHandle, OCSP_REVOKEDINFO_it_procname);
  FuncLoadError := not assigned(OCSP_REVOKEDINFO_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REVOKEDINFO_it_allownil)}
    OCSP_REVOKEDINFO_it := ERR_OCSP_REVOKEDINFO_it;
    {$ifend}
    {$if declared(OCSP_REVOKEDINFO_it_introduced)}
    if LibVersion < OCSP_REVOKEDINFO_it_introduced then
    begin
      {$if declared(FC_OCSP_REVOKEDINFO_it)}
      OCSP_REVOKEDINFO_it := FC_OCSP_REVOKEDINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REVOKEDINFO_it_removed)}
    if OCSP_REVOKEDINFO_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REVOKEDINFO_it)}
      OCSP_REVOKEDINFO_it := _OCSP_REVOKEDINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REVOKEDINFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REVOKEDINFO_it');
    {$ifend}
  end;
  
  OCSP_BASICRESP_new := LoadLibFunction(ADllHandle, OCSP_BASICRESP_new_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_new_allownil)}
    OCSP_BASICRESP_new := ERR_OCSP_BASICRESP_new;
    {$ifend}
    {$if declared(OCSP_BASICRESP_new_introduced)}
    if LibVersion < OCSP_BASICRESP_new_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_new)}
      OCSP_BASICRESP_new := FC_OCSP_BASICRESP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_new_removed)}
    if OCSP_BASICRESP_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_new)}
      OCSP_BASICRESP_new := _OCSP_BASICRESP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_new');
    {$ifend}
  end;
  
  OCSP_BASICRESP_free := LoadLibFunction(ADllHandle, OCSP_BASICRESP_free_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_free_allownil)}
    OCSP_BASICRESP_free := ERR_OCSP_BASICRESP_free;
    {$ifend}
    {$if declared(OCSP_BASICRESP_free_introduced)}
    if LibVersion < OCSP_BASICRESP_free_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_free)}
      OCSP_BASICRESP_free := FC_OCSP_BASICRESP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_free_removed)}
    if OCSP_BASICRESP_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_free)}
      OCSP_BASICRESP_free := _OCSP_BASICRESP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_free');
    {$ifend}
  end;
  
  d2i_OCSP_BASICRESP := LoadLibFunction(ADllHandle, d2i_OCSP_BASICRESP_procname);
  FuncLoadError := not assigned(d2i_OCSP_BASICRESP);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_BASICRESP_allownil)}
    d2i_OCSP_BASICRESP := ERR_d2i_OCSP_BASICRESP;
    {$ifend}
    {$if declared(d2i_OCSP_BASICRESP_introduced)}
    if LibVersion < d2i_OCSP_BASICRESP_introduced then
    begin
      {$if declared(FC_d2i_OCSP_BASICRESP)}
      d2i_OCSP_BASICRESP := FC_d2i_OCSP_BASICRESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_BASICRESP_removed)}
    if d2i_OCSP_BASICRESP_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_BASICRESP)}
      d2i_OCSP_BASICRESP := _d2i_OCSP_BASICRESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_BASICRESP_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_BASICRESP');
    {$ifend}
  end;
  
  i2d_OCSP_BASICRESP := LoadLibFunction(ADllHandle, i2d_OCSP_BASICRESP_procname);
  FuncLoadError := not assigned(i2d_OCSP_BASICRESP);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_BASICRESP_allownil)}
    i2d_OCSP_BASICRESP := ERR_i2d_OCSP_BASICRESP;
    {$ifend}
    {$if declared(i2d_OCSP_BASICRESP_introduced)}
    if LibVersion < i2d_OCSP_BASICRESP_introduced then
    begin
      {$if declared(FC_i2d_OCSP_BASICRESP)}
      i2d_OCSP_BASICRESP := FC_i2d_OCSP_BASICRESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_BASICRESP_removed)}
    if i2d_OCSP_BASICRESP_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_BASICRESP)}
      i2d_OCSP_BASICRESP := _i2d_OCSP_BASICRESP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_BASICRESP_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_BASICRESP');
    {$ifend}
  end;
  
  OCSP_BASICRESP_it := LoadLibFunction(ADllHandle, OCSP_BASICRESP_it_procname);
  FuncLoadError := not assigned(OCSP_BASICRESP_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_BASICRESP_it_allownil)}
    OCSP_BASICRESP_it := ERR_OCSP_BASICRESP_it;
    {$ifend}
    {$if declared(OCSP_BASICRESP_it_introduced)}
    if LibVersion < OCSP_BASICRESP_it_introduced then
    begin
      {$if declared(FC_OCSP_BASICRESP_it)}
      OCSP_BASICRESP_it := FC_OCSP_BASICRESP_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_BASICRESP_it_removed)}
    if OCSP_BASICRESP_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_BASICRESP_it)}
      OCSP_BASICRESP_it := _OCSP_BASICRESP_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_BASICRESP_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_BASICRESP_it');
    {$ifend}
  end;
  
  OCSP_RESPDATA_new := LoadLibFunction(ADllHandle, OCSP_RESPDATA_new_procname);
  FuncLoadError := not assigned(OCSP_RESPDATA_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPDATA_new_allownil)}
    OCSP_RESPDATA_new := ERR_OCSP_RESPDATA_new;
    {$ifend}
    {$if declared(OCSP_RESPDATA_new_introduced)}
    if LibVersion < OCSP_RESPDATA_new_introduced then
    begin
      {$if declared(FC_OCSP_RESPDATA_new)}
      OCSP_RESPDATA_new := FC_OCSP_RESPDATA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPDATA_new_removed)}
    if OCSP_RESPDATA_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPDATA_new)}
      OCSP_RESPDATA_new := _OCSP_RESPDATA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPDATA_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPDATA_new');
    {$ifend}
  end;
  
  OCSP_RESPDATA_free := LoadLibFunction(ADllHandle, OCSP_RESPDATA_free_procname);
  FuncLoadError := not assigned(OCSP_RESPDATA_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPDATA_free_allownil)}
    OCSP_RESPDATA_free := ERR_OCSP_RESPDATA_free;
    {$ifend}
    {$if declared(OCSP_RESPDATA_free_introduced)}
    if LibVersion < OCSP_RESPDATA_free_introduced then
    begin
      {$if declared(FC_OCSP_RESPDATA_free)}
      OCSP_RESPDATA_free := FC_OCSP_RESPDATA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPDATA_free_removed)}
    if OCSP_RESPDATA_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPDATA_free)}
      OCSP_RESPDATA_free := _OCSP_RESPDATA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPDATA_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPDATA_free');
    {$ifend}
  end;
  
  d2i_OCSP_RESPDATA := LoadLibFunction(ADllHandle, d2i_OCSP_RESPDATA_procname);
  FuncLoadError := not assigned(d2i_OCSP_RESPDATA);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_RESPDATA_allownil)}
    d2i_OCSP_RESPDATA := ERR_d2i_OCSP_RESPDATA;
    {$ifend}
    {$if declared(d2i_OCSP_RESPDATA_introduced)}
    if LibVersion < d2i_OCSP_RESPDATA_introduced then
    begin
      {$if declared(FC_d2i_OCSP_RESPDATA)}
      d2i_OCSP_RESPDATA := FC_d2i_OCSP_RESPDATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_RESPDATA_removed)}
    if d2i_OCSP_RESPDATA_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_RESPDATA)}
      d2i_OCSP_RESPDATA := _d2i_OCSP_RESPDATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_RESPDATA_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_RESPDATA');
    {$ifend}
  end;
  
  i2d_OCSP_RESPDATA := LoadLibFunction(ADllHandle, i2d_OCSP_RESPDATA_procname);
  FuncLoadError := not assigned(i2d_OCSP_RESPDATA);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_RESPDATA_allownil)}
    i2d_OCSP_RESPDATA := ERR_i2d_OCSP_RESPDATA;
    {$ifend}
    {$if declared(i2d_OCSP_RESPDATA_introduced)}
    if LibVersion < i2d_OCSP_RESPDATA_introduced then
    begin
      {$if declared(FC_i2d_OCSP_RESPDATA)}
      i2d_OCSP_RESPDATA := FC_i2d_OCSP_RESPDATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_RESPDATA_removed)}
    if i2d_OCSP_RESPDATA_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_RESPDATA)}
      i2d_OCSP_RESPDATA := _i2d_OCSP_RESPDATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_RESPDATA_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_RESPDATA');
    {$ifend}
  end;
  
  OCSP_RESPDATA_it := LoadLibFunction(ADllHandle, OCSP_RESPDATA_it_procname);
  FuncLoadError := not assigned(OCSP_RESPDATA_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPDATA_it_allownil)}
    OCSP_RESPDATA_it := ERR_OCSP_RESPDATA_it;
    {$ifend}
    {$if declared(OCSP_RESPDATA_it_introduced)}
    if LibVersion < OCSP_RESPDATA_it_introduced then
    begin
      {$if declared(FC_OCSP_RESPDATA_it)}
      OCSP_RESPDATA_it := FC_OCSP_RESPDATA_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPDATA_it_removed)}
    if OCSP_RESPDATA_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPDATA_it)}
      OCSP_RESPDATA_it := _OCSP_RESPDATA_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPDATA_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPDATA_it');
    {$ifend}
  end;
  
  OCSP_RESPID_new := LoadLibFunction(ADllHandle, OCSP_RESPID_new_procname);
  FuncLoadError := not assigned(OCSP_RESPID_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_new_allownil)}
    OCSP_RESPID_new := ERR_OCSP_RESPID_new;
    {$ifend}
    {$if declared(OCSP_RESPID_new_introduced)}
    if LibVersion < OCSP_RESPID_new_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_new)}
      OCSP_RESPID_new := FC_OCSP_RESPID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_new_removed)}
    if OCSP_RESPID_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_new)}
      OCSP_RESPID_new := _OCSP_RESPID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_new');
    {$ifend}
  end;
  
  OCSP_RESPID_free := LoadLibFunction(ADllHandle, OCSP_RESPID_free_procname);
  FuncLoadError := not assigned(OCSP_RESPID_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_free_allownil)}
    OCSP_RESPID_free := ERR_OCSP_RESPID_free;
    {$ifend}
    {$if declared(OCSP_RESPID_free_introduced)}
    if LibVersion < OCSP_RESPID_free_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_free)}
      OCSP_RESPID_free := FC_OCSP_RESPID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_free_removed)}
    if OCSP_RESPID_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_free)}
      OCSP_RESPID_free := _OCSP_RESPID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_free');
    {$ifend}
  end;
  
  d2i_OCSP_RESPID := LoadLibFunction(ADllHandle, d2i_OCSP_RESPID_procname);
  FuncLoadError := not assigned(d2i_OCSP_RESPID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_RESPID_allownil)}
    d2i_OCSP_RESPID := ERR_d2i_OCSP_RESPID;
    {$ifend}
    {$if declared(d2i_OCSP_RESPID_introduced)}
    if LibVersion < d2i_OCSP_RESPID_introduced then
    begin
      {$if declared(FC_d2i_OCSP_RESPID)}
      d2i_OCSP_RESPID := FC_d2i_OCSP_RESPID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_RESPID_removed)}
    if d2i_OCSP_RESPID_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_RESPID)}
      d2i_OCSP_RESPID := _d2i_OCSP_RESPID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_RESPID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_RESPID');
    {$ifend}
  end;
  
  i2d_OCSP_RESPID := LoadLibFunction(ADllHandle, i2d_OCSP_RESPID_procname);
  FuncLoadError := not assigned(i2d_OCSP_RESPID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_RESPID_allownil)}
    i2d_OCSP_RESPID := ERR_i2d_OCSP_RESPID;
    {$ifend}
    {$if declared(i2d_OCSP_RESPID_introduced)}
    if LibVersion < i2d_OCSP_RESPID_introduced then
    begin
      {$if declared(FC_i2d_OCSP_RESPID)}
      i2d_OCSP_RESPID := FC_i2d_OCSP_RESPID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_RESPID_removed)}
    if i2d_OCSP_RESPID_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_RESPID)}
      i2d_OCSP_RESPID := _i2d_OCSP_RESPID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_RESPID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_RESPID');
    {$ifend}
  end;
  
  OCSP_RESPID_it := LoadLibFunction(ADllHandle, OCSP_RESPID_it_procname);
  FuncLoadError := not assigned(OCSP_RESPID_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPID_it_allownil)}
    OCSP_RESPID_it := ERR_OCSP_RESPID_it;
    {$ifend}
    {$if declared(OCSP_RESPID_it_introduced)}
    if LibVersion < OCSP_RESPID_it_introduced then
    begin
      {$if declared(FC_OCSP_RESPID_it)}
      OCSP_RESPID_it := FC_OCSP_RESPID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPID_it_removed)}
    if OCSP_RESPID_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPID_it)}
      OCSP_RESPID_it := _OCSP_RESPID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPID_it');
    {$ifend}
  end;
  
  OCSP_RESPONSE_new := LoadLibFunction(ADllHandle, OCSP_RESPONSE_new_procname);
  FuncLoadError := not assigned(OCSP_RESPONSE_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPONSE_new_allownil)}
    OCSP_RESPONSE_new := ERR_OCSP_RESPONSE_new;
    {$ifend}
    {$if declared(OCSP_RESPONSE_new_introduced)}
    if LibVersion < OCSP_RESPONSE_new_introduced then
    begin
      {$if declared(FC_OCSP_RESPONSE_new)}
      OCSP_RESPONSE_new := FC_OCSP_RESPONSE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPONSE_new_removed)}
    if OCSP_RESPONSE_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPONSE_new)}
      OCSP_RESPONSE_new := _OCSP_RESPONSE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPONSE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPONSE_new');
    {$ifend}
  end;
  
  OCSP_RESPONSE_free := LoadLibFunction(ADllHandle, OCSP_RESPONSE_free_procname);
  FuncLoadError := not assigned(OCSP_RESPONSE_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPONSE_free_allownil)}
    OCSP_RESPONSE_free := ERR_OCSP_RESPONSE_free;
    {$ifend}
    {$if declared(OCSP_RESPONSE_free_introduced)}
    if LibVersion < OCSP_RESPONSE_free_introduced then
    begin
      {$if declared(FC_OCSP_RESPONSE_free)}
      OCSP_RESPONSE_free := FC_OCSP_RESPONSE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPONSE_free_removed)}
    if OCSP_RESPONSE_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPONSE_free)}
      OCSP_RESPONSE_free := _OCSP_RESPONSE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPONSE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPONSE_free');
    {$ifend}
  end;
  
  d2i_OCSP_RESPONSE := LoadLibFunction(ADllHandle, d2i_OCSP_RESPONSE_procname);
  FuncLoadError := not assigned(d2i_OCSP_RESPONSE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_RESPONSE_allownil)}
    d2i_OCSP_RESPONSE := ERR_d2i_OCSP_RESPONSE;
    {$ifend}
    {$if declared(d2i_OCSP_RESPONSE_introduced)}
    if LibVersion < d2i_OCSP_RESPONSE_introduced then
    begin
      {$if declared(FC_d2i_OCSP_RESPONSE)}
      d2i_OCSP_RESPONSE := FC_d2i_OCSP_RESPONSE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_RESPONSE_removed)}
    if d2i_OCSP_RESPONSE_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_RESPONSE)}
      d2i_OCSP_RESPONSE := _d2i_OCSP_RESPONSE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_RESPONSE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_RESPONSE');
    {$ifend}
  end;
  
  i2d_OCSP_RESPONSE := LoadLibFunction(ADllHandle, i2d_OCSP_RESPONSE_procname);
  FuncLoadError := not assigned(i2d_OCSP_RESPONSE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_RESPONSE_allownil)}
    i2d_OCSP_RESPONSE := ERR_i2d_OCSP_RESPONSE;
    {$ifend}
    {$if declared(i2d_OCSP_RESPONSE_introduced)}
    if LibVersion < i2d_OCSP_RESPONSE_introduced then
    begin
      {$if declared(FC_i2d_OCSP_RESPONSE)}
      i2d_OCSP_RESPONSE := FC_i2d_OCSP_RESPONSE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_RESPONSE_removed)}
    if i2d_OCSP_RESPONSE_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_RESPONSE)}
      i2d_OCSP_RESPONSE := _i2d_OCSP_RESPONSE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_RESPONSE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_RESPONSE');
    {$ifend}
  end;
  
  OCSP_RESPONSE_it := LoadLibFunction(ADllHandle, OCSP_RESPONSE_it_procname);
  FuncLoadError := not assigned(OCSP_RESPONSE_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPONSE_it_allownil)}
    OCSP_RESPONSE_it := ERR_OCSP_RESPONSE_it;
    {$ifend}
    {$if declared(OCSP_RESPONSE_it_introduced)}
    if LibVersion < OCSP_RESPONSE_it_introduced then
    begin
      {$if declared(FC_OCSP_RESPONSE_it)}
      OCSP_RESPONSE_it := FC_OCSP_RESPONSE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPONSE_it_removed)}
    if OCSP_RESPONSE_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPONSE_it)}
      OCSP_RESPONSE_it := _OCSP_RESPONSE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPONSE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPONSE_it');
    {$ifend}
  end;
  
  OCSP_RESPBYTES_new := LoadLibFunction(ADllHandle, OCSP_RESPBYTES_new_procname);
  FuncLoadError := not assigned(OCSP_RESPBYTES_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPBYTES_new_allownil)}
    OCSP_RESPBYTES_new := ERR_OCSP_RESPBYTES_new;
    {$ifend}
    {$if declared(OCSP_RESPBYTES_new_introduced)}
    if LibVersion < OCSP_RESPBYTES_new_introduced then
    begin
      {$if declared(FC_OCSP_RESPBYTES_new)}
      OCSP_RESPBYTES_new := FC_OCSP_RESPBYTES_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPBYTES_new_removed)}
    if OCSP_RESPBYTES_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPBYTES_new)}
      OCSP_RESPBYTES_new := _OCSP_RESPBYTES_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPBYTES_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPBYTES_new');
    {$ifend}
  end;
  
  OCSP_RESPBYTES_free := LoadLibFunction(ADllHandle, OCSP_RESPBYTES_free_procname);
  FuncLoadError := not assigned(OCSP_RESPBYTES_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPBYTES_free_allownil)}
    OCSP_RESPBYTES_free := ERR_OCSP_RESPBYTES_free;
    {$ifend}
    {$if declared(OCSP_RESPBYTES_free_introduced)}
    if LibVersion < OCSP_RESPBYTES_free_introduced then
    begin
      {$if declared(FC_OCSP_RESPBYTES_free)}
      OCSP_RESPBYTES_free := FC_OCSP_RESPBYTES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPBYTES_free_removed)}
    if OCSP_RESPBYTES_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPBYTES_free)}
      OCSP_RESPBYTES_free := _OCSP_RESPBYTES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPBYTES_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPBYTES_free');
    {$ifend}
  end;
  
  d2i_OCSP_RESPBYTES := LoadLibFunction(ADllHandle, d2i_OCSP_RESPBYTES_procname);
  FuncLoadError := not assigned(d2i_OCSP_RESPBYTES);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_RESPBYTES_allownil)}
    d2i_OCSP_RESPBYTES := ERR_d2i_OCSP_RESPBYTES;
    {$ifend}
    {$if declared(d2i_OCSP_RESPBYTES_introduced)}
    if LibVersion < d2i_OCSP_RESPBYTES_introduced then
    begin
      {$if declared(FC_d2i_OCSP_RESPBYTES)}
      d2i_OCSP_RESPBYTES := FC_d2i_OCSP_RESPBYTES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_RESPBYTES_removed)}
    if d2i_OCSP_RESPBYTES_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_RESPBYTES)}
      d2i_OCSP_RESPBYTES := _d2i_OCSP_RESPBYTES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_RESPBYTES_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_RESPBYTES');
    {$ifend}
  end;
  
  i2d_OCSP_RESPBYTES := LoadLibFunction(ADllHandle, i2d_OCSP_RESPBYTES_procname);
  FuncLoadError := not assigned(i2d_OCSP_RESPBYTES);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_RESPBYTES_allownil)}
    i2d_OCSP_RESPBYTES := ERR_i2d_OCSP_RESPBYTES;
    {$ifend}
    {$if declared(i2d_OCSP_RESPBYTES_introduced)}
    if LibVersion < i2d_OCSP_RESPBYTES_introduced then
    begin
      {$if declared(FC_i2d_OCSP_RESPBYTES)}
      i2d_OCSP_RESPBYTES := FC_i2d_OCSP_RESPBYTES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_RESPBYTES_removed)}
    if i2d_OCSP_RESPBYTES_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_RESPBYTES)}
      i2d_OCSP_RESPBYTES := _i2d_OCSP_RESPBYTES;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_RESPBYTES_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_RESPBYTES');
    {$ifend}
  end;
  
  OCSP_RESPBYTES_it := LoadLibFunction(ADllHandle, OCSP_RESPBYTES_it_procname);
  FuncLoadError := not assigned(OCSP_RESPBYTES_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPBYTES_it_allownil)}
    OCSP_RESPBYTES_it := ERR_OCSP_RESPBYTES_it;
    {$ifend}
    {$if declared(OCSP_RESPBYTES_it_introduced)}
    if LibVersion < OCSP_RESPBYTES_it_introduced then
    begin
      {$if declared(FC_OCSP_RESPBYTES_it)}
      OCSP_RESPBYTES_it := FC_OCSP_RESPBYTES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPBYTES_it_removed)}
    if OCSP_RESPBYTES_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPBYTES_it)}
      OCSP_RESPBYTES_it := _OCSP_RESPBYTES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPBYTES_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPBYTES_it');
    {$ifend}
  end;
  
  OCSP_ONEREQ_new := LoadLibFunction(ADllHandle, OCSP_ONEREQ_new_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_new_allownil)}
    OCSP_ONEREQ_new := ERR_OCSP_ONEREQ_new;
    {$ifend}
    {$if declared(OCSP_ONEREQ_new_introduced)}
    if LibVersion < OCSP_ONEREQ_new_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_new)}
      OCSP_ONEREQ_new := FC_OCSP_ONEREQ_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_new_removed)}
    if OCSP_ONEREQ_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_new)}
      OCSP_ONEREQ_new := _OCSP_ONEREQ_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_new');
    {$ifend}
  end;
  
  OCSP_ONEREQ_free := LoadLibFunction(ADllHandle, OCSP_ONEREQ_free_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_free_allownil)}
    OCSP_ONEREQ_free := ERR_OCSP_ONEREQ_free;
    {$ifend}
    {$if declared(OCSP_ONEREQ_free_introduced)}
    if LibVersion < OCSP_ONEREQ_free_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_free)}
      OCSP_ONEREQ_free := FC_OCSP_ONEREQ_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_free_removed)}
    if OCSP_ONEREQ_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_free)}
      OCSP_ONEREQ_free := _OCSP_ONEREQ_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_free');
    {$ifend}
  end;
  
  d2i_OCSP_ONEREQ := LoadLibFunction(ADllHandle, d2i_OCSP_ONEREQ_procname);
  FuncLoadError := not assigned(d2i_OCSP_ONEREQ);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_ONEREQ_allownil)}
    d2i_OCSP_ONEREQ := ERR_d2i_OCSP_ONEREQ;
    {$ifend}
    {$if declared(d2i_OCSP_ONEREQ_introduced)}
    if LibVersion < d2i_OCSP_ONEREQ_introduced then
    begin
      {$if declared(FC_d2i_OCSP_ONEREQ)}
      d2i_OCSP_ONEREQ := FC_d2i_OCSP_ONEREQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_ONEREQ_removed)}
    if d2i_OCSP_ONEREQ_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_ONEREQ)}
      d2i_OCSP_ONEREQ := _d2i_OCSP_ONEREQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_ONEREQ_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_ONEREQ');
    {$ifend}
  end;
  
  i2d_OCSP_ONEREQ := LoadLibFunction(ADllHandle, i2d_OCSP_ONEREQ_procname);
  FuncLoadError := not assigned(i2d_OCSP_ONEREQ);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_ONEREQ_allownil)}
    i2d_OCSP_ONEREQ := ERR_i2d_OCSP_ONEREQ;
    {$ifend}
    {$if declared(i2d_OCSP_ONEREQ_introduced)}
    if LibVersion < i2d_OCSP_ONEREQ_introduced then
    begin
      {$if declared(FC_i2d_OCSP_ONEREQ)}
      i2d_OCSP_ONEREQ := FC_i2d_OCSP_ONEREQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_ONEREQ_removed)}
    if i2d_OCSP_ONEREQ_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_ONEREQ)}
      i2d_OCSP_ONEREQ := _i2d_OCSP_ONEREQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_ONEREQ_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_ONEREQ');
    {$ifend}
  end;
  
  OCSP_ONEREQ_it := LoadLibFunction(ADllHandle, OCSP_ONEREQ_it_procname);
  FuncLoadError := not assigned(OCSP_ONEREQ_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_ONEREQ_it_allownil)}
    OCSP_ONEREQ_it := ERR_OCSP_ONEREQ_it;
    {$ifend}
    {$if declared(OCSP_ONEREQ_it_introduced)}
    if LibVersion < OCSP_ONEREQ_it_introduced then
    begin
      {$if declared(FC_OCSP_ONEREQ_it)}
      OCSP_ONEREQ_it := FC_OCSP_ONEREQ_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_ONEREQ_it_removed)}
    if OCSP_ONEREQ_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_ONEREQ_it)}
      OCSP_ONEREQ_it := _OCSP_ONEREQ_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_ONEREQ_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_ONEREQ_it');
    {$ifend}
  end;
  
  OCSP_CERTID_new := LoadLibFunction(ADllHandle, OCSP_CERTID_new_procname);
  FuncLoadError := not assigned(OCSP_CERTID_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CERTID_new_allownil)}
    OCSP_CERTID_new := ERR_OCSP_CERTID_new;
    {$ifend}
    {$if declared(OCSP_CERTID_new_introduced)}
    if LibVersion < OCSP_CERTID_new_introduced then
    begin
      {$if declared(FC_OCSP_CERTID_new)}
      OCSP_CERTID_new := FC_OCSP_CERTID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CERTID_new_removed)}
    if OCSP_CERTID_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CERTID_new)}
      OCSP_CERTID_new := _OCSP_CERTID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CERTID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CERTID_new');
    {$ifend}
  end;
  
  OCSP_CERTID_free := LoadLibFunction(ADllHandle, OCSP_CERTID_free_procname);
  FuncLoadError := not assigned(OCSP_CERTID_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CERTID_free_allownil)}
    OCSP_CERTID_free := ERR_OCSP_CERTID_free;
    {$ifend}
    {$if declared(OCSP_CERTID_free_introduced)}
    if LibVersion < OCSP_CERTID_free_introduced then
    begin
      {$if declared(FC_OCSP_CERTID_free)}
      OCSP_CERTID_free := FC_OCSP_CERTID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CERTID_free_removed)}
    if OCSP_CERTID_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CERTID_free)}
      OCSP_CERTID_free := _OCSP_CERTID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CERTID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CERTID_free');
    {$ifend}
  end;
  
  d2i_OCSP_CERTID := LoadLibFunction(ADllHandle, d2i_OCSP_CERTID_procname);
  FuncLoadError := not assigned(d2i_OCSP_CERTID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_CERTID_allownil)}
    d2i_OCSP_CERTID := ERR_d2i_OCSP_CERTID;
    {$ifend}
    {$if declared(d2i_OCSP_CERTID_introduced)}
    if LibVersion < d2i_OCSP_CERTID_introduced then
    begin
      {$if declared(FC_d2i_OCSP_CERTID)}
      d2i_OCSP_CERTID := FC_d2i_OCSP_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_CERTID_removed)}
    if d2i_OCSP_CERTID_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_CERTID)}
      d2i_OCSP_CERTID := _d2i_OCSP_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_CERTID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_CERTID');
    {$ifend}
  end;
  
  i2d_OCSP_CERTID := LoadLibFunction(ADllHandle, i2d_OCSP_CERTID_procname);
  FuncLoadError := not assigned(i2d_OCSP_CERTID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_CERTID_allownil)}
    i2d_OCSP_CERTID := ERR_i2d_OCSP_CERTID;
    {$ifend}
    {$if declared(i2d_OCSP_CERTID_introduced)}
    if LibVersion < i2d_OCSP_CERTID_introduced then
    begin
      {$if declared(FC_i2d_OCSP_CERTID)}
      i2d_OCSP_CERTID := FC_i2d_OCSP_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_CERTID_removed)}
    if i2d_OCSP_CERTID_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_CERTID)}
      i2d_OCSP_CERTID := _i2d_OCSP_CERTID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_CERTID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_CERTID');
    {$ifend}
  end;
  
  OCSP_CERTID_it := LoadLibFunction(ADllHandle, OCSP_CERTID_it_procname);
  FuncLoadError := not assigned(OCSP_CERTID_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CERTID_it_allownil)}
    OCSP_CERTID_it := ERR_OCSP_CERTID_it;
    {$ifend}
    {$if declared(OCSP_CERTID_it_introduced)}
    if LibVersion < OCSP_CERTID_it_introduced then
    begin
      {$if declared(FC_OCSP_CERTID_it)}
      OCSP_CERTID_it := FC_OCSP_CERTID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CERTID_it_removed)}
    if OCSP_CERTID_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CERTID_it)}
      OCSP_CERTID_it := _OCSP_CERTID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CERTID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CERTID_it');
    {$ifend}
  end;
  
  OCSP_REQUEST_new := LoadLibFunction(ADllHandle, OCSP_REQUEST_new_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_new_allownil)}
    OCSP_REQUEST_new := ERR_OCSP_REQUEST_new;
    {$ifend}
    {$if declared(OCSP_REQUEST_new_introduced)}
    if LibVersion < OCSP_REQUEST_new_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_new)}
      OCSP_REQUEST_new := FC_OCSP_REQUEST_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_new_removed)}
    if OCSP_REQUEST_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_new)}
      OCSP_REQUEST_new := _OCSP_REQUEST_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_new');
    {$ifend}
  end;
  
  OCSP_REQUEST_free := LoadLibFunction(ADllHandle, OCSP_REQUEST_free_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_free_allownil)}
    OCSP_REQUEST_free := ERR_OCSP_REQUEST_free;
    {$ifend}
    {$if declared(OCSP_REQUEST_free_introduced)}
    if LibVersion < OCSP_REQUEST_free_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_free)}
      OCSP_REQUEST_free := FC_OCSP_REQUEST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_free_removed)}
    if OCSP_REQUEST_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_free)}
      OCSP_REQUEST_free := _OCSP_REQUEST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_free');
    {$ifend}
  end;
  
  d2i_OCSP_REQUEST := LoadLibFunction(ADllHandle, d2i_OCSP_REQUEST_procname);
  FuncLoadError := not assigned(d2i_OCSP_REQUEST);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_REQUEST_allownil)}
    d2i_OCSP_REQUEST := ERR_d2i_OCSP_REQUEST;
    {$ifend}
    {$if declared(d2i_OCSP_REQUEST_introduced)}
    if LibVersion < d2i_OCSP_REQUEST_introduced then
    begin
      {$if declared(FC_d2i_OCSP_REQUEST)}
      d2i_OCSP_REQUEST := FC_d2i_OCSP_REQUEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_REQUEST_removed)}
    if d2i_OCSP_REQUEST_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_REQUEST)}
      d2i_OCSP_REQUEST := _d2i_OCSP_REQUEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_REQUEST_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_REQUEST');
    {$ifend}
  end;
  
  i2d_OCSP_REQUEST := LoadLibFunction(ADllHandle, i2d_OCSP_REQUEST_procname);
  FuncLoadError := not assigned(i2d_OCSP_REQUEST);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_REQUEST_allownil)}
    i2d_OCSP_REQUEST := ERR_i2d_OCSP_REQUEST;
    {$ifend}
    {$if declared(i2d_OCSP_REQUEST_introduced)}
    if LibVersion < i2d_OCSP_REQUEST_introduced then
    begin
      {$if declared(FC_i2d_OCSP_REQUEST)}
      i2d_OCSP_REQUEST := FC_i2d_OCSP_REQUEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_REQUEST_removed)}
    if i2d_OCSP_REQUEST_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_REQUEST)}
      i2d_OCSP_REQUEST := _i2d_OCSP_REQUEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_REQUEST_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_REQUEST');
    {$ifend}
  end;
  
  OCSP_REQUEST_it := LoadLibFunction(ADllHandle, OCSP_REQUEST_it_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_it_allownil)}
    OCSP_REQUEST_it := ERR_OCSP_REQUEST_it;
    {$ifend}
    {$if declared(OCSP_REQUEST_it_introduced)}
    if LibVersion < OCSP_REQUEST_it_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_it)}
      OCSP_REQUEST_it := FC_OCSP_REQUEST_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_it_removed)}
    if OCSP_REQUEST_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_it)}
      OCSP_REQUEST_it := _OCSP_REQUEST_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_it');
    {$ifend}
  end;
  
  OCSP_SIGNATURE_new := LoadLibFunction(ADllHandle, OCSP_SIGNATURE_new_procname);
  FuncLoadError := not assigned(OCSP_SIGNATURE_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SIGNATURE_new_allownil)}
    OCSP_SIGNATURE_new := ERR_OCSP_SIGNATURE_new;
    {$ifend}
    {$if declared(OCSP_SIGNATURE_new_introduced)}
    if LibVersion < OCSP_SIGNATURE_new_introduced then
    begin
      {$if declared(FC_OCSP_SIGNATURE_new)}
      OCSP_SIGNATURE_new := FC_OCSP_SIGNATURE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SIGNATURE_new_removed)}
    if OCSP_SIGNATURE_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SIGNATURE_new)}
      OCSP_SIGNATURE_new := _OCSP_SIGNATURE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SIGNATURE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SIGNATURE_new');
    {$ifend}
  end;
  
  OCSP_SIGNATURE_free := LoadLibFunction(ADllHandle, OCSP_SIGNATURE_free_procname);
  FuncLoadError := not assigned(OCSP_SIGNATURE_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SIGNATURE_free_allownil)}
    OCSP_SIGNATURE_free := ERR_OCSP_SIGNATURE_free;
    {$ifend}
    {$if declared(OCSP_SIGNATURE_free_introduced)}
    if LibVersion < OCSP_SIGNATURE_free_introduced then
    begin
      {$if declared(FC_OCSP_SIGNATURE_free)}
      OCSP_SIGNATURE_free := FC_OCSP_SIGNATURE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SIGNATURE_free_removed)}
    if OCSP_SIGNATURE_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SIGNATURE_free)}
      OCSP_SIGNATURE_free := _OCSP_SIGNATURE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SIGNATURE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SIGNATURE_free');
    {$ifend}
  end;
  
  d2i_OCSP_SIGNATURE := LoadLibFunction(ADllHandle, d2i_OCSP_SIGNATURE_procname);
  FuncLoadError := not assigned(d2i_OCSP_SIGNATURE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_SIGNATURE_allownil)}
    d2i_OCSP_SIGNATURE := ERR_d2i_OCSP_SIGNATURE;
    {$ifend}
    {$if declared(d2i_OCSP_SIGNATURE_introduced)}
    if LibVersion < d2i_OCSP_SIGNATURE_introduced then
    begin
      {$if declared(FC_d2i_OCSP_SIGNATURE)}
      d2i_OCSP_SIGNATURE := FC_d2i_OCSP_SIGNATURE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_SIGNATURE_removed)}
    if d2i_OCSP_SIGNATURE_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_SIGNATURE)}
      d2i_OCSP_SIGNATURE := _d2i_OCSP_SIGNATURE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_SIGNATURE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_SIGNATURE');
    {$ifend}
  end;
  
  i2d_OCSP_SIGNATURE := LoadLibFunction(ADllHandle, i2d_OCSP_SIGNATURE_procname);
  FuncLoadError := not assigned(i2d_OCSP_SIGNATURE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_SIGNATURE_allownil)}
    i2d_OCSP_SIGNATURE := ERR_i2d_OCSP_SIGNATURE;
    {$ifend}
    {$if declared(i2d_OCSP_SIGNATURE_introduced)}
    if LibVersion < i2d_OCSP_SIGNATURE_introduced then
    begin
      {$if declared(FC_i2d_OCSP_SIGNATURE)}
      i2d_OCSP_SIGNATURE := FC_i2d_OCSP_SIGNATURE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_SIGNATURE_removed)}
    if i2d_OCSP_SIGNATURE_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_SIGNATURE)}
      i2d_OCSP_SIGNATURE := _i2d_OCSP_SIGNATURE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_SIGNATURE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_SIGNATURE');
    {$ifend}
  end;
  
  OCSP_SIGNATURE_it := LoadLibFunction(ADllHandle, OCSP_SIGNATURE_it_procname);
  FuncLoadError := not assigned(OCSP_SIGNATURE_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SIGNATURE_it_allownil)}
    OCSP_SIGNATURE_it := ERR_OCSP_SIGNATURE_it;
    {$ifend}
    {$if declared(OCSP_SIGNATURE_it_introduced)}
    if LibVersion < OCSP_SIGNATURE_it_introduced then
    begin
      {$if declared(FC_OCSP_SIGNATURE_it)}
      OCSP_SIGNATURE_it := FC_OCSP_SIGNATURE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SIGNATURE_it_removed)}
    if OCSP_SIGNATURE_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SIGNATURE_it)}
      OCSP_SIGNATURE_it := _OCSP_SIGNATURE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SIGNATURE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SIGNATURE_it');
    {$ifend}
  end;
  
  OCSP_REQINFO_new := LoadLibFunction(ADllHandle, OCSP_REQINFO_new_procname);
  FuncLoadError := not assigned(OCSP_REQINFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQINFO_new_allownil)}
    OCSP_REQINFO_new := ERR_OCSP_REQINFO_new;
    {$ifend}
    {$if declared(OCSP_REQINFO_new_introduced)}
    if LibVersion < OCSP_REQINFO_new_introduced then
    begin
      {$if declared(FC_OCSP_REQINFO_new)}
      OCSP_REQINFO_new := FC_OCSP_REQINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQINFO_new_removed)}
    if OCSP_REQINFO_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQINFO_new)}
      OCSP_REQINFO_new := _OCSP_REQINFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQINFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQINFO_new');
    {$ifend}
  end;
  
  OCSP_REQINFO_free := LoadLibFunction(ADllHandle, OCSP_REQINFO_free_procname);
  FuncLoadError := not assigned(OCSP_REQINFO_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQINFO_free_allownil)}
    OCSP_REQINFO_free := ERR_OCSP_REQINFO_free;
    {$ifend}
    {$if declared(OCSP_REQINFO_free_introduced)}
    if LibVersion < OCSP_REQINFO_free_introduced then
    begin
      {$if declared(FC_OCSP_REQINFO_free)}
      OCSP_REQINFO_free := FC_OCSP_REQINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQINFO_free_removed)}
    if OCSP_REQINFO_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQINFO_free)}
      OCSP_REQINFO_free := _OCSP_REQINFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQINFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQINFO_free');
    {$ifend}
  end;
  
  d2i_OCSP_REQINFO := LoadLibFunction(ADllHandle, d2i_OCSP_REQINFO_procname);
  FuncLoadError := not assigned(d2i_OCSP_REQINFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_REQINFO_allownil)}
    d2i_OCSP_REQINFO := ERR_d2i_OCSP_REQINFO;
    {$ifend}
    {$if declared(d2i_OCSP_REQINFO_introduced)}
    if LibVersion < d2i_OCSP_REQINFO_introduced then
    begin
      {$if declared(FC_d2i_OCSP_REQINFO)}
      d2i_OCSP_REQINFO := FC_d2i_OCSP_REQINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_REQINFO_removed)}
    if d2i_OCSP_REQINFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_REQINFO)}
      d2i_OCSP_REQINFO := _d2i_OCSP_REQINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_REQINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_REQINFO');
    {$ifend}
  end;
  
  i2d_OCSP_REQINFO := LoadLibFunction(ADllHandle, i2d_OCSP_REQINFO_procname);
  FuncLoadError := not assigned(i2d_OCSP_REQINFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_REQINFO_allownil)}
    i2d_OCSP_REQINFO := ERR_i2d_OCSP_REQINFO;
    {$ifend}
    {$if declared(i2d_OCSP_REQINFO_introduced)}
    if LibVersion < i2d_OCSP_REQINFO_introduced then
    begin
      {$if declared(FC_i2d_OCSP_REQINFO)}
      i2d_OCSP_REQINFO := FC_i2d_OCSP_REQINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_REQINFO_removed)}
    if i2d_OCSP_REQINFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_REQINFO)}
      i2d_OCSP_REQINFO := _i2d_OCSP_REQINFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_REQINFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_REQINFO');
    {$ifend}
  end;
  
  OCSP_REQINFO_it := LoadLibFunction(ADllHandle, OCSP_REQINFO_it_procname);
  FuncLoadError := not assigned(OCSP_REQINFO_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQINFO_it_allownil)}
    OCSP_REQINFO_it := ERR_OCSP_REQINFO_it;
    {$ifend}
    {$if declared(OCSP_REQINFO_it_introduced)}
    if LibVersion < OCSP_REQINFO_it_introduced then
    begin
      {$if declared(FC_OCSP_REQINFO_it)}
      OCSP_REQINFO_it := FC_OCSP_REQINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQINFO_it_removed)}
    if OCSP_REQINFO_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQINFO_it)}
      OCSP_REQINFO_it := _OCSP_REQINFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQINFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQINFO_it');
    {$ifend}
  end;
  
  OCSP_CRLID_new := LoadLibFunction(ADllHandle, OCSP_CRLID_new_procname);
  FuncLoadError := not assigned(OCSP_CRLID_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CRLID_new_allownil)}
    OCSP_CRLID_new := ERR_OCSP_CRLID_new;
    {$ifend}
    {$if declared(OCSP_CRLID_new_introduced)}
    if LibVersion < OCSP_CRLID_new_introduced then
    begin
      {$if declared(FC_OCSP_CRLID_new)}
      OCSP_CRLID_new := FC_OCSP_CRLID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CRLID_new_removed)}
    if OCSP_CRLID_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CRLID_new)}
      OCSP_CRLID_new := _OCSP_CRLID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CRLID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CRLID_new');
    {$ifend}
  end;
  
  OCSP_CRLID_free := LoadLibFunction(ADllHandle, OCSP_CRLID_free_procname);
  FuncLoadError := not assigned(OCSP_CRLID_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CRLID_free_allownil)}
    OCSP_CRLID_free := ERR_OCSP_CRLID_free;
    {$ifend}
    {$if declared(OCSP_CRLID_free_introduced)}
    if LibVersion < OCSP_CRLID_free_introduced then
    begin
      {$if declared(FC_OCSP_CRLID_free)}
      OCSP_CRLID_free := FC_OCSP_CRLID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CRLID_free_removed)}
    if OCSP_CRLID_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CRLID_free)}
      OCSP_CRLID_free := _OCSP_CRLID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CRLID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CRLID_free');
    {$ifend}
  end;
  
  d2i_OCSP_CRLID := LoadLibFunction(ADllHandle, d2i_OCSP_CRLID_procname);
  FuncLoadError := not assigned(d2i_OCSP_CRLID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_CRLID_allownil)}
    d2i_OCSP_CRLID := ERR_d2i_OCSP_CRLID;
    {$ifend}
    {$if declared(d2i_OCSP_CRLID_introduced)}
    if LibVersion < d2i_OCSP_CRLID_introduced then
    begin
      {$if declared(FC_d2i_OCSP_CRLID)}
      d2i_OCSP_CRLID := FC_d2i_OCSP_CRLID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_CRLID_removed)}
    if d2i_OCSP_CRLID_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_CRLID)}
      d2i_OCSP_CRLID := _d2i_OCSP_CRLID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_CRLID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_CRLID');
    {$ifend}
  end;
  
  i2d_OCSP_CRLID := LoadLibFunction(ADllHandle, i2d_OCSP_CRLID_procname);
  FuncLoadError := not assigned(i2d_OCSP_CRLID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_CRLID_allownil)}
    i2d_OCSP_CRLID := ERR_i2d_OCSP_CRLID;
    {$ifend}
    {$if declared(i2d_OCSP_CRLID_introduced)}
    if LibVersion < i2d_OCSP_CRLID_introduced then
    begin
      {$if declared(FC_i2d_OCSP_CRLID)}
      i2d_OCSP_CRLID := FC_i2d_OCSP_CRLID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_CRLID_removed)}
    if i2d_OCSP_CRLID_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_CRLID)}
      i2d_OCSP_CRLID := _i2d_OCSP_CRLID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_CRLID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_CRLID');
    {$ifend}
  end;
  
  OCSP_CRLID_it := LoadLibFunction(ADllHandle, OCSP_CRLID_it_procname);
  FuncLoadError := not assigned(OCSP_CRLID_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_CRLID_it_allownil)}
    OCSP_CRLID_it := ERR_OCSP_CRLID_it;
    {$ifend}
    {$if declared(OCSP_CRLID_it_introduced)}
    if LibVersion < OCSP_CRLID_it_introduced then
    begin
      {$if declared(FC_OCSP_CRLID_it)}
      OCSP_CRLID_it := FC_OCSP_CRLID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_CRLID_it_removed)}
    if OCSP_CRLID_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_CRLID_it)}
      OCSP_CRLID_it := _OCSP_CRLID_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_CRLID_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_CRLID_it');
    {$ifend}
  end;
  
  OCSP_SERVICELOC_new := LoadLibFunction(ADllHandle, OCSP_SERVICELOC_new_procname);
  FuncLoadError := not assigned(OCSP_SERVICELOC_new);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SERVICELOC_new_allownil)}
    OCSP_SERVICELOC_new := ERR_OCSP_SERVICELOC_new;
    {$ifend}
    {$if declared(OCSP_SERVICELOC_new_introduced)}
    if LibVersion < OCSP_SERVICELOC_new_introduced then
    begin
      {$if declared(FC_OCSP_SERVICELOC_new)}
      OCSP_SERVICELOC_new := FC_OCSP_SERVICELOC_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SERVICELOC_new_removed)}
    if OCSP_SERVICELOC_new_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SERVICELOC_new)}
      OCSP_SERVICELOC_new := _OCSP_SERVICELOC_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SERVICELOC_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SERVICELOC_new');
    {$ifend}
  end;
  
  OCSP_SERVICELOC_free := LoadLibFunction(ADllHandle, OCSP_SERVICELOC_free_procname);
  FuncLoadError := not assigned(OCSP_SERVICELOC_free);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SERVICELOC_free_allownil)}
    OCSP_SERVICELOC_free := ERR_OCSP_SERVICELOC_free;
    {$ifend}
    {$if declared(OCSP_SERVICELOC_free_introduced)}
    if LibVersion < OCSP_SERVICELOC_free_introduced then
    begin
      {$if declared(FC_OCSP_SERVICELOC_free)}
      OCSP_SERVICELOC_free := FC_OCSP_SERVICELOC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SERVICELOC_free_removed)}
    if OCSP_SERVICELOC_free_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SERVICELOC_free)}
      OCSP_SERVICELOC_free := _OCSP_SERVICELOC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SERVICELOC_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SERVICELOC_free');
    {$ifend}
  end;
  
  d2i_OCSP_SERVICELOC := LoadLibFunction(ADllHandle, d2i_OCSP_SERVICELOC_procname);
  FuncLoadError := not assigned(d2i_OCSP_SERVICELOC);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OCSP_SERVICELOC_allownil)}
    d2i_OCSP_SERVICELOC := ERR_d2i_OCSP_SERVICELOC;
    {$ifend}
    {$if declared(d2i_OCSP_SERVICELOC_introduced)}
    if LibVersion < d2i_OCSP_SERVICELOC_introduced then
    begin
      {$if declared(FC_d2i_OCSP_SERVICELOC)}
      d2i_OCSP_SERVICELOC := FC_d2i_OCSP_SERVICELOC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OCSP_SERVICELOC_removed)}
    if d2i_OCSP_SERVICELOC_removed <= LibVersion then
    begin
      {$if declared(_d2i_OCSP_SERVICELOC)}
      d2i_OCSP_SERVICELOC := _d2i_OCSP_SERVICELOC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OCSP_SERVICELOC_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OCSP_SERVICELOC');
    {$ifend}
  end;
  
  i2d_OCSP_SERVICELOC := LoadLibFunction(ADllHandle, i2d_OCSP_SERVICELOC_procname);
  FuncLoadError := not assigned(i2d_OCSP_SERVICELOC);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OCSP_SERVICELOC_allownil)}
    i2d_OCSP_SERVICELOC := ERR_i2d_OCSP_SERVICELOC;
    {$ifend}
    {$if declared(i2d_OCSP_SERVICELOC_introduced)}
    if LibVersion < i2d_OCSP_SERVICELOC_introduced then
    begin
      {$if declared(FC_i2d_OCSP_SERVICELOC)}
      i2d_OCSP_SERVICELOC := FC_i2d_OCSP_SERVICELOC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OCSP_SERVICELOC_removed)}
    if i2d_OCSP_SERVICELOC_removed <= LibVersion then
    begin
      {$if declared(_i2d_OCSP_SERVICELOC)}
      i2d_OCSP_SERVICELOC := _i2d_OCSP_SERVICELOC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OCSP_SERVICELOC_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OCSP_SERVICELOC');
    {$ifend}
  end;
  
  OCSP_SERVICELOC_it := LoadLibFunction(ADllHandle, OCSP_SERVICELOC_it_procname);
  FuncLoadError := not assigned(OCSP_SERVICELOC_it);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_SERVICELOC_it_allownil)}
    OCSP_SERVICELOC_it := ERR_OCSP_SERVICELOC_it;
    {$ifend}
    {$if declared(OCSP_SERVICELOC_it_introduced)}
    if LibVersion < OCSP_SERVICELOC_it_introduced then
    begin
      {$if declared(FC_OCSP_SERVICELOC_it)}
      OCSP_SERVICELOC_it := FC_OCSP_SERVICELOC_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_SERVICELOC_it_removed)}
    if OCSP_SERVICELOC_it_removed <= LibVersion then
    begin
      {$if declared(_OCSP_SERVICELOC_it)}
      OCSP_SERVICELOC_it := _OCSP_SERVICELOC_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_SERVICELOC_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_SERVICELOC_it');
    {$ifend}
  end;
  
  OCSP_response_status_str := LoadLibFunction(ADllHandle, OCSP_response_status_str_procname);
  FuncLoadError := not assigned(OCSP_response_status_str);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_response_status_str_allownil)}
    OCSP_response_status_str := ERR_OCSP_response_status_str;
    {$ifend}
    {$if declared(OCSP_response_status_str_introduced)}
    if LibVersion < OCSP_response_status_str_introduced then
    begin
      {$if declared(FC_OCSP_response_status_str)}
      OCSP_response_status_str := FC_OCSP_response_status_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_response_status_str_removed)}
    if OCSP_response_status_str_removed <= LibVersion then
    begin
      {$if declared(_OCSP_response_status_str)}
      OCSP_response_status_str := _OCSP_response_status_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_response_status_str_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_response_status_str');
    {$ifend}
  end;
  
  OCSP_cert_status_str := LoadLibFunction(ADllHandle, OCSP_cert_status_str_procname);
  FuncLoadError := not assigned(OCSP_cert_status_str);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_cert_status_str_allownil)}
    OCSP_cert_status_str := ERR_OCSP_cert_status_str;
    {$ifend}
    {$if declared(OCSP_cert_status_str_introduced)}
    if LibVersion < OCSP_cert_status_str_introduced then
    begin
      {$if declared(FC_OCSP_cert_status_str)}
      OCSP_cert_status_str := FC_OCSP_cert_status_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_cert_status_str_removed)}
    if OCSP_cert_status_str_removed <= LibVersion then
    begin
      {$if declared(_OCSP_cert_status_str)}
      OCSP_cert_status_str := _OCSP_cert_status_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_cert_status_str_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_cert_status_str');
    {$ifend}
  end;
  
  OCSP_crl_reason_str := LoadLibFunction(ADllHandle, OCSP_crl_reason_str_procname);
  FuncLoadError := not assigned(OCSP_crl_reason_str);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_crl_reason_str_allownil)}
    OCSP_crl_reason_str := ERR_OCSP_crl_reason_str;
    {$ifend}
    {$if declared(OCSP_crl_reason_str_introduced)}
    if LibVersion < OCSP_crl_reason_str_introduced then
    begin
      {$if declared(FC_OCSP_crl_reason_str)}
      OCSP_crl_reason_str := FC_OCSP_crl_reason_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_crl_reason_str_removed)}
    if OCSP_crl_reason_str_removed <= LibVersion then
    begin
      {$if declared(_OCSP_crl_reason_str)}
      OCSP_crl_reason_str := _OCSP_crl_reason_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_crl_reason_str_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_crl_reason_str');
    {$ifend}
  end;
  
  OCSP_REQUEST_print := LoadLibFunction(ADllHandle, OCSP_REQUEST_print_procname);
  FuncLoadError := not assigned(OCSP_REQUEST_print);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_REQUEST_print_allownil)}
    OCSP_REQUEST_print := ERR_OCSP_REQUEST_print;
    {$ifend}
    {$if declared(OCSP_REQUEST_print_introduced)}
    if LibVersion < OCSP_REQUEST_print_introduced then
    begin
      {$if declared(FC_OCSP_REQUEST_print)}
      OCSP_REQUEST_print := FC_OCSP_REQUEST_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_REQUEST_print_removed)}
    if OCSP_REQUEST_print_removed <= LibVersion then
    begin
      {$if declared(_OCSP_REQUEST_print)}
      OCSP_REQUEST_print := _OCSP_REQUEST_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_REQUEST_print_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_REQUEST_print');
    {$ifend}
  end;
  
  OCSP_RESPONSE_print := LoadLibFunction(ADllHandle, OCSP_RESPONSE_print_procname);
  FuncLoadError := not assigned(OCSP_RESPONSE_print);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_RESPONSE_print_allownil)}
    OCSP_RESPONSE_print := ERR_OCSP_RESPONSE_print;
    {$ifend}
    {$if declared(OCSP_RESPONSE_print_introduced)}
    if LibVersion < OCSP_RESPONSE_print_introduced then
    begin
      {$if declared(FC_OCSP_RESPONSE_print)}
      OCSP_RESPONSE_print := FC_OCSP_RESPONSE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_RESPONSE_print_removed)}
    if OCSP_RESPONSE_print_removed <= LibVersion then
    begin
      {$if declared(_OCSP_RESPONSE_print)}
      OCSP_RESPONSE_print := _OCSP_RESPONSE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_RESPONSE_print_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_RESPONSE_print');
    {$ifend}
  end;
  
  OCSP_basic_verify := LoadLibFunction(ADllHandle, OCSP_basic_verify_procname);
  FuncLoadError := not assigned(OCSP_basic_verify);
  if FuncLoadError then
  begin
    {$if not defined(OCSP_basic_verify_allownil)}
    OCSP_basic_verify := ERR_OCSP_basic_verify;
    {$ifend}
    {$if declared(OCSP_basic_verify_introduced)}
    if LibVersion < OCSP_basic_verify_introduced then
    begin
      {$if declared(FC_OCSP_basic_verify)}
      OCSP_basic_verify := FC_OCSP_basic_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OCSP_basic_verify_removed)}
    if OCSP_basic_verify_removed <= LibVersion then
    begin
      {$if declared(_OCSP_basic_verify)}
      OCSP_basic_verify := _OCSP_basic_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OCSP_basic_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('OCSP_basic_verify');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OCSP_CERTID_dup := nil;
  OCSP_sendreq_new := nil;
  OCSP_sendreq_bio := nil;
  OCSP_cert_to_id := nil;
  OCSP_cert_id_new := nil;
  OCSP_request_add0_id := nil;
  OCSP_request_add1_nonce := nil;
  OCSP_basic_add1_nonce := nil;
  OCSP_check_nonce := nil;
  OCSP_copy_nonce := nil;
  OCSP_request_set1_name := nil;
  OCSP_request_add1_cert := nil;
  OCSP_request_sign := nil;
  OCSP_response_status := nil;
  OCSP_response_get1_basic := nil;
  OCSP_resp_get0_signature := nil;
  OCSP_resp_get0_tbs_sigalg := nil;
  OCSP_resp_get0_respdata := nil;
  OCSP_resp_get0_signer := nil;
  OCSP_resp_count := nil;
  OCSP_resp_get0 := nil;
  OCSP_resp_get0_produced_at := nil;
  OCSP_resp_get0_certs := nil;
  OCSP_resp_get0_id := nil;
  OCSP_resp_get1_id := nil;
  OCSP_resp_find := nil;
  OCSP_single_get0_status := nil;
  OCSP_resp_find_status := nil;
  OCSP_check_validity := nil;
  OCSP_request_verify := nil;
  OCSP_id_issuer_cmp := nil;
  OCSP_id_cmp := nil;
  OCSP_request_onereq_count := nil;
  OCSP_request_onereq_get0 := nil;
  OCSP_onereq_get0_id := nil;
  OCSP_id_get0_info := nil;
  OCSP_request_is_signed := nil;
  OCSP_response_create := nil;
  OCSP_basic_add1_status := nil;
  OCSP_basic_add1_cert := nil;
  OCSP_basic_sign := nil;
  OCSP_basic_sign_ctx := nil;
  OCSP_RESPID_set_by_name := nil;
  OCSP_RESPID_set_by_key_ex := nil;
  OCSP_RESPID_set_by_key := nil;
  OCSP_RESPID_match_ex := nil;
  OCSP_RESPID_match := nil;
  OCSP_crlID_new := nil;
  OCSP_accept_responses_new := nil;
  OCSP_archive_cutoff_new := nil;
  OCSP_url_svcloc_new := nil;
  OCSP_REQUEST_get_ext_count := nil;
  OCSP_REQUEST_get_ext_by_NID := nil;
  OCSP_REQUEST_get_ext_by_OBJ := nil;
  OCSP_REQUEST_get_ext_by_critical := nil;
  OCSP_REQUEST_get_ext := nil;
  OCSP_REQUEST_delete_ext := nil;
  OCSP_REQUEST_get1_ext_d2i := nil;
  OCSP_REQUEST_add1_ext_i2d := nil;
  OCSP_REQUEST_add_ext := nil;
  OCSP_ONEREQ_get_ext_count := nil;
  OCSP_ONEREQ_get_ext_by_NID := nil;
  OCSP_ONEREQ_get_ext_by_OBJ := nil;
  OCSP_ONEREQ_get_ext_by_critical := nil;
  OCSP_ONEREQ_get_ext := nil;
  OCSP_ONEREQ_delete_ext := nil;
  OCSP_ONEREQ_get1_ext_d2i := nil;
  OCSP_ONEREQ_add1_ext_i2d := nil;
  OCSP_ONEREQ_add_ext := nil;
  OCSP_BASICRESP_get_ext_count := nil;
  OCSP_BASICRESP_get_ext_by_NID := nil;
  OCSP_BASICRESP_get_ext_by_OBJ := nil;
  OCSP_BASICRESP_get_ext_by_critical := nil;
  OCSP_BASICRESP_get_ext := nil;
  OCSP_BASICRESP_delete_ext := nil;
  OCSP_BASICRESP_get1_ext_d2i := nil;
  OCSP_BASICRESP_add1_ext_i2d := nil;
  OCSP_BASICRESP_add_ext := nil;
  OCSP_SINGLERESP_get_ext_count := nil;
  OCSP_SINGLERESP_get_ext_by_NID := nil;
  OCSP_SINGLERESP_get_ext_by_OBJ := nil;
  OCSP_SINGLERESP_get_ext_by_critical := nil;
  OCSP_SINGLERESP_get_ext := nil;
  OCSP_SINGLERESP_delete_ext := nil;
  OCSP_SINGLERESP_get1_ext_d2i := nil;
  OCSP_SINGLERESP_add1_ext_i2d := nil;
  OCSP_SINGLERESP_add_ext := nil;
  OCSP_SINGLERESP_get0_id := nil;
  OCSP_SINGLERESP_new := nil;
  OCSP_SINGLERESP_free := nil;
  d2i_OCSP_SINGLERESP := nil;
  i2d_OCSP_SINGLERESP := nil;
  OCSP_SINGLERESP_it := nil;
  OCSP_CERTSTATUS_new := nil;
  OCSP_CERTSTATUS_free := nil;
  d2i_OCSP_CERTSTATUS := nil;
  i2d_OCSP_CERTSTATUS := nil;
  OCSP_CERTSTATUS_it := nil;
  OCSP_REVOKEDINFO_new := nil;
  OCSP_REVOKEDINFO_free := nil;
  d2i_OCSP_REVOKEDINFO := nil;
  i2d_OCSP_REVOKEDINFO := nil;
  OCSP_REVOKEDINFO_it := nil;
  OCSP_BASICRESP_new := nil;
  OCSP_BASICRESP_free := nil;
  d2i_OCSP_BASICRESP := nil;
  i2d_OCSP_BASICRESP := nil;
  OCSP_BASICRESP_it := nil;
  OCSP_RESPDATA_new := nil;
  OCSP_RESPDATA_free := nil;
  d2i_OCSP_RESPDATA := nil;
  i2d_OCSP_RESPDATA := nil;
  OCSP_RESPDATA_it := nil;
  OCSP_RESPID_new := nil;
  OCSP_RESPID_free := nil;
  d2i_OCSP_RESPID := nil;
  i2d_OCSP_RESPID := nil;
  OCSP_RESPID_it := nil;
  OCSP_RESPONSE_new := nil;
  OCSP_RESPONSE_free := nil;
  d2i_OCSP_RESPONSE := nil;
  i2d_OCSP_RESPONSE := nil;
  OCSP_RESPONSE_it := nil;
  OCSP_RESPBYTES_new := nil;
  OCSP_RESPBYTES_free := nil;
  d2i_OCSP_RESPBYTES := nil;
  i2d_OCSP_RESPBYTES := nil;
  OCSP_RESPBYTES_it := nil;
  OCSP_ONEREQ_new := nil;
  OCSP_ONEREQ_free := nil;
  d2i_OCSP_ONEREQ := nil;
  i2d_OCSP_ONEREQ := nil;
  OCSP_ONEREQ_it := nil;
  OCSP_CERTID_new := nil;
  OCSP_CERTID_free := nil;
  d2i_OCSP_CERTID := nil;
  i2d_OCSP_CERTID := nil;
  OCSP_CERTID_it := nil;
  OCSP_REQUEST_new := nil;
  OCSP_REQUEST_free := nil;
  d2i_OCSP_REQUEST := nil;
  i2d_OCSP_REQUEST := nil;
  OCSP_REQUEST_it := nil;
  OCSP_SIGNATURE_new := nil;
  OCSP_SIGNATURE_free := nil;
  d2i_OCSP_SIGNATURE := nil;
  i2d_OCSP_SIGNATURE := nil;
  OCSP_SIGNATURE_it := nil;
  OCSP_REQINFO_new := nil;
  OCSP_REQINFO_free := nil;
  d2i_OCSP_REQINFO := nil;
  i2d_OCSP_REQINFO := nil;
  OCSP_REQINFO_it := nil;
  OCSP_CRLID_new := nil;
  OCSP_CRLID_free := nil;
  d2i_OCSP_CRLID := nil;
  i2d_OCSP_CRLID := nil;
  OCSP_CRLID_it := nil;
  OCSP_SERVICELOC_new := nil;
  OCSP_SERVICELOC_free := nil;
  d2i_OCSP_SERVICELOC := nil;
  i2d_OCSP_SERVICELOC := nil;
  OCSP_SERVICELOC_it := nil;
  OCSP_response_status_str := nil;
  OCSP_cert_status_str := nil;
  OCSP_crl_reason_str := nil;
  OCSP_REQUEST_print := nil;
  OCSP_RESPONSE_print := nil;
  OCSP_basic_verify := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.