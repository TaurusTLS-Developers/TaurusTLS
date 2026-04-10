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

unit TaurusTLSHeaders_http;

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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_HTTP_bio_cb_t = function(bio: PBIO; arg: Pointer; connect: TIdC_INT; detail: TIdC_INT): Pbio_st; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_HTTP_NAME = 'http';
  OSSL_HTTPS_NAME = 'https';
  OSSL_HTTP_PREFIX = OSSL_HTTP_NAME':;
  OSSL_HTTPS_PREFIX = OSSL_HTTPS_NAME':;
  OSSL_HTTP_PORT = '80';
  OSSL_HTTPS_PORT = '443';
  OPENSSL_NO_PROXY = 'NO_PROXY';
  OPENSSL_HTTP_PROXY = 'HTTP_PROXY';
  OPENSSL_HTTPS_PROXY = 'HTTPS_PROXY';
  OSSL_HTTP_DEFAULT_MAX_LINE_LEN = (4*1024);
  OSSL_HTTP_DEFAULT_MAX_RESP_LEN = (100*1024);
  OSSL_HTTP_DEFAULT_MAX_CRL_LEN = (32*1024*1024);
  OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES = 256;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_parse_url: function(url: PIdAnsiChar; pscheme: PPIdAnsiChar; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_parse_url}

  OSSL_HTTP_REQ_CTX_new: function(wbio: PBIO; rbio: PBIO; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_new}

  OSSL_HTTP_REQ_CTX_free: function(rctx: POSSL_HTTP_REQ_CTX): void; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_free}

  OSSL_HTTP_REQ_CTX_set_request_line: function(rctx: POSSL_HTTP_REQ_CTX; method_POST: TIdC_INT; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set_request_line}

  OSSL_HTTP_REQ_CTX_add1_header: function(rctx: POSSL_HTTP_REQ_CTX; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_add1_header}

  OSSL_HTTP_REQ_CTX_set_expected: function(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; asn1: TIdC_INT; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set_expected}

  OSSL_HTTP_REQ_CTX_set1_req: function(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set1_req}

  OSSL_HTTP_REQ_CTX_nbio: function(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_nbio}

  OSSL_HTTP_REQ_CTX_nbio_d2i: function(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_nbio_d2i}

  OSSL_HTTP_REQ_CTX_exchange: function(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_exchange}

  OSSL_HTTP_REQ_CTX_get0_mem_bio: function(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_get0_mem_bio}

  OSSL_HTTP_REQ_CTX_get_resp_len: function(rctx: POSSL_HTTP_REQ_CTX): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_get_resp_len}

  OSSL_HTTP_REQ_CTX_set_max_response_length: function(rctx: POSSL_HTTP_REQ_CTX; len: TIdC_ULONG): void; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set_max_response_length}

  OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines: function(rctx: POSSL_HTTP_REQ_CTX; count: TIdC_SIZET): void; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines}

  OSSL_HTTP_is_alive: function(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_is_alive}

  OSSL_HTTP_open: function(server: PIdAnsiChar; port: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; use_ssl: TIdC_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; overall_timeout: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_open}

  OSSL_HTTP_proxy_connect: function(bio: PBIO; server: PIdAnsiChar; port: PIdAnsiChar; proxyuser: PIdAnsiChar; proxypass: PIdAnsiChar; timeout: TIdC_INT; bio_err: PBIO; prog: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_proxy_connect}

  OSSL_HTTP_set1_request: function(rctx: POSSL_HTTP_REQ_CTX; path: PIdAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_set1_request}

  OSSL_HTTP_exchange: function(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPIdAnsiChar): PBIO; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_exchange}

  OSSL_HTTP_get: function(url: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_get}

  OSSL_HTTP_transfer: function(prctx: PPOSSL_HTTP_REQ_CTX; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar; use_ssl: TIdC_INT; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_transfer}

  OSSL_HTTP_close: function(rctx: POSSL_HTTP_REQ_CTX; ok: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_close}

  OSSL_HTTP_parse_url: function(url: PIdAnsiChar; pssl: PIdC_INT; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_parse_url}

  OSSL_HTTP_adapt_proxy: function(proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; server: PIdAnsiChar; use_ssl: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_HTTP_adapt_proxy}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_parse_url(url: PIdAnsiChar; pscheme: PPIdAnsiChar; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_HTTP_REQ_CTX_new(wbio: PBIO; rbio: PBIO; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl;
function OSSL_HTTP_REQ_CTX_free(rctx: POSSL_HTTP_REQ_CTX): void; cdecl;
function OSSL_HTTP_REQ_CTX_set_request_line(rctx: POSSL_HTTP_REQ_CTX; method_POST: TIdC_INT; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_HTTP_REQ_CTX_add1_header(rctx: POSSL_HTTP_REQ_CTX; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_HTTP_REQ_CTX_set_expected(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; asn1: TIdC_INT; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl;
function OSSL_HTTP_REQ_CTX_set1_req(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TIdC_INT; cdecl;
function OSSL_HTTP_REQ_CTX_nbio(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl;
function OSSL_HTTP_REQ_CTX_nbio_d2i(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl;
function OSSL_HTTP_REQ_CTX_exchange(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl;
function OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl;
function OSSL_HTTP_REQ_CTX_get_resp_len(rctx: POSSL_HTTP_REQ_CTX): TIdC_SIZET; cdecl;
function OSSL_HTTP_REQ_CTX_set_max_response_length(rctx: POSSL_HTTP_REQ_CTX; len: TIdC_ULONG): void; cdecl;
function OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(rctx: POSSL_HTTP_REQ_CTX; count: TIdC_SIZET): void; cdecl;
function OSSL_HTTP_is_alive(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl;
function OSSL_HTTP_open(server: PIdAnsiChar; port: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; use_ssl: TIdC_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; overall_timeout: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl;
function OSSL_HTTP_proxy_connect(bio: PBIO; server: PIdAnsiChar; port: PIdAnsiChar; proxyuser: PIdAnsiChar; proxypass: PIdAnsiChar; timeout: TIdC_INT; bio_err: PBIO; prog: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_HTTP_set1_request(rctx: POSSL_HTTP_REQ_CTX; path: PIdAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl;
function OSSL_HTTP_exchange(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPIdAnsiChar): PBIO; cdecl;
function OSSL_HTTP_get(url: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT): PBIO; cdecl;
function OSSL_HTTP_transfer(prctx: PPOSSL_HTTP_REQ_CTX; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar; use_ssl: TIdC_INT; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): PBIO; cdecl;
function OSSL_HTTP_close(rctx: POSSL_HTTP_REQ_CTX; ok: TIdC_INT): TIdC_INT; cdecl;
function OSSL_HTTP_parse_url(url: PIdAnsiChar; pssl: PIdC_INT; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_HTTP_adapt_proxy(proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; server: PIdAnsiChar; use_ssl: TIdC_INT): PIdAnsiChar; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

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

function OSSL_parse_url(url: PIdAnsiChar; pscheme: PPIdAnsiChar; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_parse_url';
function OSSL_HTTP_REQ_CTX_new(wbio: PBIO; rbio: PBIO; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_new';
function OSSL_HTTP_REQ_CTX_free(rctx: POSSL_HTTP_REQ_CTX): void; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_free';
function OSSL_HTTP_REQ_CTX_set_request_line(rctx: POSSL_HTTP_REQ_CTX; method_POST: TIdC_INT; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set_request_line';
function OSSL_HTTP_REQ_CTX_add1_header(rctx: POSSL_HTTP_REQ_CTX; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_add1_header';
function OSSL_HTTP_REQ_CTX_set_expected(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; asn1: TIdC_INT; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set_expected';
function OSSL_HTTP_REQ_CTX_set1_req(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set1_req';
function OSSL_HTTP_REQ_CTX_nbio(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_nbio';
function OSSL_HTTP_REQ_CTX_nbio_d2i(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_nbio_d2i';
function OSSL_HTTP_REQ_CTX_exchange(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_exchange';
function OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_get0_mem_bio';
function OSSL_HTTP_REQ_CTX_get_resp_len(rctx: POSSL_HTTP_REQ_CTX): TIdC_SIZET; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_get_resp_len';
function OSSL_HTTP_REQ_CTX_set_max_response_length(rctx: POSSL_HTTP_REQ_CTX; len: TIdC_ULONG): void; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set_max_response_length';
function OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(rctx: POSSL_HTTP_REQ_CTX; count: TIdC_SIZET): void; cdecl external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines';
function OSSL_HTTP_is_alive(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_is_alive';
function OSSL_HTTP_open(server: PIdAnsiChar; port: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; use_ssl: TIdC_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; overall_timeout: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl external CLibCrypto name 'OSSL_HTTP_open';
function OSSL_HTTP_proxy_connect(bio: PBIO; server: PIdAnsiChar; port: PIdAnsiChar; proxyuser: PIdAnsiChar; proxypass: PIdAnsiChar; timeout: TIdC_INT; bio_err: PBIO; prog: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_proxy_connect';
function OSSL_HTTP_set1_request(rctx: POSSL_HTTP_REQ_CTX; path: PIdAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_set1_request';
function OSSL_HTTP_exchange(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPIdAnsiChar): PBIO; cdecl external CLibCrypto name 'OSSL_HTTP_exchange';
function OSSL_HTTP_get(url: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT): PBIO; cdecl external CLibCrypto name 'OSSL_HTTP_get';
function OSSL_HTTP_transfer(prctx: PPOSSL_HTTP_REQ_CTX; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar; use_ssl: TIdC_INT; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): PBIO; cdecl external CLibCrypto name 'OSSL_HTTP_transfer';
function OSSL_HTTP_close(rctx: POSSL_HTTP_REQ_CTX; ok: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_close';
function OSSL_HTTP_parse_url(url: PIdAnsiChar; pssl: PIdC_INT; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_HTTP_parse_url';
function OSSL_HTTP_adapt_proxy(proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; server: PIdAnsiChar; use_ssl: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_HTTP_adapt_proxy';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_parse_url_procname = 'OSSL_parse_url';
  OSSL_parse_url_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_new_procname = 'OSSL_HTTP_REQ_CTX_new';
  OSSL_HTTP_REQ_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_free_procname = 'OSSL_HTTP_REQ_CTX_free';
  OSSL_HTTP_REQ_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_set_request_line_procname = 'OSSL_HTTP_REQ_CTX_set_request_line';
  OSSL_HTTP_REQ_CTX_set_request_line_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_add1_header_procname = 'OSSL_HTTP_REQ_CTX_add1_header';
  OSSL_HTTP_REQ_CTX_add1_header_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_set_expected_procname = 'OSSL_HTTP_REQ_CTX_set_expected';
  OSSL_HTTP_REQ_CTX_set_expected_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_set1_req_procname = 'OSSL_HTTP_REQ_CTX_set1_req';
  OSSL_HTTP_REQ_CTX_set1_req_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_nbio_procname = 'OSSL_HTTP_REQ_CTX_nbio';
  OSSL_HTTP_REQ_CTX_nbio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_nbio_d2i_procname = 'OSSL_HTTP_REQ_CTX_nbio_d2i';
  OSSL_HTTP_REQ_CTX_nbio_d2i_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_exchange_procname = 'OSSL_HTTP_REQ_CTX_exchange';
  OSSL_HTTP_REQ_CTX_exchange_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_get0_mem_bio_procname = 'OSSL_HTTP_REQ_CTX_get0_mem_bio';
  OSSL_HTTP_REQ_CTX_get0_mem_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_get_resp_len_procname = 'OSSL_HTTP_REQ_CTX_get_resp_len';
  OSSL_HTTP_REQ_CTX_get_resp_len_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_set_max_response_length_procname = 'OSSL_HTTP_REQ_CTX_set_max_response_length';
  OSSL_HTTP_REQ_CTX_set_max_response_length_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_procname = 'OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines';
  OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_HTTP_is_alive_procname = 'OSSL_HTTP_is_alive';
  OSSL_HTTP_is_alive_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_open_procname = 'OSSL_HTTP_open';
  OSSL_HTTP_open_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_proxy_connect_procname = 'OSSL_HTTP_proxy_connect';
  OSSL_HTTP_proxy_connect_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_set1_request_procname = 'OSSL_HTTP_set1_request';
  OSSL_HTTP_set1_request_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_exchange_procname = 'OSSL_HTTP_exchange';
  OSSL_HTTP_exchange_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_get_procname = 'OSSL_HTTP_get';
  OSSL_HTTP_get_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_transfer_procname = 'OSSL_HTTP_transfer';
  OSSL_HTTP_transfer_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_close_procname = 'OSSL_HTTP_close';
  OSSL_HTTP_close_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_parse_url_procname = 'OSSL_HTTP_parse_url';
  OSSL_HTTP_parse_url_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_HTTP_adapt_proxy_procname = 'OSSL_HTTP_adapt_proxy';
  OSSL_HTTP_adapt_proxy_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_parse_url(url: PIdAnsiChar; pscheme: PPIdAnsiChar; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_parse_url_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_new(wbio: PBIO; rbio: PBIO; buf_size: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_new_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_free(rctx: POSSL_HTTP_REQ_CTX): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_free_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_set_request_line(rctx: POSSL_HTTP_REQ_CTX; method_POST: TIdC_INT; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_set_request_line_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_add1_header(rctx: POSSL_HTTP_REQ_CTX; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_add1_header_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_set_expected(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; asn1: TIdC_INT; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_set_expected_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_set1_req(rctx: POSSL_HTTP_REQ_CTX; content_type: PIdAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_set1_req_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_nbio(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_nbio_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_nbio_d2i(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_nbio_d2i_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_exchange(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_exchange_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_get0_mem_bio_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_get_resp_len(rctx: POSSL_HTTP_REQ_CTX): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_get_resp_len_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_set_max_response_length(rctx: POSSL_HTTP_REQ_CTX; len: TIdC_ULONG): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_set_max_response_length_procname);
end;

function ERR_OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(rctx: POSSL_HTTP_REQ_CTX; count: TIdC_SIZET): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_procname);
end;

function ERR_OSSL_HTTP_is_alive(rctx: POSSL_HTTP_REQ_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_is_alive_procname);
end;

function ERR_OSSL_HTTP_open(server: PIdAnsiChar; port: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; use_ssl: TIdC_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; overall_timeout: TIdC_INT): POSSL_HTTP_REQ_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_open_procname);
end;

function ERR_OSSL_HTTP_proxy_connect(bio: PBIO; server: PIdAnsiChar; port: PIdAnsiChar; proxyuser: PIdAnsiChar; proxypass: PIdAnsiChar; timeout: TIdC_INT; bio_err: PBIO; prog: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_proxy_connect_procname);
end;

function ERR_OSSL_HTTP_set1_request(rctx: POSSL_HTTP_REQ_CTX; path: PIdAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_set1_request_procname);
end;

function ERR_OSSL_HTTP_exchange(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPIdAnsiChar): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_exchange_procname);
end;

function ERR_OSSL_HTTP_get(url: PIdAnsiChar; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_get_procname);
end;

function ERR_OSSL_HTTP_transfer(prctx: PPOSSL_HTTP_REQ_CTX; server: PIdAnsiChar; port: PIdAnsiChar; path: PIdAnsiChar; use_ssl: TIdC_INT; proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: Pointer; buf_size: TIdC_INT; headers: Pstack_st_CONF_VALUE; content_type: PIdAnsiChar; req: PBIO; expected_content_type: PIdAnsiChar; expect_asn1: TIdC_INT; max_resp_len: TIdC_SIZET; timeout: TIdC_INT; keep_alive: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_transfer_procname);
end;

function ERR_OSSL_HTTP_close(rctx: POSSL_HTTP_REQ_CTX; ok: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_close_procname);
end;

function ERR_OSSL_HTTP_parse_url(url: PIdAnsiChar; pssl: PIdC_INT; puser: PPIdAnsiChar; phost: PPIdAnsiChar; pport: PPIdAnsiChar; pport_num: PIdC_INT; ppath: PPIdAnsiChar; pquery: PPIdAnsiChar; pfrag: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_parse_url_procname);
end;

function ERR_OSSL_HTTP_adapt_proxy(proxy: PIdAnsiChar; no_proxy: PIdAnsiChar; server: PIdAnsiChar; use_ssl: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_HTTP_adapt_proxy_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_parse_url := LoadLibFunction(ADllHandle, OSSL_parse_url_procname);
  FuncLoadError := not assigned(OSSL_parse_url);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_parse_url_allownil)}
    OSSL_parse_url := ERR_OSSL_parse_url;
    {$ifend}
    {$if declared(OSSL_parse_url_introduced)}
    if LibVersion < OSSL_parse_url_introduced then
    begin
      {$if declared(FC_OSSL_parse_url)}
      OSSL_parse_url := FC_OSSL_parse_url;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_parse_url_removed)}
    if OSSL_parse_url_removed <= LibVersion then
    begin
      {$if declared(_OSSL_parse_url)}
      OSSL_parse_url := _OSSL_parse_url;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_parse_url_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_parse_url');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_new := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_new_allownil)}
    OSSL_HTTP_REQ_CTX_new := ERR_OSSL_HTTP_REQ_CTX_new;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_new_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_new_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_new)}
      OSSL_HTTP_REQ_CTX_new := FC_OSSL_HTTP_REQ_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_new_removed)}
    if OSSL_HTTP_REQ_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_new)}
      OSSL_HTTP_REQ_CTX_new := _OSSL_HTTP_REQ_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_new');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_free := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_free_allownil)}
    OSSL_HTTP_REQ_CTX_free := ERR_OSSL_HTTP_REQ_CTX_free;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_free_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_free_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_free)}
      OSSL_HTTP_REQ_CTX_free := FC_OSSL_HTTP_REQ_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_free_removed)}
    if OSSL_HTTP_REQ_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_free)}
      OSSL_HTTP_REQ_CTX_free := _OSSL_HTTP_REQ_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_free');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_set_request_line := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_set_request_line_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_set_request_line);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_set_request_line_allownil)}
    OSSL_HTTP_REQ_CTX_set_request_line := ERR_OSSL_HTTP_REQ_CTX_set_request_line;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_request_line_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_set_request_line_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_set_request_line)}
      OSSL_HTTP_REQ_CTX_set_request_line := FC_OSSL_HTTP_REQ_CTX_set_request_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_request_line_removed)}
    if OSSL_HTTP_REQ_CTX_set_request_line_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_set_request_line)}
      OSSL_HTTP_REQ_CTX_set_request_line := _OSSL_HTTP_REQ_CTX_set_request_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_set_request_line_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_set_request_line');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_add1_header := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_add1_header_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_add1_header);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_add1_header_allownil)}
    OSSL_HTTP_REQ_CTX_add1_header := ERR_OSSL_HTTP_REQ_CTX_add1_header;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_add1_header_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_add1_header_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_add1_header)}
      OSSL_HTTP_REQ_CTX_add1_header := FC_OSSL_HTTP_REQ_CTX_add1_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_add1_header_removed)}
    if OSSL_HTTP_REQ_CTX_add1_header_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_add1_header)}
      OSSL_HTTP_REQ_CTX_add1_header := _OSSL_HTTP_REQ_CTX_add1_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_add1_header_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_add1_header');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_set_expected := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_set_expected_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_set_expected);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_set_expected_allownil)}
    OSSL_HTTP_REQ_CTX_set_expected := ERR_OSSL_HTTP_REQ_CTX_set_expected;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_expected_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_set_expected_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_set_expected)}
      OSSL_HTTP_REQ_CTX_set_expected := FC_OSSL_HTTP_REQ_CTX_set_expected;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_expected_removed)}
    if OSSL_HTTP_REQ_CTX_set_expected_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_set_expected)}
      OSSL_HTTP_REQ_CTX_set_expected := _OSSL_HTTP_REQ_CTX_set_expected;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_set_expected_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_set_expected');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_set1_req := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_set1_req_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_set1_req);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_set1_req_allownil)}
    OSSL_HTTP_REQ_CTX_set1_req := ERR_OSSL_HTTP_REQ_CTX_set1_req;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set1_req_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_set1_req_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_set1_req)}
      OSSL_HTTP_REQ_CTX_set1_req := FC_OSSL_HTTP_REQ_CTX_set1_req;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set1_req_removed)}
    if OSSL_HTTP_REQ_CTX_set1_req_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_set1_req)}
      OSSL_HTTP_REQ_CTX_set1_req := _OSSL_HTTP_REQ_CTX_set1_req;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_set1_req_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_set1_req');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_nbio := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_nbio_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_nbio);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_nbio_allownil)}
    OSSL_HTTP_REQ_CTX_nbio := ERR_OSSL_HTTP_REQ_CTX_nbio;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_nbio_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_nbio_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_nbio)}
      OSSL_HTTP_REQ_CTX_nbio := FC_OSSL_HTTP_REQ_CTX_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_nbio_removed)}
    if OSSL_HTTP_REQ_CTX_nbio_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_nbio)}
      OSSL_HTTP_REQ_CTX_nbio := _OSSL_HTTP_REQ_CTX_nbio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_nbio_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_nbio');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_nbio_d2i := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_nbio_d2i_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_nbio_d2i);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_nbio_d2i_allownil)}
    OSSL_HTTP_REQ_CTX_nbio_d2i := ERR_OSSL_HTTP_REQ_CTX_nbio_d2i;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_nbio_d2i_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_nbio_d2i_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_nbio_d2i)}
      OSSL_HTTP_REQ_CTX_nbio_d2i := FC_OSSL_HTTP_REQ_CTX_nbio_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_nbio_d2i_removed)}
    if OSSL_HTTP_REQ_CTX_nbio_d2i_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_nbio_d2i)}
      OSSL_HTTP_REQ_CTX_nbio_d2i := _OSSL_HTTP_REQ_CTX_nbio_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_nbio_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_nbio_d2i');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_exchange := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_exchange_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_exchange);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_exchange_allownil)}
    OSSL_HTTP_REQ_CTX_exchange := ERR_OSSL_HTTP_REQ_CTX_exchange;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_exchange_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_exchange_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_exchange)}
      OSSL_HTTP_REQ_CTX_exchange := FC_OSSL_HTTP_REQ_CTX_exchange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_exchange_removed)}
    if OSSL_HTTP_REQ_CTX_exchange_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_exchange)}
      OSSL_HTTP_REQ_CTX_exchange := _OSSL_HTTP_REQ_CTX_exchange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_exchange_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_exchange');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_get0_mem_bio := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_get0_mem_bio_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_get0_mem_bio);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_get0_mem_bio_allownil)}
    OSSL_HTTP_REQ_CTX_get0_mem_bio := ERR_OSSL_HTTP_REQ_CTX_get0_mem_bio;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_get0_mem_bio_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_get0_mem_bio_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_get0_mem_bio)}
      OSSL_HTTP_REQ_CTX_get0_mem_bio := FC_OSSL_HTTP_REQ_CTX_get0_mem_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_get0_mem_bio_removed)}
    if OSSL_HTTP_REQ_CTX_get0_mem_bio_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_get0_mem_bio)}
      OSSL_HTTP_REQ_CTX_get0_mem_bio := _OSSL_HTTP_REQ_CTX_get0_mem_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_get0_mem_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_get0_mem_bio');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_get_resp_len := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_get_resp_len_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_get_resp_len);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_get_resp_len_allownil)}
    OSSL_HTTP_REQ_CTX_get_resp_len := ERR_OSSL_HTTP_REQ_CTX_get_resp_len;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_get_resp_len_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_get_resp_len_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_get_resp_len)}
      OSSL_HTTP_REQ_CTX_get_resp_len := FC_OSSL_HTTP_REQ_CTX_get_resp_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_get_resp_len_removed)}
    if OSSL_HTTP_REQ_CTX_get_resp_len_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_get_resp_len)}
      OSSL_HTTP_REQ_CTX_get_resp_len := _OSSL_HTTP_REQ_CTX_get_resp_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_get_resp_len_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_get_resp_len');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_set_max_response_length := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_set_max_response_length_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_set_max_response_length);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_set_max_response_length_allownil)}
    OSSL_HTTP_REQ_CTX_set_max_response_length := ERR_OSSL_HTTP_REQ_CTX_set_max_response_length;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_max_response_length_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_set_max_response_length_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_set_max_response_length)}
      OSSL_HTTP_REQ_CTX_set_max_response_length := FC_OSSL_HTTP_REQ_CTX_set_max_response_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_max_response_length_removed)}
    if OSSL_HTTP_REQ_CTX_set_max_response_length_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_set_max_response_length)}
      OSSL_HTTP_REQ_CTX_set_max_response_length := _OSSL_HTTP_REQ_CTX_set_max_response_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_set_max_response_length_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_set_max_response_length');
    {$ifend}
  end;
  
  OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines := LoadLibFunction(ADllHandle, OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_procname);
  FuncLoadError := not assigned(OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_allownil)}
    OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines := ERR_OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_introduced)}
    if LibVersion < OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines)}
      OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines := FC_OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_removed)}
    if OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines)}
      OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines := _OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines');
    {$ifend}
  end;
  
  OSSL_HTTP_is_alive := LoadLibFunction(ADllHandle, OSSL_HTTP_is_alive_procname);
  FuncLoadError := not assigned(OSSL_HTTP_is_alive);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_is_alive_allownil)}
    OSSL_HTTP_is_alive := ERR_OSSL_HTTP_is_alive;
    {$ifend}
    {$if declared(OSSL_HTTP_is_alive_introduced)}
    if LibVersion < OSSL_HTTP_is_alive_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_is_alive)}
      OSSL_HTTP_is_alive := FC_OSSL_HTTP_is_alive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_is_alive_removed)}
    if OSSL_HTTP_is_alive_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_is_alive)}
      OSSL_HTTP_is_alive := _OSSL_HTTP_is_alive;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_is_alive_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_is_alive');
    {$ifend}
  end;
  
  OSSL_HTTP_open := LoadLibFunction(ADllHandle, OSSL_HTTP_open_procname);
  FuncLoadError := not assigned(OSSL_HTTP_open);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_open_allownil)}
    OSSL_HTTP_open := ERR_OSSL_HTTP_open;
    {$ifend}
    {$if declared(OSSL_HTTP_open_introduced)}
    if LibVersion < OSSL_HTTP_open_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_open)}
      OSSL_HTTP_open := FC_OSSL_HTTP_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_open_removed)}
    if OSSL_HTTP_open_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_open)}
      OSSL_HTTP_open := _OSSL_HTTP_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_open_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_open');
    {$ifend}
  end;
  
  OSSL_HTTP_proxy_connect := LoadLibFunction(ADllHandle, OSSL_HTTP_proxy_connect_procname);
  FuncLoadError := not assigned(OSSL_HTTP_proxy_connect);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_proxy_connect_allownil)}
    OSSL_HTTP_proxy_connect := ERR_OSSL_HTTP_proxy_connect;
    {$ifend}
    {$if declared(OSSL_HTTP_proxy_connect_introduced)}
    if LibVersion < OSSL_HTTP_proxy_connect_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_proxy_connect)}
      OSSL_HTTP_proxy_connect := FC_OSSL_HTTP_proxy_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_proxy_connect_removed)}
    if OSSL_HTTP_proxy_connect_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_proxy_connect)}
      OSSL_HTTP_proxy_connect := _OSSL_HTTP_proxy_connect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_proxy_connect_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_proxy_connect');
    {$ifend}
  end;
  
  OSSL_HTTP_set1_request := LoadLibFunction(ADllHandle, OSSL_HTTP_set1_request_procname);
  FuncLoadError := not assigned(OSSL_HTTP_set1_request);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_set1_request_allownil)}
    OSSL_HTTP_set1_request := ERR_OSSL_HTTP_set1_request;
    {$ifend}
    {$if declared(OSSL_HTTP_set1_request_introduced)}
    if LibVersion < OSSL_HTTP_set1_request_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_set1_request)}
      OSSL_HTTP_set1_request := FC_OSSL_HTTP_set1_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_set1_request_removed)}
    if OSSL_HTTP_set1_request_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_set1_request)}
      OSSL_HTTP_set1_request := _OSSL_HTTP_set1_request;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_set1_request_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_set1_request');
    {$ifend}
  end;
  
  OSSL_HTTP_exchange := LoadLibFunction(ADllHandle, OSSL_HTTP_exchange_procname);
  FuncLoadError := not assigned(OSSL_HTTP_exchange);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_exchange_allownil)}
    OSSL_HTTP_exchange := ERR_OSSL_HTTP_exchange;
    {$ifend}
    {$if declared(OSSL_HTTP_exchange_introduced)}
    if LibVersion < OSSL_HTTP_exchange_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_exchange)}
      OSSL_HTTP_exchange := FC_OSSL_HTTP_exchange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_exchange_removed)}
    if OSSL_HTTP_exchange_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_exchange)}
      OSSL_HTTP_exchange := _OSSL_HTTP_exchange;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_exchange_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_exchange');
    {$ifend}
  end;
  
  OSSL_HTTP_get := LoadLibFunction(ADllHandle, OSSL_HTTP_get_procname);
  FuncLoadError := not assigned(OSSL_HTTP_get);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_get_allownil)}
    OSSL_HTTP_get := ERR_OSSL_HTTP_get;
    {$ifend}
    {$if declared(OSSL_HTTP_get_introduced)}
    if LibVersion < OSSL_HTTP_get_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_get)}
      OSSL_HTTP_get := FC_OSSL_HTTP_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_get_removed)}
    if OSSL_HTTP_get_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_get)}
      OSSL_HTTP_get := _OSSL_HTTP_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_get_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_get');
    {$ifend}
  end;
  
  OSSL_HTTP_transfer := LoadLibFunction(ADllHandle, OSSL_HTTP_transfer_procname);
  FuncLoadError := not assigned(OSSL_HTTP_transfer);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_transfer_allownil)}
    OSSL_HTTP_transfer := ERR_OSSL_HTTP_transfer;
    {$ifend}
    {$if declared(OSSL_HTTP_transfer_introduced)}
    if LibVersion < OSSL_HTTP_transfer_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_transfer)}
      OSSL_HTTP_transfer := FC_OSSL_HTTP_transfer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_transfer_removed)}
    if OSSL_HTTP_transfer_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_transfer)}
      OSSL_HTTP_transfer := _OSSL_HTTP_transfer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_transfer_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_transfer');
    {$ifend}
  end;
  
  OSSL_HTTP_close := LoadLibFunction(ADllHandle, OSSL_HTTP_close_procname);
  FuncLoadError := not assigned(OSSL_HTTP_close);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_close_allownil)}
    OSSL_HTTP_close := ERR_OSSL_HTTP_close;
    {$ifend}
    {$if declared(OSSL_HTTP_close_introduced)}
    if LibVersion < OSSL_HTTP_close_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_close)}
      OSSL_HTTP_close := FC_OSSL_HTTP_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_close_removed)}
    if OSSL_HTTP_close_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_close)}
      OSSL_HTTP_close := _OSSL_HTTP_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_close_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_close');
    {$ifend}
  end;
  
  OSSL_HTTP_parse_url := LoadLibFunction(ADllHandle, OSSL_HTTP_parse_url_procname);
  FuncLoadError := not assigned(OSSL_HTTP_parse_url);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_parse_url_allownil)}
    OSSL_HTTP_parse_url := ERR_OSSL_HTTP_parse_url;
    {$ifend}
    {$if declared(OSSL_HTTP_parse_url_introduced)}
    if LibVersion < OSSL_HTTP_parse_url_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_parse_url)}
      OSSL_HTTP_parse_url := FC_OSSL_HTTP_parse_url;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_parse_url_removed)}
    if OSSL_HTTP_parse_url_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_parse_url)}
      OSSL_HTTP_parse_url := _OSSL_HTTP_parse_url;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_parse_url_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_parse_url');
    {$ifend}
  end;
  
  OSSL_HTTP_adapt_proxy := LoadLibFunction(ADllHandle, OSSL_HTTP_adapt_proxy_procname);
  FuncLoadError := not assigned(OSSL_HTTP_adapt_proxy);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_HTTP_adapt_proxy_allownil)}
    OSSL_HTTP_adapt_proxy := ERR_OSSL_HTTP_adapt_proxy;
    {$ifend}
    {$if declared(OSSL_HTTP_adapt_proxy_introduced)}
    if LibVersion < OSSL_HTTP_adapt_proxy_introduced then
    begin
      {$if declared(FC_OSSL_HTTP_adapt_proxy)}
      OSSL_HTTP_adapt_proxy := FC_OSSL_HTTP_adapt_proxy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_HTTP_adapt_proxy_removed)}
    if OSSL_HTTP_adapt_proxy_removed <= LibVersion then
    begin
      {$if declared(_OSSL_HTTP_adapt_proxy)}
      OSSL_HTTP_adapt_proxy := _OSSL_HTTP_adapt_proxy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_HTTP_adapt_proxy_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_HTTP_adapt_proxy');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_parse_url := nil;
  OSSL_HTTP_REQ_CTX_new := nil;
  OSSL_HTTP_REQ_CTX_free := nil;
  OSSL_HTTP_REQ_CTX_set_request_line := nil;
  OSSL_HTTP_REQ_CTX_add1_header := nil;
  OSSL_HTTP_REQ_CTX_set_expected := nil;
  OSSL_HTTP_REQ_CTX_set1_req := nil;
  OSSL_HTTP_REQ_CTX_nbio := nil;
  OSSL_HTTP_REQ_CTX_nbio_d2i := nil;
  OSSL_HTTP_REQ_CTX_exchange := nil;
  OSSL_HTTP_REQ_CTX_get0_mem_bio := nil;
  OSSL_HTTP_REQ_CTX_get_resp_len := nil;
  OSSL_HTTP_REQ_CTX_set_max_response_length := nil;
  OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines := nil;
  OSSL_HTTP_is_alive := nil;
  OSSL_HTTP_open := nil;
  OSSL_HTTP_proxy_connect := nil;
  OSSL_HTTP_set1_request := nil;
  OSSL_HTTP_exchange := nil;
  OSSL_HTTP_get := nil;
  OSSL_HTTP_transfer := nil;
  OSSL_HTTP_close := nil;
  OSSL_HTTP_parse_url := nil;
  OSSL_HTTP_adapt_proxy := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.