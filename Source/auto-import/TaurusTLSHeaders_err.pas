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

unit TaurusTLSHeaders_err;

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
  Perr_state_st = ^Terr_state_st;
  Terr_state_st = record end;
  {$EXTERNALSYM Perr_state_st}

  PERR_string_data_st = ^TERR_string_data_st;
  TERR_string_data_st = record end;
  {$EXTERNALSYM PERR_string_data_st}

  PERR_STRING_DATA = ^TERR_STRING_DATA;
  TERR_STRING_DATA = TERR_string_data_st;
  {$EXTERNALSYM PERR_STRING_DATA}

  Plhash_st_ERR_STRING_DATA = ^Tlhash_st_ERR_STRING_DATA;
  Tlhash_st_ERR_STRING_DATA = record end;
  {$EXTERNALSYM Plhash_st_ERR_STRING_DATA}

  Plh_ERR_STRING_DATA_dummy = ^Tlh_ERR_STRING_DATA_dummy;
  {$EXTERNALSYM Plh_ERR_STRING_DATA_dummy}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tlh_ERR_STRING_DATA_compfunc_func_cb = function(arg1: PERR_STRING_DATA; arg2: PERR_STRING_DATA): TIdC_INT; cdecl;
  Tlh_ERR_STRING_DATA_hashfunc_func_cb = function(arg1: PERR_STRING_DATA): TIdC_ULONG; cdecl;
  Tlh_ERR_STRING_DATA_doallfunc_func_cb = procedure(arg1: PERR_STRING_DATA); cdecl;
  TERR_print_errors_cb_cb_cb = function(arg1: PIdAnsiChar; arg2: TIdC_SIZET; arg3: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  ERR_TXT_MALLOCED = $01;
  ERR_TXT_STRING = $02;
  ERR_FLAG_MARK = $01;
  ERR_FLAG_CLEAR = $02;
  ERR_NUM_ERRORS = 16;
  ERR_LIB_NONE = 1;
  ERR_LIB_SYS = 2;
  ERR_LIB_BN = 3;
  ERR_LIB_RSA = 4;
  ERR_LIB_DH = 5;
  ERR_LIB_EVP = 6;
  ERR_LIB_BUF = 7;
  ERR_LIB_OBJ = 8;
  ERR_LIB_PEM = 9;
  ERR_LIB_DSA = 10;
  ERR_LIB_X509 = 11;
  ERR_LIB_ASN1 = 13;
  ERR_LIB_CONF = 14;
  ERR_LIB_CRYPTO = 15;
  ERR_LIB_EC = 16;
  ERR_LIB_SSL = 20;
  ERR_LIB_BIO = 32;
  ERR_LIB_PKCS7 = 33;
  ERR_LIB_X509V3 = 34;
  ERR_LIB_PKCS12 = 35;
  ERR_LIB_RAND = 36;
  ERR_LIB_DSO = 37;
  ERR_LIB_ENGINE = 38;
  ERR_LIB_OCSP = 39;
  ERR_LIB_UI = 40;
  ERR_LIB_COMP = 41;
  ERR_LIB_ECDSA = 42;
  ERR_LIB_ECDH = 43;
  ERR_LIB_OSSL_STORE = 44;
  ERR_LIB_FIPS = 45;
  ERR_LIB_CMS = 46;
  ERR_LIB_TS = 47;
  ERR_LIB_HMAC = 48;
  ERR_LIB_CT = 50;
  ERR_LIB_ASYNC = 51;
  ERR_LIB_KDF = 52;
  ERR_LIB_SM2 = 53;
  ERR_LIB_ESS = 54;
  ERR_LIB_PROP = 55;
  ERR_LIB_CRMF = 56;
  ERR_LIB_PROV = 57;
  ERR_LIB_CMP = 58;
  ERR_LIB_OSSL_ENCODER = 59;
  ERR_LIB_OSSL_DECODER = 60;
  ERR_LIB_HTTP = 61;
  ERR_LIB_USER = 128;
  ERR_SYSTEM_FLAG = ((unsignedint)INT_MAX+1);
  ERR_SYSTEM_MASK = ((unsignedint)INT_MAX);
  ERR_LIB_OFFSET = 23;
  ERR_LIB_MASK = $FF;
  ERR_RFLAGS_OFFSET = 18;
  ERR_RFLAGS_MASK = $1F;
  ERR_REASON_MASK = $7FFFFF;
  ERR_RFLAG_FATAL = ($1 shl ERR_RFLAGS_OFFSET);
  ERR_RFLAG_COMMON = ($2 shl ERR_RFLAGS_OFFSET);
  SYS_F_FOPEN = 0;
  SYS_F_CONNECT = 0;
  SYS_F_GETSERVBYNAME = 0;
  SYS_F_SOCKET = 0;
  SYS_F_IOCTLSOCKET = 0;
  SYS_F_BIND = 0;
  SYS_F_LISTEN = 0;
  SYS_F_ACCEPT = 0;
  SYS_F_WSASTARTUP = 0;
  SYS_F_OPENDIR = 0;
  SYS_F_FREAD = 0;
  SYS_F_GETADDRINFO = 0;
  SYS_F_GETNAMEINFO = 0;
  SYS_F_SETSOCKOPT = 0;
  SYS_F_GETSOCKOPT = 0;
  SYS_F_GETSOCKNAME = 0;
  SYS_F_GETHOSTBYNAME = 0;
  SYS_F_FFLUSH = 0;
  SYS_F_OPEN = 0;
  SYS_F_CLOSE = 0;
  SYS_F_IOCTL = 0;
  SYS_F_STAT = 0;
  SYS_F_FCNTL = 0;
  SYS_F_FSTAT = 0;
  SYS_F_SENDFILE = 0;
  ERR_R_SYS_LIB = (ERR_LIB_SYS/* 2 */ or ERR_RFLAG_COMMON);
  ERR_R_BN_LIB = (ERR_LIB_BN/* 3 */ or ERR_RFLAG_COMMON);
  ERR_R_RSA_LIB = (ERR_LIB_RSA/* 4 */ or ERR_RFLAG_COMMON);
  ERR_R_DH_LIB = (ERR_LIB_DH/* 5 */ or ERR_RFLAG_COMMON);
  ERR_R_EVP_LIB = (ERR_LIB_EVP/* 6 */ or ERR_RFLAG_COMMON);
  ERR_R_BUF_LIB = (ERR_LIB_BUF/* 7 */ or ERR_RFLAG_COMMON);
  ERR_R_OBJ_LIB = (ERR_LIB_OBJ/* 8 */ or ERR_RFLAG_COMMON);
  ERR_R_PEM_LIB = (ERR_LIB_PEM/* 9 */ or ERR_RFLAG_COMMON);
  ERR_R_DSA_LIB = (ERR_LIB_DSA/* 10 */ or ERR_RFLAG_COMMON);
  ERR_R_X509_LIB = (ERR_LIB_X509/* 11 */ or ERR_RFLAG_COMMON);
  ERR_R_ASN1_LIB = (ERR_LIB_ASN1/* 13 */ or ERR_RFLAG_COMMON);
  ERR_R_CONF_LIB = (ERR_LIB_CONF/* 14 */ or ERR_RFLAG_COMMON);
  ERR_R_CRYPTO_LIB = (ERR_LIB_CRYPTO/* 15 */ or ERR_RFLAG_COMMON);
  ERR_R_EC_LIB = (ERR_LIB_EC/* 16 */ or ERR_RFLAG_COMMON);
  ERR_R_SSL_LIB = (ERR_LIB_SSL/* 20 */ or ERR_RFLAG_COMMON);
  ERR_R_BIO_LIB = (ERR_LIB_BIO/* 32 */ or ERR_RFLAG_COMMON);
  ERR_R_PKCS7_LIB = (ERR_LIB_PKCS7/* 33 */ or ERR_RFLAG_COMMON);
  ERR_R_X509V3_LIB = (ERR_LIB_X509V3/* 34 */ or ERR_RFLAG_COMMON);
  ERR_R_PKCS12_LIB = (ERR_LIB_PKCS12/* 35 */ or ERR_RFLAG_COMMON);
  ERR_R_RAND_LIB = (ERR_LIB_RAND/* 36 */ or ERR_RFLAG_COMMON);
  ERR_R_DSO_LIB = (ERR_LIB_DSO/* 37 */ or ERR_RFLAG_COMMON);
  ERR_R_ENGINE_LIB = (ERR_LIB_ENGINE/* 38 */ or ERR_RFLAG_COMMON);
  ERR_R_UI_LIB = (ERR_LIB_UI/* 40 */ or ERR_RFLAG_COMMON);
  ERR_R_ECDSA_LIB = (ERR_LIB_ECDSA/* 42 */ or ERR_RFLAG_COMMON);
  ERR_R_OSSL_STORE_LIB = (ERR_LIB_OSSL_STORE/* 44 */ or ERR_RFLAG_COMMON);
  ERR_R_CMS_LIB = (ERR_LIB_CMS/* 46 */ or ERR_RFLAG_COMMON);
  ERR_R_TS_LIB = (ERR_LIB_TS/* 47 */ or ERR_RFLAG_COMMON);
  ERR_R_CT_LIB = (ERR_LIB_CT/* 50 */ or ERR_RFLAG_COMMON);
  ERR_R_PROV_LIB = (ERR_LIB_PROV/* 57 */ or ERR_RFLAG_COMMON);
  ERR_R_ESS_LIB = (ERR_LIB_ESS/* 54 */ or ERR_RFLAG_COMMON);
  ERR_R_CMP_LIB = (ERR_LIB_CMP/* 58 */ or ERR_RFLAG_COMMON);
  ERR_R_OSSL_ENCODER_LIB = (ERR_LIB_OSSL_ENCODER/* 59 */ or ERR_RFLAG_COMMON);
  ERR_R_OSSL_DECODER_LIB = (ERR_LIB_OSSL_DECODER/* 60 */ or ERR_RFLAG_COMMON);
  ERR_R_FATAL = (ERR_RFLAG_FATAL or ERR_RFLAG_COMMON);
  ERR_R_MALLOC_FAILURE = (256 or ERR_R_FATAL);
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = (257 or ERR_R_FATAL);
  ERR_R_PASSED_NULL_PARAMETER = (258 or ERR_R_FATAL);
  ERR_R_INTERNAL_ERROR = (259 or ERR_R_FATAL);
  ERR_R_DISABLED = (260 or ERR_R_FATAL);
  ERR_R_INIT_FAIL = (261 or ERR_R_FATAL);
  ERR_R_PASSED_INVALID_ARGUMENT = (262 or ERR_RFLAG_COMMON);
  ERR_R_OPERATION_FAIL = (263 or ERR_R_FATAL);
  ERR_R_INVALID_PROVIDER_FUNCTIONS = (264 or ERR_R_FATAL);
  ERR_R_INTERRUPTED_OR_CANCELLED = (265 or ERR_RFLAG_COMMON);
  ERR_R_NESTED_ASN1_ERROR = (266 or ERR_RFLAG_COMMON);
  ERR_R_MISSING_ASN1_EOS = (267 or ERR_RFLAG_COMMON);
  ERR_R_UNSUPPORTED = (268 or ERR_RFLAG_COMMON);
  ERR_R_FETCH_FAILED = (269 or ERR_RFLAG_COMMON);
  ERR_R_INVALID_PROPERTY_DEFINITION = (270 or ERR_RFLAG_COMMON);
  ERR_R_UNABLE_TO_GET_READ_LOCK = (271 or ERR_R_FATAL);
  ERR_R_UNABLE_TO_GET_WRITE_LOCK = (272 or ERR_R_FATAL);
  ERR_MAX_DATA_SIZE = 1024;
  ERR_raise_data = (ERR_new(),ERR_set_debug(OPENSSL_FILE,OPENSSL_LINE,OPENSSL_FUNC),ERR_set_error);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  ERR_GET_LIB: function(errcode: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_GET_LIB}

  ERR_GET_REASON: function(errcode: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_GET_REASON}

  ERR_FATAL_ERROR: function(errcode: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_FATAL_ERROR}

  ERR_new: procedure; cdecl = nil;
  {$EXTERNALSYM ERR_new}

  ERR_set_debug: procedure(_file: PIdAnsiChar; line: TIdC_INT; func: PIdAnsiChar); cdecl = nil;
  {$EXTERNALSYM ERR_set_debug}

  ERR_set_error: procedure(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar); cdecl = nil;
  {$EXTERNALSYM ERR_set_error}

  ERR_vset_error: procedure(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar; args: Tva_list); cdecl = nil;
  {$EXTERNALSYM ERR_vset_error}

  ERR_set_error_data: procedure(data: PIdAnsiChar; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM ERR_set_error_data}

  ERR_get_error: function: TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_get_error}

  ERR_get_error_all: function(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_get_error_all}

  ERR_get_error_line: function(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ERR_get_error_line}

  ERR_get_error_line_data: function(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ERR_get_error_line_data}

  ERR_peek_error: function: TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_error}

  ERR_peek_error_line: function(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_error_line}

  ERR_peek_error_func: function(func: PPIdAnsiChar): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_error_func}

  ERR_peek_error_data: function(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_error_data}

  ERR_peek_error_all: function(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_error_all}

  ERR_peek_error_line_data: function(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ERR_peek_error_line_data}

  ERR_peek_last_error: function: TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_last_error}

  ERR_peek_last_error_line: function(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_last_error_line}

  ERR_peek_last_error_func: function(func: PPIdAnsiChar): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_last_error_func}

  ERR_peek_last_error_data: function(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_last_error_data}

  ERR_peek_last_error_all: function(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_last_error_all}

  ERR_peek_last_error_line_data: function(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ERR_peek_last_error_line_data}

  ERR_clear_error: procedure; cdecl = nil;
  {$EXTERNALSYM ERR_clear_error}

  ERR_error_string: function(e: TIdC_ULONG; buf: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ERR_error_string}

  ERR_error_string_n: procedure(e: TIdC_ULONG; buf: PIdAnsiChar; len: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM ERR_error_string_n}

  ERR_lib_error_string: function(e: TIdC_ULONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ERR_lib_error_string}

  ERR_func_error_string: function(e: TIdC_ULONG): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ERR_func_error_string}

  ERR_reason_error_string: function(e: TIdC_ULONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ERR_reason_error_string}

  ERR_print_errors_cb: procedure(cb: TERR_print_errors_cb_cb_cb; u: Pointer); cdecl = nil;
  {$EXTERNALSYM ERR_print_errors_cb}

  ERR_print_errors_fp: procedure(fp: PFILE); cdecl = nil;
  {$EXTERNALSYM ERR_print_errors_fp}

  ERR_print_errors: procedure(bp: PBIO); cdecl = nil;
  {$EXTERNALSYM ERR_print_errors}

  ERR_add_error_data: procedure(num: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM ERR_add_error_data}

  ERR_add_error_vdata: procedure(num: TIdC_INT; args: Tva_list); cdecl = nil;
  {$EXTERNALSYM ERR_add_error_vdata}

  ERR_add_error_txt: procedure(sepr: PIdAnsiChar; txt: PIdAnsiChar); cdecl = nil;
  {$EXTERNALSYM ERR_add_error_txt}

  ERR_add_error_mem_bio: procedure(sep: PIdAnsiChar; bio: PBIO); cdecl = nil;
  {$EXTERNALSYM ERR_add_error_mem_bio}

  ERR_load_strings: function(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_load_strings}

  ERR_load_strings_const: function(str: PERR_STRING_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_load_strings_const}

  ERR_unload_strings: function(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_unload_strings}

  ERR_get_state: function: PERR_STATE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ERR_get_state}

  ERR_get_next_error_library: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_get_next_error_library}

  ERR_set_mark: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_set_mark}

  ERR_pop_to_mark: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_pop_to_mark}

  ERR_clear_last_mark: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_clear_last_mark}

  ERR_count_to_mark: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_count_to_mark}

  ERR_pop: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_pop}

  OSSL_ERR_STATE_new: function: PERR_STATE; cdecl = nil;
  {$EXTERNALSYM OSSL_ERR_STATE_new}

  OSSL_ERR_STATE_save: procedure(es: PERR_STATE); cdecl = nil;
  {$EXTERNALSYM OSSL_ERR_STATE_save}

  OSSL_ERR_STATE_save_to_mark: procedure(es: PERR_STATE); cdecl = nil;
  {$EXTERNALSYM OSSL_ERR_STATE_save_to_mark}

  OSSL_ERR_STATE_restore: procedure(es: PERR_STATE); cdecl = nil;
  {$EXTERNALSYM OSSL_ERR_STATE_restore}

  OSSL_ERR_STATE_free: procedure(es: PERR_STATE); cdecl = nil;
  {$EXTERNALSYM OSSL_ERR_STATE_free}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function ERR_GET_LIB(errcode: TIdC_ULONG): TIdC_INT; cdecl;
function ERR_GET_REASON(errcode: TIdC_ULONG): TIdC_INT; cdecl;
function ERR_FATAL_ERROR(errcode: TIdC_ULONG): TIdC_INT; cdecl;
procedure ERR_new; cdecl;
procedure ERR_set_debug(_file: PIdAnsiChar; line: TIdC_INT; func: PIdAnsiChar); cdecl;
procedure ERR_set_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar); cdecl;
procedure ERR_vset_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar; args: Tva_list); cdecl;
procedure ERR_set_error_data(data: PIdAnsiChar; flags: TIdC_INT); cdecl;
function ERR_get_error: TIdC_ULONG; cdecl;
function ERR_get_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl;
function ERR_get_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl; deprecated 'In OpenSSL 3_0_0';
function ERR_get_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl; deprecated 'In OpenSSL 3_0_0';
function ERR_peek_error: TIdC_ULONG; cdecl;
function ERR_peek_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl;
function ERR_peek_error_func(func: PPIdAnsiChar): TIdC_ULONG; cdecl;
function ERR_peek_error_data(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl;
function ERR_peek_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl;
function ERR_peek_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl; deprecated 'In OpenSSL 3_0_0';
function ERR_peek_last_error: TIdC_ULONG; cdecl;
function ERR_peek_last_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl;
function ERR_peek_last_error_func(func: PPIdAnsiChar): TIdC_ULONG; cdecl;
function ERR_peek_last_error_data(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl;
function ERR_peek_last_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl;
function ERR_peek_last_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ERR_clear_error; cdecl;
function ERR_error_string(e: TIdC_ULONG; buf: PIdAnsiChar): PIdAnsiChar; cdecl;
procedure ERR_error_string_n(e: TIdC_ULONG; buf: PIdAnsiChar; len: TIdC_SIZET); cdecl;
function ERR_lib_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl;
function ERR_func_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function ERR_reason_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl;
procedure ERR_print_errors_cb(cb: TERR_print_errors_cb_cb_cb; u: Pointer); cdecl;
procedure ERR_print_errors_fp(fp: PFILE); cdecl;
procedure ERR_print_errors(bp: PBIO); cdecl;
procedure ERR_add_error_data(num: TIdC_INT); cdecl;
procedure ERR_add_error_vdata(num: TIdC_INT; args: Tva_list); cdecl;
procedure ERR_add_error_txt(sepr: PIdAnsiChar; txt: PIdAnsiChar); cdecl;
procedure ERR_add_error_mem_bio(sep: PIdAnsiChar; bio: PBIO); cdecl;
function ERR_load_strings(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl;
function ERR_load_strings_const(str: PERR_STRING_DATA): TIdC_INT; cdecl;
function ERR_unload_strings(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl;
function ERR_get_state: PERR_STATE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ERR_get_next_error_library: TIdC_INT; cdecl;
function ERR_set_mark: TIdC_INT; cdecl;
function ERR_pop_to_mark: TIdC_INT; cdecl;
function ERR_clear_last_mark: TIdC_INT; cdecl;
function ERR_count_to_mark: TIdC_INT; cdecl;
function ERR_pop: TIdC_INT; cdecl;
function OSSL_ERR_STATE_new: PERR_STATE; cdecl;
procedure OSSL_ERR_STATE_save(es: PERR_STATE); cdecl;
procedure OSSL_ERR_STATE_save_to_mark(es: PERR_STATE); cdecl;
procedure OSSL_ERR_STATE_restore(es: PERR_STATE); cdecl;
procedure OSSL_ERR_STATE_free(es: PERR_STATE); cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function ERR_PACK(lib: Pointer; func: Pointer; reason: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function ERR_raise(lib: Pointer; reason: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function ERR_put_error(lib: Pointer; func: Pointer; reason: Pointer; _file: Pointer; line: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function ERR_load_crypto_strings: TIdC_INT; cdecl; deprecated 'In OpenSSL 1_1_0';
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function ERR_free_strings: TIdC_INT; cdecl; deprecated 'In OpenSSL 1_1_0';
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

function ERR_GET_LIB(errcode: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ERR_GET_LIB';
function ERR_GET_REASON(errcode: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ERR_GET_REASON';
function ERR_FATAL_ERROR(errcode: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'ERR_FATAL_ERROR';
procedure ERR_new; cdecl external CLibCrypto name 'ERR_new';
procedure ERR_set_debug(_file: PIdAnsiChar; line: TIdC_INT; func: PIdAnsiChar); cdecl external CLibCrypto name 'ERR_set_debug';
procedure ERR_set_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar); cdecl external CLibCrypto name 'ERR_set_error';
procedure ERR_vset_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar; args: Tva_list); cdecl external CLibCrypto name 'ERR_vset_error';
procedure ERR_set_error_data(data: PIdAnsiChar; flags: TIdC_INT); cdecl external CLibCrypto name 'ERR_set_error_data';
function ERR_get_error: TIdC_ULONG; cdecl external CLibCrypto name 'ERR_get_error';
function ERR_get_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_get_error_all';
function ERR_get_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_get_error_line';
function ERR_get_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_get_error_line_data';
function ERR_peek_error: TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_error';
function ERR_peek_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_error_line';
function ERR_peek_error_func(func: PPIdAnsiChar): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_error_func';
function ERR_peek_error_data(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_error_data';
function ERR_peek_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_error_all';
function ERR_peek_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_error_line_data';
function ERR_peek_last_error: TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_last_error';
function ERR_peek_last_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_last_error_line';
function ERR_peek_last_error_func(func: PPIdAnsiChar): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_last_error_func';
function ERR_peek_last_error_data(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_last_error_data';
function ERR_peek_last_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_last_error_all';
function ERR_peek_last_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'ERR_peek_last_error_line_data';
procedure ERR_clear_error; cdecl external CLibCrypto name 'ERR_clear_error';
function ERR_error_string(e: TIdC_ULONG; buf: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'ERR_error_string';
procedure ERR_error_string_n(e: TIdC_ULONG; buf: PIdAnsiChar; len: TIdC_SIZET); cdecl external CLibCrypto name 'ERR_error_string_n';
function ERR_lib_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl external CLibCrypto name 'ERR_lib_error_string';
function ERR_func_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl external CLibCrypto name 'ERR_func_error_string';
function ERR_reason_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl external CLibCrypto name 'ERR_reason_error_string';
procedure ERR_print_errors_cb(cb: TERR_print_errors_cb_cb_cb; u: Pointer); cdecl external CLibCrypto name 'ERR_print_errors_cb';
procedure ERR_print_errors_fp(fp: PFILE); cdecl external CLibCrypto name 'ERR_print_errors_fp';
procedure ERR_print_errors(bp: PBIO); cdecl external CLibCrypto name 'ERR_print_errors';
procedure ERR_add_error_data(num: TIdC_INT); cdecl external CLibCrypto name 'ERR_add_error_data';
procedure ERR_add_error_vdata(num: TIdC_INT; args: Tva_list); cdecl external CLibCrypto name 'ERR_add_error_vdata';
procedure ERR_add_error_txt(sepr: PIdAnsiChar; txt: PIdAnsiChar); cdecl external CLibCrypto name 'ERR_add_error_txt';
procedure ERR_add_error_mem_bio(sep: PIdAnsiChar; bio: PBIO); cdecl external CLibCrypto name 'ERR_add_error_mem_bio';
function ERR_load_strings(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl external CLibCrypto name 'ERR_load_strings';
function ERR_load_strings_const(str: PERR_STRING_DATA): TIdC_INT; cdecl external CLibCrypto name 'ERR_load_strings_const';
function ERR_unload_strings(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl external CLibCrypto name 'ERR_unload_strings';
function ERR_get_state: PERR_STATE; cdecl external CLibCrypto name 'ERR_get_state';
function ERR_get_next_error_library: TIdC_INT; cdecl external CLibCrypto name 'ERR_get_next_error_library';
function ERR_set_mark: TIdC_INT; cdecl external CLibCrypto name 'ERR_set_mark';
function ERR_pop_to_mark: TIdC_INT; cdecl external CLibCrypto name 'ERR_pop_to_mark';
function ERR_clear_last_mark: TIdC_INT; cdecl external CLibCrypto name 'ERR_clear_last_mark';
function ERR_count_to_mark: TIdC_INT; cdecl external CLibCrypto name 'ERR_count_to_mark';
function ERR_pop: TIdC_INT; cdecl external CLibCrypto name 'ERR_pop';
function OSSL_ERR_STATE_new: PERR_STATE; cdecl external CLibCrypto name 'OSSL_ERR_STATE_new';
procedure OSSL_ERR_STATE_save(es: PERR_STATE); cdecl external CLibCrypto name 'OSSL_ERR_STATE_save';
procedure OSSL_ERR_STATE_save_to_mark(es: PERR_STATE); cdecl external CLibCrypto name 'OSSL_ERR_STATE_save_to_mark';
procedure OSSL_ERR_STATE_restore(es: PERR_STATE); cdecl external CLibCrypto name 'OSSL_ERR_STATE_restore';
procedure OSSL_ERR_STATE_free(es: PERR_STATE); cdecl external CLibCrypto name 'OSSL_ERR_STATE_free';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  ERR_GET_LIB_procname = 'ERR_GET_LIB';
  ERR_GET_LIB_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_GET_REASON_procname = 'ERR_GET_REASON';
  ERR_GET_REASON_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_FATAL_ERROR_procname = 'ERR_FATAL_ERROR';
  ERR_FATAL_ERROR_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_new_procname = 'ERR_new';
  ERR_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_set_debug_procname = 'ERR_set_debug';
  ERR_set_debug_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_set_error_procname = 'ERR_set_error';
  ERR_set_error_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_vset_error_procname = 'ERR_vset_error';
  ERR_vset_error_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_set_error_data_procname = 'ERR_set_error_data';
  ERR_set_error_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_get_error_procname = 'ERR_get_error';
  ERR_get_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_get_error_all_procname = 'ERR_get_error_all';
  ERR_get_error_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_get_error_line_procname = 'ERR_get_error_line';
  ERR_get_error_line_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_get_error_line_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_get_error_line_data_procname = 'ERR_get_error_line_data';
  ERR_get_error_line_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_get_error_line_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_error_procname = 'ERR_peek_error';
  ERR_peek_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_peek_error_line_procname = 'ERR_peek_error_line';
  ERR_peek_error_line_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_peek_error_func_procname = 'ERR_peek_error_func';
  ERR_peek_error_func_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_error_data_procname = 'ERR_peek_error_data';
  ERR_peek_error_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_error_all_procname = 'ERR_peek_error_all';
  ERR_peek_error_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_error_line_data_procname = 'ERR_peek_error_line_data';
  ERR_peek_error_line_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_peek_error_line_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_last_error_procname = 'ERR_peek_last_error';
  ERR_peek_last_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_peek_last_error_line_procname = 'ERR_peek_last_error_line';
  ERR_peek_last_error_line_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_peek_last_error_func_procname = 'ERR_peek_last_error_func';
  ERR_peek_last_error_func_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_last_error_data_procname = 'ERR_peek_last_error_data';
  ERR_peek_last_error_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_last_error_all_procname = 'ERR_peek_last_error_all';
  ERR_peek_last_error_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_peek_last_error_line_data_procname = 'ERR_peek_last_error_line_data';
  ERR_peek_last_error_line_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_peek_last_error_line_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_clear_error_procname = 'ERR_clear_error';
  ERR_clear_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_error_string_procname = 'ERR_error_string';
  ERR_error_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_error_string_n_procname = 'ERR_error_string_n';
  ERR_error_string_n_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_lib_error_string_procname = 'ERR_lib_error_string';
  ERR_lib_error_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_func_error_string_procname = 'ERR_func_error_string';
  ERR_func_error_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_func_error_string_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_reason_error_string_procname = 'ERR_reason_error_string';
  ERR_reason_error_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_print_errors_cb_procname = 'ERR_print_errors_cb';
  ERR_print_errors_cb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_print_errors_fp_procname = 'ERR_print_errors_fp';
  ERR_print_errors_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_print_errors_procname = 'ERR_print_errors';
  ERR_print_errors_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_add_error_data_procname = 'ERR_add_error_data';
  ERR_add_error_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_add_error_vdata_procname = 'ERR_add_error_vdata';
  ERR_add_error_vdata_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_add_error_txt_procname = 'ERR_add_error_txt';
  ERR_add_error_txt_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_add_error_mem_bio_procname = 'ERR_add_error_mem_bio';
  ERR_add_error_mem_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_load_strings_procname = 'ERR_load_strings';
  ERR_load_strings_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_load_strings_const_procname = 'ERR_load_strings_const';
  ERR_load_strings_const_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ERR_unload_strings_procname = 'ERR_unload_strings';
  ERR_unload_strings_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_get_state_procname = 'ERR_get_state';
  ERR_get_state_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_get_state_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ERR_get_next_error_library_procname = 'ERR_get_next_error_library';
  ERR_get_next_error_library_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_set_mark_procname = 'ERR_set_mark';
  ERR_set_mark_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_pop_to_mark_procname = 'ERR_pop_to_mark';
  ERR_pop_to_mark_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ERR_clear_last_mark_procname = 'ERR_clear_last_mark';
  ERR_clear_last_mark_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ERR_count_to_mark_procname = 'ERR_count_to_mark';
  ERR_count_to_mark_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  ERR_pop_procname = 'ERR_pop';
  ERR_pop_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OSSL_ERR_STATE_new_procname = 'OSSL_ERR_STATE_new';
  OSSL_ERR_STATE_new_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_ERR_STATE_save_procname = 'OSSL_ERR_STATE_save';
  OSSL_ERR_STATE_save_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_ERR_STATE_save_to_mark_procname = 'OSSL_ERR_STATE_save_to_mark';
  OSSL_ERR_STATE_save_to_mark_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_ERR_STATE_restore_procname = 'OSSL_ERR_STATE_restore';
  OSSL_ERR_STATE_restore_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_ERR_STATE_free_procname = 'OSSL_ERR_STATE_free';
  OSSL_ERR_STATE_free_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function ERR_PACK(lib: Pointer; func: Pointer; reason: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    ERR_PACK(lib, func, reason) \
    ((((unsigned long)(lib) & ERR_LIB_MASK) << ERR_LIB_OFFSET) | (((unsigned long)(reason) & ERR_REASON_MASK)))
  }
end;

function ERR_raise(lib: Pointer; reason: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    ERR_raise(lib, reason) ERR_raise_data((lib), (reason), NULL)
  }
end;

function ERR_put_error(lib: Pointer; func: Pointer; reason: Pointer; _file: Pointer; line: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    ERR_put_error(lib, func, reason, file, line) \
    (ERR_new(),                                      \
        ERR_set_debug((file), (line), OPENSSL_FUNC), \
        ERR_set_error((lib), (reason), NULL))
  }
end;

function ERR_load_crypto_strings: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    ERR_load_crypto_strings() \
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
  }
end;

function ERR_free_strings: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    ERR_free_strings() \
    while (0)              \
    continue
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_ERR_GET_LIB(errcode: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_GET_LIB_procname);
end;

function ERR_ERR_GET_REASON(errcode: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_GET_REASON_procname);
end;

function ERR_ERR_FATAL_ERROR(errcode: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_FATAL_ERROR_procname);
end;

procedure ERR_ERR_new; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_new_procname);
end;

procedure ERR_ERR_set_debug(_file: PIdAnsiChar; line: TIdC_INT; func: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_debug_procname);
end;

procedure ERR_ERR_set_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_error_procname);
end;

procedure ERR_ERR_vset_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar; args: Tva_list); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_vset_error_procname);
end;

procedure ERR_ERR_set_error_data(data: PIdAnsiChar; flags: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_error_data_procname);
end;

function ERR_ERR_get_error: TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_error_procname);
end;

function ERR_ERR_get_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_error_all_procname);
end;

function ERR_ERR_get_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_error_line_procname);
end;

function ERR_ERR_get_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_error_line_data_procname);
end;

function ERR_ERR_peek_error: TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_procname);
end;

function ERR_ERR_peek_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_line_procname);
end;

function ERR_ERR_peek_error_func(func: PPIdAnsiChar): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_func_procname);
end;

function ERR_ERR_peek_error_data(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_data_procname);
end;

function ERR_ERR_peek_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_all_procname);
end;

function ERR_ERR_peek_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_line_data_procname);
end;

function ERR_ERR_peek_last_error: TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_procname);
end;

function ERR_ERR_peek_last_error_line(_file: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_line_procname);
end;

function ERR_ERR_peek_last_error_func(func: PPIdAnsiChar): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_func_procname);
end;

function ERR_ERR_peek_last_error_data(data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_data_procname);
end;

function ERR_ERR_peek_last_error_all(_file: PPIdAnsiChar; line: PIdC_INT; func: PPIdAnsiChar; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_all_procname);
end;

function ERR_ERR_peek_last_error_line_data(_file: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_line_data_procname);
end;

procedure ERR_ERR_clear_error; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_clear_error_procname);
end;

function ERR_ERR_error_string(e: TIdC_ULONG; buf: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_error_string_procname);
end;

procedure ERR_ERR_error_string_n(e: TIdC_ULONG; buf: PIdAnsiChar; len: TIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_error_string_n_procname);
end;

function ERR_ERR_lib_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_lib_error_string_procname);
end;

function ERR_ERR_func_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_func_error_string_procname);
end;

function ERR_ERR_reason_error_string(e: TIdC_ULONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_reason_error_string_procname);
end;

procedure ERR_ERR_print_errors_cb(cb: TERR_print_errors_cb_cb_cb; u: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_print_errors_cb_procname);
end;

procedure ERR_ERR_print_errors_fp(fp: PFILE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_print_errors_fp_procname);
end;

procedure ERR_ERR_print_errors(bp: PBIO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_print_errors_procname);
end;

procedure ERR_ERR_add_error_data(num: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_add_error_data_procname);
end;

procedure ERR_ERR_add_error_vdata(num: TIdC_INT; args: Tva_list); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_add_error_vdata_procname);
end;

procedure ERR_ERR_add_error_txt(sepr: PIdAnsiChar; txt: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_add_error_txt_procname);
end;

procedure ERR_ERR_add_error_mem_bio(sep: PIdAnsiChar; bio: PBIO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_add_error_mem_bio_procname);
end;

function ERR_ERR_load_strings(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_strings_procname);
end;

function ERR_ERR_load_strings_const(str: PERR_STRING_DATA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_strings_const_procname);
end;

function ERR_ERR_unload_strings(lib: TIdC_INT; str: PERR_STRING_DATA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_unload_strings_procname);
end;

function ERR_ERR_get_state: PERR_STATE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_state_procname);
end;

function ERR_ERR_get_next_error_library: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_next_error_library_procname);
end;

function ERR_ERR_set_mark: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_mark_procname);
end;

function ERR_ERR_pop_to_mark: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_pop_to_mark_procname);
end;

function ERR_ERR_clear_last_mark: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_clear_last_mark_procname);
end;

function ERR_ERR_count_to_mark: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_count_to_mark_procname);
end;

function ERR_ERR_pop: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_pop_procname);
end;

function ERR_OSSL_ERR_STATE_new: PERR_STATE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ERR_STATE_new_procname);
end;

procedure ERR_OSSL_ERR_STATE_save(es: PERR_STATE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ERR_STATE_save_procname);
end;

procedure ERR_OSSL_ERR_STATE_save_to_mark(es: PERR_STATE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ERR_STATE_save_to_mark_procname);
end;

procedure ERR_OSSL_ERR_STATE_restore(es: PERR_STATE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ERR_STATE_restore_procname);
end;

procedure ERR_OSSL_ERR_STATE_free(es: PERR_STATE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ERR_STATE_free_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  ERR_GET_LIB := LoadLibFunction(ADllHandle, ERR_GET_LIB_procname);
  FuncLoadError := not assigned(ERR_GET_LIB);
  if FuncLoadError then
  begin
    {$if not defined(ERR_GET_LIB_allownil)}
    ERR_GET_LIB := ERR_ERR_GET_LIB;
    {$ifend}
    {$if declared(ERR_GET_LIB_introduced)}
    if LibVersion < ERR_GET_LIB_introduced then
    begin
      {$if declared(FC_ERR_GET_LIB)}
      ERR_GET_LIB := FC_ERR_GET_LIB;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_GET_LIB_removed)}
    if ERR_GET_LIB_removed <= LibVersion then
    begin
      {$if declared(_ERR_GET_LIB)}
      ERR_GET_LIB := _ERR_GET_LIB;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_GET_LIB_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_GET_LIB');
    {$ifend}
  end;
  
  ERR_GET_REASON := LoadLibFunction(ADllHandle, ERR_GET_REASON_procname);
  FuncLoadError := not assigned(ERR_GET_REASON);
  if FuncLoadError then
  begin
    {$if not defined(ERR_GET_REASON_allownil)}
    ERR_GET_REASON := ERR_ERR_GET_REASON;
    {$ifend}
    {$if declared(ERR_GET_REASON_introduced)}
    if LibVersion < ERR_GET_REASON_introduced then
    begin
      {$if declared(FC_ERR_GET_REASON)}
      ERR_GET_REASON := FC_ERR_GET_REASON;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_GET_REASON_removed)}
    if ERR_GET_REASON_removed <= LibVersion then
    begin
      {$if declared(_ERR_GET_REASON)}
      ERR_GET_REASON := _ERR_GET_REASON;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_GET_REASON_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_GET_REASON');
    {$ifend}
  end;
  
  ERR_FATAL_ERROR := LoadLibFunction(ADllHandle, ERR_FATAL_ERROR_procname);
  FuncLoadError := not assigned(ERR_FATAL_ERROR);
  if FuncLoadError then
  begin
    {$if not defined(ERR_FATAL_ERROR_allownil)}
    ERR_FATAL_ERROR := ERR_ERR_FATAL_ERROR;
    {$ifend}
    {$if declared(ERR_FATAL_ERROR_introduced)}
    if LibVersion < ERR_FATAL_ERROR_introduced then
    begin
      {$if declared(FC_ERR_FATAL_ERROR)}
      ERR_FATAL_ERROR := FC_ERR_FATAL_ERROR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_FATAL_ERROR_removed)}
    if ERR_FATAL_ERROR_removed <= LibVersion then
    begin
      {$if declared(_ERR_FATAL_ERROR)}
      ERR_FATAL_ERROR := _ERR_FATAL_ERROR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_FATAL_ERROR_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_FATAL_ERROR');
    {$ifend}
  end;
  
  ERR_new := LoadLibFunction(ADllHandle, ERR_new_procname);
  FuncLoadError := not assigned(ERR_new);
  if FuncLoadError then
  begin
    {$if not defined(ERR_new_allownil)}
    ERR_new := ERR_ERR_new;
    {$ifend}
    {$if declared(ERR_new_introduced)}
    if LibVersion < ERR_new_introduced then
    begin
      {$if declared(FC_ERR_new)}
      ERR_new := FC_ERR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_new_removed)}
    if ERR_new_removed <= LibVersion then
    begin
      {$if declared(_ERR_new)}
      ERR_new := _ERR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_new');
    {$ifend}
  end;
  
  ERR_set_debug := LoadLibFunction(ADllHandle, ERR_set_debug_procname);
  FuncLoadError := not assigned(ERR_set_debug);
  if FuncLoadError then
  begin
    {$if not defined(ERR_set_debug_allownil)}
    ERR_set_debug := ERR_ERR_set_debug;
    {$ifend}
    {$if declared(ERR_set_debug_introduced)}
    if LibVersion < ERR_set_debug_introduced then
    begin
      {$if declared(FC_ERR_set_debug)}
      ERR_set_debug := FC_ERR_set_debug;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_set_debug_removed)}
    if ERR_set_debug_removed <= LibVersion then
    begin
      {$if declared(_ERR_set_debug)}
      ERR_set_debug := _ERR_set_debug;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_set_debug_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_set_debug');
    {$ifend}
  end;
  
  ERR_set_error := LoadLibFunction(ADllHandle, ERR_set_error_procname);
  FuncLoadError := not assigned(ERR_set_error);
  if FuncLoadError then
  begin
    {$if not defined(ERR_set_error_allownil)}
    ERR_set_error := ERR_ERR_set_error;
    {$ifend}
    {$if declared(ERR_set_error_introduced)}
    if LibVersion < ERR_set_error_introduced then
    begin
      {$if declared(FC_ERR_set_error)}
      ERR_set_error := FC_ERR_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_set_error_removed)}
    if ERR_set_error_removed <= LibVersion then
    begin
      {$if declared(_ERR_set_error)}
      ERR_set_error := _ERR_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_set_error_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_set_error');
    {$ifend}
  end;
  
  ERR_vset_error := LoadLibFunction(ADllHandle, ERR_vset_error_procname);
  FuncLoadError := not assigned(ERR_vset_error);
  if FuncLoadError then
  begin
    {$if not defined(ERR_vset_error_allownil)}
    ERR_vset_error := ERR_ERR_vset_error;
    {$ifend}
    {$if declared(ERR_vset_error_introduced)}
    if LibVersion < ERR_vset_error_introduced then
    begin
      {$if declared(FC_ERR_vset_error)}
      ERR_vset_error := FC_ERR_vset_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_vset_error_removed)}
    if ERR_vset_error_removed <= LibVersion then
    begin
      {$if declared(_ERR_vset_error)}
      ERR_vset_error := _ERR_vset_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_vset_error_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_vset_error');
    {$ifend}
  end;
  
  ERR_set_error_data := LoadLibFunction(ADllHandle, ERR_set_error_data_procname);
  FuncLoadError := not assigned(ERR_set_error_data);
  if FuncLoadError then
  begin
    {$if not defined(ERR_set_error_data_allownil)}
    ERR_set_error_data := ERR_ERR_set_error_data;
    {$ifend}
    {$if declared(ERR_set_error_data_introduced)}
    if LibVersion < ERR_set_error_data_introduced then
    begin
      {$if declared(FC_ERR_set_error_data)}
      ERR_set_error_data := FC_ERR_set_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_set_error_data_removed)}
    if ERR_set_error_data_removed <= LibVersion then
    begin
      {$if declared(_ERR_set_error_data)}
      ERR_set_error_data := _ERR_set_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_set_error_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_set_error_data');
    {$ifend}
  end;
  
  ERR_get_error := LoadLibFunction(ADllHandle, ERR_get_error_procname);
  FuncLoadError := not assigned(ERR_get_error);
  if FuncLoadError then
  begin
    {$if not defined(ERR_get_error_allownil)}
    ERR_get_error := ERR_ERR_get_error;
    {$ifend}
    {$if declared(ERR_get_error_introduced)}
    if LibVersion < ERR_get_error_introduced then
    begin
      {$if declared(FC_ERR_get_error)}
      ERR_get_error := FC_ERR_get_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_get_error_removed)}
    if ERR_get_error_removed <= LibVersion then
    begin
      {$if declared(_ERR_get_error)}
      ERR_get_error := _ERR_get_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_get_error_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_get_error');
    {$ifend}
  end;
  
  ERR_get_error_all := LoadLibFunction(ADllHandle, ERR_get_error_all_procname);
  FuncLoadError := not assigned(ERR_get_error_all);
  if FuncLoadError then
  begin
    {$if not defined(ERR_get_error_all_allownil)}
    ERR_get_error_all := ERR_ERR_get_error_all;
    {$ifend}
    {$if declared(ERR_get_error_all_introduced)}
    if LibVersion < ERR_get_error_all_introduced then
    begin
      {$if declared(FC_ERR_get_error_all)}
      ERR_get_error_all := FC_ERR_get_error_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_get_error_all_removed)}
    if ERR_get_error_all_removed <= LibVersion then
    begin
      {$if declared(_ERR_get_error_all)}
      ERR_get_error_all := _ERR_get_error_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_get_error_all_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_get_error_all');
    {$ifend}
  end;
  
  ERR_get_error_line := LoadLibFunction(ADllHandle, ERR_get_error_line_procname);
  FuncLoadError := not assigned(ERR_get_error_line);
  if FuncLoadError then
  begin
    {$if not defined(ERR_get_error_line_allownil)}
    ERR_get_error_line := ERR_ERR_get_error_line;
    {$ifend}
    {$if declared(ERR_get_error_line_introduced)}
    if LibVersion < ERR_get_error_line_introduced then
    begin
      {$if declared(FC_ERR_get_error_line)}
      ERR_get_error_line := FC_ERR_get_error_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_get_error_line_removed)}
    if ERR_get_error_line_removed <= LibVersion then
    begin
      {$if declared(_ERR_get_error_line)}
      ERR_get_error_line := _ERR_get_error_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_get_error_line_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_get_error_line');
    {$ifend}
  end;
  
  ERR_get_error_line_data := LoadLibFunction(ADllHandle, ERR_get_error_line_data_procname);
  FuncLoadError := not assigned(ERR_get_error_line_data);
  if FuncLoadError then
  begin
    {$if not defined(ERR_get_error_line_data_allownil)}
    ERR_get_error_line_data := ERR_ERR_get_error_line_data;
    {$ifend}
    {$if declared(ERR_get_error_line_data_introduced)}
    if LibVersion < ERR_get_error_line_data_introduced then
    begin
      {$if declared(FC_ERR_get_error_line_data)}
      ERR_get_error_line_data := FC_ERR_get_error_line_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_get_error_line_data_removed)}
    if ERR_get_error_line_data_removed <= LibVersion then
    begin
      {$if declared(_ERR_get_error_line_data)}
      ERR_get_error_line_data := _ERR_get_error_line_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_get_error_line_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_get_error_line_data');
    {$ifend}
  end;
  
  ERR_peek_error := LoadLibFunction(ADllHandle, ERR_peek_error_procname);
  FuncLoadError := not assigned(ERR_peek_error);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_error_allownil)}
    ERR_peek_error := ERR_ERR_peek_error;
    {$ifend}
    {$if declared(ERR_peek_error_introduced)}
    if LibVersion < ERR_peek_error_introduced then
    begin
      {$if declared(FC_ERR_peek_error)}
      ERR_peek_error := FC_ERR_peek_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_error_removed)}
    if ERR_peek_error_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_error)}
      ERR_peek_error := _ERR_peek_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_error_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_error');
    {$ifend}
  end;
  
  ERR_peek_error_line := LoadLibFunction(ADllHandle, ERR_peek_error_line_procname);
  FuncLoadError := not assigned(ERR_peek_error_line);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_error_line_allownil)}
    ERR_peek_error_line := ERR_ERR_peek_error_line;
    {$ifend}
    {$if declared(ERR_peek_error_line_introduced)}
    if LibVersion < ERR_peek_error_line_introduced then
    begin
      {$if declared(FC_ERR_peek_error_line)}
      ERR_peek_error_line := FC_ERR_peek_error_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_error_line_removed)}
    if ERR_peek_error_line_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_error_line)}
      ERR_peek_error_line := _ERR_peek_error_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_error_line_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_error_line');
    {$ifend}
  end;
  
  ERR_peek_error_func := LoadLibFunction(ADllHandle, ERR_peek_error_func_procname);
  FuncLoadError := not assigned(ERR_peek_error_func);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_error_func_allownil)}
    ERR_peek_error_func := ERR_ERR_peek_error_func;
    {$ifend}
    {$if declared(ERR_peek_error_func_introduced)}
    if LibVersion < ERR_peek_error_func_introduced then
    begin
      {$if declared(FC_ERR_peek_error_func)}
      ERR_peek_error_func := FC_ERR_peek_error_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_error_func_removed)}
    if ERR_peek_error_func_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_error_func)}
      ERR_peek_error_func := _ERR_peek_error_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_error_func_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_error_func');
    {$ifend}
  end;
  
  ERR_peek_error_data := LoadLibFunction(ADllHandle, ERR_peek_error_data_procname);
  FuncLoadError := not assigned(ERR_peek_error_data);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_error_data_allownil)}
    ERR_peek_error_data := ERR_ERR_peek_error_data;
    {$ifend}
    {$if declared(ERR_peek_error_data_introduced)}
    if LibVersion < ERR_peek_error_data_introduced then
    begin
      {$if declared(FC_ERR_peek_error_data)}
      ERR_peek_error_data := FC_ERR_peek_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_error_data_removed)}
    if ERR_peek_error_data_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_error_data)}
      ERR_peek_error_data := _ERR_peek_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_error_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_error_data');
    {$ifend}
  end;
  
  ERR_peek_error_all := LoadLibFunction(ADllHandle, ERR_peek_error_all_procname);
  FuncLoadError := not assigned(ERR_peek_error_all);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_error_all_allownil)}
    ERR_peek_error_all := ERR_ERR_peek_error_all;
    {$ifend}
    {$if declared(ERR_peek_error_all_introduced)}
    if LibVersion < ERR_peek_error_all_introduced then
    begin
      {$if declared(FC_ERR_peek_error_all)}
      ERR_peek_error_all := FC_ERR_peek_error_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_error_all_removed)}
    if ERR_peek_error_all_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_error_all)}
      ERR_peek_error_all := _ERR_peek_error_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_error_all_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_error_all');
    {$ifend}
  end;
  
  ERR_peek_error_line_data := LoadLibFunction(ADllHandle, ERR_peek_error_line_data_procname);
  FuncLoadError := not assigned(ERR_peek_error_line_data);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_error_line_data_allownil)}
    ERR_peek_error_line_data := ERR_ERR_peek_error_line_data;
    {$ifend}
    {$if declared(ERR_peek_error_line_data_introduced)}
    if LibVersion < ERR_peek_error_line_data_introduced then
    begin
      {$if declared(FC_ERR_peek_error_line_data)}
      ERR_peek_error_line_data := FC_ERR_peek_error_line_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_error_line_data_removed)}
    if ERR_peek_error_line_data_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_error_line_data)}
      ERR_peek_error_line_data := _ERR_peek_error_line_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_error_line_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_error_line_data');
    {$ifend}
  end;
  
  ERR_peek_last_error := LoadLibFunction(ADllHandle, ERR_peek_last_error_procname);
  FuncLoadError := not assigned(ERR_peek_last_error);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_last_error_allownil)}
    ERR_peek_last_error := ERR_ERR_peek_last_error;
    {$ifend}
    {$if declared(ERR_peek_last_error_introduced)}
    if LibVersion < ERR_peek_last_error_introduced then
    begin
      {$if declared(FC_ERR_peek_last_error)}
      ERR_peek_last_error := FC_ERR_peek_last_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_last_error_removed)}
    if ERR_peek_last_error_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_last_error)}
      ERR_peek_last_error := _ERR_peek_last_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_last_error_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_last_error');
    {$ifend}
  end;
  
  ERR_peek_last_error_line := LoadLibFunction(ADllHandle, ERR_peek_last_error_line_procname);
  FuncLoadError := not assigned(ERR_peek_last_error_line);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_last_error_line_allownil)}
    ERR_peek_last_error_line := ERR_ERR_peek_last_error_line;
    {$ifend}
    {$if declared(ERR_peek_last_error_line_introduced)}
    if LibVersion < ERR_peek_last_error_line_introduced then
    begin
      {$if declared(FC_ERR_peek_last_error_line)}
      ERR_peek_last_error_line := FC_ERR_peek_last_error_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_last_error_line_removed)}
    if ERR_peek_last_error_line_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_last_error_line)}
      ERR_peek_last_error_line := _ERR_peek_last_error_line;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_last_error_line_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_last_error_line');
    {$ifend}
  end;
  
  ERR_peek_last_error_func := LoadLibFunction(ADllHandle, ERR_peek_last_error_func_procname);
  FuncLoadError := not assigned(ERR_peek_last_error_func);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_last_error_func_allownil)}
    ERR_peek_last_error_func := ERR_ERR_peek_last_error_func;
    {$ifend}
    {$if declared(ERR_peek_last_error_func_introduced)}
    if LibVersion < ERR_peek_last_error_func_introduced then
    begin
      {$if declared(FC_ERR_peek_last_error_func)}
      ERR_peek_last_error_func := FC_ERR_peek_last_error_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_last_error_func_removed)}
    if ERR_peek_last_error_func_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_last_error_func)}
      ERR_peek_last_error_func := _ERR_peek_last_error_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_last_error_func_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_last_error_func');
    {$ifend}
  end;
  
  ERR_peek_last_error_data := LoadLibFunction(ADllHandle, ERR_peek_last_error_data_procname);
  FuncLoadError := not assigned(ERR_peek_last_error_data);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_last_error_data_allownil)}
    ERR_peek_last_error_data := ERR_ERR_peek_last_error_data;
    {$ifend}
    {$if declared(ERR_peek_last_error_data_introduced)}
    if LibVersion < ERR_peek_last_error_data_introduced then
    begin
      {$if declared(FC_ERR_peek_last_error_data)}
      ERR_peek_last_error_data := FC_ERR_peek_last_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_last_error_data_removed)}
    if ERR_peek_last_error_data_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_last_error_data)}
      ERR_peek_last_error_data := _ERR_peek_last_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_last_error_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_last_error_data');
    {$ifend}
  end;
  
  ERR_peek_last_error_all := LoadLibFunction(ADllHandle, ERR_peek_last_error_all_procname);
  FuncLoadError := not assigned(ERR_peek_last_error_all);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_last_error_all_allownil)}
    ERR_peek_last_error_all := ERR_ERR_peek_last_error_all;
    {$ifend}
    {$if declared(ERR_peek_last_error_all_introduced)}
    if LibVersion < ERR_peek_last_error_all_introduced then
    begin
      {$if declared(FC_ERR_peek_last_error_all)}
      ERR_peek_last_error_all := FC_ERR_peek_last_error_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_last_error_all_removed)}
    if ERR_peek_last_error_all_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_last_error_all)}
      ERR_peek_last_error_all := _ERR_peek_last_error_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_last_error_all_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_last_error_all');
    {$ifend}
  end;
  
  ERR_peek_last_error_line_data := LoadLibFunction(ADllHandle, ERR_peek_last_error_line_data_procname);
  FuncLoadError := not assigned(ERR_peek_last_error_line_data);
  if FuncLoadError then
  begin
    {$if not defined(ERR_peek_last_error_line_data_allownil)}
    ERR_peek_last_error_line_data := ERR_ERR_peek_last_error_line_data;
    {$ifend}
    {$if declared(ERR_peek_last_error_line_data_introduced)}
    if LibVersion < ERR_peek_last_error_line_data_introduced then
    begin
      {$if declared(FC_ERR_peek_last_error_line_data)}
      ERR_peek_last_error_line_data := FC_ERR_peek_last_error_line_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_peek_last_error_line_data_removed)}
    if ERR_peek_last_error_line_data_removed <= LibVersion then
    begin
      {$if declared(_ERR_peek_last_error_line_data)}
      ERR_peek_last_error_line_data := _ERR_peek_last_error_line_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_peek_last_error_line_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_peek_last_error_line_data');
    {$ifend}
  end;
  
  ERR_clear_error := LoadLibFunction(ADllHandle, ERR_clear_error_procname);
  FuncLoadError := not assigned(ERR_clear_error);
  if FuncLoadError then
  begin
    {$if not defined(ERR_clear_error_allownil)}
    ERR_clear_error := ERR_ERR_clear_error;
    {$ifend}
    {$if declared(ERR_clear_error_introduced)}
    if LibVersion < ERR_clear_error_introduced then
    begin
      {$if declared(FC_ERR_clear_error)}
      ERR_clear_error := FC_ERR_clear_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_clear_error_removed)}
    if ERR_clear_error_removed <= LibVersion then
    begin
      {$if declared(_ERR_clear_error)}
      ERR_clear_error := _ERR_clear_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_clear_error_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_clear_error');
    {$ifend}
  end;
  
  ERR_error_string := LoadLibFunction(ADllHandle, ERR_error_string_procname);
  FuncLoadError := not assigned(ERR_error_string);
  if FuncLoadError then
  begin
    {$if not defined(ERR_error_string_allownil)}
    ERR_error_string := ERR_ERR_error_string;
    {$ifend}
    {$if declared(ERR_error_string_introduced)}
    if LibVersion < ERR_error_string_introduced then
    begin
      {$if declared(FC_ERR_error_string)}
      ERR_error_string := FC_ERR_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_error_string_removed)}
    if ERR_error_string_removed <= LibVersion then
    begin
      {$if declared(_ERR_error_string)}
      ERR_error_string := _ERR_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_error_string');
    {$ifend}
  end;
  
  ERR_error_string_n := LoadLibFunction(ADllHandle, ERR_error_string_n_procname);
  FuncLoadError := not assigned(ERR_error_string_n);
  if FuncLoadError then
  begin
    {$if not defined(ERR_error_string_n_allownil)}
    ERR_error_string_n := ERR_ERR_error_string_n;
    {$ifend}
    {$if declared(ERR_error_string_n_introduced)}
    if LibVersion < ERR_error_string_n_introduced then
    begin
      {$if declared(FC_ERR_error_string_n)}
      ERR_error_string_n := FC_ERR_error_string_n;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_error_string_n_removed)}
    if ERR_error_string_n_removed <= LibVersion then
    begin
      {$if declared(_ERR_error_string_n)}
      ERR_error_string_n := _ERR_error_string_n;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_error_string_n_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_error_string_n');
    {$ifend}
  end;
  
  ERR_lib_error_string := LoadLibFunction(ADllHandle, ERR_lib_error_string_procname);
  FuncLoadError := not assigned(ERR_lib_error_string);
  if FuncLoadError then
  begin
    {$if not defined(ERR_lib_error_string_allownil)}
    ERR_lib_error_string := ERR_ERR_lib_error_string;
    {$ifend}
    {$if declared(ERR_lib_error_string_introduced)}
    if LibVersion < ERR_lib_error_string_introduced then
    begin
      {$if declared(FC_ERR_lib_error_string)}
      ERR_lib_error_string := FC_ERR_lib_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_lib_error_string_removed)}
    if ERR_lib_error_string_removed <= LibVersion then
    begin
      {$if declared(_ERR_lib_error_string)}
      ERR_lib_error_string := _ERR_lib_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_lib_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_lib_error_string');
    {$ifend}
  end;
  
  ERR_func_error_string := LoadLibFunction(ADllHandle, ERR_func_error_string_procname);
  FuncLoadError := not assigned(ERR_func_error_string);
  if FuncLoadError then
  begin
    {$if not defined(ERR_func_error_string_allownil)}
    ERR_func_error_string := ERR_ERR_func_error_string;
    {$ifend}
    {$if declared(ERR_func_error_string_introduced)}
    if LibVersion < ERR_func_error_string_introduced then
    begin
      {$if declared(FC_ERR_func_error_string)}
      ERR_func_error_string := FC_ERR_func_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_func_error_string_removed)}
    if ERR_func_error_string_removed <= LibVersion then
    begin
      {$if declared(_ERR_func_error_string)}
      ERR_func_error_string := _ERR_func_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_func_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_func_error_string');
    {$ifend}
  end;
  
  ERR_reason_error_string := LoadLibFunction(ADllHandle, ERR_reason_error_string_procname);
  FuncLoadError := not assigned(ERR_reason_error_string);
  if FuncLoadError then
  begin
    {$if not defined(ERR_reason_error_string_allownil)}
    ERR_reason_error_string := ERR_ERR_reason_error_string;
    {$ifend}
    {$if declared(ERR_reason_error_string_introduced)}
    if LibVersion < ERR_reason_error_string_introduced then
    begin
      {$if declared(FC_ERR_reason_error_string)}
      ERR_reason_error_string := FC_ERR_reason_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_reason_error_string_removed)}
    if ERR_reason_error_string_removed <= LibVersion then
    begin
      {$if declared(_ERR_reason_error_string)}
      ERR_reason_error_string := _ERR_reason_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_reason_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_reason_error_string');
    {$ifend}
  end;
  
  ERR_print_errors_cb := LoadLibFunction(ADllHandle, ERR_print_errors_cb_procname);
  FuncLoadError := not assigned(ERR_print_errors_cb);
  if FuncLoadError then
  begin
    {$if not defined(ERR_print_errors_cb_allownil)}
    ERR_print_errors_cb := ERR_ERR_print_errors_cb;
    {$ifend}
    {$if declared(ERR_print_errors_cb_introduced)}
    if LibVersion < ERR_print_errors_cb_introduced then
    begin
      {$if declared(FC_ERR_print_errors_cb)}
      ERR_print_errors_cb := FC_ERR_print_errors_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_print_errors_cb_removed)}
    if ERR_print_errors_cb_removed <= LibVersion then
    begin
      {$if declared(_ERR_print_errors_cb)}
      ERR_print_errors_cb := _ERR_print_errors_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_print_errors_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_print_errors_cb');
    {$ifend}
  end;
  
  ERR_print_errors_fp := LoadLibFunction(ADllHandle, ERR_print_errors_fp_procname);
  FuncLoadError := not assigned(ERR_print_errors_fp);
  if FuncLoadError then
  begin
    {$if not defined(ERR_print_errors_fp_allownil)}
    ERR_print_errors_fp := ERR_ERR_print_errors_fp;
    {$ifend}
    {$if declared(ERR_print_errors_fp_introduced)}
    if LibVersion < ERR_print_errors_fp_introduced then
    begin
      {$if declared(FC_ERR_print_errors_fp)}
      ERR_print_errors_fp := FC_ERR_print_errors_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_print_errors_fp_removed)}
    if ERR_print_errors_fp_removed <= LibVersion then
    begin
      {$if declared(_ERR_print_errors_fp)}
      ERR_print_errors_fp := _ERR_print_errors_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_print_errors_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_print_errors_fp');
    {$ifend}
  end;
  
  ERR_print_errors := LoadLibFunction(ADllHandle, ERR_print_errors_procname);
  FuncLoadError := not assigned(ERR_print_errors);
  if FuncLoadError then
  begin
    {$if not defined(ERR_print_errors_allownil)}
    ERR_print_errors := ERR_ERR_print_errors;
    {$ifend}
    {$if declared(ERR_print_errors_introduced)}
    if LibVersion < ERR_print_errors_introduced then
    begin
      {$if declared(FC_ERR_print_errors)}
      ERR_print_errors := FC_ERR_print_errors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_print_errors_removed)}
    if ERR_print_errors_removed <= LibVersion then
    begin
      {$if declared(_ERR_print_errors)}
      ERR_print_errors := _ERR_print_errors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_print_errors_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_print_errors');
    {$ifend}
  end;
  
  ERR_add_error_data := LoadLibFunction(ADllHandle, ERR_add_error_data_procname);
  FuncLoadError := not assigned(ERR_add_error_data);
  if FuncLoadError then
  begin
    {$if not defined(ERR_add_error_data_allownil)}
    ERR_add_error_data := ERR_ERR_add_error_data;
    {$ifend}
    {$if declared(ERR_add_error_data_introduced)}
    if LibVersion < ERR_add_error_data_introduced then
    begin
      {$if declared(FC_ERR_add_error_data)}
      ERR_add_error_data := FC_ERR_add_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_add_error_data_removed)}
    if ERR_add_error_data_removed <= LibVersion then
    begin
      {$if declared(_ERR_add_error_data)}
      ERR_add_error_data := _ERR_add_error_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_add_error_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_add_error_data');
    {$ifend}
  end;
  
  ERR_add_error_vdata := LoadLibFunction(ADllHandle, ERR_add_error_vdata_procname);
  FuncLoadError := not assigned(ERR_add_error_vdata);
  if FuncLoadError then
  begin
    {$if not defined(ERR_add_error_vdata_allownil)}
    ERR_add_error_vdata := ERR_ERR_add_error_vdata;
    {$ifend}
    {$if declared(ERR_add_error_vdata_introduced)}
    if LibVersion < ERR_add_error_vdata_introduced then
    begin
      {$if declared(FC_ERR_add_error_vdata)}
      ERR_add_error_vdata := FC_ERR_add_error_vdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_add_error_vdata_removed)}
    if ERR_add_error_vdata_removed <= LibVersion then
    begin
      {$if declared(_ERR_add_error_vdata)}
      ERR_add_error_vdata := _ERR_add_error_vdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_add_error_vdata_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_add_error_vdata');
    {$ifend}
  end;
  
  ERR_add_error_txt := LoadLibFunction(ADllHandle, ERR_add_error_txt_procname);
  FuncLoadError := not assigned(ERR_add_error_txt);
  if FuncLoadError then
  begin
    {$if not defined(ERR_add_error_txt_allownil)}
    ERR_add_error_txt := ERR_ERR_add_error_txt;
    {$ifend}
    {$if declared(ERR_add_error_txt_introduced)}
    if LibVersion < ERR_add_error_txt_introduced then
    begin
      {$if declared(FC_ERR_add_error_txt)}
      ERR_add_error_txt := FC_ERR_add_error_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_add_error_txt_removed)}
    if ERR_add_error_txt_removed <= LibVersion then
    begin
      {$if declared(_ERR_add_error_txt)}
      ERR_add_error_txt := _ERR_add_error_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_add_error_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_add_error_txt');
    {$ifend}
  end;
  
  ERR_add_error_mem_bio := LoadLibFunction(ADllHandle, ERR_add_error_mem_bio_procname);
  FuncLoadError := not assigned(ERR_add_error_mem_bio);
  if FuncLoadError then
  begin
    {$if not defined(ERR_add_error_mem_bio_allownil)}
    ERR_add_error_mem_bio := ERR_ERR_add_error_mem_bio;
    {$ifend}
    {$if declared(ERR_add_error_mem_bio_introduced)}
    if LibVersion < ERR_add_error_mem_bio_introduced then
    begin
      {$if declared(FC_ERR_add_error_mem_bio)}
      ERR_add_error_mem_bio := FC_ERR_add_error_mem_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_add_error_mem_bio_removed)}
    if ERR_add_error_mem_bio_removed <= LibVersion then
    begin
      {$if declared(_ERR_add_error_mem_bio)}
      ERR_add_error_mem_bio := _ERR_add_error_mem_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_add_error_mem_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_add_error_mem_bio');
    {$ifend}
  end;
  
  ERR_load_strings := LoadLibFunction(ADllHandle, ERR_load_strings_procname);
  FuncLoadError := not assigned(ERR_load_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_strings_allownil)}
    ERR_load_strings := ERR_ERR_load_strings;
    {$ifend}
    {$if declared(ERR_load_strings_introduced)}
    if LibVersion < ERR_load_strings_introduced then
    begin
      {$if declared(FC_ERR_load_strings)}
      ERR_load_strings := FC_ERR_load_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_strings_removed)}
    if ERR_load_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_strings)}
      ERR_load_strings := _ERR_load_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_strings');
    {$ifend}
  end;
  
  ERR_load_strings_const := LoadLibFunction(ADllHandle, ERR_load_strings_const_procname);
  FuncLoadError := not assigned(ERR_load_strings_const);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_strings_const_allownil)}
    ERR_load_strings_const := ERR_ERR_load_strings_const;
    {$ifend}
    {$if declared(ERR_load_strings_const_introduced)}
    if LibVersion < ERR_load_strings_const_introduced then
    begin
      {$if declared(FC_ERR_load_strings_const)}
      ERR_load_strings_const := FC_ERR_load_strings_const;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_strings_const_removed)}
    if ERR_load_strings_const_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_strings_const)}
      ERR_load_strings_const := _ERR_load_strings_const;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_strings_const_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_strings_const');
    {$ifend}
  end;
  
  ERR_unload_strings := LoadLibFunction(ADllHandle, ERR_unload_strings_procname);
  FuncLoadError := not assigned(ERR_unload_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_unload_strings_allownil)}
    ERR_unload_strings := ERR_ERR_unload_strings;
    {$ifend}
    {$if declared(ERR_unload_strings_introduced)}
    if LibVersion < ERR_unload_strings_introduced then
    begin
      {$if declared(FC_ERR_unload_strings)}
      ERR_unload_strings := FC_ERR_unload_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_unload_strings_removed)}
    if ERR_unload_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_unload_strings)}
      ERR_unload_strings := _ERR_unload_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_unload_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_unload_strings');
    {$ifend}
  end;
  
  
  
  ERR_get_state := LoadLibFunction(ADllHandle, ERR_get_state_procname);
  FuncLoadError := not assigned(ERR_get_state);
  if FuncLoadError then
  begin
    {$if not defined(ERR_get_state_allownil)}
    ERR_get_state := ERR_ERR_get_state;
    {$ifend}
    {$if declared(ERR_get_state_introduced)}
    if LibVersion < ERR_get_state_introduced then
    begin
      {$if declared(FC_ERR_get_state)}
      ERR_get_state := FC_ERR_get_state;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_get_state_removed)}
    if ERR_get_state_removed <= LibVersion then
    begin
      {$if declared(_ERR_get_state)}
      ERR_get_state := _ERR_get_state;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_get_state_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_get_state');
    {$ifend}
  end;
  
  ERR_get_next_error_library := LoadLibFunction(ADllHandle, ERR_get_next_error_library_procname);
  FuncLoadError := not assigned(ERR_get_next_error_library);
  if FuncLoadError then
  begin
    {$if not defined(ERR_get_next_error_library_allownil)}
    ERR_get_next_error_library := ERR_ERR_get_next_error_library;
    {$ifend}
    {$if declared(ERR_get_next_error_library_introduced)}
    if LibVersion < ERR_get_next_error_library_introduced then
    begin
      {$if declared(FC_ERR_get_next_error_library)}
      ERR_get_next_error_library := FC_ERR_get_next_error_library;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_get_next_error_library_removed)}
    if ERR_get_next_error_library_removed <= LibVersion then
    begin
      {$if declared(_ERR_get_next_error_library)}
      ERR_get_next_error_library := _ERR_get_next_error_library;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_get_next_error_library_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_get_next_error_library');
    {$ifend}
  end;
  
  ERR_set_mark := LoadLibFunction(ADllHandle, ERR_set_mark_procname);
  FuncLoadError := not assigned(ERR_set_mark);
  if FuncLoadError then
  begin
    {$if not defined(ERR_set_mark_allownil)}
    ERR_set_mark := ERR_ERR_set_mark;
    {$ifend}
    {$if declared(ERR_set_mark_introduced)}
    if LibVersion < ERR_set_mark_introduced then
    begin
      {$if declared(FC_ERR_set_mark)}
      ERR_set_mark := FC_ERR_set_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_set_mark_removed)}
    if ERR_set_mark_removed <= LibVersion then
    begin
      {$if declared(_ERR_set_mark)}
      ERR_set_mark := _ERR_set_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_set_mark_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_set_mark');
    {$ifend}
  end;
  
  ERR_pop_to_mark := LoadLibFunction(ADllHandle, ERR_pop_to_mark_procname);
  FuncLoadError := not assigned(ERR_pop_to_mark);
  if FuncLoadError then
  begin
    {$if not defined(ERR_pop_to_mark_allownil)}
    ERR_pop_to_mark := ERR_ERR_pop_to_mark;
    {$ifend}
    {$if declared(ERR_pop_to_mark_introduced)}
    if LibVersion < ERR_pop_to_mark_introduced then
    begin
      {$if declared(FC_ERR_pop_to_mark)}
      ERR_pop_to_mark := FC_ERR_pop_to_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_pop_to_mark_removed)}
    if ERR_pop_to_mark_removed <= LibVersion then
    begin
      {$if declared(_ERR_pop_to_mark)}
      ERR_pop_to_mark := _ERR_pop_to_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_pop_to_mark_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_pop_to_mark');
    {$ifend}
  end;
  
  ERR_clear_last_mark := LoadLibFunction(ADllHandle, ERR_clear_last_mark_procname);
  FuncLoadError := not assigned(ERR_clear_last_mark);
  if FuncLoadError then
  begin
    {$if not defined(ERR_clear_last_mark_allownil)}
    ERR_clear_last_mark := ERR_ERR_clear_last_mark;
    {$ifend}
    {$if declared(ERR_clear_last_mark_introduced)}
    if LibVersion < ERR_clear_last_mark_introduced then
    begin
      {$if declared(FC_ERR_clear_last_mark)}
      ERR_clear_last_mark := FC_ERR_clear_last_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_clear_last_mark_removed)}
    if ERR_clear_last_mark_removed <= LibVersion then
    begin
      {$if declared(_ERR_clear_last_mark)}
      ERR_clear_last_mark := _ERR_clear_last_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_clear_last_mark_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_clear_last_mark');
    {$ifend}
  end;
  
  ERR_count_to_mark := LoadLibFunction(ADllHandle, ERR_count_to_mark_procname);
  FuncLoadError := not assigned(ERR_count_to_mark);
  if FuncLoadError then
  begin
    {$if not defined(ERR_count_to_mark_allownil)}
    ERR_count_to_mark := ERR_ERR_count_to_mark;
    {$ifend}
    {$if declared(ERR_count_to_mark_introduced)}
    if LibVersion < ERR_count_to_mark_introduced then
    begin
      {$if declared(FC_ERR_count_to_mark)}
      ERR_count_to_mark := FC_ERR_count_to_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_count_to_mark_removed)}
    if ERR_count_to_mark_removed <= LibVersion then
    begin
      {$if declared(_ERR_count_to_mark)}
      ERR_count_to_mark := _ERR_count_to_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_count_to_mark_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_count_to_mark');
    {$ifend}
  end;
  
  ERR_pop := LoadLibFunction(ADllHandle, ERR_pop_procname);
  FuncLoadError := not assigned(ERR_pop);
  if FuncLoadError then
  begin
    {$if not defined(ERR_pop_allownil)}
    ERR_pop := ERR_ERR_pop;
    {$ifend}
    {$if declared(ERR_pop_introduced)}
    if LibVersion < ERR_pop_introduced then
    begin
      {$if declared(FC_ERR_pop)}
      ERR_pop := FC_ERR_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_pop_removed)}
    if ERR_pop_removed <= LibVersion then
    begin
      {$if declared(_ERR_pop)}
      ERR_pop := _ERR_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_pop_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_pop');
    {$ifend}
  end;
  
  OSSL_ERR_STATE_new := LoadLibFunction(ADllHandle, OSSL_ERR_STATE_new_procname);
  FuncLoadError := not assigned(OSSL_ERR_STATE_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ERR_STATE_new_allownil)}
    OSSL_ERR_STATE_new := ERR_OSSL_ERR_STATE_new;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_new_introduced)}
    if LibVersion < OSSL_ERR_STATE_new_introduced then
    begin
      {$if declared(FC_OSSL_ERR_STATE_new)}
      OSSL_ERR_STATE_new := FC_OSSL_ERR_STATE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_new_removed)}
    if OSSL_ERR_STATE_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ERR_STATE_new)}
      OSSL_ERR_STATE_new := _OSSL_ERR_STATE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ERR_STATE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ERR_STATE_new');
    {$ifend}
  end;
  
  OSSL_ERR_STATE_save := LoadLibFunction(ADllHandle, OSSL_ERR_STATE_save_procname);
  FuncLoadError := not assigned(OSSL_ERR_STATE_save);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ERR_STATE_save_allownil)}
    OSSL_ERR_STATE_save := ERR_OSSL_ERR_STATE_save;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_save_introduced)}
    if LibVersion < OSSL_ERR_STATE_save_introduced then
    begin
      {$if declared(FC_OSSL_ERR_STATE_save)}
      OSSL_ERR_STATE_save := FC_OSSL_ERR_STATE_save;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_save_removed)}
    if OSSL_ERR_STATE_save_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ERR_STATE_save)}
      OSSL_ERR_STATE_save := _OSSL_ERR_STATE_save;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ERR_STATE_save_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ERR_STATE_save');
    {$ifend}
  end;
  
  OSSL_ERR_STATE_save_to_mark := LoadLibFunction(ADllHandle, OSSL_ERR_STATE_save_to_mark_procname);
  FuncLoadError := not assigned(OSSL_ERR_STATE_save_to_mark);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ERR_STATE_save_to_mark_allownil)}
    OSSL_ERR_STATE_save_to_mark := ERR_OSSL_ERR_STATE_save_to_mark;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_save_to_mark_introduced)}
    if LibVersion < OSSL_ERR_STATE_save_to_mark_introduced then
    begin
      {$if declared(FC_OSSL_ERR_STATE_save_to_mark)}
      OSSL_ERR_STATE_save_to_mark := FC_OSSL_ERR_STATE_save_to_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_save_to_mark_removed)}
    if OSSL_ERR_STATE_save_to_mark_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ERR_STATE_save_to_mark)}
      OSSL_ERR_STATE_save_to_mark := _OSSL_ERR_STATE_save_to_mark;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ERR_STATE_save_to_mark_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ERR_STATE_save_to_mark');
    {$ifend}
  end;
  
  OSSL_ERR_STATE_restore := LoadLibFunction(ADllHandle, OSSL_ERR_STATE_restore_procname);
  FuncLoadError := not assigned(OSSL_ERR_STATE_restore);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ERR_STATE_restore_allownil)}
    OSSL_ERR_STATE_restore := ERR_OSSL_ERR_STATE_restore;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_restore_introduced)}
    if LibVersion < OSSL_ERR_STATE_restore_introduced then
    begin
      {$if declared(FC_OSSL_ERR_STATE_restore)}
      OSSL_ERR_STATE_restore := FC_OSSL_ERR_STATE_restore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_restore_removed)}
    if OSSL_ERR_STATE_restore_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ERR_STATE_restore)}
      OSSL_ERR_STATE_restore := _OSSL_ERR_STATE_restore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ERR_STATE_restore_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ERR_STATE_restore');
    {$ifend}
  end;
  
  OSSL_ERR_STATE_free := LoadLibFunction(ADllHandle, OSSL_ERR_STATE_free_procname);
  FuncLoadError := not assigned(OSSL_ERR_STATE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ERR_STATE_free_allownil)}
    OSSL_ERR_STATE_free := ERR_OSSL_ERR_STATE_free;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_free_introduced)}
    if LibVersion < OSSL_ERR_STATE_free_introduced then
    begin
      {$if declared(FC_OSSL_ERR_STATE_free)}
      OSSL_ERR_STATE_free := FC_OSSL_ERR_STATE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ERR_STATE_free_removed)}
    if OSSL_ERR_STATE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ERR_STATE_free)}
      OSSL_ERR_STATE_free := _OSSL_ERR_STATE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ERR_STATE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ERR_STATE_free');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  ERR_GET_LIB := nil;
  ERR_GET_REASON := nil;
  ERR_FATAL_ERROR := nil;
  ERR_new := nil;
  ERR_set_debug := nil;
  ERR_set_error := nil;
  ERR_vset_error := nil;
  ERR_set_error_data := nil;
  ERR_get_error := nil;
  ERR_get_error_all := nil;
  ERR_get_error_line := nil;
  ERR_get_error_line_data := nil;
  ERR_peek_error := nil;
  ERR_peek_error_line := nil;
  ERR_peek_error_func := nil;
  ERR_peek_error_data := nil;
  ERR_peek_error_all := nil;
  ERR_peek_error_line_data := nil;
  ERR_peek_last_error := nil;
  ERR_peek_last_error_line := nil;
  ERR_peek_last_error_func := nil;
  ERR_peek_last_error_data := nil;
  ERR_peek_last_error_all := nil;
  ERR_peek_last_error_line_data := nil;
  ERR_clear_error := nil;
  ERR_error_string := nil;
  ERR_error_string_n := nil;
  ERR_lib_error_string := nil;
  ERR_func_error_string := nil;
  ERR_reason_error_string := nil;
  ERR_print_errors_cb := nil;
  ERR_print_errors_fp := nil;
  ERR_print_errors := nil;
  ERR_add_error_data := nil;
  ERR_add_error_vdata := nil;
  ERR_add_error_txt := nil;
  ERR_add_error_mem_bio := nil;
  ERR_load_strings := nil;
  ERR_load_strings_const := nil;
  ERR_unload_strings := nil;
  ERR_get_state := nil;
  ERR_get_next_error_library := nil;
  ERR_set_mark := nil;
  ERR_pop_to_mark := nil;
  ERR_clear_last_mark := nil;
  ERR_count_to_mark := nil;
  ERR_pop := nil;
  OSSL_ERR_STATE_new := nil;
  OSSL_ERR_STATE_save := nil;
  OSSL_ERR_STATE_save_to_mark := nil;
  OSSL_ERR_STATE_restore := nil;
  OSSL_ERR_STATE_free := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.