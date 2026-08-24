/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_err.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_err.h2pas
     and this file regenerated. TaurusTLSHeaders_err.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_err;

interface

// Headers for OpenSSL 1.1.1
// err.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types;

const
  {$EXTERNALSYM ERR_TXT_MALLOCED}
  ERR_TXT_MALLOCED = $01;
  {$EXTERNALSYM ERR_TXT_STRING}
  ERR_TXT_STRING = $02;
  {$EXTERNALSYM ERR_FLAG_MARK}
  ERR_FLAG_MARK = $01;
  {$EXTERNALSYM ERR_FLAG_CLEAR}
  ERR_FLAG_CLEAR = $02;

  {$EXTERNALSYM ERR_NUM_ERRORS}
  ERR_NUM_ERRORS = 16;

//* library */
  {$EXTERNALSYM ERR_LIB_SYS}
  ERR_LIB_SYS =    2;
  {$EXTERNALSYM ERR_LIB_BN}
  ERR_LIB_BN =    3;
  {$EXTERNALSYM ERR_LIB_RSA}
  ERR_LIB_RSA =    4;
  {$EXTERNALSYM ERR_LIB_DH}
  ERR_LIB_DH =    5;
  {$EXTERNALSYM ERR_LIB_EVP}
  ERR_LIB_EVP =    6;
  {$EXTERNALSYM ERR_LIB_BUF}
  ERR_LIB_BUF =    7;
  {$EXTERNALSYM ERR_LIB_OBJ}
  ERR_LIB_OBJ =    8;
  {$EXTERNALSYM ERR_LIB_PEM}
  ERR_LIB_PEM =    9;
  {$EXTERNALSYM ERR_LIB_DSA}
  ERR_LIB_DSA =    10;
  {$EXTERNALSYM ERR_LIB_X509}
  ERR_LIB_X509 =    11;
  // ERR_LIB_METH         12
  {$EXTERNALSYM ERR_LIB_ASN1}
  ERR_LIB_ASN1 =    13;
  {$EXTERNALSYM ERR_LIB_CONF}
  ERR_LIB_CONF =    14;
  {$EXTERNALSYM ERR_LIB_CRYPTO}
  ERR_LIB_CRYPTO =   15;
  {$EXTERNALSYM ERR_LIB_EC}
  ERR_LIB_EC =    16;
  {$EXTERNALSYM ERR_LIB_SSL}
  ERR_LIB_SSL =    20;
(* #define ERR_LIB_SSL23        21 *)
(* #define ERR_LIB_SSL2         22 *)
(* #define ERR_LIB_SSL3         23 *)
(* #define ERR_LIB_RSAREF       30 *)
(* #define ERR_LIB_PROXY        31 *)
  {$EXTERNALSYM ERR_LIB_BIO}
  ERR_LIB_BIO =    32;
  {$EXTERNALSYM ERR_LIB_PKCS7}
  ERR_LIB_PKCS7 =    33;
  {$EXTERNALSYM ERR_LIB_X509V3}
  ERR_LIB_X509V3 =   34;
  {$EXTERNALSYM ERR_LIB_PKCS12}
  ERR_LIB_PKCS12 =   35;
  {$EXTERNALSYM ERR_LIB_RAND}
  ERR_LIB_RAND =    36;
  {$EXTERNALSYM ERR_LIB_DSO}
  ERR_LIB_DSO =    37;
  {$EXTERNALSYM ERR_LIB_ENGINE}
  ERR_LIB_ENGINE =   38;
  {$EXTERNALSYM ERR_LIB_OCSP}
  ERR_LIB_OCSP =    39;
  {$EXTERNALSYM ERR_LIB_UI}
  ERR_LIB_UI =    40;
  {$EXTERNALSYM ERR_LIB_COMP}
  ERR_LIB_COMP =    41;
  {$EXTERNALSYM ERR_LIB_ECDSA}
  ERR_LIB_ECDSA =    42;
  {$EXTERNALSYM ERR_LIB_ECDH}
  ERR_LIB_ECDH =    43;
  {$EXTERNALSYM ERR_LIB_OSSL_STORE}
  ERR_LIB_OSSL_STORE =  44;
  {$EXTERNALSYM ERR_LIB_FIPS}
  ERR_LIB_FIPS =    45;
  {$EXTERNALSYM ERR_LIB_CMS}
  ERR_LIB_CMS =    46;
  {$EXTERNALSYM ERR_LIB_TS}
  ERR_LIB_TS =    47;
  {$EXTERNALSYM ERR_LIB_HMAC}
  ERR_LIB_HMAC =    48;
(* # define ERR_LIB_JPAKE       49 *)
  {$EXTERNALSYM ERR_LIB_CT}
  ERR_LIB_CT =    50;
  {$EXTERNALSYM ERR_LIB_ASYNC}
  ERR_LIB_ASYNC =    51;
  {$EXTERNALSYM ERR_LIB_KDF}
  ERR_LIB_KDF =    52;
  {$EXTERNALSYM ERR_LIB_SM2}
  ERR_LIB_SM2 =    53;
  {$EXTERNALSYM ERR_LIB_USER}
  ERR_LIB_USER =    128;

//* OS functions */
  {$EXTERNALSYM SYS_F_FOPEN}
  SYS_F_FOPEN = 1;
  {$EXTERNALSYM SYS_F_CONNECT}
  SYS_F_CONNECT = 2;
  {$EXTERNALSYM SYS_F_GETSERVBYNAME}
  SYS_F_GETSERVBYNAME = 3;
  {$EXTERNALSYM SYS_F_SOCKET}
  SYS_F_SOCKET = 4;
  {$EXTERNALSYM SYS_F_IOCTLSOCKET}
  SYS_F_IOCTLSOCKET = 5;
  {$EXTERNALSYM SYS_F_BIND}
  SYS_F_BIND = 6;
  {$EXTERNALSYM SYS_F_LISTEN}
  SYS_F_LISTEN = 7;
  {$EXTERNALSYM SYS_F_ACCEPT}
  SYS_F_ACCEPT = 8;
  {$EXTERNALSYM SYS_F_WSASTARTUP}
  SYS_F_WSASTARTUP = 9; (* Winsock stuff *)
  {$EXTERNALSYM SYS_F_OPENDIR}
  SYS_F_OPENDIR = 10;
  {$EXTERNALSYM SYS_F_FREAD}
  SYS_F_FREAD = 11;
  {$EXTERNALSYM SYS_F_GETADDRINFO}
  SYS_F_GETADDRINFO = 12;
  {$EXTERNALSYM SYS_F_GETNAMEINFO}
  SYS_F_GETNAMEINFO = 13;
  {$EXTERNALSYM SYS_F_SETSOCKOPT}
  SYS_F_SETSOCKOPT = 14;
  {$EXTERNALSYM SYS_F_GETSOCKOPT}
  SYS_F_GETSOCKOPT = 15;
  {$EXTERNALSYM SYS_F_GETSOCKNAME}
  SYS_F_GETSOCKNAME = 16;
  {$EXTERNALSYM SYS_F_GETHOSTBYNAME}
  SYS_F_GETHOSTBYNAME = 17;
  {$EXTERNALSYM SYS_F_FFLUSH}
  SYS_F_FFLUSH = 18;
  {$EXTERNALSYM SYS_F_OPEN}
  SYS_F_OPEN = 19;
  {$EXTERNALSYM SYS_F_CLOSE}
  SYS_F_CLOSE = 20;
  {$EXTERNALSYM SYS_F_IOCTL}
  SYS_F_IOCTL = 21;
  {$EXTERNALSYM SYS_F_STAT}
  SYS_F_STAT = 22;
  {$EXTERNALSYM SYS_F_FCNTL}
  SYS_F_FCNTL = 23;
  {$EXTERNALSYM SYS_F_FSTAT}
  SYS_F_FSTAT = 24;

//* reasons */
  {$EXTERNALSYM ERR_R_SYS_LIB}
  ERR_R_SYS_LIB = ERR_LIB_SYS; //2
  {$EXTERNALSYM ERR_R_BN_LIB}
  ERR_R_BN_LIB = ERR_LIB_BN; //3
  {$EXTERNALSYM ERR_R_RSA_LIB}
  ERR_R_RSA_LIB = ERR_LIB_RSA; //4
  {$EXTERNALSYM ERR_R_DH_LIB}
  ERR_R_DH_LIB = ERR_LIB_DH; //5
  {$EXTERNALSYM ERR_R_EVP_LIB}
  ERR_R_EVP_LIB = ERR_LIB_EVP; //6
  {$EXTERNALSYM ERR_R_BUF_LIB}
  ERR_R_BUF_LIB = ERR_LIB_BUF; //7
  {$EXTERNALSYM ERR_R_OBJ_LIB}
  ERR_R_OBJ_LIB = ERR_LIB_OBJ; //8
  {$EXTERNALSYM ERR_R_PEM_LIB}
  ERR_R_PEM_LIB = ERR_LIB_PEM; //9
  {$EXTERNALSYM ERR_R_DSA_LIB}
  ERR_R_DSA_LIB = ERR_LIB_DSA; //10
  {$EXTERNALSYM ERR_R_X509_LIB}
  ERR_R_X509_LIB = ERR_LIB_X509; //11
  {$EXTERNALSYM ERR_R_ASN1_LIB}
  ERR_R_ASN1_LIB = ERR_LIB_ASN1; //13
  {$EXTERNALSYM ERR_R_EC_LIB}
  ERR_R_EC_LIB = ERR_LIB_EC; //16
  {$EXTERNALSYM ERR_R_BIO_LIB}
  ERR_R_BIO_LIB = ERR_LIB_BIO; //32
  {$EXTERNALSYM ERR_R_PKCS7_LIB}
  ERR_R_PKCS7_LIB = ERR_LIB_PKCS7; //33
  {$EXTERNALSYM ERR_R_X509V3_LIB}
  ERR_R_X509V3_LIB = ERR_LIB_X509V3; //34
  {$EXTERNALSYM ERR_R_ENGINE_LIB}
  ERR_R_ENGINE_LIB = ERR_LIB_ENGINE; //38
  {$EXTERNALSYM ERR_R_UI_LIB}
  ERR_R_UI_LIB = ERR_LIB_UI; //40
  {$EXTERNALSYM ERR_R_ECDSA_LIB}
  ERR_R_ECDSA_LIB = ERR_LIB_ECDSA; //42
  {$EXTERNALSYM ERR_R_OSSL_STORE_LIB}
  ERR_R_OSSL_STORE_LIB = ERR_LIB_OSSL_STORE; //44

  {$EXTERNALSYM ERR_R_NESTED_ASN1_ERROR}
  ERR_R_NESTED_ASN1_ERROR =  58;
  {$EXTERNALSYM ERR_R_MISSING_ASN1_EOS}
  ERR_R_MISSING_ASN1_EOS =  63;

  //* fatal error */
  {$EXTERNALSYM ERR_R_FATAL}
  ERR_R_FATAL =  64;
  {$EXTERNALSYM ERR_R_MALLOC_FAILURE}
  ERR_R_MALLOC_FAILURE = (1 or ERR_R_FATAL);
  {$EXTERNALSYM ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED}
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = (2 or ERR_R_FATAL);
  {$EXTERNALSYM ERR_R_PASSED_NULL_PARAMETER}
  ERR_R_PASSED_NULL_PARAMETER = (3 or ERR_R_FATAL);
  {$EXTERNALSYM ERR_R_INTERNAL_ERROR}
  ERR_R_INTERNAL_ERROR = (4 or ERR_R_FATAL);
  {$EXTERNALSYM ERR_R_DISABLED}
  ERR_R_DISABLED = (5 or ERR_R_FATAL);
  {$EXTERNALSYM ERR_R_INIT_FAIL}
  ERR_R_INIT_FAIL = (6 or ERR_R_FATAL);
  {$EXTERNALSYM ERR_R_PASSED_INVALID_ARGUMENT}
  ERR_R_PASSED_INVALID_ARGUMENT = (7);
  {$EXTERNALSYM ERR_R_OPERATION_FAIL}
  ERR_R_OPERATION_FAIL = (8 or ERR_R_FATAL);
  {$EXTERNALSYM ERR_R_PKCS12_LIB}
  ERR_R_PKCS12_LIB = ERR_LIB_PKCS12;


(*
 * 99 is the maximum possible ERR_R_... code, higher values are reserved for
 * the individual libraries
 *)

type
  //This is now opaque in OpenSSL 4.0.0
  {$EXTERNALSYM err_state_st}
  err_state_st = record
{    err_flags: array[0..ERR_NUM_ERRORS -1] of TIdC_INT;
    err_buffer: array[0..ERR_NUM_ERRORS -1] of TIdC_ULONG;
    err_data: array[0..ERR_NUM_ERRORS -1] of PIdAnsiChar;
    err_data_flags: array[0..ERR_NUM_ERRORS -1] of TIdC_INT;
    err_file: array[0..ERR_NUM_ERRORS -1] of PIdAnsiChar;
    err_line: array[0..ERR_NUM_ERRORS -1] of TIdC_INT;
    top, bottom: TIdC_INT;   }
  end;
  {$EXTERNALSYM ERR_STATE}
  ERR_STATE = err_state_st;
  {$EXTERNALSYM PERR_STATE}
  PERR_STATE = ^ERR_STATE;

  {$EXTERNALSYM ERR_string_data_st}
  ERR_string_data_st = record
    _error: TIdC_ULONG;
    string_: PIdAnsiChar;
  end;
  {$EXTERNALSYM ERR_STRING_DATA}
  ERR_STRING_DATA = ERR_string_data_st;
  {$EXTERNALSYM PERR_STRING_DATA}
  PERR_STRING_DATA = ^ERR_STRING_DATA;

  {$EXTERNALSYM ERR_print_errors_cb_cb}
  ERR_print_errors_cb_cb = function(_str: PIdAnsiChar; len: TIdC_SIZET; u: Pointer): TIdC_INT; cdecl;

// DEFINE_LHASH_OF(ERR_STRING_DATA);

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
{helper_functions}
  {$EXTERNALSYM ERR_GET_LIB}
function ERR_GET_LIB(l: TIdC_INT): TIdC_ULONG;
{\helper_functions}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_put_error}
  ERR_put_error: procedure (lib: TIdC_INT; func: TIdC_INT; reason: TIdC_INT; file_: PIdAnsiChar; line: TIdC_INT); cdecl = nil; {removed 3.0.0}

{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), NULL))}

  {$EXTERNALSYM ERR_new}
  ERR_new: procedure ; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM ERR_set_debug}
  ERR_set_debug: procedure (const file_: PIdAnsiChar; line: TIdC_INT; const func: PIdAnsiChar); cdecl = nil;  {introduced 3.0.0}
//  ERR_set_error: procedure (lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar; args: array of const); cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM ERR_set_error}
  ERR_set_error: procedure (lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar); cdecl varargs = nil; {introduced 3.0.0}


  {$EXTERNALSYM ERR_set_error_data}
  ERR_set_error_data: procedure (data: PIdAnsiChar; flags: TIdC_INT); cdecl = nil;
  
  {$EXTERNALSYM ERR_get_error}
  ERR_get_error: function : TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_get_error_line}
  ERR_get_error_line: function (file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_get_error_line_data}
  ERR_get_error_line_data: function (file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;

  {$EXTERNALSYM ERR_peek_error}
  ERR_peek_error: function : TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_error_line}
  ERR_peek_error_line: function (file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_error_line_data}
  ERR_peek_error_line_data: function (file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;

  {$EXTERNALSYM ERR_peek_last_error}
  ERR_peek_last_error: function : TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_last_error_line}
  ERR_peek_last_error_line: function (file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM ERR_peek_last_error_line_data}
  ERR_peek_last_error_line_data: function (file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG; cdecl = nil;

  {$EXTERNALSYM ERR_clear_error}
  ERR_clear_error: procedure ; cdecl = nil;
  {$EXTERNALSYM ERR_error_string}
  ERR_error_string: function (e: TIdC_ULONG; buf: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ERR_error_string_n}
  ERR_error_string_n: procedure (e: TIdC_ULONG; buf: PIdAnsiChar; len: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM ERR_lib_error_string}
  ERR_lib_error_string: function (e: TIdC_ULONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ERR_func_error_string}
  ERR_func_error_string: function (e: TIdC_ULONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ERR_reason_error_string}
  ERR_reason_error_string: function (e: TIdC_ULONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ERR_print_errors_cb}
  ERR_print_errors_cb: procedure (cb: ERR_print_errors_cb_cb; u: Pointer); cdecl = nil;

  {$EXTERNALSYM ERR_print_errors}
  ERR_print_errors: procedure (bp: PBIO); cdecl = nil;
  // void ERR_add_error_data(int num, ...);
  // procedure ERR_add_error_vdata(num: TIdC_INT; args: va_list);
  {$EXTERNALSYM ERR_load_strings}
  ERR_load_strings: function (lib: TIdC_INT; _str: PERR_STRING_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_load_strings_const}
  ERR_load_strings_const: function (_str: PERR_STRING_DATA): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ERR_unload_strings}
  ERR_unload_strings: function (lib: TIdC_INT; _str: PERR_STRING_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_load_ERR_strings}
  ERR_load_ERR_strings: function : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ERR_get_state}
  ERR_get_state: function : PERR_STATE; cdecl = nil;
  {$EXTERNALSYM ERR_get_next_error_library}
  ERR_get_next_error_library: function : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_set_mark}
  ERR_set_mark: function : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_pop_to_mark}
  ERR_pop_to_mark: function : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ERR_clear_last_mark}
  ERR_clear_last_mark: function : TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM SSLErr}
  SSLErr: procedure (func: TIdC_INT; reason: TIdC_INT); cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM X509err}
  X509err: procedure (const f,r : TIdC_INT); cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM ERR_GET_REASON}
  ERR_GET_REASON: function (const l : TIdC_INT) : TIdC_INT; cdecl = nil; {removed 1.0.0}

{$ELSE}

{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), NULL))}

  {$EXTERNALSYM ERR_new}
  procedure ERR_new cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM ERR_set_debug}
  procedure ERR_set_debug(const file_: PIdAnsiChar; line: TIdC_INT; const func: PIdAnsiChar) cdecl; external CLibCrypto;  {introduced 3.0.0}
//  procedure ERR_set_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar; args: array of const) cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM ERR_set_error}
  procedure ERR_set_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar) cdecl; varargs; external CLibCrypto; {introduced 3.0.0}

  {$EXTERNALSYM ERR_set_error_data}
  procedure ERR_set_error_data(data: PIdAnsiChar; flags: TIdC_INT) cdecl; external CLibCrypto;

  {$EXTERNALSYM ERR_get_error}
  function ERR_get_error: TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_get_error_line}
  function ERR_get_error_line(file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_get_error_line_data}
  function ERR_get_error_line_data(file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG cdecl; external CLibCrypto;

  {$EXTERNALSYM ERR_peek_error}
  function ERR_peek_error: TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_peek_error_line}
  function ERR_peek_error_line(file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_peek_error_line_data}
  function ERR_peek_error_line_data(file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG cdecl; external CLibCrypto;

  {$EXTERNALSYM ERR_peek_last_error}
  function ERR_peek_last_error: TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_peek_last_error_line}
  function ERR_peek_last_error_line(file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_peek_last_error_line_data}
  function ERR_peek_last_error_line_data(file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar; flags: PIdC_INT): TIdC_ULONG cdecl; external CLibCrypto;

  {$EXTERNALSYM ERR_clear_error}
  procedure ERR_clear_error cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_error_string}
  function ERR_error_string(e: TIdC_ULONG; buf: PIdAnsiChar): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_error_string_n}
  procedure ERR_error_string_n(e: TIdC_ULONG; buf: PIdAnsiChar; len: TIdC_SIZET) cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_lib_error_string}
  function ERR_lib_error_string(e: TIdC_ULONG): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_func_error_string}
  function ERR_func_error_string(e: TIdC_ULONG): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_reason_error_string}
  function ERR_reason_error_string(e: TIdC_ULONG): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_print_errors_cb}
  procedure ERR_print_errors_cb(cb: ERR_print_errors_cb_cb; u: Pointer) cdecl; external CLibCrypto;

  {$EXTERNALSYM ERR_print_errors}
  procedure ERR_print_errors(bp: PBIO) cdecl; external CLibCrypto;
  // void ERR_add_error_data(int num, ...);
  // procedure ERR_add_error_vdata(num: TIdC_INT; args: va_list);
  {$EXTERNALSYM ERR_load_strings}
  function ERR_load_strings(lib: TIdC_INT; _str: PERR_STRING_DATA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_load_strings_const}
  function ERR_load_strings_const(_str: PERR_STRING_DATA): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ERR_unload_strings}
  function ERR_unload_strings(lib: TIdC_INT; _str: PERR_STRING_DATA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_load_ERR_strings}
  function ERR_load_ERR_strings: TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ERR_get_state}
  function ERR_get_state: PERR_STATE cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_get_next_error_library}
  function ERR_get_next_error_library: TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_set_mark}
  function ERR_set_mark: TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_pop_to_mark}
  function ERR_pop_to_mark: TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ERR_clear_last_mark}
  function ERR_clear_last_mark: TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}


  {$EXTERNALSYM ERR_put_error}
  procedure ERR_put_error(lib: TIdC_INT; func: TIdC_INT; reason: TIdC_INT; file_: PIdAnsiChar; line: TIdC_INT); {removed 3.0.0}
  {$EXTERNALSYM SSLErr}
  procedure SSLErr(func: TIdC_INT; reason: TIdC_INT); {removed 1.0.0}
  {$EXTERNALSYM X509err}
  procedure X509err(const f,r : TIdC_INT); {removed 1.0.0}
  {$EXTERNALSYM ERR_GET_REASON}
  function ERR_GET_REASON(const l : TIdC_INT) : TIdC_INT; {removed 1.0.0}
{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
const
  ERR_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  ERR_set_debug_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  ERR_set_error_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  ERR_load_strings_const_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_clear_last_mark_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ERR_get_state_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  ERR_put_error_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  SSLErr_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  X509err_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  ERR_GET_REASON_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);

{helper_functions}
function ERR_GET_LIB(l: TIdC_INT): TIdC_ULONG;
begin
  Result := (l shr 24) and $ff;
end;
{\helper_functions}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  ERR_put_error_procname = 'ERR_put_error'; {removed 3.0.0}

{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), NULL))}

  ERR_new_procname = 'ERR_new'; {introduced 3.0.0}
  ERR_set_debug_procname = 'ERR_set_debug';  {introduced 3.0.0}
  ERR_set_error_procname = 'ERR_set_error'; {introduced 3.0.0}


  ERR_set_error_data_procname = 'ERR_set_error_data';
  
  ERR_get_error_procname = 'ERR_get_error';
  ERR_get_error_line_procname = 'ERR_get_error_line';
  ERR_get_error_line_data_procname = 'ERR_get_error_line_data';

  ERR_peek_error_procname = 'ERR_peek_error';
  ERR_peek_error_line_procname = 'ERR_peek_error_line';
  ERR_peek_error_line_data_procname = 'ERR_peek_error_line_data';

  ERR_peek_last_error_procname = 'ERR_peek_last_error';
  ERR_peek_last_error_line_procname = 'ERR_peek_last_error_line';
  ERR_peek_last_error_line_data_procname = 'ERR_peek_last_error_line_data';

  ERR_clear_error_procname = 'ERR_clear_error';
  ERR_error_string_procname = 'ERR_error_string';
  ERR_error_string_n_procname = 'ERR_error_string_n';
  ERR_lib_error_string_procname = 'ERR_lib_error_string';
  ERR_func_error_string_procname = 'ERR_func_error_string';
  ERR_reason_error_string_procname = 'ERR_reason_error_string';
  ERR_print_errors_cb_procname = 'ERR_print_errors_cb';

  ERR_print_errors_procname = 'ERR_print_errors';
  // void ERR_add_error_data(int num, ...);
  // procedure ERR_add_error_vdata(num: TIdC_INT; args: va_list);
  ERR_load_strings_procname = 'ERR_load_strings';
  ERR_load_strings_const_procname = 'ERR_load_strings_const'; {introduced 1.1.0}
  ERR_unload_strings_procname = 'ERR_unload_strings';
  ERR_load_ERR_strings_procname = 'ERR_load_ERR_strings';

  ERR_get_state_procname = 'ERR_get_state';
  ERR_get_next_error_library_procname = 'ERR_get_next_error_library';
  ERR_set_mark_procname = 'ERR_set_mark';
  ERR_pop_to_mark_procname = 'ERR_pop_to_mark';
  ERR_clear_last_mark_procname = 'ERR_clear_last_mark'; {introduced 1.1.0}

  SSLErr_procname = 'SSLErr'; {removed 1.0.0}
  X509err_procname = 'X509err'; {removed 1.0.0}
  ERR_GET_REASON_procname = 'ERR_GET_REASON'; {removed 1.0.0}

  {$IFNDEF _FIXINSIGHT_}
{$I TaurusTLSNoRetValOff.inc}

procedure  _SSLErr(func: TIdC_INT; reason: TIdC_INT); cdecl;
begin
  ERR_put_error(ERR_LIB_SSL,func,reason,'',0);
end;

procedure  _ERR_put_error(lib: TIdC_INT; func: TIdC_INT; reason: TIdC_INT; file_: PIdAnsiChar; line: TIdC_INT); cdecl;
{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), '',[]))}
begin
  ERR_new;
  ERR_set_debug(file_,line, '');
//  ERR_set_error(lib,reason,'',[]);
    ERR_set_error(lib,reason,'');
end;

procedure  _X509err(const f,r : TIdC_INT); cdecl;
begin
  ERR_PUT_error(ERR_LIB_X509,f,r,nil,0);
end;

function  _ERR_GET_REASON(const l : TIdC_INT) : TIdC_INT; cdecl;
begin
  Result := l and $fff;
end;

procedure  ERR_ERR_put_error(lib: TIdC_INT; func: TIdC_INT; reason: TIdC_INT;
  file_: PIdAnsiChar; line: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_put_error_procname);
end;



{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), NULL))}

procedure  ERR_ERR_new; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_new_procname);
end;

 {introduced 3.0.0}
procedure  ERR_ERR_set_debug(const file_: PIdAnsiChar; line: TIdC_INT; const func: PIdAnsiChar); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_debug_procname);
end;

  {introduced 3.0.0}
//procedure  ERR_ERR_set_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar; args: array of const);
procedure  ERR_ERR_set_error(lib: TIdC_INT; reason: TIdC_INT; fmt: PIdAnsiChar); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_error_procname);
end;

 {introduced 3.0.0}


procedure  ERR_ERR_set_error_data(data: PIdAnsiChar; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_error_data_procname);
end;



function  ERR_ERR_get_error: TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_error_procname);
end;


function  ERR_ERR_get_error_line(file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_error_line_procname);
end;


function  ERR_ERR_get_error_line_data(file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar;
  flags: PIdC_INT): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_error_line_data_procname);
end;



function  ERR_ERR_peek_error: TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_procname);
end;


function  ERR_ERR_peek_error_line(file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_line_procname);
end;


function  ERR_ERR_peek_error_line_data(file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar;
  flags: PIdC_INT): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_error_line_data_procname);
end;



function  ERR_ERR_peek_last_error: TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_procname);
end;


function  ERR_ERR_peek_last_error_line(file_: PPIdAnsiChar; line: PIdC_INT): TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_line_procname);
end;


function  ERR_ERR_peek_last_error_line_data(file_: PPIdAnsiChar; line: PIdC_INT; data: PPIdAnsiChar;
  flags: PIdC_INT): TIdC_ULONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_peek_last_error_line_data_procname);
end;



procedure  ERR_ERR_clear_error;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_clear_error_procname);
end;


function  ERR_ERR_error_string(e: TIdC_ULONG; buf: PIdAnsiChar): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_error_string_procname);
end;


procedure  ERR_ERR_error_string_n(e: TIdC_ULONG; buf: PIdAnsiChar; len: TIdC_SIZET);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_error_string_n_procname);
end;


function  ERR_ERR_lib_error_string(e: TIdC_ULONG): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_lib_error_string_procname);
end;


function  ERR_ERR_func_error_string(e: TIdC_ULONG): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_func_error_string_procname);
end;


function  ERR_ERR_reason_error_string(e: TIdC_ULONG): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_reason_error_string_procname);
end;


procedure  ERR_ERR_print_errors_cb(cb: ERR_print_errors_cb_cb; u: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_print_errors_cb_procname);
end;



procedure  ERR_ERR_print_errors(bp: PBIO);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_print_errors_procname);
end;


  // void ERR_add_error_data(int num, ...);
  // procedure ERR_add_error_vdata(num: TIdC_INT; args: va_list);
function  ERR_ERR_load_strings(lib: TIdC_INT; _str: PERR_STRING_DATA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_strings_procname);
end;


function  ERR_ERR_load_strings_const(_str: PERR_STRING_DATA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_strings_const_procname);
end;

 {introduced 1.1.0}
function  ERR_ERR_unload_strings(lib: TIdC_INT; _str: PERR_STRING_DATA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_unload_strings_procname);
end;


function  ERR_ERR_load_ERR_strings: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_ERR_strings_procname);
end;



function  ERR_ERR_get_state: PERR_STATE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_state_procname);
end;


function  ERR_ERR_get_next_error_library: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_get_next_error_library_procname);
end;


function  ERR_ERR_set_mark: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_set_mark_procname);
end;


function  ERR_ERR_pop_to_mark: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_pop_to_mark_procname);
end;


function  ERR_ERR_clear_last_mark: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_clear_last_mark_procname);
end;

 {introduced 1.1.0}

procedure  ERR_SSLErr(func: TIdC_INT; reason: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSLErr_procname);
end;


procedure  ERR_X509err(const f,r : TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509err_procname);
end;


function  ERR_ERR_GET_REASON(const l : TIdC_INT) : TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_GET_REASON_procname);
end;


{$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_put_error := LoadLibFunction(ADllHandle, ERR_put_error_procname);
  FuncLoadError := not assigned(ERR_put_error);
  if FuncLoadError then
  begin
    {$if not defined(ERR_put_error_allownil)}
    ERR_put_error := ERR_ERR_put_error;
    {$ifend}
    {$if declared(ERR_put_error_introduced)}
    if LibVersion < ERR_put_error_introduced then
    begin
      {$if declared(FC_ERR_put_error)}
      ERR_put_error := FC_ERR_put_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_put_error_removed)}
    if ERR_put_error_removed <= LibVersion then
    begin
      {$if declared(_ERR_put_error)}
      ERR_put_error := _ERR_put_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_put_error_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_put_error');
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

 {introduced 3.0.0}
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

  {introduced 3.0.0}
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

 {introduced 3.0.0}
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

 {introduced 1.1.0}
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


  ERR_load_ERR_strings := LoadLibFunction(ADllHandle, ERR_load_ERR_strings_procname);
  FuncLoadError := not assigned(ERR_load_ERR_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_ERR_strings_allownil)}
    ERR_load_ERR_strings := ERR_ERR_load_ERR_strings;
    {$ifend}
    {$if declared(ERR_load_ERR_strings_introduced)}
    if LibVersion < ERR_load_ERR_strings_introduced then
    begin
      {$if declared(FC_ERR_load_ERR_strings)}
      ERR_load_ERR_strings := FC_ERR_load_ERR_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_ERR_strings_removed)}
    if ERR_load_ERR_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_ERR_strings)}
      ERR_load_ERR_strings := _ERR_load_ERR_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_ERR_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_ERR_strings');
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

 {introduced 1.1.0}
  SSLErr := LoadLibFunction(ADllHandle, SSLErr_procname);
  FuncLoadError := not assigned(SSLErr);
  if FuncLoadError then
  begin
    {$if not defined(SSLErr_allownil)}
    SSLErr := ERR_SSLErr;
    {$ifend}
    {$if declared(SSLErr_introduced)}
    if LibVersion < SSLErr_introduced then
    begin
      {$if declared(FC_SSLErr)}
      SSLErr := FC_SSLErr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSLErr_removed)}
    if SSLErr_removed <= LibVersion then
    begin
      {$if declared(_SSLErr)}
      SSLErr := _SSLErr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSLErr_allownil)}
    if FuncLoadError then
      AFailed.Add('SSLErr');
    {$ifend}
  end;

 
  X509err := LoadLibFunction(ADllHandle, X509err_procname);
  FuncLoadError := not assigned(X509err);
  if FuncLoadError then
  begin
    {$if not defined(X509err_allownil)}
    X509err := ERR_X509err;
    {$ifend}
    {$if declared(X509err_introduced)}
    if LibVersion < X509err_introduced then
    begin
      {$if declared(FC_X509err)}
      X509err := FC_X509err;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509err_removed)}
    if X509err_removed <= LibVersion then
    begin
      {$if declared(_X509err)}
      X509err := _X509err;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509err_allownil)}
    if FuncLoadError then
      AFailed.Add('X509err');
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


end;

procedure Unload;
begin
  ERR_put_error := nil; {removed 3.0.0}
  ERR_new := nil; {introduced 3.0.0}
  ERR_set_debug := nil;  {introduced 3.0.0}
  ERR_set_error := nil; {introduced 3.0.0}
  ERR_set_error_data := nil;
  ERR_get_error := nil;
  ERR_get_error_line := nil;
  ERR_get_error_line_data := nil;
  ERR_peek_error := nil;
  ERR_peek_error_line := nil;
  ERR_peek_error_line_data := nil;
  ERR_peek_last_error := nil;
  ERR_peek_last_error_line := nil;
  ERR_peek_last_error_line_data := nil;
  ERR_clear_error := nil;
  ERR_error_string := nil;
  ERR_error_string_n := nil;
  ERR_lib_error_string := nil;
  ERR_func_error_string := nil;
  ERR_reason_error_string := nil;
  ERR_print_errors_cb := nil;
  ERR_print_errors := nil;
  ERR_load_strings := nil;
  ERR_load_strings_const := nil; {introduced 1.1.0}
  ERR_unload_strings := nil;
  ERR_load_ERR_strings := nil;
  ERR_get_state := nil;
  ERR_get_next_error_library := nil;
  ERR_set_mark := nil;
  ERR_pop_to_mark := nil;
  ERR_clear_last_mark := nil; {introduced 1.1.0}
  SSLErr := nil; {removed 1.0.0}
  X509err := nil; {removed 1.0.0}
  ERR_GET_REASON := nil; {removed 1.0.0}
end;
  {$ENDIF}
{$ELSE}
procedure SSLErr(func: TIdC_INT; reason: TIdC_INT);
begin
  ERR_put_error(ERR_LIB_SSL,func,reason,'',0);
end;

procedure ERR_put_error(lib: TIdC_INT; func: TIdC_INT; reason: TIdC_INT; file_: PIdAnsiChar; line: TIdC_INT);
{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), '',[]))}
begin
  ERR_new;
  ERR_set_debug(file_,line, '');
  ERR_set_error(lib,reason,'',[]);
end;

procedure X509err(const f,r : TIdC_INT);
begin
  ERR_PUT_error(ERR_LIB_X509,f,r,nil,0);
end;

function ERR_GET_REASON(const l : TIdC_INT) : TIdC_INT;
begin
  Result := l and $fff;
end;

{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
