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

unit TaurusTLSHeaders_srp;

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
  PSRP_gN_cache_st = ^TSRP_gN_cache_st;
  TSRP_gN_cache_st = record end;
  {$EXTERNALSYM PSRP_gN_cache_st}

  PSRP_gN_cache = ^TSRP_gN_cache;
  TSRP_gN_cache = TSRP_gN_cache_st;
  {$EXTERNALSYM PSRP_gN_cache}

  Pstack_st_SRP_gN_cache = ^Tstack_st_SRP_gN_cache;
  Tstack_st_SRP_gN_cache = record end;
  {$EXTERNALSYM Pstack_st_SRP_gN_cache}

  PSRP_user_pwd_st = ^TSRP_user_pwd_st;
  TSRP_user_pwd_st = record end;
  {$EXTERNALSYM PSRP_user_pwd_st}

  PSRP_user_pwd = ^TSRP_user_pwd;
  TSRP_user_pwd = TSRP_user_pwd_st;
  {$EXTERNALSYM PSRP_user_pwd}

  Pstack_st_SRP_user_pwd = ^Tstack_st_SRP_user_pwd;
  Tstack_st_SRP_user_pwd = record end;
  {$EXTERNALSYM Pstack_st_SRP_user_pwd}

  PSRP_VBASE_st = ^TSRP_VBASE_st;
  TSRP_VBASE_st = record end;
  {$EXTERNALSYM PSRP_VBASE_st}

  PSRP_VBASE = ^TSRP_VBASE;
  TSRP_VBASE = TSRP_VBASE_st;
  {$EXTERNALSYM PSRP_VBASE}

  PSRP_gN_st = ^TSRP_gN_st;
  TSRP_gN_st = record end;
  {$EXTERNALSYM PSRP_gN_st}

  PSRP_gN = ^TSRP_gN;
  TSRP_gN = TSRP_gN_st;
  {$EXTERNALSYM PSRP_gN}

  Pstack_st_SRP_gN = ^Tstack_st_SRP_gN;
  Tstack_st_SRP_gN = record end;
  {$EXTERNALSYM Pstack_st_SRP_gN}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tsk_SRP_gN_cache_compfunc_func_cb = function(arg1: PPSRP_gN_cache; arg2: PPSRP_gN_cache): TIdC_INT; cdecl;
  Tsk_SRP_gN_cache_freefunc_func_cb = procedure(arg1: PSRP_gN_cache); cdecl;
  Tsk_SRP_gN_cache_copyfunc_func_cb = function(arg1: PSRP_gN_cache): PSRP_gN_cache; cdecl;
  Tsk_SRP_user_pwd_compfunc_func_cb = function(arg1: PPSRP_user_pwd; arg2: PPSRP_user_pwd): TIdC_INT; cdecl;
  Tsk_SRP_user_pwd_freefunc_func_cb = procedure(arg1: PSRP_user_pwd); cdecl;
  Tsk_SRP_user_pwd_copyfunc_func_cb = function(arg1: PSRP_user_pwd): PSRP_user_pwd; cdecl;
  Tsk_SRP_gN_compfunc_func_cb = function(arg1: PPSRP_gN; arg2: PPSRP_gN): TIdC_INT; cdecl;
  Tsk_SRP_gN_freefunc_func_cb = procedure(arg1: PSRP_gN); cdecl;
  Tsk_SRP_gN_copyfunc_func_cb = function(arg1: PSRP_gN): PSRP_gN; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  SRP_NO_ERROR = 0;
  SRP_ERR_VBASE_INCOMPLETE_FILE = 1;
  SRP_ERR_VBASE_BN_LIB = 2;
  SRP_ERR_OPEN_FILE = 3;
  SRP_ERR_MEMORY = 4;
  DB_srptype = 0;
  DB_srpverifier = 1;
  DB_srpsalt = 2;
  DB_srpid = 3;
  DB_srpgN = 4;
  DB_srpinfo = 5;
  DB_NUMBER = 6;
  DB_SRP_INDEX = ''I'';
  DB_SRP_VALID = ''V'';
  DB_SRP_REVOKED = ''R'';
  DB_SRP_MODIF = ''v'';
  SRP_MINIMAL_N = 1024;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  SRP_user_pwd_new: function: PSRP_user_pwd; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_user_pwd_new}

  SRP_user_pwd_free: procedure(user_pwd: PSRP_user_pwd); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_user_pwd_free}

  SRP_user_pwd_set_gN: procedure(user_pwd: PSRP_user_pwd; g: PBIGNUM; N: PBIGNUM); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_user_pwd_set_gN}

  SRP_user_pwd_set1_ids: function(user_pwd: PSRP_user_pwd; id: PIdAnsiChar; info: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_user_pwd_set1_ids}

  SRP_user_pwd_set0_sv: function(user_pwd: PSRP_user_pwd; s: PBIGNUM; v: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_user_pwd_set0_sv}

  SRP_VBASE_new: function(seed_key: PIdAnsiChar): PSRP_VBASE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_VBASE_new}

  SRP_VBASE_free: procedure(vb: PSRP_VBASE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_VBASE_free}

  SRP_VBASE_init: function(vb: PSRP_VBASE; verifier_file: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_VBASE_init}

  SRP_VBASE_add0_user: function(vb: PSRP_VBASE; user_pwd: PSRP_user_pwd): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_VBASE_add0_user}

  SRP_VBASE_get1_by_user: function(vb: PSRP_VBASE; username: PIdAnsiChar): PSRP_user_pwd; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_VBASE_get1_by_user}

  SRP_create_verifier_ex: function(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_create_verifier_ex}

  SRP_create_verifier: function(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_create_verifier}

  SRP_create_verifier_BN_ex: function(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_create_verifier_BN_ex}

  SRP_create_verifier_BN: function(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_create_verifier_BN}

  SRP_check_known_gN_param: function(g: PBIGNUM; N: PBIGNUM): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_check_known_gN_param}

  SRP_get_default_gN: function(id: PIdAnsiChar): PSRP_gN; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_get_default_gN}

  SRP_Calc_server_key: function(A: PBIGNUM; v: PBIGNUM; u: PBIGNUM; b: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_server_key}

  SRP_Calc_B_ex: function(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_B_ex}

  SRP_Calc_B: function(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_B}

  SRP_Verify_A_mod_N: function(A: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Verify_A_mod_N}

  SRP_Calc_u_ex: function(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_u_ex}

  SRP_Calc_u: function(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_u}

  SRP_Calc_x_ex: function(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_x_ex}

  SRP_Calc_x: function(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_x}

  SRP_Calc_A: function(a: PBIGNUM; N: PBIGNUM; g: PBIGNUM): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_A}

  SRP_Calc_client_key_ex: function(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_client_key_ex}

  SRP_Calc_client_key: function(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Calc_client_key}

  SRP_Verify_B_mod_N: function(B: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SRP_Verify_B_mod_N}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function SRP_user_pwd_new: PSRP_user_pwd; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SRP_user_pwd_free(user_pwd: PSRP_user_pwd); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SRP_user_pwd_set_gN(user_pwd: PSRP_user_pwd; g: PBIGNUM; N: PBIGNUM); cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_user_pwd_set1_ids(user_pwd: PSRP_user_pwd; id: PIdAnsiChar; info: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_user_pwd_set0_sv(user_pwd: PSRP_user_pwd; s: PBIGNUM; v: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_VBASE_new(seed_key: PIdAnsiChar): PSRP_VBASE; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SRP_VBASE_free(vb: PSRP_VBASE); cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_VBASE_init(vb: PSRP_VBASE; verifier_file: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_VBASE_add0_user(vb: PSRP_VBASE; user_pwd: PSRP_user_pwd): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_VBASE_get1_by_user(vb: PSRP_VBASE; username: PIdAnsiChar): PSRP_user_pwd; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_create_verifier_ex(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_create_verifier(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_create_verifier_BN_ex(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_create_verifier_BN(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_check_known_gN_param(g: PBIGNUM; N: PBIGNUM): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_get_default_gN(id: PIdAnsiChar): PSRP_gN; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_server_key(A: PBIGNUM; v: PBIGNUM; u: PBIGNUM; b: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_B_ex(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_B(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Verify_A_mod_N(A: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_u_ex(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_u(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_x_ex(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_x(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_A(a: PBIGNUM; N: PBIGNUM; g: PBIGNUM): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_client_key_ex(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Calc_client_key(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function SRP_Verify_B_mod_N(B: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function SRP_user_pwd_new: PSRP_user_pwd; cdecl external CLibCrypto name 'SRP_user_pwd_new';
procedure SRP_user_pwd_free(user_pwd: PSRP_user_pwd); cdecl external CLibCrypto name 'SRP_user_pwd_free';
procedure SRP_user_pwd_set_gN(user_pwd: PSRP_user_pwd; g: PBIGNUM; N: PBIGNUM); cdecl external CLibCrypto name 'SRP_user_pwd_set_gN';
function SRP_user_pwd_set1_ids(user_pwd: PSRP_user_pwd; id: PIdAnsiChar; info: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'SRP_user_pwd_set1_ids';
function SRP_user_pwd_set0_sv(user_pwd: PSRP_user_pwd; s: PBIGNUM; v: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'SRP_user_pwd_set0_sv';
function SRP_VBASE_new(seed_key: PIdAnsiChar): PSRP_VBASE; cdecl external CLibCrypto name 'SRP_VBASE_new';
procedure SRP_VBASE_free(vb: PSRP_VBASE); cdecl external CLibCrypto name 'SRP_VBASE_free';
function SRP_VBASE_init(vb: PSRP_VBASE; verifier_file: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'SRP_VBASE_init';
function SRP_VBASE_add0_user(vb: PSRP_VBASE; user_pwd: PSRP_user_pwd): TIdC_INT; cdecl external CLibCrypto name 'SRP_VBASE_add0_user';
function SRP_VBASE_get1_by_user(vb: PSRP_VBASE; username: PIdAnsiChar): PSRP_user_pwd; cdecl external CLibCrypto name 'SRP_VBASE_get1_by_user';
function SRP_create_verifier_ex(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'SRP_create_verifier_ex';
function SRP_create_verifier(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'SRP_create_verifier';
function SRP_create_verifier_BN_ex(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'SRP_create_verifier_BN_ex';
function SRP_create_verifier_BN(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'SRP_create_verifier_BN';
function SRP_check_known_gN_param(g: PBIGNUM; N: PBIGNUM): PIdAnsiChar; cdecl external CLibCrypto name 'SRP_check_known_gN_param';
function SRP_get_default_gN(id: PIdAnsiChar): PSRP_gN; cdecl external CLibCrypto name 'SRP_get_default_gN';
function SRP_Calc_server_key(A: PBIGNUM; v: PBIGNUM; u: PBIGNUM; b: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_server_key';
function SRP_Calc_B_ex(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_B_ex';
function SRP_Calc_B(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_B';
function SRP_Verify_A_mod_N(A: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'SRP_Verify_A_mod_N';
function SRP_Calc_u_ex(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_u_ex';
function SRP_Calc_u(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_u';
function SRP_Calc_x_ex(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_x_ex';
function SRP_Calc_x(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_x';
function SRP_Calc_A(a: PBIGNUM; N: PBIGNUM; g: PBIGNUM): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_A';
function SRP_Calc_client_key_ex(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_client_key_ex';
function SRP_Calc_client_key(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM): PBIGNUM; cdecl external CLibCrypto name 'SRP_Calc_client_key';
function SRP_Verify_B_mod_N(B: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'SRP_Verify_B_mod_N';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  SRP_user_pwd_new_procname = 'SRP_user_pwd_new';
  SRP_user_pwd_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_user_pwd_free_procname = 'SRP_user_pwd_free';
  SRP_user_pwd_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_user_pwd_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_user_pwd_set_gN_procname = 'SRP_user_pwd_set_gN';
  SRP_user_pwd_set_gN_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_user_pwd_set1_ids_procname = 'SRP_user_pwd_set1_ids';
  SRP_user_pwd_set1_ids_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_user_pwd_set0_sv_procname = 'SRP_user_pwd_set0_sv';
  SRP_user_pwd_set0_sv_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_VBASE_new_procname = 'SRP_VBASE_new';
  SRP_VBASE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_VBASE_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_VBASE_free_procname = 'SRP_VBASE_free';
  SRP_VBASE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_VBASE_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_VBASE_init_procname = 'SRP_VBASE_init';
  SRP_VBASE_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_VBASE_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_VBASE_add0_user_procname = 'SRP_VBASE_add0_user';
  SRP_VBASE_add0_user_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_VBASE_get1_by_user_procname = 'SRP_VBASE_get1_by_user';
  SRP_VBASE_get1_by_user_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_VBASE_get1_by_user_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_create_verifier_ex_procname = 'SRP_create_verifier_ex';
  SRP_create_verifier_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_create_verifier_procname = 'SRP_create_verifier';
  SRP_create_verifier_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_create_verifier_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_create_verifier_BN_ex_procname = 'SRP_create_verifier_BN_ex';
  SRP_create_verifier_BN_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_create_verifier_BN_procname = 'SRP_create_verifier_BN';
  SRP_create_verifier_BN_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_create_verifier_BN_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_check_known_gN_param_procname = 'SRP_check_known_gN_param';
  SRP_check_known_gN_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_check_known_gN_param_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_get_default_gN_procname = 'SRP_get_default_gN';
  SRP_get_default_gN_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_get_default_gN_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_server_key_procname = 'SRP_Calc_server_key';
  SRP_Calc_server_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Calc_server_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_B_ex_procname = 'SRP_Calc_B_ex';
  SRP_Calc_B_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_B_procname = 'SRP_Calc_B';
  SRP_Calc_B_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Calc_B_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Verify_A_mod_N_procname = 'SRP_Verify_A_mod_N';
  SRP_Verify_A_mod_N_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Verify_A_mod_N_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_u_ex_procname = 'SRP_Calc_u_ex';
  SRP_Calc_u_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_u_procname = 'SRP_Calc_u';
  SRP_Calc_u_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Calc_u_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_x_ex_procname = 'SRP_Calc_x_ex';
  SRP_Calc_x_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_x_procname = 'SRP_Calc_x';
  SRP_Calc_x_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Calc_x_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_A_procname = 'SRP_Calc_A';
  SRP_Calc_A_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Calc_A_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_client_key_ex_procname = 'SRP_Calc_client_key_ex';
  SRP_Calc_client_key_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Calc_client_key_procname = 'SRP_Calc_client_key';
  SRP_Calc_client_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Calc_client_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SRP_Verify_B_mod_N_procname = 'SRP_Verify_B_mod_N';
  SRP_Verify_B_mod_N_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SRP_Verify_B_mod_N_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_SRP_user_pwd_new: PSRP_user_pwd; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_user_pwd_new_procname);
end;

procedure ERR_SRP_user_pwd_free(user_pwd: PSRP_user_pwd); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_user_pwd_free_procname);
end;

procedure ERR_SRP_user_pwd_set_gN(user_pwd: PSRP_user_pwd; g: PBIGNUM; N: PBIGNUM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_user_pwd_set_gN_procname);
end;

function ERR_SRP_user_pwd_set1_ids(user_pwd: PSRP_user_pwd; id: PIdAnsiChar; info: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_user_pwd_set1_ids_procname);
end;

function ERR_SRP_user_pwd_set0_sv(user_pwd: PSRP_user_pwd; s: PBIGNUM; v: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_user_pwd_set0_sv_procname);
end;

function ERR_SRP_VBASE_new(seed_key: PIdAnsiChar): PSRP_VBASE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_VBASE_new_procname);
end;

procedure ERR_SRP_VBASE_free(vb: PSRP_VBASE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_VBASE_free_procname);
end;

function ERR_SRP_VBASE_init(vb: PSRP_VBASE; verifier_file: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_VBASE_init_procname);
end;

function ERR_SRP_VBASE_add0_user(vb: PSRP_VBASE; user_pwd: PSRP_user_pwd): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_VBASE_add0_user_procname);
end;

function ERR_SRP_VBASE_get1_by_user(vb: PSRP_VBASE; username: PIdAnsiChar): PSRP_user_pwd; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_VBASE_get1_by_user_procname);
end;

function ERR_SRP_create_verifier_ex(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_create_verifier_ex_procname);
end;

function ERR_SRP_create_verifier(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPIdAnsiChar; verifier: PPIdAnsiChar; N: PIdAnsiChar; g: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_create_verifier_procname);
end;

function ERR_SRP_create_verifier_BN_ex(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_create_verifier_BN_ex_procname);
end;

function ERR_SRP_create_verifier_BN(user: PIdAnsiChar; pass: PIdAnsiChar; salt: PPBIGNUM; verifier: PPBIGNUM; N: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_create_verifier_BN_procname);
end;

function ERR_SRP_check_known_gN_param(g: PBIGNUM; N: PBIGNUM): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_check_known_gN_param_procname);
end;

function ERR_SRP_get_default_gN(id: PIdAnsiChar): PSRP_gN; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_get_default_gN_procname);
end;

function ERR_SRP_Calc_server_key(A: PBIGNUM; v: PBIGNUM; u: PBIGNUM; b: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_server_key_procname);
end;

function ERR_SRP_Calc_B_ex(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_B_ex_procname);
end;

function ERR_SRP_Calc_B(b: PBIGNUM; N: PBIGNUM; g: PBIGNUM; v: PBIGNUM): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_B_procname);
end;

function ERR_SRP_Verify_A_mod_N(A: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Verify_A_mod_N_procname);
end;

function ERR_SRP_Calc_u_ex(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_u_ex_procname);
end;

function ERR_SRP_Calc_u(A: PBIGNUM; B: PBIGNUM; N: PBIGNUM): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_u_procname);
end;

function ERR_SRP_Calc_x_ex(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_x_ex_procname);
end;

function ERR_SRP_Calc_x(s: PBIGNUM; user: PIdAnsiChar; pass: PIdAnsiChar): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_x_procname);
end;

function ERR_SRP_Calc_A(a: PBIGNUM; N: PBIGNUM; g: PBIGNUM): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_A_procname);
end;

function ERR_SRP_Calc_client_key_ex(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_client_key_ex_procname);
end;

function ERR_SRP_Calc_client_key(N: PBIGNUM; B: PBIGNUM; g: PBIGNUM; x: PBIGNUM; a: PBIGNUM; u: PBIGNUM): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Calc_client_key_procname);
end;

function ERR_SRP_Verify_B_mod_N(B: PBIGNUM; N: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SRP_Verify_B_mod_N_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  SRP_user_pwd_new := LoadLibFunction(ADllHandle, SRP_user_pwd_new_procname);
  FuncLoadError := not assigned(SRP_user_pwd_new);
  if FuncLoadError then
  begin
    {$if not defined(SRP_user_pwd_new_allownil)}
    SRP_user_pwd_new := ERR_SRP_user_pwd_new;
    {$ifend}
    {$if declared(SRP_user_pwd_new_introduced)}
    if LibVersion < SRP_user_pwd_new_introduced then
    begin
      {$if declared(FC_SRP_user_pwd_new)}
      SRP_user_pwd_new := FC_SRP_user_pwd_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_user_pwd_new_removed)}
    if SRP_user_pwd_new_removed <= LibVersion then
    begin
      {$if declared(_SRP_user_pwd_new)}
      SRP_user_pwd_new := _SRP_user_pwd_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_user_pwd_new_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_user_pwd_new');
    {$ifend}
  end;
  
  SRP_user_pwd_free := LoadLibFunction(ADllHandle, SRP_user_pwd_free_procname);
  FuncLoadError := not assigned(SRP_user_pwd_free);
  if FuncLoadError then
  begin
    {$if not defined(SRP_user_pwd_free_allownil)}
    SRP_user_pwd_free := ERR_SRP_user_pwd_free;
    {$ifend}
    {$if declared(SRP_user_pwd_free_introduced)}
    if LibVersion < SRP_user_pwd_free_introduced then
    begin
      {$if declared(FC_SRP_user_pwd_free)}
      SRP_user_pwd_free := FC_SRP_user_pwd_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_user_pwd_free_removed)}
    if SRP_user_pwd_free_removed <= LibVersion then
    begin
      {$if declared(_SRP_user_pwd_free)}
      SRP_user_pwd_free := _SRP_user_pwd_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_user_pwd_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_user_pwd_free');
    {$ifend}
  end;
  
  SRP_user_pwd_set_gN := LoadLibFunction(ADllHandle, SRP_user_pwd_set_gN_procname);
  FuncLoadError := not assigned(SRP_user_pwd_set_gN);
  if FuncLoadError then
  begin
    {$if not defined(SRP_user_pwd_set_gN_allownil)}
    SRP_user_pwd_set_gN := ERR_SRP_user_pwd_set_gN;
    {$ifend}
    {$if declared(SRP_user_pwd_set_gN_introduced)}
    if LibVersion < SRP_user_pwd_set_gN_introduced then
    begin
      {$if declared(FC_SRP_user_pwd_set_gN)}
      SRP_user_pwd_set_gN := FC_SRP_user_pwd_set_gN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_user_pwd_set_gN_removed)}
    if SRP_user_pwd_set_gN_removed <= LibVersion then
    begin
      {$if declared(_SRP_user_pwd_set_gN)}
      SRP_user_pwd_set_gN := _SRP_user_pwd_set_gN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_user_pwd_set_gN_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_user_pwd_set_gN');
    {$ifend}
  end;
  
  SRP_user_pwd_set1_ids := LoadLibFunction(ADllHandle, SRP_user_pwd_set1_ids_procname);
  FuncLoadError := not assigned(SRP_user_pwd_set1_ids);
  if FuncLoadError then
  begin
    {$if not defined(SRP_user_pwd_set1_ids_allownil)}
    SRP_user_pwd_set1_ids := ERR_SRP_user_pwd_set1_ids;
    {$ifend}
    {$if declared(SRP_user_pwd_set1_ids_introduced)}
    if LibVersion < SRP_user_pwd_set1_ids_introduced then
    begin
      {$if declared(FC_SRP_user_pwd_set1_ids)}
      SRP_user_pwd_set1_ids := FC_SRP_user_pwd_set1_ids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_user_pwd_set1_ids_removed)}
    if SRP_user_pwd_set1_ids_removed <= LibVersion then
    begin
      {$if declared(_SRP_user_pwd_set1_ids)}
      SRP_user_pwd_set1_ids := _SRP_user_pwd_set1_ids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_user_pwd_set1_ids_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_user_pwd_set1_ids');
    {$ifend}
  end;
  
  SRP_user_pwd_set0_sv := LoadLibFunction(ADllHandle, SRP_user_pwd_set0_sv_procname);
  FuncLoadError := not assigned(SRP_user_pwd_set0_sv);
  if FuncLoadError then
  begin
    {$if not defined(SRP_user_pwd_set0_sv_allownil)}
    SRP_user_pwd_set0_sv := ERR_SRP_user_pwd_set0_sv;
    {$ifend}
    {$if declared(SRP_user_pwd_set0_sv_introduced)}
    if LibVersion < SRP_user_pwd_set0_sv_introduced then
    begin
      {$if declared(FC_SRP_user_pwd_set0_sv)}
      SRP_user_pwd_set0_sv := FC_SRP_user_pwd_set0_sv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_user_pwd_set0_sv_removed)}
    if SRP_user_pwd_set0_sv_removed <= LibVersion then
    begin
      {$if declared(_SRP_user_pwd_set0_sv)}
      SRP_user_pwd_set0_sv := _SRP_user_pwd_set0_sv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_user_pwd_set0_sv_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_user_pwd_set0_sv');
    {$ifend}
  end;
  
  SRP_VBASE_new := LoadLibFunction(ADllHandle, SRP_VBASE_new_procname);
  FuncLoadError := not assigned(SRP_VBASE_new);
  if FuncLoadError then
  begin
    {$if not defined(SRP_VBASE_new_allownil)}
    SRP_VBASE_new := ERR_SRP_VBASE_new;
    {$ifend}
    {$if declared(SRP_VBASE_new_introduced)}
    if LibVersion < SRP_VBASE_new_introduced then
    begin
      {$if declared(FC_SRP_VBASE_new)}
      SRP_VBASE_new := FC_SRP_VBASE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_VBASE_new_removed)}
    if SRP_VBASE_new_removed <= LibVersion then
    begin
      {$if declared(_SRP_VBASE_new)}
      SRP_VBASE_new := _SRP_VBASE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_VBASE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_VBASE_new');
    {$ifend}
  end;
  
  SRP_VBASE_free := LoadLibFunction(ADllHandle, SRP_VBASE_free_procname);
  FuncLoadError := not assigned(SRP_VBASE_free);
  if FuncLoadError then
  begin
    {$if not defined(SRP_VBASE_free_allownil)}
    SRP_VBASE_free := ERR_SRP_VBASE_free;
    {$ifend}
    {$if declared(SRP_VBASE_free_introduced)}
    if LibVersion < SRP_VBASE_free_introduced then
    begin
      {$if declared(FC_SRP_VBASE_free)}
      SRP_VBASE_free := FC_SRP_VBASE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_VBASE_free_removed)}
    if SRP_VBASE_free_removed <= LibVersion then
    begin
      {$if declared(_SRP_VBASE_free)}
      SRP_VBASE_free := _SRP_VBASE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_VBASE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_VBASE_free');
    {$ifend}
  end;
  
  SRP_VBASE_init := LoadLibFunction(ADllHandle, SRP_VBASE_init_procname);
  FuncLoadError := not assigned(SRP_VBASE_init);
  if FuncLoadError then
  begin
    {$if not defined(SRP_VBASE_init_allownil)}
    SRP_VBASE_init := ERR_SRP_VBASE_init;
    {$ifend}
    {$if declared(SRP_VBASE_init_introduced)}
    if LibVersion < SRP_VBASE_init_introduced then
    begin
      {$if declared(FC_SRP_VBASE_init)}
      SRP_VBASE_init := FC_SRP_VBASE_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_VBASE_init_removed)}
    if SRP_VBASE_init_removed <= LibVersion then
    begin
      {$if declared(_SRP_VBASE_init)}
      SRP_VBASE_init := _SRP_VBASE_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_VBASE_init_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_VBASE_init');
    {$ifend}
  end;
  
  SRP_VBASE_add0_user := LoadLibFunction(ADllHandle, SRP_VBASE_add0_user_procname);
  FuncLoadError := not assigned(SRP_VBASE_add0_user);
  if FuncLoadError then
  begin
    {$if not defined(SRP_VBASE_add0_user_allownil)}
    SRP_VBASE_add0_user := ERR_SRP_VBASE_add0_user;
    {$ifend}
    {$if declared(SRP_VBASE_add0_user_introduced)}
    if LibVersion < SRP_VBASE_add0_user_introduced then
    begin
      {$if declared(FC_SRP_VBASE_add0_user)}
      SRP_VBASE_add0_user := FC_SRP_VBASE_add0_user;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_VBASE_add0_user_removed)}
    if SRP_VBASE_add0_user_removed <= LibVersion then
    begin
      {$if declared(_SRP_VBASE_add0_user)}
      SRP_VBASE_add0_user := _SRP_VBASE_add0_user;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_VBASE_add0_user_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_VBASE_add0_user');
    {$ifend}
  end;
  
  SRP_VBASE_get1_by_user := LoadLibFunction(ADllHandle, SRP_VBASE_get1_by_user_procname);
  FuncLoadError := not assigned(SRP_VBASE_get1_by_user);
  if FuncLoadError then
  begin
    {$if not defined(SRP_VBASE_get1_by_user_allownil)}
    SRP_VBASE_get1_by_user := ERR_SRP_VBASE_get1_by_user;
    {$ifend}
    {$if declared(SRP_VBASE_get1_by_user_introduced)}
    if LibVersion < SRP_VBASE_get1_by_user_introduced then
    begin
      {$if declared(FC_SRP_VBASE_get1_by_user)}
      SRP_VBASE_get1_by_user := FC_SRP_VBASE_get1_by_user;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_VBASE_get1_by_user_removed)}
    if SRP_VBASE_get1_by_user_removed <= LibVersion then
    begin
      {$if declared(_SRP_VBASE_get1_by_user)}
      SRP_VBASE_get1_by_user := _SRP_VBASE_get1_by_user;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_VBASE_get1_by_user_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_VBASE_get1_by_user');
    {$ifend}
  end;
  
  SRP_create_verifier_ex := LoadLibFunction(ADllHandle, SRP_create_verifier_ex_procname);
  FuncLoadError := not assigned(SRP_create_verifier_ex);
  if FuncLoadError then
  begin
    {$if not defined(SRP_create_verifier_ex_allownil)}
    SRP_create_verifier_ex := ERR_SRP_create_verifier_ex;
    {$ifend}
    {$if declared(SRP_create_verifier_ex_introduced)}
    if LibVersion < SRP_create_verifier_ex_introduced then
    begin
      {$if declared(FC_SRP_create_verifier_ex)}
      SRP_create_verifier_ex := FC_SRP_create_verifier_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_create_verifier_ex_removed)}
    if SRP_create_verifier_ex_removed <= LibVersion then
    begin
      {$if declared(_SRP_create_verifier_ex)}
      SRP_create_verifier_ex := _SRP_create_verifier_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_create_verifier_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_create_verifier_ex');
    {$ifend}
  end;
  
  SRP_create_verifier := LoadLibFunction(ADllHandle, SRP_create_verifier_procname);
  FuncLoadError := not assigned(SRP_create_verifier);
  if FuncLoadError then
  begin
    {$if not defined(SRP_create_verifier_allownil)}
    SRP_create_verifier := ERR_SRP_create_verifier;
    {$ifend}
    {$if declared(SRP_create_verifier_introduced)}
    if LibVersion < SRP_create_verifier_introduced then
    begin
      {$if declared(FC_SRP_create_verifier)}
      SRP_create_verifier := FC_SRP_create_verifier;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_create_verifier_removed)}
    if SRP_create_verifier_removed <= LibVersion then
    begin
      {$if declared(_SRP_create_verifier)}
      SRP_create_verifier := _SRP_create_verifier;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_create_verifier_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_create_verifier');
    {$ifend}
  end;
  
  SRP_create_verifier_BN_ex := LoadLibFunction(ADllHandle, SRP_create_verifier_BN_ex_procname);
  FuncLoadError := not assigned(SRP_create_verifier_BN_ex);
  if FuncLoadError then
  begin
    {$if not defined(SRP_create_verifier_BN_ex_allownil)}
    SRP_create_verifier_BN_ex := ERR_SRP_create_verifier_BN_ex;
    {$ifend}
    {$if declared(SRP_create_verifier_BN_ex_introduced)}
    if LibVersion < SRP_create_verifier_BN_ex_introduced then
    begin
      {$if declared(FC_SRP_create_verifier_BN_ex)}
      SRP_create_verifier_BN_ex := FC_SRP_create_verifier_BN_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_create_verifier_BN_ex_removed)}
    if SRP_create_verifier_BN_ex_removed <= LibVersion then
    begin
      {$if declared(_SRP_create_verifier_BN_ex)}
      SRP_create_verifier_BN_ex := _SRP_create_verifier_BN_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_create_verifier_BN_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_create_verifier_BN_ex');
    {$ifend}
  end;
  
  SRP_create_verifier_BN := LoadLibFunction(ADllHandle, SRP_create_verifier_BN_procname);
  FuncLoadError := not assigned(SRP_create_verifier_BN);
  if FuncLoadError then
  begin
    {$if not defined(SRP_create_verifier_BN_allownil)}
    SRP_create_verifier_BN := ERR_SRP_create_verifier_BN;
    {$ifend}
    {$if declared(SRP_create_verifier_BN_introduced)}
    if LibVersion < SRP_create_verifier_BN_introduced then
    begin
      {$if declared(FC_SRP_create_verifier_BN)}
      SRP_create_verifier_BN := FC_SRP_create_verifier_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_create_verifier_BN_removed)}
    if SRP_create_verifier_BN_removed <= LibVersion then
    begin
      {$if declared(_SRP_create_verifier_BN)}
      SRP_create_verifier_BN := _SRP_create_verifier_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_create_verifier_BN_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_create_verifier_BN');
    {$ifend}
  end;
  
  SRP_check_known_gN_param := LoadLibFunction(ADllHandle, SRP_check_known_gN_param_procname);
  FuncLoadError := not assigned(SRP_check_known_gN_param);
  if FuncLoadError then
  begin
    {$if not defined(SRP_check_known_gN_param_allownil)}
    SRP_check_known_gN_param := ERR_SRP_check_known_gN_param;
    {$ifend}
    {$if declared(SRP_check_known_gN_param_introduced)}
    if LibVersion < SRP_check_known_gN_param_introduced then
    begin
      {$if declared(FC_SRP_check_known_gN_param)}
      SRP_check_known_gN_param := FC_SRP_check_known_gN_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_check_known_gN_param_removed)}
    if SRP_check_known_gN_param_removed <= LibVersion then
    begin
      {$if declared(_SRP_check_known_gN_param)}
      SRP_check_known_gN_param := _SRP_check_known_gN_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_check_known_gN_param_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_check_known_gN_param');
    {$ifend}
  end;
  
  SRP_get_default_gN := LoadLibFunction(ADllHandle, SRP_get_default_gN_procname);
  FuncLoadError := not assigned(SRP_get_default_gN);
  if FuncLoadError then
  begin
    {$if not defined(SRP_get_default_gN_allownil)}
    SRP_get_default_gN := ERR_SRP_get_default_gN;
    {$ifend}
    {$if declared(SRP_get_default_gN_introduced)}
    if LibVersion < SRP_get_default_gN_introduced then
    begin
      {$if declared(FC_SRP_get_default_gN)}
      SRP_get_default_gN := FC_SRP_get_default_gN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_get_default_gN_removed)}
    if SRP_get_default_gN_removed <= LibVersion then
    begin
      {$if declared(_SRP_get_default_gN)}
      SRP_get_default_gN := _SRP_get_default_gN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_get_default_gN_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_get_default_gN');
    {$ifend}
  end;
  
  SRP_Calc_server_key := LoadLibFunction(ADllHandle, SRP_Calc_server_key_procname);
  FuncLoadError := not assigned(SRP_Calc_server_key);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_server_key_allownil)}
    SRP_Calc_server_key := ERR_SRP_Calc_server_key;
    {$ifend}
    {$if declared(SRP_Calc_server_key_introduced)}
    if LibVersion < SRP_Calc_server_key_introduced then
    begin
      {$if declared(FC_SRP_Calc_server_key)}
      SRP_Calc_server_key := FC_SRP_Calc_server_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_server_key_removed)}
    if SRP_Calc_server_key_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_server_key)}
      SRP_Calc_server_key := _SRP_Calc_server_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_server_key_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_server_key');
    {$ifend}
  end;
  
  SRP_Calc_B_ex := LoadLibFunction(ADllHandle, SRP_Calc_B_ex_procname);
  FuncLoadError := not assigned(SRP_Calc_B_ex);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_B_ex_allownil)}
    SRP_Calc_B_ex := ERR_SRP_Calc_B_ex;
    {$ifend}
    {$if declared(SRP_Calc_B_ex_introduced)}
    if LibVersion < SRP_Calc_B_ex_introduced then
    begin
      {$if declared(FC_SRP_Calc_B_ex)}
      SRP_Calc_B_ex := FC_SRP_Calc_B_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_B_ex_removed)}
    if SRP_Calc_B_ex_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_B_ex)}
      SRP_Calc_B_ex := _SRP_Calc_B_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_B_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_B_ex');
    {$ifend}
  end;
  
  SRP_Calc_B := LoadLibFunction(ADllHandle, SRP_Calc_B_procname);
  FuncLoadError := not assigned(SRP_Calc_B);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_B_allownil)}
    SRP_Calc_B := ERR_SRP_Calc_B;
    {$ifend}
    {$if declared(SRP_Calc_B_introduced)}
    if LibVersion < SRP_Calc_B_introduced then
    begin
      {$if declared(FC_SRP_Calc_B)}
      SRP_Calc_B := FC_SRP_Calc_B;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_B_removed)}
    if SRP_Calc_B_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_B)}
      SRP_Calc_B := _SRP_Calc_B;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_B_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_B');
    {$ifend}
  end;
  
  SRP_Verify_A_mod_N := LoadLibFunction(ADllHandle, SRP_Verify_A_mod_N_procname);
  FuncLoadError := not assigned(SRP_Verify_A_mod_N);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Verify_A_mod_N_allownil)}
    SRP_Verify_A_mod_N := ERR_SRP_Verify_A_mod_N;
    {$ifend}
    {$if declared(SRP_Verify_A_mod_N_introduced)}
    if LibVersion < SRP_Verify_A_mod_N_introduced then
    begin
      {$if declared(FC_SRP_Verify_A_mod_N)}
      SRP_Verify_A_mod_N := FC_SRP_Verify_A_mod_N;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Verify_A_mod_N_removed)}
    if SRP_Verify_A_mod_N_removed <= LibVersion then
    begin
      {$if declared(_SRP_Verify_A_mod_N)}
      SRP_Verify_A_mod_N := _SRP_Verify_A_mod_N;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Verify_A_mod_N_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Verify_A_mod_N');
    {$ifend}
  end;
  
  SRP_Calc_u_ex := LoadLibFunction(ADllHandle, SRP_Calc_u_ex_procname);
  FuncLoadError := not assigned(SRP_Calc_u_ex);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_u_ex_allownil)}
    SRP_Calc_u_ex := ERR_SRP_Calc_u_ex;
    {$ifend}
    {$if declared(SRP_Calc_u_ex_introduced)}
    if LibVersion < SRP_Calc_u_ex_introduced then
    begin
      {$if declared(FC_SRP_Calc_u_ex)}
      SRP_Calc_u_ex := FC_SRP_Calc_u_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_u_ex_removed)}
    if SRP_Calc_u_ex_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_u_ex)}
      SRP_Calc_u_ex := _SRP_Calc_u_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_u_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_u_ex');
    {$ifend}
  end;
  
  SRP_Calc_u := LoadLibFunction(ADllHandle, SRP_Calc_u_procname);
  FuncLoadError := not assigned(SRP_Calc_u);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_u_allownil)}
    SRP_Calc_u := ERR_SRP_Calc_u;
    {$ifend}
    {$if declared(SRP_Calc_u_introduced)}
    if LibVersion < SRP_Calc_u_introduced then
    begin
      {$if declared(FC_SRP_Calc_u)}
      SRP_Calc_u := FC_SRP_Calc_u;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_u_removed)}
    if SRP_Calc_u_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_u)}
      SRP_Calc_u := _SRP_Calc_u;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_u_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_u');
    {$ifend}
  end;
  
  SRP_Calc_x_ex := LoadLibFunction(ADllHandle, SRP_Calc_x_ex_procname);
  FuncLoadError := not assigned(SRP_Calc_x_ex);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_x_ex_allownil)}
    SRP_Calc_x_ex := ERR_SRP_Calc_x_ex;
    {$ifend}
    {$if declared(SRP_Calc_x_ex_introduced)}
    if LibVersion < SRP_Calc_x_ex_introduced then
    begin
      {$if declared(FC_SRP_Calc_x_ex)}
      SRP_Calc_x_ex := FC_SRP_Calc_x_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_x_ex_removed)}
    if SRP_Calc_x_ex_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_x_ex)}
      SRP_Calc_x_ex := _SRP_Calc_x_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_x_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_x_ex');
    {$ifend}
  end;
  
  SRP_Calc_x := LoadLibFunction(ADllHandle, SRP_Calc_x_procname);
  FuncLoadError := not assigned(SRP_Calc_x);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_x_allownil)}
    SRP_Calc_x := ERR_SRP_Calc_x;
    {$ifend}
    {$if declared(SRP_Calc_x_introduced)}
    if LibVersion < SRP_Calc_x_introduced then
    begin
      {$if declared(FC_SRP_Calc_x)}
      SRP_Calc_x := FC_SRP_Calc_x;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_x_removed)}
    if SRP_Calc_x_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_x)}
      SRP_Calc_x := _SRP_Calc_x;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_x_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_x');
    {$ifend}
  end;
  
  SRP_Calc_A := LoadLibFunction(ADllHandle, SRP_Calc_A_procname);
  FuncLoadError := not assigned(SRP_Calc_A);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_A_allownil)}
    SRP_Calc_A := ERR_SRP_Calc_A;
    {$ifend}
    {$if declared(SRP_Calc_A_introduced)}
    if LibVersion < SRP_Calc_A_introduced then
    begin
      {$if declared(FC_SRP_Calc_A)}
      SRP_Calc_A := FC_SRP_Calc_A;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_A_removed)}
    if SRP_Calc_A_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_A)}
      SRP_Calc_A := _SRP_Calc_A;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_A_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_A');
    {$ifend}
  end;
  
  SRP_Calc_client_key_ex := LoadLibFunction(ADllHandle, SRP_Calc_client_key_ex_procname);
  FuncLoadError := not assigned(SRP_Calc_client_key_ex);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_client_key_ex_allownil)}
    SRP_Calc_client_key_ex := ERR_SRP_Calc_client_key_ex;
    {$ifend}
    {$if declared(SRP_Calc_client_key_ex_introduced)}
    if LibVersion < SRP_Calc_client_key_ex_introduced then
    begin
      {$if declared(FC_SRP_Calc_client_key_ex)}
      SRP_Calc_client_key_ex := FC_SRP_Calc_client_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_client_key_ex_removed)}
    if SRP_Calc_client_key_ex_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_client_key_ex)}
      SRP_Calc_client_key_ex := _SRP_Calc_client_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_client_key_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_client_key_ex');
    {$ifend}
  end;
  
  SRP_Calc_client_key := LoadLibFunction(ADllHandle, SRP_Calc_client_key_procname);
  FuncLoadError := not assigned(SRP_Calc_client_key);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Calc_client_key_allownil)}
    SRP_Calc_client_key := ERR_SRP_Calc_client_key;
    {$ifend}
    {$if declared(SRP_Calc_client_key_introduced)}
    if LibVersion < SRP_Calc_client_key_introduced then
    begin
      {$if declared(FC_SRP_Calc_client_key)}
      SRP_Calc_client_key := FC_SRP_Calc_client_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Calc_client_key_removed)}
    if SRP_Calc_client_key_removed <= LibVersion then
    begin
      {$if declared(_SRP_Calc_client_key)}
      SRP_Calc_client_key := _SRP_Calc_client_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Calc_client_key_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Calc_client_key');
    {$ifend}
  end;
  
  SRP_Verify_B_mod_N := LoadLibFunction(ADllHandle, SRP_Verify_B_mod_N_procname);
  FuncLoadError := not assigned(SRP_Verify_B_mod_N);
  if FuncLoadError then
  begin
    {$if not defined(SRP_Verify_B_mod_N_allownil)}
    SRP_Verify_B_mod_N := ERR_SRP_Verify_B_mod_N;
    {$ifend}
    {$if declared(SRP_Verify_B_mod_N_introduced)}
    if LibVersion < SRP_Verify_B_mod_N_introduced then
    begin
      {$if declared(FC_SRP_Verify_B_mod_N)}
      SRP_Verify_B_mod_N := FC_SRP_Verify_B_mod_N;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SRP_Verify_B_mod_N_removed)}
    if SRP_Verify_B_mod_N_removed <= LibVersion then
    begin
      {$if declared(_SRP_Verify_B_mod_N)}
      SRP_Verify_B_mod_N := _SRP_Verify_B_mod_N;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SRP_Verify_B_mod_N_allownil)}
    if FuncLoadError then
      AFailed.Add('SRP_Verify_B_mod_N');
    {$ifend}
  end;
  
  
end;

procedure Unload;
begin
  SRP_user_pwd_new := nil;
  SRP_user_pwd_free := nil;
  SRP_user_pwd_set_gN := nil;
  SRP_user_pwd_set1_ids := nil;
  SRP_user_pwd_set0_sv := nil;
  SRP_VBASE_new := nil;
  SRP_VBASE_free := nil;
  SRP_VBASE_init := nil;
  SRP_VBASE_add0_user := nil;
  SRP_VBASE_get1_by_user := nil;
  SRP_create_verifier_ex := nil;
  SRP_create_verifier := nil;
  SRP_create_verifier_BN_ex := nil;
  SRP_create_verifier_BN := nil;
  SRP_check_known_gN_param := nil;
  SRP_get_default_gN := nil;
  SRP_Calc_server_key := nil;
  SRP_Calc_B_ex := nil;
  SRP_Calc_B := nil;
  SRP_Verify_A_mod_N := nil;
  SRP_Calc_u_ex := nil;
  SRP_Calc_u := nil;
  SRP_Calc_x_ex := nil;
  SRP_Calc_x := nil;
  SRP_Calc_A := nil;
  SRP_Calc_client_key_ex := nil;
  SRP_Calc_client_key := nil;
  SRP_Verify_B_mod_N := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.