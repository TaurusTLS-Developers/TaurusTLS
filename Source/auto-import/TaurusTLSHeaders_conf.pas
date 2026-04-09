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

unit TaurusTLSHeaders_conf;

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
  PCONF_VALUE = ^TCONF_VALUE;
  TCONF_VALUE = record end;
  {$EXTERNALSYM PCONF_VALUE}

  Pstack_st_CONF_VALUE = ^Tstack_st_CONF_VALUE;
  Tstack_st_CONF_VALUE = record end;
  {$EXTERNALSYM Pstack_st_CONF_VALUE}

  Plhash_st_CONF_VALUE = ^Tlhash_st_CONF_VALUE;
  Tlhash_st_CONF_VALUE = record end;
  {$EXTERNALSYM Plhash_st_CONF_VALUE}

  Plh_CONF_VALUE_dummy = ^Tlh_CONF_VALUE_dummy;
  {$EXTERNALSYM Plh_CONF_VALUE_dummy}

  Pconf_st = ^Tconf_st;
  Tconf_st = record end;
  {$EXTERNALSYM Pconf_st}

  Pconf_method_st = ^Tconf_method_st;
  Tconf_method_st = record end;
  {$EXTERNALSYM Pconf_method_st}

  PCONF_METHOD = ^TCONF_METHOD;
  TCONF_METHOD = Tconf_method_st;
  {$EXTERNALSYM PCONF_METHOD}

  Pconf_imodule_st = ^Tconf_imodule_st;
  Tconf_imodule_st = record end;
  {$EXTERNALSYM Pconf_imodule_st}

  PCONF_IMODULE = ^TCONF_IMODULE;
  TCONF_IMODULE = Tconf_imodule_st;
  {$EXTERNALSYM PCONF_IMODULE}

  Pconf_module_st = ^Tconf_module_st;
  Tconf_module_st = record end;
  {$EXTERNALSYM Pconf_module_st}

  PCONF_MODULE = ^TCONF_MODULE;
  TCONF_MODULE = Tconf_module_st;
  {$EXTERNALSYM PCONF_MODULE}

  Pstack_st_CONF_MODULE = ^Tstack_st_CONF_MODULE;
  Tstack_st_CONF_MODULE = record end;
  {$EXTERNALSYM Pstack_st_CONF_MODULE}

  Pstack_st_CONF_IMODULE = ^Tstack_st_CONF_IMODULE;
  Tstack_st_CONF_IMODULE = record end;
  {$EXTERNALSYM Pstack_st_CONF_IMODULE}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tsk_CONF_VALUE_compfunc_func_cb = function(arg1: PPCONF_VALUE; arg2: PPCONF_VALUE): TIdC_INT; cdecl;
  Tsk_CONF_VALUE_freefunc_func_cb = procedure(arg1: PCONF_VALUE); cdecl;
  Tsk_CONF_VALUE_copyfunc_func_cb = function(arg1: PCONF_VALUE): PCONF_VALUE; cdecl;
  Tlh_CONF_VALUE_compfunc_func_cb = function(arg1: PCONF_VALUE; arg2: PCONF_VALUE): TIdC_INT; cdecl;
  Tlh_CONF_VALUE_hashfunc_func_cb = function(arg1: PCONF_VALUE): TIdC_ULONG; cdecl;
  Tconf_init_func_func_cb = function(arg1: PCONF_IMODULE; arg2: PCONF): TIdC_INT; cdecl;
  Tconf_finish_func_func_cb = procedure(arg1: PCONF_IMODULE); cdecl;
  TCONF_parse_list_list_cb_cb = function(arg1: PIdAnsiChar; arg2: TIdC_INT; arg3: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  CONF_MFLAGS_IGNORE_ERRORS = $1;
  CONF_MFLAGS_IGNORE_RETURN_CODES = $2;
  CONF_MFLAGS_SILENT = $4;
  CONF_MFLAGS_NO_DSO = $8;
  CONF_MFLAGS_IGNORE_MISSING_FILE = $10;
  CONF_MFLAGS_DEFAULT_SECTION = $20;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  CONF_set_default_method: function(meth: PCONF_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_set_default_method}

  CONF_set_nconf: procedure(conf: PCONF; hash: Plhash_st_CONF_VALUE); cdecl = nil;
  {$EXTERNALSYM CONF_set_nconf}

  CONF_load: function(conf: Plhash_st_CONF_VALUE; _file: PIdAnsiChar; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM CONF_load}

  CONF_load_fp: function(conf: Plhash_st_CONF_VALUE; fp: PFILE; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM CONF_load_fp}

  CONF_load_bio: function(conf: Plhash_st_CONF_VALUE; bp: PBIO; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM CONF_load_bio}

  CONF_get_section: function(conf: Plhash_st_CONF_VALUE; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM CONF_get_section}

  CONF_get_string: function(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CONF_get_string}

  CONF_get_number: function(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM CONF_get_number}

  CONF_free: procedure(conf: Plhash_st_CONF_VALUE); cdecl = nil;
  {$EXTERNALSYM CONF_free}

  CONF_dump_fp: function(conf: Plhash_st_CONF_VALUE; _out: PFILE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_dump_fp}

  CONF_dump_bio: function(conf: Plhash_st_CONF_VALUE; _out: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_dump_bio}

  NCONF_new_ex: function(libctx: POSSL_LIB_CTX; meth: PCONF_METHOD): PCONF; cdecl = nil;
  {$EXTERNALSYM NCONF_new_ex}

  NCONF_get0_libctx: function(conf: PCONF): POSSL_LIB_CTX; cdecl = nil;
  {$EXTERNALSYM NCONF_get0_libctx}

  NCONF_new: function(meth: PCONF_METHOD): PCONF; cdecl = nil;
  {$EXTERNALSYM NCONF_new}

  NCONF_default: function: PCONF_METHOD; cdecl = nil;
  {$EXTERNALSYM NCONF_default}

  NCONF_WIN32: function: PCONF_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM NCONF_WIN32}

  NCONF_free: procedure(conf: PCONF); cdecl = nil;
  {$EXTERNALSYM NCONF_free}

  NCONF_free_data: procedure(conf: PCONF); cdecl = nil;
  {$EXTERNALSYM NCONF_free_data}

  NCONF_load: function(conf: PCONF; _file: PIdAnsiChar; eline: PIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NCONF_load}

  NCONF_load_fp: function(conf: PCONF; fp: PFILE; eline: PIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NCONF_load_fp}

  NCONF_load_bio: function(conf: PCONF; bp: PBIO; eline: PIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NCONF_load_bio}

  NCONF_get_section_names: function(conf: PCONF): Pstack_st_OPENSSL_CSTRING; cdecl = nil;
  {$EXTERNALSYM NCONF_get_section_names}

  NCONF_get_section: function(conf: PCONF; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl = nil;
  {$EXTERNALSYM NCONF_get_section}

  NCONF_get_string: function(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM NCONF_get_string}

  NCONF_get_number_e: function(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar; result: PIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NCONF_get_number_e}

  NCONF_dump_fp: function(conf: PCONF; _out: PFILE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NCONF_dump_fp}

  NCONF_dump_bio: function(conf: PCONF; _out: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NCONF_dump_bio}

  CONF_modules_load: function(cnf: PCONF; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_modules_load}

  CONF_modules_load_file_ex: function(libctx: POSSL_LIB_CTX; filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_modules_load_file_ex}

  CONF_modules_load_file: function(filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_modules_load_file}

  CONF_modules_unload: procedure(all: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM CONF_modules_unload}

  CONF_modules_finish: procedure; cdecl = nil;
  {$EXTERNALSYM CONF_modules_finish}

  CONF_module_add: function(name: PIdAnsiChar; ifunc: Tconf_init_func_func_cb; ffunc: Tconf_finish_func_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_module_add}

  CONF_imodule_get_name: function(md: PCONF_IMODULE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CONF_imodule_get_name}

  CONF_imodule_get_value: function(md: PCONF_IMODULE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CONF_imodule_get_value}

  CONF_imodule_get_usr_data: function(md: PCONF_IMODULE): Pointer; cdecl = nil;
  {$EXTERNALSYM CONF_imodule_get_usr_data}

  CONF_imodule_set_usr_data: procedure(md: PCONF_IMODULE; usr_data: Pointer); cdecl = nil;
  {$EXTERNALSYM CONF_imodule_set_usr_data}

  CONF_imodule_get_module: function(md: PCONF_IMODULE): PCONF_MODULE; cdecl = nil;
  {$EXTERNALSYM CONF_imodule_get_module}

  CONF_imodule_get_flags: function(md: PCONF_IMODULE): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM CONF_imodule_get_flags}

  CONF_imodule_set_flags: procedure(md: PCONF_IMODULE; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM CONF_imodule_set_flags}

  CONF_module_get_usr_data: function(pmod: PCONF_MODULE): Pointer; cdecl = nil;
  {$EXTERNALSYM CONF_module_get_usr_data}

  CONF_module_set_usr_data: procedure(pmod: PCONF_MODULE; usr_data: Pointer); cdecl = nil;
  {$EXTERNALSYM CONF_module_set_usr_data}

  CONF_get1_default_config_file: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CONF_get1_default_config_file}

  CONF_parse_list: function(list: PIdAnsiChar; sep: TIdC_INT; nospc: TIdC_INT; list_cb: TCONF_parse_list_list_cb_cb; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CONF_parse_list}

  OPENSSL_load_builtin_modules: procedure; cdecl = nil;
  {$EXTERNALSYM OPENSSL_load_builtin_modules}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function CONF_set_default_method(meth: PCONF_METHOD): TIdC_INT; cdecl;
procedure CONF_set_nconf(conf: PCONF; hash: Plhash_st_CONF_VALUE); cdecl;
function CONF_load(conf: Plhash_st_CONF_VALUE; _file: PIdAnsiChar; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl;
function CONF_load_fp(conf: Plhash_st_CONF_VALUE; fp: PFILE; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl;
function CONF_load_bio(conf: Plhash_st_CONF_VALUE; bp: PBIO; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl;
function CONF_get_section(conf: Plhash_st_CONF_VALUE; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl;
function CONF_get_string(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl;
function CONF_get_number(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): TIdC_LONG; cdecl;
procedure CONF_free(conf: Plhash_st_CONF_VALUE); cdecl;
function CONF_dump_fp(conf: Plhash_st_CONF_VALUE; _out: PFILE): TIdC_INT; cdecl;
function CONF_dump_bio(conf: Plhash_st_CONF_VALUE; _out: PBIO): TIdC_INT; cdecl;
function NCONF_new_ex(libctx: POSSL_LIB_CTX; meth: PCONF_METHOD): PCONF; cdecl;
function NCONF_get0_libctx(conf: PCONF): POSSL_LIB_CTX; cdecl;
function NCONF_new(meth: PCONF_METHOD): PCONF; cdecl;
function NCONF_default: PCONF_METHOD; cdecl;
function NCONF_WIN32: PCONF_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure NCONF_free(conf: PCONF); cdecl;
procedure NCONF_free_data(conf: PCONF); cdecl;
function NCONF_load(conf: PCONF; _file: PIdAnsiChar; eline: PIdC_LONG): TIdC_INT; cdecl;
function NCONF_load_fp(conf: PCONF; fp: PFILE; eline: PIdC_LONG): TIdC_INT; cdecl;
function NCONF_load_bio(conf: PCONF; bp: PBIO; eline: PIdC_LONG): TIdC_INT; cdecl;
function NCONF_get_section_names(conf: PCONF): Pstack_st_OPENSSL_CSTRING; cdecl;
function NCONF_get_section(conf: PCONF; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl;
function NCONF_get_string(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl;
function NCONF_get_number_e(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar; result: PIdC_LONG): TIdC_INT; cdecl;
function NCONF_dump_fp(conf: PCONF; _out: PFILE): TIdC_INT; cdecl;
function NCONF_dump_bio(conf: PCONF; _out: PBIO): TIdC_INT; cdecl;
function CONF_modules_load(cnf: PCONF; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl;
function CONF_modules_load_file_ex(libctx: POSSL_LIB_CTX; filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl;
function CONF_modules_load_file(filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl;
procedure CONF_modules_unload(all: TIdC_INT); cdecl;
procedure CONF_modules_finish; cdecl;
function CONF_module_add(name: PIdAnsiChar; ifunc: Tconf_init_func_func_cb; ffunc: Tconf_finish_func_func_cb): TIdC_INT; cdecl;
function CONF_imodule_get_name(md: PCONF_IMODULE): PIdAnsiChar; cdecl;
function CONF_imodule_get_value(md: PCONF_IMODULE): PIdAnsiChar; cdecl;
function CONF_imodule_get_usr_data(md: PCONF_IMODULE): Pointer; cdecl;
procedure CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl;
function CONF_imodule_get_module(md: PCONF_IMODULE): PCONF_MODULE; cdecl;
function CONF_imodule_get_flags(md: PCONF_IMODULE): TIdC_ULONG; cdecl;
procedure CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TIdC_ULONG); cdecl;
function CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl;
procedure CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl;
function CONF_get1_default_config_file: PIdAnsiChar; cdecl;
function CONF_parse_list(list: PIdAnsiChar; sep: TIdC_INT; nospc: TIdC_INT; list_cb: TCONF_parse_list_list_cb_cb; arg: Pointer): TIdC_INT; cdecl;
procedure OPENSSL_load_builtin_modules; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function OPENSSL_no_config: TIdC_INT; cdecl; deprecated 'In OpenSSL 1_1_0';
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function CONF_modules_free: TIdC_INT; cdecl; deprecated 'In OpenSSL 1_1_0';
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

function CONF_set_default_method(meth: PCONF_METHOD): TIdC_INT; cdecl external CLibCrypto name 'CONF_set_default_method';
procedure CONF_set_nconf(conf: PCONF; hash: Plhash_st_CONF_VALUE); cdecl external CLibCrypto name 'CONF_set_nconf';
function CONF_load(conf: Plhash_st_CONF_VALUE; _file: PIdAnsiChar; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl external CLibCrypto name 'CONF_load';
function CONF_load_fp(conf: Plhash_st_CONF_VALUE; fp: PFILE; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl external CLibCrypto name 'CONF_load_fp';
function CONF_load_bio(conf: Plhash_st_CONF_VALUE; bp: PBIO; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl external CLibCrypto name 'CONF_load_bio';
function CONF_get_section(conf: Plhash_st_CONF_VALUE; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl external CLibCrypto name 'CONF_get_section';
function CONF_get_string(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'CONF_get_string';
function CONF_get_number(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): TIdC_LONG; cdecl external CLibCrypto name 'CONF_get_number';
procedure CONF_free(conf: Plhash_st_CONF_VALUE); cdecl external CLibCrypto name 'CONF_free';
function CONF_dump_fp(conf: Plhash_st_CONF_VALUE; _out: PFILE): TIdC_INT; cdecl external CLibCrypto name 'CONF_dump_fp';
function CONF_dump_bio(conf: Plhash_st_CONF_VALUE; _out: PBIO): TIdC_INT; cdecl external CLibCrypto name 'CONF_dump_bio';
function NCONF_new_ex(libctx: POSSL_LIB_CTX; meth: PCONF_METHOD): PCONF; cdecl external CLibCrypto name 'NCONF_new_ex';
function NCONF_get0_libctx(conf: PCONF): POSSL_LIB_CTX; cdecl external CLibCrypto name 'NCONF_get0_libctx';
function NCONF_new(meth: PCONF_METHOD): PCONF; cdecl external CLibCrypto name 'NCONF_new';
function NCONF_default: PCONF_METHOD; cdecl external CLibCrypto name 'NCONF_default';
function NCONF_WIN32: PCONF_METHOD; cdecl external CLibCrypto name 'NCONF_WIN32';
procedure NCONF_free(conf: PCONF); cdecl external CLibCrypto name 'NCONF_free';
procedure NCONF_free_data(conf: PCONF); cdecl external CLibCrypto name 'NCONF_free_data';
function NCONF_load(conf: PCONF; _file: PIdAnsiChar; eline: PIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'NCONF_load';
function NCONF_load_fp(conf: PCONF; fp: PFILE; eline: PIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'NCONF_load_fp';
function NCONF_load_bio(conf: PCONF; bp: PBIO; eline: PIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'NCONF_load_bio';
function NCONF_get_section_names(conf: PCONF): Pstack_st_OPENSSL_CSTRING; cdecl external CLibCrypto name 'NCONF_get_section_names';
function NCONF_get_section(conf: PCONF; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl external CLibCrypto name 'NCONF_get_section';
function NCONF_get_string(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'NCONF_get_string';
function NCONF_get_number_e(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar; result: PIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'NCONF_get_number_e';
function NCONF_dump_fp(conf: PCONF; _out: PFILE): TIdC_INT; cdecl external CLibCrypto name 'NCONF_dump_fp';
function NCONF_dump_bio(conf: PCONF; _out: PBIO): TIdC_INT; cdecl external CLibCrypto name 'NCONF_dump_bio';
function CONF_modules_load(cnf: PCONF; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'CONF_modules_load';
function CONF_modules_load_file_ex(libctx: POSSL_LIB_CTX; filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'CONF_modules_load_file_ex';
function CONF_modules_load_file(filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'CONF_modules_load_file';
procedure CONF_modules_unload(all: TIdC_INT); cdecl external CLibCrypto name 'CONF_modules_unload';
procedure CONF_modules_finish; cdecl external CLibCrypto name 'CONF_modules_finish';
function CONF_module_add(name: PIdAnsiChar; ifunc: Tconf_init_func_func_cb; ffunc: Tconf_finish_func_func_cb): TIdC_INT; cdecl external CLibCrypto name 'CONF_module_add';
function CONF_imodule_get_name(md: PCONF_IMODULE): PIdAnsiChar; cdecl external CLibCrypto name 'CONF_imodule_get_name';
function CONF_imodule_get_value(md: PCONF_IMODULE): PIdAnsiChar; cdecl external CLibCrypto name 'CONF_imodule_get_value';
function CONF_imodule_get_usr_data(md: PCONF_IMODULE): Pointer; cdecl external CLibCrypto name 'CONF_imodule_get_usr_data';
procedure CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl external CLibCrypto name 'CONF_imodule_set_usr_data';
function CONF_imodule_get_module(md: PCONF_IMODULE): PCONF_MODULE; cdecl external CLibCrypto name 'CONF_imodule_get_module';
function CONF_imodule_get_flags(md: PCONF_IMODULE): TIdC_ULONG; cdecl external CLibCrypto name 'CONF_imodule_get_flags';
procedure CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TIdC_ULONG); cdecl external CLibCrypto name 'CONF_imodule_set_flags';
function CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl external CLibCrypto name 'CONF_module_get_usr_data';
procedure CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl external CLibCrypto name 'CONF_module_set_usr_data';
function CONF_get1_default_config_file: PIdAnsiChar; cdecl external CLibCrypto name 'CONF_get1_default_config_file';
function CONF_parse_list(list: PIdAnsiChar; sep: TIdC_INT; nospc: TIdC_INT; list_cb: TCONF_parse_list_list_cb_cb; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'CONF_parse_list';
procedure OPENSSL_load_builtin_modules; cdecl external CLibCrypto name 'OPENSSL_load_builtin_modules';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  CONF_set_default_method_procname = 'CONF_set_default_method';
  CONF_set_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_set_nconf_procname = 'CONF_set_nconf';
  CONF_set_nconf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_load_procname = 'CONF_load';
  CONF_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_load_fp_procname = 'CONF_load_fp';
  CONF_load_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_load_bio_procname = 'CONF_load_bio';
  CONF_load_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_get_section_procname = 'CONF_get_section';
  CONF_get_section_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_get_string_procname = 'CONF_get_string';
  CONF_get_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_get_number_procname = 'CONF_get_number';
  CONF_get_number_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_free_procname = 'CONF_free';
  CONF_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_dump_fp_procname = 'CONF_dump_fp';
  CONF_dump_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_dump_bio_procname = 'CONF_dump_bio';
  CONF_dump_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_new_ex_procname = 'NCONF_new_ex';
  NCONF_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  NCONF_get0_libctx_procname = 'NCONF_get0_libctx';
  NCONF_get0_libctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  NCONF_new_procname = 'NCONF_new';
  NCONF_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_default_procname = 'NCONF_default';
  NCONF_default_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_WIN32_procname = 'NCONF_WIN32';
  NCONF_WIN32_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  NCONF_WIN32_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  NCONF_free_procname = 'NCONF_free';
  NCONF_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_free_data_procname = 'NCONF_free_data';
  NCONF_free_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_load_procname = 'NCONF_load';
  NCONF_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_load_fp_procname = 'NCONF_load_fp';
  NCONF_load_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_load_bio_procname = 'NCONF_load_bio';
  NCONF_load_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_get_section_names_procname = 'NCONF_get_section_names';
  NCONF_get_section_names_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  NCONF_get_section_procname = 'NCONF_get_section';
  NCONF_get_section_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_get_string_procname = 'NCONF_get_string';
  NCONF_get_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_get_number_e_procname = 'NCONF_get_number_e';
  NCONF_get_number_e_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_dump_fp_procname = 'NCONF_dump_fp';
  NCONF_dump_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NCONF_dump_bio_procname = 'NCONF_dump_bio';
  NCONF_dump_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_modules_load_procname = 'CONF_modules_load';
  CONF_modules_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_modules_load_file_ex_procname = 'CONF_modules_load_file_ex';
  CONF_modules_load_file_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CONF_modules_load_file_procname = 'CONF_modules_load_file';
  CONF_modules_load_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_modules_unload_procname = 'CONF_modules_unload';
  CONF_modules_unload_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_modules_finish_procname = 'CONF_modules_finish';
  CONF_modules_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_module_add_procname = 'CONF_module_add';
  CONF_module_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_imodule_get_name_procname = 'CONF_imodule_get_name';
  CONF_imodule_get_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_imodule_get_value_procname = 'CONF_imodule_get_value';
  CONF_imodule_get_value_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_imodule_get_usr_data_procname = 'CONF_imodule_get_usr_data';
  CONF_imodule_get_usr_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_imodule_set_usr_data_procname = 'CONF_imodule_set_usr_data';
  CONF_imodule_set_usr_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_imodule_get_module_procname = 'CONF_imodule_get_module';
  CONF_imodule_get_module_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_imodule_get_flags_procname = 'CONF_imodule_get_flags';
  CONF_imodule_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_imodule_set_flags_procname = 'CONF_imodule_set_flags';
  CONF_imodule_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_module_get_usr_data_procname = 'CONF_module_get_usr_data';
  CONF_module_get_usr_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_module_set_usr_data_procname = 'CONF_module_set_usr_data';
  CONF_module_set_usr_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_get1_default_config_file_procname = 'CONF_get1_default_config_file';
  CONF_get1_default_config_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CONF_parse_list_procname = 'CONF_parse_list';
  CONF_parse_list_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_load_builtin_modules_procname = 'OPENSSL_load_builtin_modules';
  OPENSSL_load_builtin_modules_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OPENSSL_no_config: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_no_config() \
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)
  }
end;

function CONF_modules_free: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    CONF_modules_free() \
    while (0)               \
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

function ERR_CONF_set_default_method(meth: PCONF_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_set_default_method_procname);
end;

procedure ERR_CONF_set_nconf(conf: PCONF; hash: Plhash_st_CONF_VALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_set_nconf_procname);
end;

function ERR_CONF_load(conf: Plhash_st_CONF_VALUE; _file: PIdAnsiChar; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_load_procname);
end;

function ERR_CONF_load_fp(conf: Plhash_st_CONF_VALUE; fp: PFILE; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_load_fp_procname);
end;

function ERR_CONF_load_bio(conf: Plhash_st_CONF_VALUE; bp: PBIO; eline: PIdC_LONG): Plhash_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_load_bio_procname);
end;

function ERR_CONF_get_section(conf: Plhash_st_CONF_VALUE; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_get_section_procname);
end;

function ERR_CONF_get_string(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_get_string_procname);
end;

function ERR_CONF_get_number(conf: Plhash_st_CONF_VALUE; group: PIdAnsiChar; name: PIdAnsiChar): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_get_number_procname);
end;

procedure ERR_CONF_free(conf: Plhash_st_CONF_VALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_free_procname);
end;

function ERR_CONF_dump_fp(conf: Plhash_st_CONF_VALUE; _out: PFILE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_dump_fp_procname);
end;

function ERR_CONF_dump_bio(conf: Plhash_st_CONF_VALUE; _out: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_dump_bio_procname);
end;

function ERR_NCONF_new_ex(libctx: POSSL_LIB_CTX; meth: PCONF_METHOD): PCONF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_new_ex_procname);
end;

function ERR_NCONF_get0_libctx(conf: PCONF): POSSL_LIB_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_get0_libctx_procname);
end;

function ERR_NCONF_new(meth: PCONF_METHOD): PCONF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_new_procname);
end;

function ERR_NCONF_default: PCONF_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_default_procname);
end;

function ERR_NCONF_WIN32: PCONF_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_WIN32_procname);
end;

procedure ERR_NCONF_free(conf: PCONF); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_free_procname);
end;

procedure ERR_NCONF_free_data(conf: PCONF); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_free_data_procname);
end;

function ERR_NCONF_load(conf: PCONF; _file: PIdAnsiChar; eline: PIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_load_procname);
end;

function ERR_NCONF_load_fp(conf: PCONF; fp: PFILE; eline: PIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_load_fp_procname);
end;

function ERR_NCONF_load_bio(conf: PCONF; bp: PBIO; eline: PIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_load_bio_procname);
end;

function ERR_NCONF_get_section_names(conf: PCONF): Pstack_st_OPENSSL_CSTRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_get_section_names_procname);
end;

function ERR_NCONF_get_section(conf: PCONF; section: PIdAnsiChar): Pstack_st_CONF_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_get_section_procname);
end;

function ERR_NCONF_get_string(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_get_string_procname);
end;

function ERR_NCONF_get_number_e(conf: PCONF; group: PIdAnsiChar; name: PIdAnsiChar; result: PIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_get_number_e_procname);
end;

function ERR_NCONF_dump_fp(conf: PCONF; _out: PFILE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_dump_fp_procname);
end;

function ERR_NCONF_dump_bio(conf: PCONF; _out: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NCONF_dump_bio_procname);
end;

function ERR_CONF_modules_load(cnf: PCONF; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_modules_load_procname);
end;

function ERR_CONF_modules_load_file_ex(libctx: POSSL_LIB_CTX; filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_modules_load_file_ex_procname);
end;

function ERR_CONF_modules_load_file(filename: PIdAnsiChar; appname: PIdAnsiChar; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_modules_load_file_procname);
end;

procedure ERR_CONF_modules_unload(all: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_modules_unload_procname);
end;

procedure ERR_CONF_modules_finish; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_modules_finish_procname);
end;

function ERR_CONF_module_add(name: PIdAnsiChar; ifunc: Tconf_init_func_func_cb; ffunc: Tconf_finish_func_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_module_add_procname);
end;

function ERR_CONF_imodule_get_name(md: PCONF_IMODULE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_imodule_get_name_procname);
end;

function ERR_CONF_imodule_get_value(md: PCONF_IMODULE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_imodule_get_value_procname);
end;

function ERR_CONF_imodule_get_usr_data(md: PCONF_IMODULE): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_imodule_get_usr_data_procname);
end;

procedure ERR_CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_imodule_set_usr_data_procname);
end;

function ERR_CONF_imodule_get_module(md: PCONF_IMODULE): PCONF_MODULE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_imodule_get_module_procname);
end;

function ERR_CONF_imodule_get_flags(md: PCONF_IMODULE): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_imodule_get_flags_procname);
end;

procedure ERR_CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_imodule_set_flags_procname);
end;

function ERR_CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_module_get_usr_data_procname);
end;

procedure ERR_CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_module_set_usr_data_procname);
end;

function ERR_CONF_get1_default_config_file: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_get1_default_config_file_procname);
end;

function ERR_CONF_parse_list(list: PIdAnsiChar; sep: TIdC_INT; nospc: TIdC_INT; list_cb: TCONF_parse_list_list_cb_cb; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CONF_parse_list_procname);
end;

procedure ERR_OPENSSL_load_builtin_modules; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_load_builtin_modules_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  CONF_set_default_method := LoadLibFunction(ADllHandle, CONF_set_default_method_procname);
  FuncLoadError := not assigned(CONF_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(CONF_set_default_method_allownil)}
    CONF_set_default_method := ERR_CONF_set_default_method;
    {$ifend}
    {$if declared(CONF_set_default_method_introduced)}
    if LibVersion < CONF_set_default_method_introduced then
    begin
      {$if declared(FC_CONF_set_default_method)}
      CONF_set_default_method := FC_CONF_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_set_default_method_removed)}
    if CONF_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_CONF_set_default_method)}
      CONF_set_default_method := _CONF_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_set_default_method');
    {$ifend}
  end;
  
  CONF_set_nconf := LoadLibFunction(ADllHandle, CONF_set_nconf_procname);
  FuncLoadError := not assigned(CONF_set_nconf);
  if FuncLoadError then
  begin
    {$if not defined(CONF_set_nconf_allownil)}
    CONF_set_nconf := ERR_CONF_set_nconf;
    {$ifend}
    {$if declared(CONF_set_nconf_introduced)}
    if LibVersion < CONF_set_nconf_introduced then
    begin
      {$if declared(FC_CONF_set_nconf)}
      CONF_set_nconf := FC_CONF_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_set_nconf_removed)}
    if CONF_set_nconf_removed <= LibVersion then
    begin
      {$if declared(_CONF_set_nconf)}
      CONF_set_nconf := _CONF_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_set_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_set_nconf');
    {$ifend}
  end;
  
  CONF_load := LoadLibFunction(ADllHandle, CONF_load_procname);
  FuncLoadError := not assigned(CONF_load);
  if FuncLoadError then
  begin
    {$if not defined(CONF_load_allownil)}
    CONF_load := ERR_CONF_load;
    {$ifend}
    {$if declared(CONF_load_introduced)}
    if LibVersion < CONF_load_introduced then
    begin
      {$if declared(FC_CONF_load)}
      CONF_load := FC_CONF_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_load_removed)}
    if CONF_load_removed <= LibVersion then
    begin
      {$if declared(_CONF_load)}
      CONF_load := _CONF_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_load_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_load');
    {$ifend}
  end;
  
  CONF_load_fp := LoadLibFunction(ADllHandle, CONF_load_fp_procname);
  FuncLoadError := not assigned(CONF_load_fp);
  if FuncLoadError then
  begin
    {$if not defined(CONF_load_fp_allownil)}
    CONF_load_fp := ERR_CONF_load_fp;
    {$ifend}
    {$if declared(CONF_load_fp_introduced)}
    if LibVersion < CONF_load_fp_introduced then
    begin
      {$if declared(FC_CONF_load_fp)}
      CONF_load_fp := FC_CONF_load_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_load_fp_removed)}
    if CONF_load_fp_removed <= LibVersion then
    begin
      {$if declared(_CONF_load_fp)}
      CONF_load_fp := _CONF_load_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_load_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_load_fp');
    {$ifend}
  end;
  
  CONF_load_bio := LoadLibFunction(ADllHandle, CONF_load_bio_procname);
  FuncLoadError := not assigned(CONF_load_bio);
  if FuncLoadError then
  begin
    {$if not defined(CONF_load_bio_allownil)}
    CONF_load_bio := ERR_CONF_load_bio;
    {$ifend}
    {$if declared(CONF_load_bio_introduced)}
    if LibVersion < CONF_load_bio_introduced then
    begin
      {$if declared(FC_CONF_load_bio)}
      CONF_load_bio := FC_CONF_load_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_load_bio_removed)}
    if CONF_load_bio_removed <= LibVersion then
    begin
      {$if declared(_CONF_load_bio)}
      CONF_load_bio := _CONF_load_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_load_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_load_bio');
    {$ifend}
  end;
  
  CONF_get_section := LoadLibFunction(ADllHandle, CONF_get_section_procname);
  FuncLoadError := not assigned(CONF_get_section);
  if FuncLoadError then
  begin
    {$if not defined(CONF_get_section_allownil)}
    CONF_get_section := ERR_CONF_get_section;
    {$ifend}
    {$if declared(CONF_get_section_introduced)}
    if LibVersion < CONF_get_section_introduced then
    begin
      {$if declared(FC_CONF_get_section)}
      CONF_get_section := FC_CONF_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_get_section_removed)}
    if CONF_get_section_removed <= LibVersion then
    begin
      {$if declared(_CONF_get_section)}
      CONF_get_section := _CONF_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_get_section_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_get_section');
    {$ifend}
  end;
  
  CONF_get_string := LoadLibFunction(ADllHandle, CONF_get_string_procname);
  FuncLoadError := not assigned(CONF_get_string);
  if FuncLoadError then
  begin
    {$if not defined(CONF_get_string_allownil)}
    CONF_get_string := ERR_CONF_get_string;
    {$ifend}
    {$if declared(CONF_get_string_introduced)}
    if LibVersion < CONF_get_string_introduced then
    begin
      {$if declared(FC_CONF_get_string)}
      CONF_get_string := FC_CONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_get_string_removed)}
    if CONF_get_string_removed <= LibVersion then
    begin
      {$if declared(_CONF_get_string)}
      CONF_get_string := _CONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_get_string_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_get_string');
    {$ifend}
  end;
  
  CONF_get_number := LoadLibFunction(ADllHandle, CONF_get_number_procname);
  FuncLoadError := not assigned(CONF_get_number);
  if FuncLoadError then
  begin
    {$if not defined(CONF_get_number_allownil)}
    CONF_get_number := ERR_CONF_get_number;
    {$ifend}
    {$if declared(CONF_get_number_introduced)}
    if LibVersion < CONF_get_number_introduced then
    begin
      {$if declared(FC_CONF_get_number)}
      CONF_get_number := FC_CONF_get_number;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_get_number_removed)}
    if CONF_get_number_removed <= LibVersion then
    begin
      {$if declared(_CONF_get_number)}
      CONF_get_number := _CONF_get_number;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_get_number_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_get_number');
    {$ifend}
  end;
  
  CONF_free := LoadLibFunction(ADllHandle, CONF_free_procname);
  FuncLoadError := not assigned(CONF_free);
  if FuncLoadError then
  begin
    {$if not defined(CONF_free_allownil)}
    CONF_free := ERR_CONF_free;
    {$ifend}
    {$if declared(CONF_free_introduced)}
    if LibVersion < CONF_free_introduced then
    begin
      {$if declared(FC_CONF_free)}
      CONF_free := FC_CONF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_free_removed)}
    if CONF_free_removed <= LibVersion then
    begin
      {$if declared(_CONF_free)}
      CONF_free := _CONF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_free');
    {$ifend}
  end;
  
  CONF_dump_fp := LoadLibFunction(ADllHandle, CONF_dump_fp_procname);
  FuncLoadError := not assigned(CONF_dump_fp);
  if FuncLoadError then
  begin
    {$if not defined(CONF_dump_fp_allownil)}
    CONF_dump_fp := ERR_CONF_dump_fp;
    {$ifend}
    {$if declared(CONF_dump_fp_introduced)}
    if LibVersion < CONF_dump_fp_introduced then
    begin
      {$if declared(FC_CONF_dump_fp)}
      CONF_dump_fp := FC_CONF_dump_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_dump_fp_removed)}
    if CONF_dump_fp_removed <= LibVersion then
    begin
      {$if declared(_CONF_dump_fp)}
      CONF_dump_fp := _CONF_dump_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_dump_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_dump_fp');
    {$ifend}
  end;
  
  CONF_dump_bio := LoadLibFunction(ADllHandle, CONF_dump_bio_procname);
  FuncLoadError := not assigned(CONF_dump_bio);
  if FuncLoadError then
  begin
    {$if not defined(CONF_dump_bio_allownil)}
    CONF_dump_bio := ERR_CONF_dump_bio;
    {$ifend}
    {$if declared(CONF_dump_bio_introduced)}
    if LibVersion < CONF_dump_bio_introduced then
    begin
      {$if declared(FC_CONF_dump_bio)}
      CONF_dump_bio := FC_CONF_dump_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_dump_bio_removed)}
    if CONF_dump_bio_removed <= LibVersion then
    begin
      {$if declared(_CONF_dump_bio)}
      CONF_dump_bio := _CONF_dump_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_dump_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_dump_bio');
    {$ifend}
  end;
  
  
  NCONF_new_ex := LoadLibFunction(ADllHandle, NCONF_new_ex_procname);
  FuncLoadError := not assigned(NCONF_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_new_ex_allownil)}
    NCONF_new_ex := ERR_NCONF_new_ex;
    {$ifend}
    {$if declared(NCONF_new_ex_introduced)}
    if LibVersion < NCONF_new_ex_introduced then
    begin
      {$if declared(FC_NCONF_new_ex)}
      NCONF_new_ex := FC_NCONF_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_new_ex_removed)}
    if NCONF_new_ex_removed <= LibVersion then
    begin
      {$if declared(_NCONF_new_ex)}
      NCONF_new_ex := _NCONF_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_new_ex');
    {$ifend}
  end;
  
  NCONF_get0_libctx := LoadLibFunction(ADllHandle, NCONF_get0_libctx_procname);
  FuncLoadError := not assigned(NCONF_get0_libctx);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_get0_libctx_allownil)}
    NCONF_get0_libctx := ERR_NCONF_get0_libctx;
    {$ifend}
    {$if declared(NCONF_get0_libctx_introduced)}
    if LibVersion < NCONF_get0_libctx_introduced then
    begin
      {$if declared(FC_NCONF_get0_libctx)}
      NCONF_get0_libctx := FC_NCONF_get0_libctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_get0_libctx_removed)}
    if NCONF_get0_libctx_removed <= LibVersion then
    begin
      {$if declared(_NCONF_get0_libctx)}
      NCONF_get0_libctx := _NCONF_get0_libctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_get0_libctx_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_get0_libctx');
    {$ifend}
  end;
  
  NCONF_new := LoadLibFunction(ADllHandle, NCONF_new_procname);
  FuncLoadError := not assigned(NCONF_new);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_new_allownil)}
    NCONF_new := ERR_NCONF_new;
    {$ifend}
    {$if declared(NCONF_new_introduced)}
    if LibVersion < NCONF_new_introduced then
    begin
      {$if declared(FC_NCONF_new)}
      NCONF_new := FC_NCONF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_new_removed)}
    if NCONF_new_removed <= LibVersion then
    begin
      {$if declared(_NCONF_new)}
      NCONF_new := _NCONF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_new');
    {$ifend}
  end;
  
  NCONF_default := LoadLibFunction(ADllHandle, NCONF_default_procname);
  FuncLoadError := not assigned(NCONF_default);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_default_allownil)}
    NCONF_default := ERR_NCONF_default;
    {$ifend}
    {$if declared(NCONF_default_introduced)}
    if LibVersion < NCONF_default_introduced then
    begin
      {$if declared(FC_NCONF_default)}
      NCONF_default := FC_NCONF_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_default_removed)}
    if NCONF_default_removed <= LibVersion then
    begin
      {$if declared(_NCONF_default)}
      NCONF_default := _NCONF_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_default_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_default');
    {$ifend}
  end;
  
  NCONF_WIN32 := LoadLibFunction(ADllHandle, NCONF_WIN32_procname);
  FuncLoadError := not assigned(NCONF_WIN32);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_WIN32_allownil)}
    NCONF_WIN32 := ERR_NCONF_WIN32;
    {$ifend}
    {$if declared(NCONF_WIN32_introduced)}
    if LibVersion < NCONF_WIN32_introduced then
    begin
      {$if declared(FC_NCONF_WIN32)}
      NCONF_WIN32 := FC_NCONF_WIN32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_WIN32_removed)}
    if NCONF_WIN32_removed <= LibVersion then
    begin
      {$if declared(_NCONF_WIN32)}
      NCONF_WIN32 := _NCONF_WIN32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_WIN32_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_WIN32');
    {$ifend}
  end;
  
  NCONF_free := LoadLibFunction(ADllHandle, NCONF_free_procname);
  FuncLoadError := not assigned(NCONF_free);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_free_allownil)}
    NCONF_free := ERR_NCONF_free;
    {$ifend}
    {$if declared(NCONF_free_introduced)}
    if LibVersion < NCONF_free_introduced then
    begin
      {$if declared(FC_NCONF_free)}
      NCONF_free := FC_NCONF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_free_removed)}
    if NCONF_free_removed <= LibVersion then
    begin
      {$if declared(_NCONF_free)}
      NCONF_free := _NCONF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_free');
    {$ifend}
  end;
  
  NCONF_free_data := LoadLibFunction(ADllHandle, NCONF_free_data_procname);
  FuncLoadError := not assigned(NCONF_free_data);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_free_data_allownil)}
    NCONF_free_data := ERR_NCONF_free_data;
    {$ifend}
    {$if declared(NCONF_free_data_introduced)}
    if LibVersion < NCONF_free_data_introduced then
    begin
      {$if declared(FC_NCONF_free_data)}
      NCONF_free_data := FC_NCONF_free_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_free_data_removed)}
    if NCONF_free_data_removed <= LibVersion then
    begin
      {$if declared(_NCONF_free_data)}
      NCONF_free_data := _NCONF_free_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_free_data_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_free_data');
    {$ifend}
  end;
  
  NCONF_load := LoadLibFunction(ADllHandle, NCONF_load_procname);
  FuncLoadError := not assigned(NCONF_load);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_load_allownil)}
    NCONF_load := ERR_NCONF_load;
    {$ifend}
    {$if declared(NCONF_load_introduced)}
    if LibVersion < NCONF_load_introduced then
    begin
      {$if declared(FC_NCONF_load)}
      NCONF_load := FC_NCONF_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_load_removed)}
    if NCONF_load_removed <= LibVersion then
    begin
      {$if declared(_NCONF_load)}
      NCONF_load := _NCONF_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_load_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_load');
    {$ifend}
  end;
  
  NCONF_load_fp := LoadLibFunction(ADllHandle, NCONF_load_fp_procname);
  FuncLoadError := not assigned(NCONF_load_fp);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_load_fp_allownil)}
    NCONF_load_fp := ERR_NCONF_load_fp;
    {$ifend}
    {$if declared(NCONF_load_fp_introduced)}
    if LibVersion < NCONF_load_fp_introduced then
    begin
      {$if declared(FC_NCONF_load_fp)}
      NCONF_load_fp := FC_NCONF_load_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_load_fp_removed)}
    if NCONF_load_fp_removed <= LibVersion then
    begin
      {$if declared(_NCONF_load_fp)}
      NCONF_load_fp := _NCONF_load_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_load_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_load_fp');
    {$ifend}
  end;
  
  NCONF_load_bio := LoadLibFunction(ADllHandle, NCONF_load_bio_procname);
  FuncLoadError := not assigned(NCONF_load_bio);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_load_bio_allownil)}
    NCONF_load_bio := ERR_NCONF_load_bio;
    {$ifend}
    {$if declared(NCONF_load_bio_introduced)}
    if LibVersion < NCONF_load_bio_introduced then
    begin
      {$if declared(FC_NCONF_load_bio)}
      NCONF_load_bio := FC_NCONF_load_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_load_bio_removed)}
    if NCONF_load_bio_removed <= LibVersion then
    begin
      {$if declared(_NCONF_load_bio)}
      NCONF_load_bio := _NCONF_load_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_load_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_load_bio');
    {$ifend}
  end;
  
  NCONF_get_section_names := LoadLibFunction(ADllHandle, NCONF_get_section_names_procname);
  FuncLoadError := not assigned(NCONF_get_section_names);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_get_section_names_allownil)}
    NCONF_get_section_names := ERR_NCONF_get_section_names;
    {$ifend}
    {$if declared(NCONF_get_section_names_introduced)}
    if LibVersion < NCONF_get_section_names_introduced then
    begin
      {$if declared(FC_NCONF_get_section_names)}
      NCONF_get_section_names := FC_NCONF_get_section_names;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_get_section_names_removed)}
    if NCONF_get_section_names_removed <= LibVersion then
    begin
      {$if declared(_NCONF_get_section_names)}
      NCONF_get_section_names := _NCONF_get_section_names;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_get_section_names_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_get_section_names');
    {$ifend}
  end;
  
  NCONF_get_section := LoadLibFunction(ADllHandle, NCONF_get_section_procname);
  FuncLoadError := not assigned(NCONF_get_section);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_get_section_allownil)}
    NCONF_get_section := ERR_NCONF_get_section;
    {$ifend}
    {$if declared(NCONF_get_section_introduced)}
    if LibVersion < NCONF_get_section_introduced then
    begin
      {$if declared(FC_NCONF_get_section)}
      NCONF_get_section := FC_NCONF_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_get_section_removed)}
    if NCONF_get_section_removed <= LibVersion then
    begin
      {$if declared(_NCONF_get_section)}
      NCONF_get_section := _NCONF_get_section;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_get_section_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_get_section');
    {$ifend}
  end;
  
  NCONF_get_string := LoadLibFunction(ADllHandle, NCONF_get_string_procname);
  FuncLoadError := not assigned(NCONF_get_string);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_get_string_allownil)}
    NCONF_get_string := ERR_NCONF_get_string;
    {$ifend}
    {$if declared(NCONF_get_string_introduced)}
    if LibVersion < NCONF_get_string_introduced then
    begin
      {$if declared(FC_NCONF_get_string)}
      NCONF_get_string := FC_NCONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_get_string_removed)}
    if NCONF_get_string_removed <= LibVersion then
    begin
      {$if declared(_NCONF_get_string)}
      NCONF_get_string := _NCONF_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_get_string_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_get_string');
    {$ifend}
  end;
  
  NCONF_get_number_e := LoadLibFunction(ADllHandle, NCONF_get_number_e_procname);
  FuncLoadError := not assigned(NCONF_get_number_e);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_get_number_e_allownil)}
    NCONF_get_number_e := ERR_NCONF_get_number_e;
    {$ifend}
    {$if declared(NCONF_get_number_e_introduced)}
    if LibVersion < NCONF_get_number_e_introduced then
    begin
      {$if declared(FC_NCONF_get_number_e)}
      NCONF_get_number_e := FC_NCONF_get_number_e;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_get_number_e_removed)}
    if NCONF_get_number_e_removed <= LibVersion then
    begin
      {$if declared(_NCONF_get_number_e)}
      NCONF_get_number_e := _NCONF_get_number_e;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_get_number_e_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_get_number_e');
    {$ifend}
  end;
  
  NCONF_dump_fp := LoadLibFunction(ADllHandle, NCONF_dump_fp_procname);
  FuncLoadError := not assigned(NCONF_dump_fp);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_dump_fp_allownil)}
    NCONF_dump_fp := ERR_NCONF_dump_fp;
    {$ifend}
    {$if declared(NCONF_dump_fp_introduced)}
    if LibVersion < NCONF_dump_fp_introduced then
    begin
      {$if declared(FC_NCONF_dump_fp)}
      NCONF_dump_fp := FC_NCONF_dump_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_dump_fp_removed)}
    if NCONF_dump_fp_removed <= LibVersion then
    begin
      {$if declared(_NCONF_dump_fp)}
      NCONF_dump_fp := _NCONF_dump_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_dump_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_dump_fp');
    {$ifend}
  end;
  
  NCONF_dump_bio := LoadLibFunction(ADllHandle, NCONF_dump_bio_procname);
  FuncLoadError := not assigned(NCONF_dump_bio);
  if FuncLoadError then
  begin
    {$if not defined(NCONF_dump_bio_allownil)}
    NCONF_dump_bio := ERR_NCONF_dump_bio;
    {$ifend}
    {$if declared(NCONF_dump_bio_introduced)}
    if LibVersion < NCONF_dump_bio_introduced then
    begin
      {$if declared(FC_NCONF_dump_bio)}
      NCONF_dump_bio := FC_NCONF_dump_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NCONF_dump_bio_removed)}
    if NCONF_dump_bio_removed <= LibVersion then
    begin
      {$if declared(_NCONF_dump_bio)}
      NCONF_dump_bio := _NCONF_dump_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NCONF_dump_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('NCONF_dump_bio');
    {$ifend}
  end;
  
  CONF_modules_load := LoadLibFunction(ADllHandle, CONF_modules_load_procname);
  FuncLoadError := not assigned(CONF_modules_load);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_load_allownil)}
    CONF_modules_load := ERR_CONF_modules_load;
    {$ifend}
    {$if declared(CONF_modules_load_introduced)}
    if LibVersion < CONF_modules_load_introduced then
    begin
      {$if declared(FC_CONF_modules_load)}
      CONF_modules_load := FC_CONF_modules_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_load_removed)}
    if CONF_modules_load_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_load)}
      CONF_modules_load := _CONF_modules_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_load_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_load');
    {$ifend}
  end;
  
  CONF_modules_load_file_ex := LoadLibFunction(ADllHandle, CONF_modules_load_file_ex_procname);
  FuncLoadError := not assigned(CONF_modules_load_file_ex);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_load_file_ex_allownil)}
    CONF_modules_load_file_ex := ERR_CONF_modules_load_file_ex;
    {$ifend}
    {$if declared(CONF_modules_load_file_ex_introduced)}
    if LibVersion < CONF_modules_load_file_ex_introduced then
    begin
      {$if declared(FC_CONF_modules_load_file_ex)}
      CONF_modules_load_file_ex := FC_CONF_modules_load_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_load_file_ex_removed)}
    if CONF_modules_load_file_ex_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_load_file_ex)}
      CONF_modules_load_file_ex := _CONF_modules_load_file_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_load_file_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_load_file_ex');
    {$ifend}
  end;
  
  CONF_modules_load_file := LoadLibFunction(ADllHandle, CONF_modules_load_file_procname);
  FuncLoadError := not assigned(CONF_modules_load_file);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_load_file_allownil)}
    CONF_modules_load_file := ERR_CONF_modules_load_file;
    {$ifend}
    {$if declared(CONF_modules_load_file_introduced)}
    if LibVersion < CONF_modules_load_file_introduced then
    begin
      {$if declared(FC_CONF_modules_load_file)}
      CONF_modules_load_file := FC_CONF_modules_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_load_file_removed)}
    if CONF_modules_load_file_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_load_file)}
      CONF_modules_load_file := _CONF_modules_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_load_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_load_file');
    {$ifend}
  end;
  
  CONF_modules_unload := LoadLibFunction(ADllHandle, CONF_modules_unload_procname);
  FuncLoadError := not assigned(CONF_modules_unload);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_unload_allownil)}
    CONF_modules_unload := ERR_CONF_modules_unload;
    {$ifend}
    {$if declared(CONF_modules_unload_introduced)}
    if LibVersion < CONF_modules_unload_introduced then
    begin
      {$if declared(FC_CONF_modules_unload)}
      CONF_modules_unload := FC_CONF_modules_unload;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_unload_removed)}
    if CONF_modules_unload_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_unload)}
      CONF_modules_unload := _CONF_modules_unload;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_unload_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_unload');
    {$ifend}
  end;
  
  CONF_modules_finish := LoadLibFunction(ADllHandle, CONF_modules_finish_procname);
  FuncLoadError := not assigned(CONF_modules_finish);
  if FuncLoadError then
  begin
    {$if not defined(CONF_modules_finish_allownil)}
    CONF_modules_finish := ERR_CONF_modules_finish;
    {$ifend}
    {$if declared(CONF_modules_finish_introduced)}
    if LibVersion < CONF_modules_finish_introduced then
    begin
      {$if declared(FC_CONF_modules_finish)}
      CONF_modules_finish := FC_CONF_modules_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_modules_finish_removed)}
    if CONF_modules_finish_removed <= LibVersion then
    begin
      {$if declared(_CONF_modules_finish)}
      CONF_modules_finish := _CONF_modules_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_modules_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_modules_finish');
    {$ifend}
  end;
  
  CONF_module_add := LoadLibFunction(ADllHandle, CONF_module_add_procname);
  FuncLoadError := not assigned(CONF_module_add);
  if FuncLoadError then
  begin
    {$if not defined(CONF_module_add_allownil)}
    CONF_module_add := ERR_CONF_module_add;
    {$ifend}
    {$if declared(CONF_module_add_introduced)}
    if LibVersion < CONF_module_add_introduced then
    begin
      {$if declared(FC_CONF_module_add)}
      CONF_module_add := FC_CONF_module_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_module_add_removed)}
    if CONF_module_add_removed <= LibVersion then
    begin
      {$if declared(_CONF_module_add)}
      CONF_module_add := _CONF_module_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_module_add_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_module_add');
    {$ifend}
  end;
  
  CONF_imodule_get_name := LoadLibFunction(ADllHandle, CONF_imodule_get_name_procname);
  FuncLoadError := not assigned(CONF_imodule_get_name);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_name_allownil)}
    CONF_imodule_get_name := ERR_CONF_imodule_get_name;
    {$ifend}
    {$if declared(CONF_imodule_get_name_introduced)}
    if LibVersion < CONF_imodule_get_name_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_name)}
      CONF_imodule_get_name := FC_CONF_imodule_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_name_removed)}
    if CONF_imodule_get_name_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_name)}
      CONF_imodule_get_name := _CONF_imodule_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_name_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_name');
    {$ifend}
  end;
  
  CONF_imodule_get_value := LoadLibFunction(ADllHandle, CONF_imodule_get_value_procname);
  FuncLoadError := not assigned(CONF_imodule_get_value);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_value_allownil)}
    CONF_imodule_get_value := ERR_CONF_imodule_get_value;
    {$ifend}
    {$if declared(CONF_imodule_get_value_introduced)}
    if LibVersion < CONF_imodule_get_value_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_value)}
      CONF_imodule_get_value := FC_CONF_imodule_get_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_value_removed)}
    if CONF_imodule_get_value_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_value)}
      CONF_imodule_get_value := _CONF_imodule_get_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_value_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_value');
    {$ifend}
  end;
  
  CONF_imodule_get_usr_data := LoadLibFunction(ADllHandle, CONF_imodule_get_usr_data_procname);
  FuncLoadError := not assigned(CONF_imodule_get_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_usr_data_allownil)}
    CONF_imodule_get_usr_data := ERR_CONF_imodule_get_usr_data;
    {$ifend}
    {$if declared(CONF_imodule_get_usr_data_introduced)}
    if LibVersion < CONF_imodule_get_usr_data_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_usr_data)}
      CONF_imodule_get_usr_data := FC_CONF_imodule_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_usr_data_removed)}
    if CONF_imodule_get_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_usr_data)}
      CONF_imodule_get_usr_data := _CONF_imodule_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_usr_data');
    {$ifend}
  end;
  
  CONF_imodule_set_usr_data := LoadLibFunction(ADllHandle, CONF_imodule_set_usr_data_procname);
  FuncLoadError := not assigned(CONF_imodule_set_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_set_usr_data_allownil)}
    CONF_imodule_set_usr_data := ERR_CONF_imodule_set_usr_data;
    {$ifend}
    {$if declared(CONF_imodule_set_usr_data_introduced)}
    if LibVersion < CONF_imodule_set_usr_data_introduced then
    begin
      {$if declared(FC_CONF_imodule_set_usr_data)}
      CONF_imodule_set_usr_data := FC_CONF_imodule_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_set_usr_data_removed)}
    if CONF_imodule_set_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_set_usr_data)}
      CONF_imodule_set_usr_data := _CONF_imodule_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_set_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_set_usr_data');
    {$ifend}
  end;
  
  CONF_imodule_get_module := LoadLibFunction(ADllHandle, CONF_imodule_get_module_procname);
  FuncLoadError := not assigned(CONF_imodule_get_module);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_module_allownil)}
    CONF_imodule_get_module := ERR_CONF_imodule_get_module;
    {$ifend}
    {$if declared(CONF_imodule_get_module_introduced)}
    if LibVersion < CONF_imodule_get_module_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_module)}
      CONF_imodule_get_module := FC_CONF_imodule_get_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_module_removed)}
    if CONF_imodule_get_module_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_module)}
      CONF_imodule_get_module := _CONF_imodule_get_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_module_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_module');
    {$ifend}
  end;
  
  CONF_imodule_get_flags := LoadLibFunction(ADllHandle, CONF_imodule_get_flags_procname);
  FuncLoadError := not assigned(CONF_imodule_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_get_flags_allownil)}
    CONF_imodule_get_flags := ERR_CONF_imodule_get_flags;
    {$ifend}
    {$if declared(CONF_imodule_get_flags_introduced)}
    if LibVersion < CONF_imodule_get_flags_introduced then
    begin
      {$if declared(FC_CONF_imodule_get_flags)}
      CONF_imodule_get_flags := FC_CONF_imodule_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_get_flags_removed)}
    if CONF_imodule_get_flags_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_get_flags)}
      CONF_imodule_get_flags := _CONF_imodule_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_get_flags');
    {$ifend}
  end;
  
  CONF_imodule_set_flags := LoadLibFunction(ADllHandle, CONF_imodule_set_flags_procname);
  FuncLoadError := not assigned(CONF_imodule_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(CONF_imodule_set_flags_allownil)}
    CONF_imodule_set_flags := ERR_CONF_imodule_set_flags;
    {$ifend}
    {$if declared(CONF_imodule_set_flags_introduced)}
    if LibVersion < CONF_imodule_set_flags_introduced then
    begin
      {$if declared(FC_CONF_imodule_set_flags)}
      CONF_imodule_set_flags := FC_CONF_imodule_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_imodule_set_flags_removed)}
    if CONF_imodule_set_flags_removed <= LibVersion then
    begin
      {$if declared(_CONF_imodule_set_flags)}
      CONF_imodule_set_flags := _CONF_imodule_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_imodule_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_imodule_set_flags');
    {$ifend}
  end;
  
  CONF_module_get_usr_data := LoadLibFunction(ADllHandle, CONF_module_get_usr_data_procname);
  FuncLoadError := not assigned(CONF_module_get_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_module_get_usr_data_allownil)}
    CONF_module_get_usr_data := ERR_CONF_module_get_usr_data;
    {$ifend}
    {$if declared(CONF_module_get_usr_data_introduced)}
    if LibVersion < CONF_module_get_usr_data_introduced then
    begin
      {$if declared(FC_CONF_module_get_usr_data)}
      CONF_module_get_usr_data := FC_CONF_module_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_module_get_usr_data_removed)}
    if CONF_module_get_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_module_get_usr_data)}
      CONF_module_get_usr_data := _CONF_module_get_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_module_get_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_module_get_usr_data');
    {$ifend}
  end;
  
  CONF_module_set_usr_data := LoadLibFunction(ADllHandle, CONF_module_set_usr_data_procname);
  FuncLoadError := not assigned(CONF_module_set_usr_data);
  if FuncLoadError then
  begin
    {$if not defined(CONF_module_set_usr_data_allownil)}
    CONF_module_set_usr_data := ERR_CONF_module_set_usr_data;
    {$ifend}
    {$if declared(CONF_module_set_usr_data_introduced)}
    if LibVersion < CONF_module_set_usr_data_introduced then
    begin
      {$if declared(FC_CONF_module_set_usr_data)}
      CONF_module_set_usr_data := FC_CONF_module_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_module_set_usr_data_removed)}
    if CONF_module_set_usr_data_removed <= LibVersion then
    begin
      {$if declared(_CONF_module_set_usr_data)}
      CONF_module_set_usr_data := _CONF_module_set_usr_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_module_set_usr_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_module_set_usr_data');
    {$ifend}
  end;
  
  CONF_get1_default_config_file := LoadLibFunction(ADllHandle, CONF_get1_default_config_file_procname);
  FuncLoadError := not assigned(CONF_get1_default_config_file);
  if FuncLoadError then
  begin
    {$if not defined(CONF_get1_default_config_file_allownil)}
    CONF_get1_default_config_file := ERR_CONF_get1_default_config_file;
    {$ifend}
    {$if declared(CONF_get1_default_config_file_introduced)}
    if LibVersion < CONF_get1_default_config_file_introduced then
    begin
      {$if declared(FC_CONF_get1_default_config_file)}
      CONF_get1_default_config_file := FC_CONF_get1_default_config_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_get1_default_config_file_removed)}
    if CONF_get1_default_config_file_removed <= LibVersion then
    begin
      {$if declared(_CONF_get1_default_config_file)}
      CONF_get1_default_config_file := _CONF_get1_default_config_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_get1_default_config_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_get1_default_config_file');
    {$ifend}
  end;
  
  CONF_parse_list := LoadLibFunction(ADllHandle, CONF_parse_list_procname);
  FuncLoadError := not assigned(CONF_parse_list);
  if FuncLoadError then
  begin
    {$if not defined(CONF_parse_list_allownil)}
    CONF_parse_list := ERR_CONF_parse_list;
    {$ifend}
    {$if declared(CONF_parse_list_introduced)}
    if LibVersion < CONF_parse_list_introduced then
    begin
      {$if declared(FC_CONF_parse_list)}
      CONF_parse_list := FC_CONF_parse_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CONF_parse_list_removed)}
    if CONF_parse_list_removed <= LibVersion then
    begin
      {$if declared(_CONF_parse_list)}
      CONF_parse_list := _CONF_parse_list;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CONF_parse_list_allownil)}
    if FuncLoadError then
      AFailed.Add('CONF_parse_list');
    {$ifend}
  end;
  
  OPENSSL_load_builtin_modules := LoadLibFunction(ADllHandle, OPENSSL_load_builtin_modules_procname);
  FuncLoadError := not assigned(OPENSSL_load_builtin_modules);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_builtin_modules_allownil)}
    OPENSSL_load_builtin_modules := ERR_OPENSSL_load_builtin_modules;
    {$ifend}
    {$if declared(OPENSSL_load_builtin_modules_introduced)}
    if LibVersion < OPENSSL_load_builtin_modules_introduced then
    begin
      {$if declared(FC_OPENSSL_load_builtin_modules)}
      OPENSSL_load_builtin_modules := FC_OPENSSL_load_builtin_modules;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_builtin_modules_removed)}
    if OPENSSL_load_builtin_modules_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_builtin_modules)}
      OPENSSL_load_builtin_modules := _OPENSSL_load_builtin_modules;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_builtin_modules_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_builtin_modules');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  CONF_set_default_method := nil;
  CONF_set_nconf := nil;
  CONF_load := nil;
  CONF_load_fp := nil;
  CONF_load_bio := nil;
  CONF_get_section := nil;
  CONF_get_string := nil;
  CONF_get_number := nil;
  CONF_free := nil;
  CONF_dump_fp := nil;
  CONF_dump_bio := nil;
  NCONF_new_ex := nil;
  NCONF_get0_libctx := nil;
  NCONF_new := nil;
  NCONF_default := nil;
  NCONF_WIN32 := nil;
  NCONF_free := nil;
  NCONF_free_data := nil;
  NCONF_load := nil;
  NCONF_load_fp := nil;
  NCONF_load_bio := nil;
  NCONF_get_section_names := nil;
  NCONF_get_section := nil;
  NCONF_get_string := nil;
  NCONF_get_number_e := nil;
  NCONF_dump_fp := nil;
  NCONF_dump_bio := nil;
  CONF_modules_load := nil;
  CONF_modules_load_file_ex := nil;
  CONF_modules_load_file := nil;
  CONF_modules_unload := nil;
  CONF_modules_finish := nil;
  CONF_module_add := nil;
  CONF_imodule_get_name := nil;
  CONF_imodule_get_value := nil;
  CONF_imodule_get_usr_data := nil;
  CONF_imodule_set_usr_data := nil;
  CONF_imodule_get_module := nil;
  CONF_imodule_get_flags := nil;
  CONF_imodule_set_flags := nil;
  CONF_module_get_usr_data := nil;
  CONF_module_set_usr_data := nil;
  CONF_get1_default_config_file := nil;
  CONF_parse_list := nil;
  OPENSSL_load_builtin_modules := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.