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

unit TaurusTLSHeaders_crypto;

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
  PCRYPTO_dynlock = ^TCRYPTO_dynlock;
  TCRYPTO_dynlock =   record
    dummy: TIdC_INT;
  end;
  {$EXTERNALSYM PCRYPTO_dynlock}

  Pcrypto_ex_data_st = ^Tcrypto_ex_data_st;
  Tcrypto_ex_data_st =   record
    ctx: POSSL_LIB_CTX;
    sk: Pstack_st_void;
  end;
  {$EXTERNALSYM Pcrypto_ex_data_st}

  Pcrypto_threadid_st = ^Tcrypto_threadid_st;
  Tcrypto_threadid_st =   record
    dummy: TIdC_INT;
  end;
  {$EXTERNALSYM Pcrypto_threadid_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TCRYPTO_EX_new = function(parent: Pointer; ptr: Pointer; ad: PCRYPTO_EX_DATA; idx: TIdC_INT; argl: TIdC_LONG; argp: Pointer): void; cdecl;
  TCRYPTO_EX_free = function(parent: Pointer; ptr: Pointer; ad: PCRYPTO_EX_DATA; idx: TIdC_INT; argl: TIdC_LONG; argp: Pointer): void; cdecl;
  TCRYPTO_EX_dup = function(_to: PCRYPTO_EX_DATA; from: PCRYPTO_EX_DATA; from_d: PPointer; idx: TIdC_INT; argl: TIdC_LONG; argp: Pointer): TIdC_INT; cdecl;
  TCRYPTO_malloc_fn = function(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
  TCRYPTO_realloc_fn = function(addr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
  TCRYPTO_free_fn = function(addr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OPENSSL_atexit_handler_cb = function: void; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  SSLEAY_VERSION_NUMBER = OPENSSL_VERSION_NUMBER;
  SSLEAY_VERSION = OPENSSL_VERSION;
  SSLEAY_CFLAGS = OPENSSL_CFLAGS;
  SSLEAY_BUILT_ON = OPENSSL_BUILT_ON;
  SSLEAY_PLATFORM = OPENSSL_PLATFORM;
  SSLEAY_DIR = OPENSSL_DIR;
  OPENSSL_VERSION = 0;
  OPENSSL_CFLAGS = 1;
  OPENSSL_BUILT_ON = 2;
  OPENSSL_PLATFORM = 3;
  OPENSSL_DIR = 4;
  OPENSSL_ENGINES_DIR = 5;
  OPENSSL_VERSION_STRING = 6;
  OPENSSL_FULL_VERSION_STRING = 7;
  OPENSSL_MODULES_DIR = 8;
  OPENSSL_CPU_INFO = 9;
  OPENSSL_WINCTX = 10;
  OPENSSL_INFO_CONFIG_DIR = 1001;
  OPENSSL_INFO_ENGINES_DIR = 1002;
  OPENSSL_INFO_MODULES_DIR = 1003;
  OPENSSL_INFO_DSO_EXTENSION = 1004;
  OPENSSL_INFO_DIR_FILENAME_SEPARATOR = 1005;
  OPENSSL_INFO_LIST_SEPARATOR = 1006;
  OPENSSL_INFO_SEED_SOURCE = 1007;
  OPENSSL_INFO_CPU_SETTINGS = 1008;
  OPENSSL_INFO_WINDOWS_CONTEXT = 1009;
  CRYPTO_EX_INDEX_SSL = 0;
  CRYPTO_EX_INDEX_SSL_CTX = 1;
  CRYPTO_EX_INDEX_SSL_SESSION = 2;
  CRYPTO_EX_INDEX_X509 = 3;
  CRYPTO_EX_INDEX_X509_STORE = 4;
  CRYPTO_EX_INDEX_X509_STORE_CTX = 5;
  CRYPTO_EX_INDEX_DH = 6;
  CRYPTO_EX_INDEX_DSA = 7;
  CRYPTO_EX_INDEX_EC_KEY = 8;
  CRYPTO_EX_INDEX_RSA = 9;
  CRYPTO_EX_INDEX_ENGINE = 10;
  CRYPTO_EX_INDEX_UI = 11;
  CRYPTO_EX_INDEX_BIO = 12;
  CRYPTO_EX_INDEX_APP = 13;
  CRYPTO_EX_INDEX_UI_METHOD = 14;
  CRYPTO_EX_INDEX_RAND_DRBG = 15;
  CRYPTO_EX_INDEX_DRBG = CRYPTO_EX_INDEX_RAND_DRBG;
  CRYPTO_EX_INDEX_OSSL_LIB_CTX = 16;
  CRYPTO_EX_INDEX_EVP_PKEY = 17;
  CRYPTO_EX_INDEX__COUNT = 18;
  CRYPTO_LOCK = 1;
  CRYPTO_UNLOCK = 2;
  CRYPTO_READ = 4;
  CRYPTO_WRITE = 8;
  OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = $00000001;
  OPENSSL_INIT_LOAD_CRYPTO_STRINGS = $00000002;
  OPENSSL_INIT_ADD_ALL_CIPHERS = $00000004;
  OPENSSL_INIT_ADD_ALL_DIGESTS = $00000008;
  OPENSSL_INIT_NO_ADD_ALL_CIPHERS = $00000010;
  OPENSSL_INIT_NO_ADD_ALL_DIGESTS = $00000020;
  OPENSSL_INIT_LOAD_CONFIG = $00000040;
  OPENSSL_INIT_NO_LOAD_CONFIG = $00000080;
  OPENSSL_INIT_ASYNC = $00000100;
  OPENSSL_INIT_ENGINE_RDRAND = $00000200;
  OPENSSL_INIT_ENGINE_DYNAMIC = $00000400;
  OPENSSL_INIT_ENGINE_OPENSSL = $00000800;
  OPENSSL_INIT_ENGINE_CRYPTODEV = $00001000;
  OPENSSL_INIT_ENGINE_CAPI = $00002000;
  OPENSSL_INIT_ENGINE_PADLOCK = $00004000;
  OPENSSL_INIT_ENGINE_AFALG = $00008000;
  OPENSSL_INIT_ATFORK = $00020000;
  OPENSSL_INIT_NO_ATEXIT = $00080000;
  OPENSSL_INIT_ENGINE_ALL_BUILTIN = (OPENSSL_INIT_ENGINE_RDRAND or OPENSSL_INIT_ENGINE_DYNAMIC or OPENSSL_INIT_ENGINE_CRYPTODEV or OPENSSL_INIT_ENGINE_CAPI or OPENSSL_INIT_ENGINE_PADLOCK);
  CRYPTO_ONCE_STATIC_INIT = PTHREAD_ONCE_INIT;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  CRYPTO_THREAD_lock_new: function: PCRYPTO_RWLOCK; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_lock_new}

  CRYPTO_THREAD_read_lock: function(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_read_lock}

  CRYPTO_THREAD_write_lock: function(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_write_lock}

  CRYPTO_THREAD_unlock: function(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_unlock}

  CRYPTO_THREAD_lock_free: function(lock: PCRYPTO_RWLOCK): void; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_lock_free}

  CRYPTO_atomic_add: function(val: PIdC_INT; amount: TIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_atomic_add}

  CRYPTO_atomic_add64: function(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_atomic_add64}

  CRYPTO_atomic_and: function(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_atomic_and}

  CRYPTO_atomic_or: function(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_atomic_or}

  CRYPTO_atomic_load: function(val: PIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_atomic_load}

  CRYPTO_atomic_load_int: function(val: PIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_atomic_load_int}

  CRYPTO_atomic_store: function(dst: PIdC_UINT64; val: TIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_atomic_store}

  OPENSSL_strlcpy: function(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM OPENSSL_strlcpy}

  OPENSSL_strlcat: function(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM OPENSSL_strlcat}

  OPENSSL_strnlen: function(str: PIdAnsiChar; maxlen: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM OPENSSL_strnlen}

  OPENSSL_strtoul: function(str: PIdAnsiChar; endptr: PPIdAnsiChar; base: TIdC_INT; num: PIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_strtoul}

  OPENSSL_buf2hexstr_ex: function(str: PIdAnsiChar; str_n: TIdC_SIZET; strlength: PIdC_SIZET; buf: PIdAnsiChar; buflen: TIdC_SIZET; sep: TIdC_INT8): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_buf2hexstr_ex}

  OPENSSL_buf2hexstr: function(buf: PIdAnsiChar; buflen: TIdC_LONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_buf2hexstr}

  OPENSSL_hexstr2buf_ex: function(buf: PIdAnsiChar; buf_n: TIdC_SIZET; buflen: PIdC_SIZET; str: PIdAnsiChar; sep: TIdC_INT8): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_hexstr2buf_ex}

  OPENSSL_hexstr2buf: function(str: PIdAnsiChar; buflen: PIdC_LONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_hexstr2buf}

  OPENSSL_hexchar2int: function(c: TIdC_UINT8): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_hexchar2int}

  OPENSSL_strcasecmp: function(s1: PIdAnsiChar; s2: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_strcasecmp}

  OPENSSL_strncasecmp: function(s1: PIdAnsiChar; s2: PIdAnsiChar; n: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_strncasecmp}

  OPENSSL_version_major: function: TIdC_UINT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_version_major}

  OPENSSL_version_minor: function: TIdC_UINT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_version_minor}

  OPENSSL_version_patch: function: TIdC_UINT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_version_patch}

  OPENSSL_version_pre_release: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_version_pre_release}

  OPENSSL_version_build_metadata: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_version_build_metadata}

  OpenSSL_version_num: function: TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM OpenSSL_version_num}

  OpenSSL_version: function(_type: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OpenSSL_version}

  OPENSSL_info: function(_type: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_info}

  OPENSSL_issetugid: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_issetugid}

  CRYPTO_get_ex_new_index: function(class_index: TIdC_INT; argl: TIdC_LONG; argp: Pointer; new_func: TCRYPTO_EX_free; dup_func: TCRYPTO_EX_dup; free_func: TCRYPTO_EX_free): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_get_ex_new_index}

  CRYPTO_free_ex_index: function(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_free_ex_index}

  CRYPTO_new_ex_data: function(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_new_ex_data}

  CRYPTO_dup_ex_data: function(class_index: TIdC_INT; _to: PCRYPTO_EX_DATA; from: PCRYPTO_EX_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_dup_ex_data}

  CRYPTO_free_ex_data: function(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): void; cdecl = nil;
  {$EXTERNALSYM CRYPTO_free_ex_data}

  CRYPTO_alloc_ex_data: function(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA; idx: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_alloc_ex_data}

  CRYPTO_set_ex_data: function(ad: PCRYPTO_EX_DATA; idx: TIdC_INT; val: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_set_ex_data}

  CRYPTO_get_ex_data: function(ad: PCRYPTO_EX_DATA; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_get_ex_data}

  CRYPTO_set_mem_functions: function(malloc_fn: TCRYPTO_malloc_fn; realloc_fn: TCRYPTO_realloc_fn; free_fn: TCRYPTO_free_fn): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_set_mem_functions}

  CRYPTO_get_mem_functions: function(malloc_fn: PCRYPTO_malloc_fn; realloc_fn: PCRYPTO_realloc_fn; free_fn: PCRYPTO_free_fn): void; cdecl = nil;
  {$EXTERNALSYM CRYPTO_get_mem_functions}

  CRYPTO_malloc: function(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_malloc}

  CRYPTO_zalloc: function(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_zalloc}

  CRYPTO_malloc_array: function(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_malloc_array}

  CRYPTO_calloc: function(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_calloc}

  CRYPTO_aligned_alloc: function(num: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_aligned_alloc}

  CRYPTO_aligned_alloc_array: function(num: TIdC_SIZET; size: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_aligned_alloc_array}

  CRYPTO_memdup: function(str: Pointer; siz: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_memdup}

  CRYPTO_strdup: function(str: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CRYPTO_strdup}

  CRYPTO_strndup: function(str: PIdAnsiChar; s: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CRYPTO_strndup}

  CRYPTO_free: function(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM CRYPTO_free}

  CRYPTO_clear_free: function(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM CRYPTO_clear_free}

  CRYPTO_realloc: function(addr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_realloc}

  CRYPTO_clear_realloc: function(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_clear_realloc}

  CRYPTO_realloc_array: function(addr: Pointer; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_realloc_array}

  CRYPTO_clear_realloc_array: function(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_clear_realloc_array}

  CRYPTO_secure_malloc_init: function(sz: TIdC_SIZET; minsize: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_malloc_init}

  CRYPTO_secure_malloc_done: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_malloc_done}

  CRYPTO_secure_malloc: function(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_malloc}

  CRYPTO_secure_zalloc: function(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_zalloc}

  CRYPTO_secure_malloc_array: function(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_malloc_array}

  CRYPTO_secure_calloc: function(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_calloc}

  CRYPTO_secure_free: function(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_free}

  CRYPTO_secure_clear_free: function(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_clear_free}

  CRYPTO_secure_allocated: function(ptr: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_allocated}

  CRYPTO_secure_malloc_initialized: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_malloc_initialized}

  CRYPTO_secure_actual_size: function(ptr: Pointer): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_actual_size}

  CRYPTO_secure_used: function: TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM CRYPTO_secure_used}

  OPENSSL_cleanse: function(ptr: Pointer; len: TIdC_SIZET): void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_cleanse}

  OPENSSL_die: function(assertion: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_die}

  OPENSSL_isservice: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_isservice}

  OPENSSL_init: function: void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_init}

  OPENSSL_fork_prepare: function: void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OPENSSL_fork_prepare}

  OPENSSL_fork_parent: function: void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OPENSSL_fork_parent}

  OPENSSL_fork_child: function: void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OPENSSL_fork_child}

  OPENSSL_gmtime: function(timer: PIdC_TIMET; result: Ptm): Ptm; cdecl = nil;
  {$EXTERNALSYM OPENSSL_gmtime}

  OPENSSL_gmtime_adj: function(tm: Ptm; offset_day: TIdC_INT; offset_sec: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_gmtime_adj}

  OPENSSL_gmtime_diff: function(pday: PIdC_INT; psec: PIdC_INT; from: Ptm; _to: Ptm): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_gmtime_diff}

  CRYPTO_memcmp: function(in_a: Pointer; in_b: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_memcmp}

  OPENSSL_cleanup: function: void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_cleanup}

  OPENSSL_init_crypto: function(opts: TIdC_UINT64; settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_init_crypto}

  OPENSSL_atexit: function(handler: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_atexit}

  OPENSSL_thread_stop: function: void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_thread_stop}

  OPENSSL_thread_stop_ex: function(ctx: POSSL_LIB_CTX): void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_thread_stop_ex}

  OPENSSL_INIT_new: function: POPENSSL_INIT_SETTINGS; cdecl = nil;
  {$EXTERNALSYM OPENSSL_INIT_new}

  OPENSSL_INIT_set_config_filename: function(settings: POPENSSL_INIT_SETTINGS; config_filename: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_INIT_set_config_filename}

  OPENSSL_INIT_set_config_file_flags: function(settings: POPENSSL_INIT_SETTINGS; flags: TIdC_ULONG): void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_INIT_set_config_file_flags}

  OPENSSL_INIT_set_config_appname: function(settings: POPENSSL_INIT_SETTINGS; config_appname: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_INIT_set_config_appname}

  OPENSSL_INIT_free: function(settings: POPENSSL_INIT_SETTINGS): void; cdecl = nil;
  {$EXTERNALSYM OPENSSL_INIT_free}

  CRYPTO_THREAD_run_once: function(once: PCRYPTO_ONCE; init: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_run_once}

  CRYPTO_THREAD_init_local: function(key: PCRYPTO_THREAD_LOCAL; cleanup: Tsk_void_freefunc): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_init_local}

  CRYPTO_THREAD_get_local: function(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_get_local}

  CRYPTO_THREAD_set_local: function(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_set_local}

  CRYPTO_THREAD_cleanup_local: function(key: PCRYPTO_THREAD_LOCAL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_cleanup_local}

  CRYPTO_THREAD_get_current_id: function: TCRYPTO_THREAD_ID; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_get_current_id}

  CRYPTO_THREAD_compare_id: function(a: TCRYPTO_THREAD_ID; b: TCRYPTO_THREAD_ID): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_THREAD_compare_id}

  OSSL_LIB_CTX_new: function: POSSL_LIB_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_new}

  OSSL_LIB_CTX_new_from_dispatch: function(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_new_from_dispatch}

  OSSL_LIB_CTX_new_child: function(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_new_child}

  OSSL_LIB_CTX_load_config: function(ctx: POSSL_LIB_CTX; config_file: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_load_config}

  OSSL_LIB_CTX_free: function(arg1: POSSL_LIB_CTX): void; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_free}

  OSSL_LIB_CTX_get0_global_default: function: POSSL_LIB_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_get0_global_default}

  OSSL_LIB_CTX_set0_default: function(libctx: POSSL_LIB_CTX): POSSL_LIB_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_set0_default}

  OSSL_LIB_CTX_get_conf_diagnostics: function(ctx: POSSL_LIB_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_get_conf_diagnostics}

  OSSL_LIB_CTX_set_conf_diagnostics: function(ctx: POSSL_LIB_CTX; value: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_set_conf_diagnostics}

  OSSL_sleep: function(millis: TIdC_UINT64): void; cdecl = nil;
  {$EXTERNALSYM OSSL_sleep}

  OSSL_LIB_CTX_get_data: function(ctx: POSSL_LIB_CTX; index: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_LIB_CTX_get_data}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl;
function CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK): void; cdecl;
function CRYPTO_atomic_add(val: PIdC_INT; amount: TIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_atomic_add64(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_atomic_and(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_atomic_or(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_atomic_load(val: PIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_atomic_load_int(val: PIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function CRYPTO_atomic_store(dst: PIdC_UINT64; val: TIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
function OPENSSL_strlcpy(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl;
function OPENSSL_strlcat(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl;
function OPENSSL_strnlen(str: PIdAnsiChar; maxlen: TIdC_SIZET): TIdC_SIZET; cdecl;
function OPENSSL_strtoul(str: PIdAnsiChar; endptr: PPIdAnsiChar; base: TIdC_INT; num: PIdC_ULONG): TIdC_INT; cdecl;
function OPENSSL_buf2hexstr_ex(str: PIdAnsiChar; str_n: TIdC_SIZET; strlength: PIdC_SIZET; buf: PIdAnsiChar; buflen: TIdC_SIZET; sep: TIdC_INT8): TIdC_INT; cdecl;
function OPENSSL_buf2hexstr(buf: PIdAnsiChar; buflen: TIdC_LONG): PIdAnsiChar; cdecl;
function OPENSSL_hexstr2buf_ex(buf: PIdAnsiChar; buf_n: TIdC_SIZET; buflen: PIdC_SIZET; str: PIdAnsiChar; sep: TIdC_INT8): TIdC_INT; cdecl;
function OPENSSL_hexstr2buf(str: PIdAnsiChar; buflen: PIdC_LONG): PIdAnsiChar; cdecl;
function OPENSSL_hexchar2int(c: TIdC_UINT8): TIdC_INT; cdecl;
function OPENSSL_strcasecmp(s1: PIdAnsiChar; s2: PIdAnsiChar): TIdC_INT; cdecl;
function OPENSSL_strncasecmp(s1: PIdAnsiChar; s2: PIdAnsiChar; n: TIdC_SIZET): TIdC_INT; cdecl;
function OPENSSL_version_major: TIdC_UINT; cdecl;
function OPENSSL_version_minor: TIdC_UINT; cdecl;
function OPENSSL_version_patch: TIdC_UINT; cdecl;
function OPENSSL_version_pre_release: PIdAnsiChar; cdecl;
function OPENSSL_version_build_metadata: PIdAnsiChar; cdecl;
function OpenSSL_version_num: TIdC_ULONG; cdecl;
function OpenSSL_version(_type: TIdC_INT): PIdAnsiChar; cdecl;
function OPENSSL_info(_type: TIdC_INT): PIdAnsiChar; cdecl;
function OPENSSL_issetugid: TIdC_INT; cdecl;
function CRYPTO_get_ex_new_index(class_index: TIdC_INT; argl: TIdC_LONG; argp: Pointer; new_func: TCRYPTO_EX_free; dup_func: TCRYPTO_EX_dup; free_func: TCRYPTO_EX_free): TIdC_INT; cdecl;
function CRYPTO_free_ex_index(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT; cdecl;
function CRYPTO_new_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TIdC_INT; cdecl;
function CRYPTO_dup_ex_data(class_index: TIdC_INT; _to: PCRYPTO_EX_DATA; from: PCRYPTO_EX_DATA): TIdC_INT; cdecl;
function CRYPTO_free_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): void; cdecl;
function CRYPTO_alloc_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA; idx: TIdC_INT): TIdC_INT; cdecl;
function CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT; val: Pointer): TIdC_INT; cdecl;
function CRYPTO_get_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT): Pointer; cdecl;
function CRYPTO_set_mem_functions(malloc_fn: TCRYPTO_malloc_fn; realloc_fn: TCRYPTO_realloc_fn; free_fn: TCRYPTO_free_fn): TIdC_INT; cdecl;
function CRYPTO_get_mem_functions(malloc_fn: PCRYPTO_malloc_fn; realloc_fn: PCRYPTO_realloc_fn; free_fn: PCRYPTO_free_fn): void; cdecl;
function CRYPTO_malloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_zalloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_malloc_array(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_calloc(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_aligned_alloc(num: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_aligned_alloc_array(num: TIdC_SIZET; size: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_memdup(str: Pointer; siz: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_strdup(str: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl;
function CRYPTO_strndup(str: PIdAnsiChar; s: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl;
function CRYPTO_free(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl;
function CRYPTO_clear_free(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl;
function CRYPTO_realloc(addr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_clear_realloc(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_realloc_array(addr: Pointer; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_clear_realloc_array(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_secure_malloc_init(sz: TIdC_SIZET; minsize: TIdC_SIZET): TIdC_INT; cdecl;
function CRYPTO_secure_malloc_done: TIdC_INT; cdecl;
function CRYPTO_secure_malloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_secure_zalloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_secure_malloc_array(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_secure_calloc(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
function CRYPTO_secure_free(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl;
function CRYPTO_secure_clear_free(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl;
function CRYPTO_secure_allocated(ptr: Pointer): TIdC_INT; cdecl;
function CRYPTO_secure_malloc_initialized: TIdC_INT; cdecl;
function CRYPTO_secure_actual_size(ptr: Pointer): TIdC_SIZET; cdecl;
function CRYPTO_secure_used: TIdC_SIZET; cdecl;
function OPENSSL_cleanse(ptr: Pointer; len: TIdC_SIZET): void; cdecl;
function OPENSSL_die(assertion: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl;
function OPENSSL_isservice: TIdC_INT; cdecl;
function OPENSSL_init: void; cdecl;
function OPENSSL_fork_prepare: void; cdecl; deprecated 'In OpenSSL 3_0_0';
function OPENSSL_fork_parent: void; cdecl; deprecated 'In OpenSSL 3_0_0';
function OPENSSL_fork_child: void; cdecl; deprecated 'In OpenSSL 3_0_0';
function OPENSSL_gmtime(timer: PIdC_TIMET; result: Ptm): Ptm; cdecl;
function OPENSSL_gmtime_adj(tm: Ptm; offset_day: TIdC_INT; offset_sec: TIdC_LONG): TIdC_INT; cdecl;
function OPENSSL_gmtime_diff(pday: PIdC_INT; psec: PIdC_INT; from: Ptm; _to: Ptm): TIdC_INT; cdecl;
function CRYPTO_memcmp(in_a: Pointer; in_b: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl;
function OPENSSL_cleanup: void; cdecl;
function OPENSSL_init_crypto(opts: TIdC_UINT64; settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl;
function OPENSSL_atexit(handler: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl;
function OPENSSL_thread_stop: void; cdecl;
function OPENSSL_thread_stop_ex(ctx: POSSL_LIB_CTX): void; cdecl;
function OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl;
function OPENSSL_INIT_set_config_filename(settings: POPENSSL_INIT_SETTINGS; config_filename: PIdAnsiChar): TIdC_INT; cdecl;
function OPENSSL_INIT_set_config_file_flags(settings: POPENSSL_INIT_SETTINGS; flags: TIdC_ULONG): void; cdecl;
function OPENSSL_INIT_set_config_appname(settings: POPENSSL_INIT_SETTINGS; config_appname: PIdAnsiChar): TIdC_INT; cdecl;
function OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS): void; cdecl;
function CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl;
function CRYPTO_THREAD_init_local(key: PCRYPTO_THREAD_LOCAL; cleanup: Tsk_void_freefunc): TIdC_INT; cdecl;
function CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl;
function CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TIdC_INT; cdecl;
function CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TIdC_INT; cdecl;
function CRYPTO_THREAD_get_current_id: TCRYPTO_THREAD_ID; cdecl;
function CRYPTO_THREAD_compare_id(a: TCRYPTO_THREAD_ID; b: TCRYPTO_THREAD_ID): TIdC_INT; cdecl;
function OSSL_LIB_CTX_new: POSSL_LIB_CTX; cdecl;
function OSSL_LIB_CTX_new_from_dispatch(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl;
function OSSL_LIB_CTX_new_child(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl;
function OSSL_LIB_CTX_load_config(ctx: POSSL_LIB_CTX; config_file: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_LIB_CTX_free(arg1: POSSL_LIB_CTX): void; cdecl;
function OSSL_LIB_CTX_get0_global_default: POSSL_LIB_CTX; cdecl;
function OSSL_LIB_CTX_set0_default(libctx: POSSL_LIB_CTX): POSSL_LIB_CTX; cdecl;
function OSSL_LIB_CTX_get_conf_diagnostics(ctx: POSSL_LIB_CTX): TIdC_INT; cdecl;
function OSSL_LIB_CTX_set_conf_diagnostics(ctx: POSSL_LIB_CTX; value: TIdC_INT): void; cdecl;
function OSSL_sleep(millis: TIdC_UINT64): void; cdecl;
function OSSL_LIB_CTX_get_data(ctx: POSSL_LIB_CTX; index: TIdC_INT): Pointer; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_malloc_init: TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_malloc(num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_zalloc(num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_malloc_array(num: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_calloc(num: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_aligned_alloc(num: Pointer; alignment: Pointer; freeptr: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_aligned_alloc_array(num: Pointer; size: Pointer; alignment: Pointer; freeptr: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_realloc(addr: Pointer; num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_clear_realloc(addr: Pointer; old_num: Pointer; num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_realloc_array(addr: Pointer; num: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_clear_realloc_array(addr: Pointer; old_num: Pointer; num: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_clear_free(addr: Pointer; num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_free(addr: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_memdup(str: Pointer; s: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_strdup(str: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_strndup(str: Pointer; n: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_secure_malloc(num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_secure_zalloc(num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_secure_malloc_array(num: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_secure_calloc(num: Pointer; size: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_secure_free(addr: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_secure_clear_free(addr: Pointer; num: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_secure_actual_size(ptr: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function SSLeay: TIdC_ULONG; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function SSLeay_version(_type: TIdC_INT): PIdAnsiChar; cdecl;


// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack void definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_void = Pointer;
  {$EXTERNALSYM PSTACK_OF_void}

  { Original Stack Macros for void:
    SKM_DEFINE_STACK_OF_INTERNAL(void, void, void)
    sk_void_num(sk) OPENSSL_sk_num(ossl_check_const_void_sk_type(sk))
    sk_void_value(sk, idx) ((void *)OPENSSL_sk_value(ossl_check_const_void_sk_type(sk), (idx)))
    sk_void_new(cmp) ((STACK_OF(void) *)OPENSSL_sk_new(ossl_check_void_compfunc_type(cmp)))
    sk_void_new_null() ((STACK_OF(void) *)OPENSSL_sk_new_null())
    sk_void_new_reserve(cmp, n) ((STACK_OF(void) *)OPENSSL_sk_new_reserve(ossl_check_void_compfunc_type(cmp), (n)))
    sk_void_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_void_sk_type(sk), (n))
    sk_void_free(sk) OPENSSL_sk_free(ossl_check_void_sk_type(sk))
    sk_void_zero(sk) OPENSSL_sk_zero(ossl_check_void_sk_type(sk))
    sk_void_delete(sk, i) ((void *)OPENSSL_sk_delete(ossl_check_void_sk_type(sk), (i)))
    sk_void_delete_ptr(sk, ptr) ((void *)OPENSSL_sk_delete_ptr(ossl_check_void_sk_type(sk), ossl_check_void_type(ptr)))
    sk_void_push(sk, ptr) OPENSSL_sk_push(ossl_check_void_sk_type(sk), ossl_check_void_type(ptr))
    sk_void_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_void_sk_type(sk), ossl_check_void_type(ptr))
    sk_void_pop(sk) ((void *)OPENSSL_sk_pop(ossl_check_void_sk_type(sk)))
    sk_void_shift(sk) ((void *)OPENSSL_sk_shift(ossl_check_void_sk_type(sk)))
    sk_void_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_void_sk_type(sk), ossl_check_void_freefunc_type(freefunc))
    sk_void_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_void_sk_type(sk), ossl_check_void_type(ptr), (idx))
    sk_void_set(sk, idx, ptr) ((void *)OPENSSL_sk_set(ossl_check_void_sk_type(sk), (idx), ossl_check_void_type(ptr)))
    sk_void_find(sk, ptr) OPENSSL_sk_find(ossl_check_void_sk_type(sk), ossl_check_void_type(ptr))
    sk_void_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_void_sk_type(sk), ossl_check_void_type(ptr))
    sk_void_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_void_sk_type(sk), ossl_check_void_type(ptr), pnum)
    sk_void_sort(sk) OPENSSL_sk_sort(ossl_check_void_sk_type(sk))
    sk_void_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_void_sk_type(sk))
    sk_void_dup(sk) ((STACK_OF(void) *)OPENSSL_sk_dup(ossl_check_const_void_sk_type(sk)))
    sk_void_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(void) *)OPENSSL_sk_deep_copy(ossl_check_const_void_sk_type(sk), ossl_check_void_copyfunc_type(copyfunc), ossl_check_void_freefunc_type(freefunc)))
    sk_void_set_cmp_func(sk, cmp) ((sk_void_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_void_sk_type(sk), ossl_check_void_compfunc_type(cmp)))
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

function CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl external CLibCrypto name 'CRYPTO_THREAD_lock_new';
function CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_read_lock';
function CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_write_lock';
function CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_unlock';
function CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK): void; cdecl external CLibCrypto name 'CRYPTO_THREAD_lock_free';
function CRYPTO_atomic_add(val: PIdC_INT; amount: TIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_atomic_add';
function CRYPTO_atomic_add64(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_atomic_add64';
function CRYPTO_atomic_and(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_atomic_and';
function CRYPTO_atomic_or(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_atomic_or';
function CRYPTO_atomic_load(val: PIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_atomic_load';
function CRYPTO_atomic_load_int(val: PIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_atomic_load_int';
function CRYPTO_atomic_store(dst: PIdC_UINT64; val: TIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_atomic_store';
function OPENSSL_strlcpy(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'OPENSSL_strlcpy';
function OPENSSL_strlcat(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'OPENSSL_strlcat';
function OPENSSL_strnlen(str: PIdAnsiChar; maxlen: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'OPENSSL_strnlen';
function OPENSSL_strtoul(str: PIdAnsiChar; endptr: PPIdAnsiChar; base: TIdC_INT; num: PIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_strtoul';
function OPENSSL_buf2hexstr_ex(str: PIdAnsiChar; str_n: TIdC_SIZET; strlength: PIdC_SIZET; buf: PIdAnsiChar; buflen: TIdC_SIZET; sep: TIdC_INT8): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_buf2hexstr_ex';
function OPENSSL_buf2hexstr(buf: PIdAnsiChar; buflen: TIdC_LONG): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_buf2hexstr';
function OPENSSL_hexstr2buf_ex(buf: PIdAnsiChar; buf_n: TIdC_SIZET; buflen: PIdC_SIZET; str: PIdAnsiChar; sep: TIdC_INT8): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_hexstr2buf_ex';
function OPENSSL_hexstr2buf(str: PIdAnsiChar; buflen: PIdC_LONG): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_hexstr2buf';
function OPENSSL_hexchar2int(c: TIdC_UINT8): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_hexchar2int';
function OPENSSL_strcasecmp(s1: PIdAnsiChar; s2: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_strcasecmp';
function OPENSSL_strncasecmp(s1: PIdAnsiChar; s2: PIdAnsiChar; n: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_strncasecmp';
function OPENSSL_version_major: TIdC_UINT; cdecl external CLibCrypto name 'OPENSSL_version_major';
function OPENSSL_version_minor: TIdC_UINT; cdecl external CLibCrypto name 'OPENSSL_version_minor';
function OPENSSL_version_patch: TIdC_UINT; cdecl external CLibCrypto name 'OPENSSL_version_patch';
function OPENSSL_version_pre_release: PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_version_pre_release';
function OPENSSL_version_build_metadata: PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_version_build_metadata';
function OpenSSL_version_num: TIdC_ULONG; cdecl external CLibCrypto name 'OpenSSL_version_num';
function OpenSSL_version(_type: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OpenSSL_version';
function OPENSSL_info(_type: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_info';
function OPENSSL_issetugid: TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_issetugid';
function CRYPTO_get_ex_new_index(class_index: TIdC_INT; argl: TIdC_LONG; argp: Pointer; new_func: TCRYPTO_EX_free; dup_func: TCRYPTO_EX_dup; free_func: TCRYPTO_EX_free): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_get_ex_new_index';
function CRYPTO_free_ex_index(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_free_ex_index';
function CRYPTO_new_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_new_ex_data';
function CRYPTO_dup_ex_data(class_index: TIdC_INT; _to: PCRYPTO_EX_DATA; from: PCRYPTO_EX_DATA): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_dup_ex_data';
function CRYPTO_free_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): void; cdecl external CLibCrypto name 'CRYPTO_free_ex_data';
function CRYPTO_alloc_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA; idx: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_alloc_ex_data';
function CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT; val: Pointer): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_set_ex_data';
function CRYPTO_get_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_get_ex_data';
function CRYPTO_set_mem_functions(malloc_fn: TCRYPTO_malloc_fn; realloc_fn: TCRYPTO_realloc_fn; free_fn: TCRYPTO_free_fn): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_set_mem_functions';
function CRYPTO_get_mem_functions(malloc_fn: PCRYPTO_malloc_fn; realloc_fn: PCRYPTO_realloc_fn; free_fn: PCRYPTO_free_fn): void; cdecl external CLibCrypto name 'CRYPTO_get_mem_functions';
function CRYPTO_malloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_malloc';
function CRYPTO_zalloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_zalloc';
function CRYPTO_malloc_array(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_malloc_array';
function CRYPTO_calloc(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_calloc';
function CRYPTO_aligned_alloc(num: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_aligned_alloc';
function CRYPTO_aligned_alloc_array(num: TIdC_SIZET; size: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_aligned_alloc_array';
function CRYPTO_memdup(str: Pointer; siz: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_memdup';
function CRYPTO_strdup(str: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'CRYPTO_strdup';
function CRYPTO_strndup(str: PIdAnsiChar; s: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'CRYPTO_strndup';
function CRYPTO_free(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl external CLibCrypto name 'CRYPTO_free';
function CRYPTO_clear_free(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl external CLibCrypto name 'CRYPTO_clear_free';
function CRYPTO_realloc(addr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_realloc';
function CRYPTO_clear_realloc(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_clear_realloc';
function CRYPTO_realloc_array(addr: Pointer; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_realloc_array';
function CRYPTO_clear_realloc_array(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_clear_realloc_array';
function CRYPTO_secure_malloc_init(sz: TIdC_SIZET; minsize: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_secure_malloc_init';
function CRYPTO_secure_malloc_done: TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_secure_malloc_done';
function CRYPTO_secure_malloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_secure_malloc';
function CRYPTO_secure_zalloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_secure_zalloc';
function CRYPTO_secure_malloc_array(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_secure_malloc_array';
function CRYPTO_secure_calloc(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CRYPTO_secure_calloc';
function CRYPTO_secure_free(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl external CLibCrypto name 'CRYPTO_secure_free';
function CRYPTO_secure_clear_free(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl external CLibCrypto name 'CRYPTO_secure_clear_free';
function CRYPTO_secure_allocated(ptr: Pointer): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_secure_allocated';
function CRYPTO_secure_malloc_initialized: TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_secure_malloc_initialized';
function CRYPTO_secure_actual_size(ptr: Pointer): TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_secure_actual_size';
function CRYPTO_secure_used: TIdC_SIZET; cdecl external CLibCrypto name 'CRYPTO_secure_used';
function OPENSSL_cleanse(ptr: Pointer; len: TIdC_SIZET): void; cdecl external CLibCrypto name 'OPENSSL_cleanse';
function OPENSSL_die(assertion: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl external CLibCrypto name 'OPENSSL_die';
function OPENSSL_isservice: TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_isservice';
function OPENSSL_init: void; cdecl external CLibCrypto name 'OPENSSL_init';
function OPENSSL_fork_prepare: void; cdecl external CLibCrypto name 'OPENSSL_fork_prepare';
function OPENSSL_fork_parent: void; cdecl external CLibCrypto name 'OPENSSL_fork_parent';
function OPENSSL_fork_child: void; cdecl external CLibCrypto name 'OPENSSL_fork_child';
function OPENSSL_gmtime(timer: PIdC_TIMET; result: Ptm): Ptm; cdecl external CLibCrypto name 'OPENSSL_gmtime';
function OPENSSL_gmtime_adj(tm: Ptm; offset_day: TIdC_INT; offset_sec: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_gmtime_adj';
function OPENSSL_gmtime_diff(pday: PIdC_INT; psec: PIdC_INT; from: Ptm; _to: Ptm): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_gmtime_diff';
function CRYPTO_memcmp(in_a: Pointer; in_b: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_memcmp';
function OPENSSL_cleanup: void; cdecl external CLibCrypto name 'OPENSSL_cleanup';
function OPENSSL_init_crypto(opts: TIdC_UINT64; settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_init_crypto';
function OPENSSL_atexit(handler: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_atexit';
function OPENSSL_thread_stop: void; cdecl external CLibCrypto name 'OPENSSL_thread_stop';
function OPENSSL_thread_stop_ex(ctx: POSSL_LIB_CTX): void; cdecl external CLibCrypto name 'OPENSSL_thread_stop_ex';
function OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl external CLibCrypto name 'OPENSSL_INIT_new';
function OPENSSL_INIT_set_config_filename(settings: POPENSSL_INIT_SETTINGS; config_filename: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_INIT_set_config_filename';
function OPENSSL_INIT_set_config_file_flags(settings: POPENSSL_INIT_SETTINGS; flags: TIdC_ULONG): void; cdecl external CLibCrypto name 'OPENSSL_INIT_set_config_file_flags';
function OPENSSL_INIT_set_config_appname(settings: POPENSSL_INIT_SETTINGS; config_appname: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_INIT_set_config_appname';
function OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS): void; cdecl external CLibCrypto name 'OPENSSL_INIT_free';
function CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_run_once';
function CRYPTO_THREAD_init_local(key: PCRYPTO_THREAD_LOCAL; cleanup: Tsk_void_freefunc): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_init_local';
function CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl external CLibCrypto name 'CRYPTO_THREAD_get_local';
function CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_set_local';
function CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_cleanup_local';
function CRYPTO_THREAD_get_current_id: TCRYPTO_THREAD_ID; cdecl external CLibCrypto name 'CRYPTO_THREAD_get_current_id';
function CRYPTO_THREAD_compare_id(a: TCRYPTO_THREAD_ID; b: TCRYPTO_THREAD_ID): TIdC_INT; cdecl external CLibCrypto name 'CRYPTO_THREAD_compare_id';
function OSSL_LIB_CTX_new: POSSL_LIB_CTX; cdecl external CLibCrypto name 'OSSL_LIB_CTX_new';
function OSSL_LIB_CTX_new_from_dispatch(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl external CLibCrypto name 'OSSL_LIB_CTX_new_from_dispatch';
function OSSL_LIB_CTX_new_child(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl external CLibCrypto name 'OSSL_LIB_CTX_new_child';
function OSSL_LIB_CTX_load_config(ctx: POSSL_LIB_CTX; config_file: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_LIB_CTX_load_config';
function OSSL_LIB_CTX_free(arg1: POSSL_LIB_CTX): void; cdecl external CLibCrypto name 'OSSL_LIB_CTX_free';
function OSSL_LIB_CTX_get0_global_default: POSSL_LIB_CTX; cdecl external CLibCrypto name 'OSSL_LIB_CTX_get0_global_default';
function OSSL_LIB_CTX_set0_default(libctx: POSSL_LIB_CTX): POSSL_LIB_CTX; cdecl external CLibCrypto name 'OSSL_LIB_CTX_set0_default';
function OSSL_LIB_CTX_get_conf_diagnostics(ctx: POSSL_LIB_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_LIB_CTX_get_conf_diagnostics';
function OSSL_LIB_CTX_set_conf_diagnostics(ctx: POSSL_LIB_CTX; value: TIdC_INT): void; cdecl external CLibCrypto name 'OSSL_LIB_CTX_set_conf_diagnostics';
function OSSL_sleep(millis: TIdC_UINT64): void; cdecl external CLibCrypto name 'OSSL_sleep';
function OSSL_LIB_CTX_get_data(ctx: POSSL_LIB_CTX; index: TIdC_INT): Pointer; cdecl external CLibCrypto name 'OSSL_LIB_CTX_get_data';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  CRYPTO_THREAD_lock_new_procname = 'CRYPTO_THREAD_lock_new';
  CRYPTO_THREAD_lock_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_read_lock_procname = 'CRYPTO_THREAD_read_lock';
  CRYPTO_THREAD_read_lock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_write_lock_procname = 'CRYPTO_THREAD_write_lock';
  CRYPTO_THREAD_write_lock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_unlock_procname = 'CRYPTO_THREAD_unlock';
  CRYPTO_THREAD_unlock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_lock_free_procname = 'CRYPTO_THREAD_lock_free';
  CRYPTO_THREAD_lock_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_atomic_add_procname = 'CRYPTO_atomic_add';
  CRYPTO_atomic_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_atomic_add64_procname = 'CRYPTO_atomic_add64';
  CRYPTO_atomic_add64_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  CRYPTO_atomic_and_procname = 'CRYPTO_atomic_and';
  CRYPTO_atomic_and_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  CRYPTO_atomic_or_procname = 'CRYPTO_atomic_or';
  CRYPTO_atomic_or_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CRYPTO_atomic_load_procname = 'CRYPTO_atomic_load';
  CRYPTO_atomic_load_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CRYPTO_atomic_load_int_procname = 'CRYPTO_atomic_load_int';
  CRYPTO_atomic_load_int_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  CRYPTO_atomic_store_procname = 'CRYPTO_atomic_store';
  CRYPTO_atomic_store_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OPENSSL_strlcpy_procname = 'OPENSSL_strlcpy';
  OPENSSL_strlcpy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_strlcat_procname = 'OPENSSL_strlcat';
  OPENSSL_strlcat_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_strnlen_procname = 'OPENSSL_strnlen';
  OPENSSL_strnlen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_strtoul_procname = 'OPENSSL_strtoul';
  OPENSSL_strtoul_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OPENSSL_buf2hexstr_ex_procname = 'OPENSSL_buf2hexstr_ex';
  OPENSSL_buf2hexstr_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_buf2hexstr_procname = 'OPENSSL_buf2hexstr';
  OPENSSL_buf2hexstr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_hexstr2buf_ex_procname = 'OPENSSL_hexstr2buf_ex';
  OPENSSL_hexstr2buf_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_hexstr2buf_procname = 'OPENSSL_hexstr2buf';
  OPENSSL_hexstr2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_hexchar2int_procname = 'OPENSSL_hexchar2int';
  OPENSSL_hexchar2int_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_strcasecmp_procname = 'OPENSSL_strcasecmp';
  OPENSSL_strcasecmp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(3);

  OPENSSL_strncasecmp_procname = 'OPENSSL_strncasecmp';
  OPENSSL_strncasecmp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(3);

  OPENSSL_version_major_procname = 'OPENSSL_version_major';
  OPENSSL_version_major_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_version_minor_procname = 'OPENSSL_version_minor';
  OPENSSL_version_minor_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_version_patch_procname = 'OPENSSL_version_patch';
  OPENSSL_version_patch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_version_pre_release_procname = 'OPENSSL_version_pre_release';
  OPENSSL_version_pre_release_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_version_build_metadata_procname = 'OPENSSL_version_build_metadata';
  OPENSSL_version_build_metadata_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OpenSSL_version_num_procname = 'OpenSSL_version_num';
  OpenSSL_version_num_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OpenSSL_version_procname = 'OpenSSL_version';
  OpenSSL_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_info_procname = 'OPENSSL_info';
  OPENSSL_info_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_issetugid_procname = 'OPENSSL_issetugid';
  OPENSSL_issetugid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_get_ex_new_index_procname = 'CRYPTO_get_ex_new_index';
  CRYPTO_get_ex_new_index_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_free_ex_index_procname = 'CRYPTO_free_ex_index';
  CRYPTO_free_ex_index_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_new_ex_data_procname = 'CRYPTO_new_ex_data';
  CRYPTO_new_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_dup_ex_data_procname = 'CRYPTO_dup_ex_data';
  CRYPTO_dup_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_free_ex_data_procname = 'CRYPTO_free_ex_data';
  CRYPTO_free_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_alloc_ex_data_procname = 'CRYPTO_alloc_ex_data';
  CRYPTO_alloc_ex_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CRYPTO_set_ex_data_procname = 'CRYPTO_set_ex_data';
  CRYPTO_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_get_ex_data_procname = 'CRYPTO_get_ex_data';
  CRYPTO_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_set_mem_functions_procname = 'CRYPTO_set_mem_functions';
  CRYPTO_set_mem_functions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_get_mem_functions_procname = 'CRYPTO_get_mem_functions';
  CRYPTO_get_mem_functions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_malloc_procname = 'CRYPTO_malloc';
  CRYPTO_malloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_zalloc_procname = 'CRYPTO_zalloc';
  CRYPTO_zalloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_malloc_array_procname = 'CRYPTO_malloc_array';
  CRYPTO_malloc_array_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CRYPTO_calloc_procname = 'CRYPTO_calloc';
  CRYPTO_calloc_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CRYPTO_aligned_alloc_procname = 'CRYPTO_aligned_alloc';
  CRYPTO_aligned_alloc_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  CRYPTO_aligned_alloc_array_procname = 'CRYPTO_aligned_alloc_array';
  CRYPTO_aligned_alloc_array_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CRYPTO_memdup_procname = 'CRYPTO_memdup';
  CRYPTO_memdup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_strdup_procname = 'CRYPTO_strdup';
  CRYPTO_strdup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_strndup_procname = 'CRYPTO_strndup';
  CRYPTO_strndup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_free_procname = 'CRYPTO_free';
  CRYPTO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_clear_free_procname = 'CRYPTO_clear_free';
  CRYPTO_clear_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_realloc_procname = 'CRYPTO_realloc';
  CRYPTO_realloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_clear_realloc_procname = 'CRYPTO_clear_realloc';
  CRYPTO_clear_realloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_realloc_array_procname = 'CRYPTO_realloc_array';
  CRYPTO_realloc_array_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CRYPTO_clear_realloc_array_procname = 'CRYPTO_clear_realloc_array';
  CRYPTO_clear_realloc_array_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CRYPTO_secure_malloc_init_procname = 'CRYPTO_secure_malloc_init';
  CRYPTO_secure_malloc_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_malloc_done_procname = 'CRYPTO_secure_malloc_done';
  CRYPTO_secure_malloc_done_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_malloc_procname = 'CRYPTO_secure_malloc';
  CRYPTO_secure_malloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_zalloc_procname = 'CRYPTO_secure_zalloc';
  CRYPTO_secure_zalloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_malloc_array_procname = 'CRYPTO_secure_malloc_array';
  CRYPTO_secure_malloc_array_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CRYPTO_secure_calloc_procname = 'CRYPTO_secure_calloc';
  CRYPTO_secure_calloc_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CRYPTO_secure_free_procname = 'CRYPTO_secure_free';
  CRYPTO_secure_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_clear_free_procname = 'CRYPTO_secure_clear_free';
  CRYPTO_secure_clear_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0g);

  CRYPTO_secure_allocated_procname = 'CRYPTO_secure_allocated';
  CRYPTO_secure_allocated_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_malloc_initialized_procname = 'CRYPTO_secure_malloc_initialized';
  CRYPTO_secure_malloc_initialized_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_actual_size_procname = 'CRYPTO_secure_actual_size';
  CRYPTO_secure_actual_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_secure_used_procname = 'CRYPTO_secure_used';
  CRYPTO_secure_used_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_cleanse_procname = 'OPENSSL_cleanse';
  OPENSSL_cleanse_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_die_procname = 'OPENSSL_die';
  OPENSSL_die_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_isservice_procname = 'OPENSSL_isservice';
  OPENSSL_isservice_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_init_procname = 'OPENSSL_init';
  OPENSSL_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_fork_prepare_procname = 'OPENSSL_fork_prepare';
  OPENSSL_fork_prepare_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OPENSSL_fork_prepare_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_fork_parent_procname = 'OPENSSL_fork_parent';
  OPENSSL_fork_parent_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OPENSSL_fork_parent_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_fork_child_procname = 'OPENSSL_fork_child';
  OPENSSL_fork_child_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OPENSSL_fork_child_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_gmtime_procname = 'OPENSSL_gmtime';
  OPENSSL_gmtime_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_gmtime_adj_procname = 'OPENSSL_gmtime_adj';
  OPENSSL_gmtime_adj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_gmtime_diff_procname = 'OPENSSL_gmtime_diff';
  OPENSSL_gmtime_diff_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_memcmp_procname = 'CRYPTO_memcmp';
  CRYPTO_memcmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_cleanup_procname = 'OPENSSL_cleanup';
  OPENSSL_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_init_crypto_procname = 'OPENSSL_init_crypto';
  OPENSSL_init_crypto_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_atexit_procname = 'OPENSSL_atexit';
  OPENSSL_atexit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_thread_stop_procname = 'OPENSSL_thread_stop';
  OPENSSL_thread_stop_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_thread_stop_ex_procname = 'OPENSSL_thread_stop_ex';
  OPENSSL_thread_stop_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_INIT_new_procname = 'OPENSSL_INIT_new';
  OPENSSL_INIT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_INIT_set_config_filename_procname = 'OPENSSL_INIT_set_config_filename';
  OPENSSL_INIT_set_config_filename_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1b);

  OPENSSL_INIT_set_config_file_flags_procname = 'OPENSSL_INIT_set_config_file_flags';
  OPENSSL_INIT_set_config_file_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1b);

  OPENSSL_INIT_set_config_appname_procname = 'OPENSSL_INIT_set_config_appname';
  OPENSSL_INIT_set_config_appname_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_INIT_free_procname = 'OPENSSL_INIT_free';
  OPENSSL_INIT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_run_once_procname = 'CRYPTO_THREAD_run_once';
  CRYPTO_THREAD_run_once_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_init_local_procname = 'CRYPTO_THREAD_init_local';
  CRYPTO_THREAD_init_local_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_get_local_procname = 'CRYPTO_THREAD_get_local';
  CRYPTO_THREAD_get_local_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_set_local_procname = 'CRYPTO_THREAD_set_local';
  CRYPTO_THREAD_set_local_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_cleanup_local_procname = 'CRYPTO_THREAD_cleanup_local';
  CRYPTO_THREAD_cleanup_local_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_get_current_id_procname = 'CRYPTO_THREAD_get_current_id';
  CRYPTO_THREAD_get_current_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CRYPTO_THREAD_compare_id_procname = 'CRYPTO_THREAD_compare_id';
  CRYPTO_THREAD_compare_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_LIB_CTX_new_procname = 'OSSL_LIB_CTX_new';
  OSSL_LIB_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_LIB_CTX_new_from_dispatch_procname = 'OSSL_LIB_CTX_new_from_dispatch';
  OSSL_LIB_CTX_new_from_dispatch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_LIB_CTX_new_child_procname = 'OSSL_LIB_CTX_new_child';
  OSSL_LIB_CTX_new_child_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_LIB_CTX_load_config_procname = 'OSSL_LIB_CTX_load_config';
  OSSL_LIB_CTX_load_config_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_LIB_CTX_free_procname = 'OSSL_LIB_CTX_free';
  OSSL_LIB_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_LIB_CTX_get0_global_default_procname = 'OSSL_LIB_CTX_get0_global_default';
  OSSL_LIB_CTX_get0_global_default_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_LIB_CTX_set0_default_procname = 'OSSL_LIB_CTX_set0_default';
  OSSL_LIB_CTX_set0_default_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_LIB_CTX_get_conf_diagnostics_procname = 'OSSL_LIB_CTX_get_conf_diagnostics';
  OSSL_LIB_CTX_get_conf_diagnostics_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_LIB_CTX_set_conf_diagnostics_procname = 'OSSL_LIB_CTX_set_conf_diagnostics';
  OSSL_LIB_CTX_set_conf_diagnostics_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_sleep_procname = 'OSSL_sleep';
  OSSL_sleep_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_LIB_CTX_get_data_procname = 'OSSL_LIB_CTX_get_data';
  OSSL_LIB_CTX_get_data_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OPENSSL_malloc_init: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_malloc_init() \
    while (0)                 \
    continue
  }
end;

function OPENSSL_malloc(num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_malloc(num) \
    CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_zalloc(num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_zalloc(num) \
    CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_malloc_array(num: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_malloc_array(num, size) \
    CRYPTO_malloc_array(num, size, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_calloc(num: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_calloc(num, size) \
    CRYPTO_calloc(num, size, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_aligned_alloc(num: Pointer; alignment: Pointer; freeptr: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_aligned_alloc(num, alignment, freeptr) \
    CRYPTO_aligned_alloc(num, alignment, freeptr,      \
        OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_aligned_alloc_array(num: Pointer; size: Pointer; alignment: Pointer; freeptr: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_aligned_alloc_array(num, size, alignment, freeptr) \
    CRYPTO_aligned_alloc_array(num, size, alignment, freeptr,      \
        OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_realloc(addr: Pointer; num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_realloc(addr, num) \
    CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_clear_realloc(addr: Pointer; old_num: Pointer; num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_clear_realloc(addr, old_num, num) \
    CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_realloc_array(addr: Pointer; num: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_realloc_array(addr, num, size) \
    CRYPTO_realloc_array(addr, num, size, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_clear_realloc_array(addr: Pointer; old_num: Pointer; num: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_clear_realloc_array(addr, old_num, num, size) \
    CRYPTO_clear_realloc_array(addr, old_num, num, size,      \
        OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_clear_free(addr: Pointer; num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_clear_free(addr, num) \
    CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_free(addr: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_free(addr) \
    CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_memdup(str: Pointer; s: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_memdup(str, s) \
    CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_strdup(str: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_strdup(str) \
    CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_strndup(str: Pointer; n: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_strndup(str, n) \
    CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_secure_malloc(num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_secure_malloc(num) \
    CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_secure_zalloc(num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_secure_zalloc(num) \
    CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_secure_malloc_array(num: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_secure_malloc_array(num, size) \
    CRYPTO_secure_malloc_array(num, size, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_secure_calloc(num: Pointer; size: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_secure_calloc(num, size) \
    CRYPTO_secure_calloc(num, size, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_secure_free(addr: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_secure_free(addr) \
    CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_secure_clear_free(addr: Pointer; num: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_secure_clear_free(addr, num) \
    CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)
  }
end;

function OPENSSL_secure_actual_size(ptr: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_secure_actual_size(ptr) \
    CRYPTO_secure_actual_size(ptr)
  }
end;

function SSLeay: TIdC_ULONG; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    SSLeay OpenSSL_version_num
  }
end;

function SSLeay_version(_type: TIdC_INT): PIdAnsiChar; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    SSLeay_version OpenSSL_version
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_lock_new_procname);
end;

function ERR_CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_read_lock_procname);
end;

function ERR_CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_write_lock_procname);
end;

function ERR_CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_unlock_procname);
end;

function ERR_CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_lock_free_procname);
end;

function ERR_CRYPTO_atomic_add(val: PIdC_INT; amount: TIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_add_procname);
end;

function ERR_CRYPTO_atomic_add64(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_add64_procname);
end;

function ERR_CRYPTO_atomic_and(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_and_procname);
end;

function ERR_CRYPTO_atomic_or(val: PIdC_UINT64; op: TIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_or_procname);
end;

function ERR_CRYPTO_atomic_load(val: PIdC_UINT64; ret: PIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_load_procname);
end;

function ERR_CRYPTO_atomic_load_int(val: PIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_load_int_procname);
end;

function ERR_CRYPTO_atomic_store(dst: PIdC_UINT64; val: TIdC_UINT64; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_store_procname);
end;

function ERR_OPENSSL_strlcpy(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strlcpy_procname);
end;

function ERR_OPENSSL_strlcat(dst: PIdAnsiChar; src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strlcat_procname);
end;

function ERR_OPENSSL_strnlen(str: PIdAnsiChar; maxlen: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strnlen_procname);
end;

function ERR_OPENSSL_strtoul(str: PIdAnsiChar; endptr: PPIdAnsiChar; base: TIdC_INT; num: PIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strtoul_procname);
end;

function ERR_OPENSSL_buf2hexstr_ex(str: PIdAnsiChar; str_n: TIdC_SIZET; strlength: PIdC_SIZET; buf: PIdAnsiChar; buflen: TIdC_SIZET; sep: TIdC_INT8): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_buf2hexstr_ex_procname);
end;

function ERR_OPENSSL_buf2hexstr(buf: PIdAnsiChar; buflen: TIdC_LONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_buf2hexstr_procname);
end;

function ERR_OPENSSL_hexstr2buf_ex(buf: PIdAnsiChar; buf_n: TIdC_SIZET; buflen: PIdC_SIZET; str: PIdAnsiChar; sep: TIdC_INT8): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_hexstr2buf_ex_procname);
end;

function ERR_OPENSSL_hexstr2buf(str: PIdAnsiChar; buflen: PIdC_LONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_hexstr2buf_procname);
end;

function ERR_OPENSSL_hexchar2int(c: TIdC_UINT8): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_hexchar2int_procname);
end;

function ERR_OPENSSL_strcasecmp(s1: PIdAnsiChar; s2: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strcasecmp_procname);
end;

function ERR_OPENSSL_strncasecmp(s1: PIdAnsiChar; s2: PIdAnsiChar; n: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strncasecmp_procname);
end;

function ERR_OPENSSL_version_major: TIdC_UINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_version_major_procname);
end;

function ERR_OPENSSL_version_minor: TIdC_UINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_version_minor_procname);
end;

function ERR_OPENSSL_version_patch: TIdC_UINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_version_patch_procname);
end;

function ERR_OPENSSL_version_pre_release: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_version_pre_release_procname);
end;

function ERR_OPENSSL_version_build_metadata: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_version_build_metadata_procname);
end;

function ERR_OpenSSL_version_num: TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OpenSSL_version_num_procname);
end;

function ERR_OpenSSL_version(_type: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OpenSSL_version_procname);
end;

function ERR_OPENSSL_info(_type: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_info_procname);
end;

function ERR_OPENSSL_issetugid: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_issetugid_procname);
end;

function ERR_CRYPTO_get_ex_new_index(class_index: TIdC_INT; argl: TIdC_LONG; argp: Pointer; new_func: TCRYPTO_EX_free; dup_func: TCRYPTO_EX_dup; free_func: TCRYPTO_EX_free): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_get_ex_new_index_procname);
end;

function ERR_CRYPTO_free_ex_index(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_free_ex_index_procname);
end;

function ERR_CRYPTO_new_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_new_ex_data_procname);
end;

function ERR_CRYPTO_dup_ex_data(class_index: TIdC_INT; _to: PCRYPTO_EX_DATA; from: PCRYPTO_EX_DATA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_dup_ex_data_procname);
end;

function ERR_CRYPTO_free_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_free_ex_data_procname);
end;

function ERR_CRYPTO_alloc_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA; idx: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_alloc_ex_data_procname);
end;

function ERR_CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT; val: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_set_ex_data_procname);
end;

function ERR_CRYPTO_get_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_get_ex_data_procname);
end;

function ERR_CRYPTO_set_mem_functions(malloc_fn: TCRYPTO_malloc_fn; realloc_fn: TCRYPTO_realloc_fn; free_fn: TCRYPTO_free_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_set_mem_functions_procname);
end;

function ERR_CRYPTO_get_mem_functions(malloc_fn: PCRYPTO_malloc_fn; realloc_fn: PCRYPTO_realloc_fn; free_fn: PCRYPTO_free_fn): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_get_mem_functions_procname);
end;

function ERR_CRYPTO_malloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_malloc_procname);
end;

function ERR_CRYPTO_zalloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_zalloc_procname);
end;

function ERR_CRYPTO_malloc_array(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_malloc_array_procname);
end;

function ERR_CRYPTO_calloc(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_calloc_procname);
end;

function ERR_CRYPTO_aligned_alloc(num: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_aligned_alloc_procname);
end;

function ERR_CRYPTO_aligned_alloc_array(num: TIdC_SIZET; size: TIdC_SIZET; align: TIdC_SIZET; freeptr: PPointer; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_aligned_alloc_array_procname);
end;

function ERR_CRYPTO_memdup(str: Pointer; siz: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_memdup_procname);
end;

function ERR_CRYPTO_strdup(str: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_strdup_procname);
end;

function ERR_CRYPTO_strndup(str: PIdAnsiChar; s: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_strndup_procname);
end;

function ERR_CRYPTO_free(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_free_procname);
end;

function ERR_CRYPTO_clear_free(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_clear_free_procname);
end;

function ERR_CRYPTO_realloc(addr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_realloc_procname);
end;

function ERR_CRYPTO_clear_realloc(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_clear_realloc_procname);
end;

function ERR_CRYPTO_realloc_array(addr: Pointer; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_realloc_array_procname);
end;

function ERR_CRYPTO_clear_realloc_array(addr: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_clear_realloc_array_procname);
end;

function ERR_CRYPTO_secure_malloc_init(sz: TIdC_SIZET; minsize: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_init_procname);
end;

function ERR_CRYPTO_secure_malloc_done: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_done_procname);
end;

function ERR_CRYPTO_secure_malloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_procname);
end;

function ERR_CRYPTO_secure_zalloc(num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_zalloc_procname);
end;

function ERR_CRYPTO_secure_malloc_array(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_array_procname);
end;

function ERR_CRYPTO_secure_calloc(num: TIdC_SIZET; size: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_calloc_procname);
end;

function ERR_CRYPTO_secure_free(ptr: Pointer; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_free_procname);
end;

function ERR_CRYPTO_secure_clear_free(ptr: Pointer; num: TIdC_SIZET; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_clear_free_procname);
end;

function ERR_CRYPTO_secure_allocated(ptr: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_allocated_procname);
end;

function ERR_CRYPTO_secure_malloc_initialized: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_initialized_procname);
end;

function ERR_CRYPTO_secure_actual_size(ptr: Pointer): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_actual_size_procname);
end;

function ERR_CRYPTO_secure_used: TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_used_procname);
end;

function ERR_OPENSSL_cleanse(ptr: Pointer; len: TIdC_SIZET): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_cleanse_procname);
end;

function ERR_OPENSSL_die(assertion: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_die_procname);
end;

function ERR_OPENSSL_isservice: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_isservice_procname);
end;

function ERR_OPENSSL_init: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_init_procname);
end;

function ERR_OPENSSL_fork_prepare: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_fork_prepare_procname);
end;

function ERR_OPENSSL_fork_parent: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_fork_parent_procname);
end;

function ERR_OPENSSL_fork_child: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_fork_child_procname);
end;

function ERR_OPENSSL_gmtime(timer: PIdC_TIMET; result: Ptm): Ptm; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_gmtime_procname);
end;

function ERR_OPENSSL_gmtime_adj(tm: Ptm; offset_day: TIdC_INT; offset_sec: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_gmtime_adj_procname);
end;

function ERR_OPENSSL_gmtime_diff(pday: PIdC_INT; psec: PIdC_INT; from: Ptm; _to: Ptm): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_gmtime_diff_procname);
end;

function ERR_CRYPTO_memcmp(in_a: Pointer; in_b: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_memcmp_procname);
end;

function ERR_OPENSSL_cleanup: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_cleanup_procname);
end;

function ERR_OPENSSL_init_crypto(opts: TIdC_UINT64; settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_init_crypto_procname);
end;

function ERR_OPENSSL_atexit(handler: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_atexit_procname);
end;

function ERR_OPENSSL_thread_stop: void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_thread_stop_procname);
end;

function ERR_OPENSSL_thread_stop_ex(ctx: POSSL_LIB_CTX): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_thread_stop_ex_procname);
end;

function ERR_OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_INIT_new_procname);
end;

function ERR_OPENSSL_INIT_set_config_filename(settings: POPENSSL_INIT_SETTINGS; config_filename: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_INIT_set_config_filename_procname);
end;

function ERR_OPENSSL_INIT_set_config_file_flags(settings: POPENSSL_INIT_SETTINGS; flags: TIdC_ULONG): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_INIT_set_config_file_flags_procname);
end;

function ERR_OPENSSL_INIT_set_config_appname(settings: POPENSSL_INIT_SETTINGS; config_appname: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_INIT_set_config_appname_procname);
end;

function ERR_OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_INIT_free_procname);
end;

function ERR_CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: TOPENSSL_atexit_handler_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_run_once_procname);
end;

function ERR_CRYPTO_THREAD_init_local(key: PCRYPTO_THREAD_LOCAL; cleanup: Tsk_void_freefunc): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_init_local_procname);
end;

function ERR_CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_get_local_procname);
end;

function ERR_CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_set_local_procname);
end;

function ERR_CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_cleanup_local_procname);
end;

function ERR_CRYPTO_THREAD_get_current_id: TCRYPTO_THREAD_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_get_current_id_procname);
end;

function ERR_CRYPTO_THREAD_compare_id(a: TCRYPTO_THREAD_ID; b: TCRYPTO_THREAD_ID): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_compare_id_procname);
end;

function ERR_OSSL_LIB_CTX_new: POSSL_LIB_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_new_procname);
end;

function ERR_OSSL_LIB_CTX_new_from_dispatch(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_new_from_dispatch_procname);
end;

function ERR_OSSL_LIB_CTX_new_child(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH): POSSL_LIB_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_new_child_procname);
end;

function ERR_OSSL_LIB_CTX_load_config(ctx: POSSL_LIB_CTX; config_file: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_load_config_procname);
end;

function ERR_OSSL_LIB_CTX_free(arg1: POSSL_LIB_CTX): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_free_procname);
end;

function ERR_OSSL_LIB_CTX_get0_global_default: POSSL_LIB_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_get0_global_default_procname);
end;

function ERR_OSSL_LIB_CTX_set0_default(libctx: POSSL_LIB_CTX): POSSL_LIB_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_set0_default_procname);
end;

function ERR_OSSL_LIB_CTX_get_conf_diagnostics(ctx: POSSL_LIB_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_get_conf_diagnostics_procname);
end;

function ERR_OSSL_LIB_CTX_set_conf_diagnostics(ctx: POSSL_LIB_CTX; value: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_set_conf_diagnostics_procname);
end;

function ERR_OSSL_sleep(millis: TIdC_UINT64): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_sleep_procname);
end;

function ERR_OSSL_LIB_CTX_get_data(ctx: POSSL_LIB_CTX; index: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_get_data_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  CRYPTO_THREAD_lock_new := LoadLibFunction(ADllHandle, CRYPTO_THREAD_lock_new_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_lock_new);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_lock_new_allownil)}
    CRYPTO_THREAD_lock_new := ERR_CRYPTO_THREAD_lock_new;
    {$ifend}
    {$if declared(CRYPTO_THREAD_lock_new_introduced)}
    if LibVersion < CRYPTO_THREAD_lock_new_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_lock_new)}
      CRYPTO_THREAD_lock_new := FC_CRYPTO_THREAD_lock_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_lock_new_removed)}
    if CRYPTO_THREAD_lock_new_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_lock_new)}
      CRYPTO_THREAD_lock_new := _CRYPTO_THREAD_lock_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_lock_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_lock_new');
    {$ifend}
  end;
  
  CRYPTO_THREAD_read_lock := LoadLibFunction(ADllHandle, CRYPTO_THREAD_read_lock_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_read_lock);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_read_lock_allownil)}
    CRYPTO_THREAD_read_lock := ERR_CRYPTO_THREAD_read_lock;
    {$ifend}
    {$if declared(CRYPTO_THREAD_read_lock_introduced)}
    if LibVersion < CRYPTO_THREAD_read_lock_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_read_lock)}
      CRYPTO_THREAD_read_lock := FC_CRYPTO_THREAD_read_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_read_lock_removed)}
    if CRYPTO_THREAD_read_lock_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_read_lock)}
      CRYPTO_THREAD_read_lock := _CRYPTO_THREAD_read_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_read_lock_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_read_lock');
    {$ifend}
  end;
  
  CRYPTO_THREAD_write_lock := LoadLibFunction(ADllHandle, CRYPTO_THREAD_write_lock_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_write_lock);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_write_lock_allownil)}
    CRYPTO_THREAD_write_lock := ERR_CRYPTO_THREAD_write_lock;
    {$ifend}
    {$if declared(CRYPTO_THREAD_write_lock_introduced)}
    if LibVersion < CRYPTO_THREAD_write_lock_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_write_lock)}
      CRYPTO_THREAD_write_lock := FC_CRYPTO_THREAD_write_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_write_lock_removed)}
    if CRYPTO_THREAD_write_lock_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_write_lock)}
      CRYPTO_THREAD_write_lock := _CRYPTO_THREAD_write_lock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_write_lock_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_write_lock');
    {$ifend}
  end;
  
  CRYPTO_THREAD_unlock := LoadLibFunction(ADllHandle, CRYPTO_THREAD_unlock_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_unlock);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_unlock_allownil)}
    CRYPTO_THREAD_unlock := ERR_CRYPTO_THREAD_unlock;
    {$ifend}
    {$if declared(CRYPTO_THREAD_unlock_introduced)}
    if LibVersion < CRYPTO_THREAD_unlock_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_unlock)}
      CRYPTO_THREAD_unlock := FC_CRYPTO_THREAD_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_unlock_removed)}
    if CRYPTO_THREAD_unlock_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_unlock)}
      CRYPTO_THREAD_unlock := _CRYPTO_THREAD_unlock;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_unlock_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_unlock');
    {$ifend}
  end;
  
  CRYPTO_THREAD_lock_free := LoadLibFunction(ADllHandle, CRYPTO_THREAD_lock_free_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_lock_free);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_lock_free_allownil)}
    CRYPTO_THREAD_lock_free := ERR_CRYPTO_THREAD_lock_free;
    {$ifend}
    {$if declared(CRYPTO_THREAD_lock_free_introduced)}
    if LibVersion < CRYPTO_THREAD_lock_free_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_lock_free)}
      CRYPTO_THREAD_lock_free := FC_CRYPTO_THREAD_lock_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_lock_free_removed)}
    if CRYPTO_THREAD_lock_free_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_lock_free)}
      CRYPTO_THREAD_lock_free := _CRYPTO_THREAD_lock_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_lock_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_lock_free');
    {$ifend}
  end;
  
  CRYPTO_atomic_add := LoadLibFunction(ADllHandle, CRYPTO_atomic_add_procname);
  FuncLoadError := not assigned(CRYPTO_atomic_add);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_atomic_add_allownil)}
    CRYPTO_atomic_add := ERR_CRYPTO_atomic_add;
    {$ifend}
    {$if declared(CRYPTO_atomic_add_introduced)}
    if LibVersion < CRYPTO_atomic_add_introduced then
    begin
      {$if declared(FC_CRYPTO_atomic_add)}
      CRYPTO_atomic_add := FC_CRYPTO_atomic_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_atomic_add_removed)}
    if CRYPTO_atomic_add_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_atomic_add)}
      CRYPTO_atomic_add := _CRYPTO_atomic_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_atomic_add_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_atomic_add');
    {$ifend}
  end;
  
  CRYPTO_atomic_add64 := LoadLibFunction(ADllHandle, CRYPTO_atomic_add64_procname);
  FuncLoadError := not assigned(CRYPTO_atomic_add64);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_atomic_add64_allownil)}
    CRYPTO_atomic_add64 := ERR_CRYPTO_atomic_add64;
    {$ifend}
    {$if declared(CRYPTO_atomic_add64_introduced)}
    if LibVersion < CRYPTO_atomic_add64_introduced then
    begin
      {$if declared(FC_CRYPTO_atomic_add64)}
      CRYPTO_atomic_add64 := FC_CRYPTO_atomic_add64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_atomic_add64_removed)}
    if CRYPTO_atomic_add64_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_atomic_add64)}
      CRYPTO_atomic_add64 := _CRYPTO_atomic_add64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_atomic_add64_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_atomic_add64');
    {$ifend}
  end;
  
  CRYPTO_atomic_and := LoadLibFunction(ADllHandle, CRYPTO_atomic_and_procname);
  FuncLoadError := not assigned(CRYPTO_atomic_and);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_atomic_and_allownil)}
    CRYPTO_atomic_and := ERR_CRYPTO_atomic_and;
    {$ifend}
    {$if declared(CRYPTO_atomic_and_introduced)}
    if LibVersion < CRYPTO_atomic_and_introduced then
    begin
      {$if declared(FC_CRYPTO_atomic_and)}
      CRYPTO_atomic_and := FC_CRYPTO_atomic_and;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_atomic_and_removed)}
    if CRYPTO_atomic_and_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_atomic_and)}
      CRYPTO_atomic_and := _CRYPTO_atomic_and;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_atomic_and_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_atomic_and');
    {$ifend}
  end;
  
  CRYPTO_atomic_or := LoadLibFunction(ADllHandle, CRYPTO_atomic_or_procname);
  FuncLoadError := not assigned(CRYPTO_atomic_or);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_atomic_or_allownil)}
    CRYPTO_atomic_or := ERR_CRYPTO_atomic_or;
    {$ifend}
    {$if declared(CRYPTO_atomic_or_introduced)}
    if LibVersion < CRYPTO_atomic_or_introduced then
    begin
      {$if declared(FC_CRYPTO_atomic_or)}
      CRYPTO_atomic_or := FC_CRYPTO_atomic_or;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_atomic_or_removed)}
    if CRYPTO_atomic_or_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_atomic_or)}
      CRYPTO_atomic_or := _CRYPTO_atomic_or;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_atomic_or_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_atomic_or');
    {$ifend}
  end;
  
  CRYPTO_atomic_load := LoadLibFunction(ADllHandle, CRYPTO_atomic_load_procname);
  FuncLoadError := not assigned(CRYPTO_atomic_load);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_atomic_load_allownil)}
    CRYPTO_atomic_load := ERR_CRYPTO_atomic_load;
    {$ifend}
    {$if declared(CRYPTO_atomic_load_introduced)}
    if LibVersion < CRYPTO_atomic_load_introduced then
    begin
      {$if declared(FC_CRYPTO_atomic_load)}
      CRYPTO_atomic_load := FC_CRYPTO_atomic_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_atomic_load_removed)}
    if CRYPTO_atomic_load_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_atomic_load)}
      CRYPTO_atomic_load := _CRYPTO_atomic_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_atomic_load_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_atomic_load');
    {$ifend}
  end;
  
  CRYPTO_atomic_load_int := LoadLibFunction(ADllHandle, CRYPTO_atomic_load_int_procname);
  FuncLoadError := not assigned(CRYPTO_atomic_load_int);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_atomic_load_int_allownil)}
    CRYPTO_atomic_load_int := ERR_CRYPTO_atomic_load_int;
    {$ifend}
    {$if declared(CRYPTO_atomic_load_int_introduced)}
    if LibVersion < CRYPTO_atomic_load_int_introduced then
    begin
      {$if declared(FC_CRYPTO_atomic_load_int)}
      CRYPTO_atomic_load_int := FC_CRYPTO_atomic_load_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_atomic_load_int_removed)}
    if CRYPTO_atomic_load_int_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_atomic_load_int)}
      CRYPTO_atomic_load_int := _CRYPTO_atomic_load_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_atomic_load_int_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_atomic_load_int');
    {$ifend}
  end;
  
  CRYPTO_atomic_store := LoadLibFunction(ADllHandle, CRYPTO_atomic_store_procname);
  FuncLoadError := not assigned(CRYPTO_atomic_store);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_atomic_store_allownil)}
    CRYPTO_atomic_store := ERR_CRYPTO_atomic_store;
    {$ifend}
    {$if declared(CRYPTO_atomic_store_introduced)}
    if LibVersion < CRYPTO_atomic_store_introduced then
    begin
      {$if declared(FC_CRYPTO_atomic_store)}
      CRYPTO_atomic_store := FC_CRYPTO_atomic_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_atomic_store_removed)}
    if CRYPTO_atomic_store_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_atomic_store)}
      CRYPTO_atomic_store := _CRYPTO_atomic_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_atomic_store_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_atomic_store');
    {$ifend}
  end;
  
  OPENSSL_strlcpy := LoadLibFunction(ADllHandle, OPENSSL_strlcpy_procname);
  FuncLoadError := not assigned(OPENSSL_strlcpy);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strlcpy_allownil)}
    OPENSSL_strlcpy := ERR_OPENSSL_strlcpy;
    {$ifend}
    {$if declared(OPENSSL_strlcpy_introduced)}
    if LibVersion < OPENSSL_strlcpy_introduced then
    begin
      {$if declared(FC_OPENSSL_strlcpy)}
      OPENSSL_strlcpy := FC_OPENSSL_strlcpy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strlcpy_removed)}
    if OPENSSL_strlcpy_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strlcpy)}
      OPENSSL_strlcpy := _OPENSSL_strlcpy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strlcpy_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strlcpy');
    {$ifend}
  end;
  
  OPENSSL_strlcat := LoadLibFunction(ADllHandle, OPENSSL_strlcat_procname);
  FuncLoadError := not assigned(OPENSSL_strlcat);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strlcat_allownil)}
    OPENSSL_strlcat := ERR_OPENSSL_strlcat;
    {$ifend}
    {$if declared(OPENSSL_strlcat_introduced)}
    if LibVersion < OPENSSL_strlcat_introduced then
    begin
      {$if declared(FC_OPENSSL_strlcat)}
      OPENSSL_strlcat := FC_OPENSSL_strlcat;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strlcat_removed)}
    if OPENSSL_strlcat_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strlcat)}
      OPENSSL_strlcat := _OPENSSL_strlcat;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strlcat_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strlcat');
    {$ifend}
  end;
  
  OPENSSL_strnlen := LoadLibFunction(ADllHandle, OPENSSL_strnlen_procname);
  FuncLoadError := not assigned(OPENSSL_strnlen);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strnlen_allownil)}
    OPENSSL_strnlen := ERR_OPENSSL_strnlen;
    {$ifend}
    {$if declared(OPENSSL_strnlen_introduced)}
    if LibVersion < OPENSSL_strnlen_introduced then
    begin
      {$if declared(FC_OPENSSL_strnlen)}
      OPENSSL_strnlen := FC_OPENSSL_strnlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strnlen_removed)}
    if OPENSSL_strnlen_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strnlen)}
      OPENSSL_strnlen := _OPENSSL_strnlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strnlen_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strnlen');
    {$ifend}
  end;
  
  OPENSSL_strtoul := LoadLibFunction(ADllHandle, OPENSSL_strtoul_procname);
  FuncLoadError := not assigned(OPENSSL_strtoul);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strtoul_allownil)}
    OPENSSL_strtoul := ERR_OPENSSL_strtoul;
    {$ifend}
    {$if declared(OPENSSL_strtoul_introduced)}
    if LibVersion < OPENSSL_strtoul_introduced then
    begin
      {$if declared(FC_OPENSSL_strtoul)}
      OPENSSL_strtoul := FC_OPENSSL_strtoul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strtoul_removed)}
    if OPENSSL_strtoul_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strtoul)}
      OPENSSL_strtoul := _OPENSSL_strtoul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strtoul_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strtoul');
    {$ifend}
  end;
  
  OPENSSL_buf2hexstr_ex := LoadLibFunction(ADllHandle, OPENSSL_buf2hexstr_ex_procname);
  FuncLoadError := not assigned(OPENSSL_buf2hexstr_ex);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_buf2hexstr_ex_allownil)}
    OPENSSL_buf2hexstr_ex := ERR_OPENSSL_buf2hexstr_ex;
    {$ifend}
    {$if declared(OPENSSL_buf2hexstr_ex_introduced)}
    if LibVersion < OPENSSL_buf2hexstr_ex_introduced then
    begin
      {$if declared(FC_OPENSSL_buf2hexstr_ex)}
      OPENSSL_buf2hexstr_ex := FC_OPENSSL_buf2hexstr_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_buf2hexstr_ex_removed)}
    if OPENSSL_buf2hexstr_ex_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_buf2hexstr_ex)}
      OPENSSL_buf2hexstr_ex := _OPENSSL_buf2hexstr_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_buf2hexstr_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_buf2hexstr_ex');
    {$ifend}
  end;
  
  OPENSSL_buf2hexstr := LoadLibFunction(ADllHandle, OPENSSL_buf2hexstr_procname);
  FuncLoadError := not assigned(OPENSSL_buf2hexstr);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_buf2hexstr_allownil)}
    OPENSSL_buf2hexstr := ERR_OPENSSL_buf2hexstr;
    {$ifend}
    {$if declared(OPENSSL_buf2hexstr_introduced)}
    if LibVersion < OPENSSL_buf2hexstr_introduced then
    begin
      {$if declared(FC_OPENSSL_buf2hexstr)}
      OPENSSL_buf2hexstr := FC_OPENSSL_buf2hexstr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_buf2hexstr_removed)}
    if OPENSSL_buf2hexstr_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_buf2hexstr)}
      OPENSSL_buf2hexstr := _OPENSSL_buf2hexstr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_buf2hexstr_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_buf2hexstr');
    {$ifend}
  end;
  
  OPENSSL_hexstr2buf_ex := LoadLibFunction(ADllHandle, OPENSSL_hexstr2buf_ex_procname);
  FuncLoadError := not assigned(OPENSSL_hexstr2buf_ex);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_hexstr2buf_ex_allownil)}
    OPENSSL_hexstr2buf_ex := ERR_OPENSSL_hexstr2buf_ex;
    {$ifend}
    {$if declared(OPENSSL_hexstr2buf_ex_introduced)}
    if LibVersion < OPENSSL_hexstr2buf_ex_introduced then
    begin
      {$if declared(FC_OPENSSL_hexstr2buf_ex)}
      OPENSSL_hexstr2buf_ex := FC_OPENSSL_hexstr2buf_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_hexstr2buf_ex_removed)}
    if OPENSSL_hexstr2buf_ex_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_hexstr2buf_ex)}
      OPENSSL_hexstr2buf_ex := _OPENSSL_hexstr2buf_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_hexstr2buf_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_hexstr2buf_ex');
    {$ifend}
  end;
  
  OPENSSL_hexstr2buf := LoadLibFunction(ADllHandle, OPENSSL_hexstr2buf_procname);
  FuncLoadError := not assigned(OPENSSL_hexstr2buf);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_hexstr2buf_allownil)}
    OPENSSL_hexstr2buf := ERR_OPENSSL_hexstr2buf;
    {$ifend}
    {$if declared(OPENSSL_hexstr2buf_introduced)}
    if LibVersion < OPENSSL_hexstr2buf_introduced then
    begin
      {$if declared(FC_OPENSSL_hexstr2buf)}
      OPENSSL_hexstr2buf := FC_OPENSSL_hexstr2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_hexstr2buf_removed)}
    if OPENSSL_hexstr2buf_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_hexstr2buf)}
      OPENSSL_hexstr2buf := _OPENSSL_hexstr2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_hexstr2buf_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_hexstr2buf');
    {$ifend}
  end;
  
  OPENSSL_hexchar2int := LoadLibFunction(ADllHandle, OPENSSL_hexchar2int_procname);
  FuncLoadError := not assigned(OPENSSL_hexchar2int);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_hexchar2int_allownil)}
    OPENSSL_hexchar2int := ERR_OPENSSL_hexchar2int;
    {$ifend}
    {$if declared(OPENSSL_hexchar2int_introduced)}
    if LibVersion < OPENSSL_hexchar2int_introduced then
    begin
      {$if declared(FC_OPENSSL_hexchar2int)}
      OPENSSL_hexchar2int := FC_OPENSSL_hexchar2int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_hexchar2int_removed)}
    if OPENSSL_hexchar2int_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_hexchar2int)}
      OPENSSL_hexchar2int := _OPENSSL_hexchar2int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_hexchar2int_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_hexchar2int');
    {$ifend}
  end;
  
  OPENSSL_strcasecmp := LoadLibFunction(ADllHandle, OPENSSL_strcasecmp_procname);
  FuncLoadError := not assigned(OPENSSL_strcasecmp);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strcasecmp_allownil)}
    OPENSSL_strcasecmp := ERR_OPENSSL_strcasecmp;
    {$ifend}
    {$if declared(OPENSSL_strcasecmp_introduced)}
    if LibVersion < OPENSSL_strcasecmp_introduced then
    begin
      {$if declared(FC_OPENSSL_strcasecmp)}
      OPENSSL_strcasecmp := FC_OPENSSL_strcasecmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strcasecmp_removed)}
    if OPENSSL_strcasecmp_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strcasecmp)}
      OPENSSL_strcasecmp := _OPENSSL_strcasecmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strcasecmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strcasecmp');
    {$ifend}
  end;
  
  OPENSSL_strncasecmp := LoadLibFunction(ADllHandle, OPENSSL_strncasecmp_procname);
  FuncLoadError := not assigned(OPENSSL_strncasecmp);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strncasecmp_allownil)}
    OPENSSL_strncasecmp := ERR_OPENSSL_strncasecmp;
    {$ifend}
    {$if declared(OPENSSL_strncasecmp_introduced)}
    if LibVersion < OPENSSL_strncasecmp_introduced then
    begin
      {$if declared(FC_OPENSSL_strncasecmp)}
      OPENSSL_strncasecmp := FC_OPENSSL_strncasecmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strncasecmp_removed)}
    if OPENSSL_strncasecmp_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strncasecmp)}
      OPENSSL_strncasecmp := _OPENSSL_strncasecmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strncasecmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strncasecmp');
    {$ifend}
  end;
  
  OPENSSL_version_major := LoadLibFunction(ADllHandle, OPENSSL_version_major_procname);
  FuncLoadError := not assigned(OPENSSL_version_major);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_version_major_allownil)}
    OPENSSL_version_major := ERR_OPENSSL_version_major;
    {$ifend}
    {$if declared(OPENSSL_version_major_introduced)}
    if LibVersion < OPENSSL_version_major_introduced then
    begin
      {$if declared(FC_OPENSSL_version_major)}
      OPENSSL_version_major := FC_OPENSSL_version_major;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_version_major_removed)}
    if OPENSSL_version_major_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_version_major)}
      OPENSSL_version_major := _OPENSSL_version_major;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_version_major_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_version_major');
    {$ifend}
  end;
  
  OPENSSL_version_minor := LoadLibFunction(ADllHandle, OPENSSL_version_minor_procname);
  FuncLoadError := not assigned(OPENSSL_version_minor);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_version_minor_allownil)}
    OPENSSL_version_minor := ERR_OPENSSL_version_minor;
    {$ifend}
    {$if declared(OPENSSL_version_minor_introduced)}
    if LibVersion < OPENSSL_version_minor_introduced then
    begin
      {$if declared(FC_OPENSSL_version_minor)}
      OPENSSL_version_minor := FC_OPENSSL_version_minor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_version_minor_removed)}
    if OPENSSL_version_minor_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_version_minor)}
      OPENSSL_version_minor := _OPENSSL_version_minor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_version_minor_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_version_minor');
    {$ifend}
  end;
  
  OPENSSL_version_patch := LoadLibFunction(ADllHandle, OPENSSL_version_patch_procname);
  FuncLoadError := not assigned(OPENSSL_version_patch);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_version_patch_allownil)}
    OPENSSL_version_patch := ERR_OPENSSL_version_patch;
    {$ifend}
    {$if declared(OPENSSL_version_patch_introduced)}
    if LibVersion < OPENSSL_version_patch_introduced then
    begin
      {$if declared(FC_OPENSSL_version_patch)}
      OPENSSL_version_patch := FC_OPENSSL_version_patch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_version_patch_removed)}
    if OPENSSL_version_patch_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_version_patch)}
      OPENSSL_version_patch := _OPENSSL_version_patch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_version_patch_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_version_patch');
    {$ifend}
  end;
  
  OPENSSL_version_pre_release := LoadLibFunction(ADllHandle, OPENSSL_version_pre_release_procname);
  FuncLoadError := not assigned(OPENSSL_version_pre_release);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_version_pre_release_allownil)}
    OPENSSL_version_pre_release := ERR_OPENSSL_version_pre_release;
    {$ifend}
    {$if declared(OPENSSL_version_pre_release_introduced)}
    if LibVersion < OPENSSL_version_pre_release_introduced then
    begin
      {$if declared(FC_OPENSSL_version_pre_release)}
      OPENSSL_version_pre_release := FC_OPENSSL_version_pre_release;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_version_pre_release_removed)}
    if OPENSSL_version_pre_release_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_version_pre_release)}
      OPENSSL_version_pre_release := _OPENSSL_version_pre_release;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_version_pre_release_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_version_pre_release');
    {$ifend}
  end;
  
  OPENSSL_version_build_metadata := LoadLibFunction(ADllHandle, OPENSSL_version_build_metadata_procname);
  FuncLoadError := not assigned(OPENSSL_version_build_metadata);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_version_build_metadata_allownil)}
    OPENSSL_version_build_metadata := ERR_OPENSSL_version_build_metadata;
    {$ifend}
    {$if declared(OPENSSL_version_build_metadata_introduced)}
    if LibVersion < OPENSSL_version_build_metadata_introduced then
    begin
      {$if declared(FC_OPENSSL_version_build_metadata)}
      OPENSSL_version_build_metadata := FC_OPENSSL_version_build_metadata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_version_build_metadata_removed)}
    if OPENSSL_version_build_metadata_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_version_build_metadata)}
      OPENSSL_version_build_metadata := _OPENSSL_version_build_metadata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_version_build_metadata_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_version_build_metadata');
    {$ifend}
  end;
  
  OpenSSL_version_num := LoadLibFunction(ADllHandle, OpenSSL_version_num_procname);
  FuncLoadError := not assigned(OpenSSL_version_num);
  if FuncLoadError then
  begin
    {$if not defined(OpenSSL_version_num_allownil)}
    OpenSSL_version_num := ERR_OpenSSL_version_num;
    {$ifend}
    {$if declared(OpenSSL_version_num_introduced)}
    if LibVersion < OpenSSL_version_num_introduced then
    begin
      {$if declared(FC_OpenSSL_version_num)}
      OpenSSL_version_num := FC_OpenSSL_version_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OpenSSL_version_num_removed)}
    if OpenSSL_version_num_removed <= LibVersion then
    begin
      {$if declared(_OpenSSL_version_num)}
      OpenSSL_version_num := _OpenSSL_version_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OpenSSL_version_num_allownil)}
    if FuncLoadError then
      AFailed.Add('OpenSSL_version_num');
    {$ifend}
  end;
  
  OpenSSL_version := LoadLibFunction(ADllHandle, OpenSSL_version_procname);
  FuncLoadError := not assigned(OpenSSL_version);
  if FuncLoadError then
  begin
    {$if not defined(OpenSSL_version_allownil)}
    OpenSSL_version := ERR_OpenSSL_version;
    {$ifend}
    {$if declared(OpenSSL_version_introduced)}
    if LibVersion < OpenSSL_version_introduced then
    begin
      {$if declared(FC_OpenSSL_version)}
      OpenSSL_version := FC_OpenSSL_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OpenSSL_version_removed)}
    if OpenSSL_version_removed <= LibVersion then
    begin
      {$if declared(_OpenSSL_version)}
      OpenSSL_version := _OpenSSL_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OpenSSL_version_allownil)}
    if FuncLoadError then
      AFailed.Add('OpenSSL_version');
    {$ifend}
  end;
  
  OPENSSL_info := LoadLibFunction(ADllHandle, OPENSSL_info_procname);
  FuncLoadError := not assigned(OPENSSL_info);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_info_allownil)}
    OPENSSL_info := ERR_OPENSSL_info;
    {$ifend}
    {$if declared(OPENSSL_info_introduced)}
    if LibVersion < OPENSSL_info_introduced then
    begin
      {$if declared(FC_OPENSSL_info)}
      OPENSSL_info := FC_OPENSSL_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_info_removed)}
    if OPENSSL_info_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_info)}
      OPENSSL_info := _OPENSSL_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_info_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_info');
    {$ifend}
  end;
  
  OPENSSL_issetugid := LoadLibFunction(ADllHandle, OPENSSL_issetugid_procname);
  FuncLoadError := not assigned(OPENSSL_issetugid);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_issetugid_allownil)}
    OPENSSL_issetugid := ERR_OPENSSL_issetugid;
    {$ifend}
    {$if declared(OPENSSL_issetugid_introduced)}
    if LibVersion < OPENSSL_issetugid_introduced then
    begin
      {$if declared(FC_OPENSSL_issetugid)}
      OPENSSL_issetugid := FC_OPENSSL_issetugid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_issetugid_removed)}
    if OPENSSL_issetugid_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_issetugid)}
      OPENSSL_issetugid := _OPENSSL_issetugid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_issetugid_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_issetugid');
    {$ifend}
  end;
  
  CRYPTO_get_ex_new_index := LoadLibFunction(ADllHandle, CRYPTO_get_ex_new_index_procname);
  FuncLoadError := not assigned(CRYPTO_get_ex_new_index);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_get_ex_new_index_allownil)}
    CRYPTO_get_ex_new_index := ERR_CRYPTO_get_ex_new_index;
    {$ifend}
    {$if declared(CRYPTO_get_ex_new_index_introduced)}
    if LibVersion < CRYPTO_get_ex_new_index_introduced then
    begin
      {$if declared(FC_CRYPTO_get_ex_new_index)}
      CRYPTO_get_ex_new_index := FC_CRYPTO_get_ex_new_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_get_ex_new_index_removed)}
    if CRYPTO_get_ex_new_index_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_get_ex_new_index)}
      CRYPTO_get_ex_new_index := _CRYPTO_get_ex_new_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_get_ex_new_index_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_get_ex_new_index');
    {$ifend}
  end;
  
  CRYPTO_free_ex_index := LoadLibFunction(ADllHandle, CRYPTO_free_ex_index_procname);
  FuncLoadError := not assigned(CRYPTO_free_ex_index);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_free_ex_index_allownil)}
    CRYPTO_free_ex_index := ERR_CRYPTO_free_ex_index;
    {$ifend}
    {$if declared(CRYPTO_free_ex_index_introduced)}
    if LibVersion < CRYPTO_free_ex_index_introduced then
    begin
      {$if declared(FC_CRYPTO_free_ex_index)}
      CRYPTO_free_ex_index := FC_CRYPTO_free_ex_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_free_ex_index_removed)}
    if CRYPTO_free_ex_index_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_free_ex_index)}
      CRYPTO_free_ex_index := _CRYPTO_free_ex_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_free_ex_index_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_free_ex_index');
    {$ifend}
  end;
  
  CRYPTO_new_ex_data := LoadLibFunction(ADllHandle, CRYPTO_new_ex_data_procname);
  FuncLoadError := not assigned(CRYPTO_new_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_new_ex_data_allownil)}
    CRYPTO_new_ex_data := ERR_CRYPTO_new_ex_data;
    {$ifend}
    {$if declared(CRYPTO_new_ex_data_introduced)}
    if LibVersion < CRYPTO_new_ex_data_introduced then
    begin
      {$if declared(FC_CRYPTO_new_ex_data)}
      CRYPTO_new_ex_data := FC_CRYPTO_new_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_new_ex_data_removed)}
    if CRYPTO_new_ex_data_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_new_ex_data)}
      CRYPTO_new_ex_data := _CRYPTO_new_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_new_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_new_ex_data');
    {$ifend}
  end;
  
  CRYPTO_dup_ex_data := LoadLibFunction(ADllHandle, CRYPTO_dup_ex_data_procname);
  FuncLoadError := not assigned(CRYPTO_dup_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_dup_ex_data_allownil)}
    CRYPTO_dup_ex_data := ERR_CRYPTO_dup_ex_data;
    {$ifend}
    {$if declared(CRYPTO_dup_ex_data_introduced)}
    if LibVersion < CRYPTO_dup_ex_data_introduced then
    begin
      {$if declared(FC_CRYPTO_dup_ex_data)}
      CRYPTO_dup_ex_data := FC_CRYPTO_dup_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_dup_ex_data_removed)}
    if CRYPTO_dup_ex_data_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_dup_ex_data)}
      CRYPTO_dup_ex_data := _CRYPTO_dup_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_dup_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_dup_ex_data');
    {$ifend}
  end;
  
  CRYPTO_free_ex_data := LoadLibFunction(ADllHandle, CRYPTO_free_ex_data_procname);
  FuncLoadError := not assigned(CRYPTO_free_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_free_ex_data_allownil)}
    CRYPTO_free_ex_data := ERR_CRYPTO_free_ex_data;
    {$ifend}
    {$if declared(CRYPTO_free_ex_data_introduced)}
    if LibVersion < CRYPTO_free_ex_data_introduced then
    begin
      {$if declared(FC_CRYPTO_free_ex_data)}
      CRYPTO_free_ex_data := FC_CRYPTO_free_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_free_ex_data_removed)}
    if CRYPTO_free_ex_data_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_free_ex_data)}
      CRYPTO_free_ex_data := _CRYPTO_free_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_free_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_free_ex_data');
    {$ifend}
  end;
  
  CRYPTO_alloc_ex_data := LoadLibFunction(ADllHandle, CRYPTO_alloc_ex_data_procname);
  FuncLoadError := not assigned(CRYPTO_alloc_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_alloc_ex_data_allownil)}
    CRYPTO_alloc_ex_data := ERR_CRYPTO_alloc_ex_data;
    {$ifend}
    {$if declared(CRYPTO_alloc_ex_data_introduced)}
    if LibVersion < CRYPTO_alloc_ex_data_introduced then
    begin
      {$if declared(FC_CRYPTO_alloc_ex_data)}
      CRYPTO_alloc_ex_data := FC_CRYPTO_alloc_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_alloc_ex_data_removed)}
    if CRYPTO_alloc_ex_data_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_alloc_ex_data)}
      CRYPTO_alloc_ex_data := _CRYPTO_alloc_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_alloc_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_alloc_ex_data');
    {$ifend}
  end;
  
  CRYPTO_set_ex_data := LoadLibFunction(ADllHandle, CRYPTO_set_ex_data_procname);
  FuncLoadError := not assigned(CRYPTO_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_set_ex_data_allownil)}
    CRYPTO_set_ex_data := ERR_CRYPTO_set_ex_data;
    {$ifend}
    {$if declared(CRYPTO_set_ex_data_introduced)}
    if LibVersion < CRYPTO_set_ex_data_introduced then
    begin
      {$if declared(FC_CRYPTO_set_ex_data)}
      CRYPTO_set_ex_data := FC_CRYPTO_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_set_ex_data_removed)}
    if CRYPTO_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_set_ex_data)}
      CRYPTO_set_ex_data := _CRYPTO_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_ex_data');
    {$ifend}
  end;
  
  CRYPTO_get_ex_data := LoadLibFunction(ADllHandle, CRYPTO_get_ex_data_procname);
  FuncLoadError := not assigned(CRYPTO_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_get_ex_data_allownil)}
    CRYPTO_get_ex_data := ERR_CRYPTO_get_ex_data;
    {$ifend}
    {$if declared(CRYPTO_get_ex_data_introduced)}
    if LibVersion < CRYPTO_get_ex_data_introduced then
    begin
      {$if declared(FC_CRYPTO_get_ex_data)}
      CRYPTO_get_ex_data := FC_CRYPTO_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_get_ex_data_removed)}
    if CRYPTO_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_get_ex_data)}
      CRYPTO_get_ex_data := _CRYPTO_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_get_ex_data');
    {$ifend}
  end;
  
  CRYPTO_set_mem_functions := LoadLibFunction(ADllHandle, CRYPTO_set_mem_functions_procname);
  FuncLoadError := not assigned(CRYPTO_set_mem_functions);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_set_mem_functions_allownil)}
    CRYPTO_set_mem_functions := ERR_CRYPTO_set_mem_functions;
    {$ifend}
    {$if declared(CRYPTO_set_mem_functions_introduced)}
    if LibVersion < CRYPTO_set_mem_functions_introduced then
    begin
      {$if declared(FC_CRYPTO_set_mem_functions)}
      CRYPTO_set_mem_functions := FC_CRYPTO_set_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_set_mem_functions_removed)}
    if CRYPTO_set_mem_functions_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_set_mem_functions)}
      CRYPTO_set_mem_functions := _CRYPTO_set_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_set_mem_functions_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_mem_functions');
    {$ifend}
  end;
  
  CRYPTO_get_mem_functions := LoadLibFunction(ADllHandle, CRYPTO_get_mem_functions_procname);
  FuncLoadError := not assigned(CRYPTO_get_mem_functions);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_get_mem_functions_allownil)}
    CRYPTO_get_mem_functions := ERR_CRYPTO_get_mem_functions;
    {$ifend}
    {$if declared(CRYPTO_get_mem_functions_introduced)}
    if LibVersion < CRYPTO_get_mem_functions_introduced then
    begin
      {$if declared(FC_CRYPTO_get_mem_functions)}
      CRYPTO_get_mem_functions := FC_CRYPTO_get_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_get_mem_functions_removed)}
    if CRYPTO_get_mem_functions_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_get_mem_functions)}
      CRYPTO_get_mem_functions := _CRYPTO_get_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_get_mem_functions_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_get_mem_functions');
    {$ifend}
  end;
  
  CRYPTO_malloc := LoadLibFunction(ADllHandle, CRYPTO_malloc_procname);
  FuncLoadError := not assigned(CRYPTO_malloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_malloc_allownil)}
    CRYPTO_malloc := ERR_CRYPTO_malloc;
    {$ifend}
    {$if declared(CRYPTO_malloc_introduced)}
    if LibVersion < CRYPTO_malloc_introduced then
    begin
      {$if declared(FC_CRYPTO_malloc)}
      CRYPTO_malloc := FC_CRYPTO_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_malloc_removed)}
    if CRYPTO_malloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_malloc)}
      CRYPTO_malloc := _CRYPTO_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_malloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_malloc');
    {$ifend}
  end;
  
  CRYPTO_zalloc := LoadLibFunction(ADllHandle, CRYPTO_zalloc_procname);
  FuncLoadError := not assigned(CRYPTO_zalloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_zalloc_allownil)}
    CRYPTO_zalloc := ERR_CRYPTO_zalloc;
    {$ifend}
    {$if declared(CRYPTO_zalloc_introduced)}
    if LibVersion < CRYPTO_zalloc_introduced then
    begin
      {$if declared(FC_CRYPTO_zalloc)}
      CRYPTO_zalloc := FC_CRYPTO_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_zalloc_removed)}
    if CRYPTO_zalloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_zalloc)}
      CRYPTO_zalloc := _CRYPTO_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_zalloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_zalloc');
    {$ifend}
  end;
  
  CRYPTO_malloc_array := LoadLibFunction(ADllHandle, CRYPTO_malloc_array_procname);
  FuncLoadError := not assigned(CRYPTO_malloc_array);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_malloc_array_allownil)}
    CRYPTO_malloc_array := ERR_CRYPTO_malloc_array;
    {$ifend}
    {$if declared(CRYPTO_malloc_array_introduced)}
    if LibVersion < CRYPTO_malloc_array_introduced then
    begin
      {$if declared(FC_CRYPTO_malloc_array)}
      CRYPTO_malloc_array := FC_CRYPTO_malloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_malloc_array_removed)}
    if CRYPTO_malloc_array_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_malloc_array)}
      CRYPTO_malloc_array := _CRYPTO_malloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_malloc_array_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_malloc_array');
    {$ifend}
  end;
  
  CRYPTO_calloc := LoadLibFunction(ADllHandle, CRYPTO_calloc_procname);
  FuncLoadError := not assigned(CRYPTO_calloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_calloc_allownil)}
    CRYPTO_calloc := ERR_CRYPTO_calloc;
    {$ifend}
    {$if declared(CRYPTO_calloc_introduced)}
    if LibVersion < CRYPTO_calloc_introduced then
    begin
      {$if declared(FC_CRYPTO_calloc)}
      CRYPTO_calloc := FC_CRYPTO_calloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_calloc_removed)}
    if CRYPTO_calloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_calloc)}
      CRYPTO_calloc := _CRYPTO_calloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_calloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_calloc');
    {$ifend}
  end;
  
  CRYPTO_aligned_alloc := LoadLibFunction(ADllHandle, CRYPTO_aligned_alloc_procname);
  FuncLoadError := not assigned(CRYPTO_aligned_alloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_aligned_alloc_allownil)}
    CRYPTO_aligned_alloc := ERR_CRYPTO_aligned_alloc;
    {$ifend}
    {$if declared(CRYPTO_aligned_alloc_introduced)}
    if LibVersion < CRYPTO_aligned_alloc_introduced then
    begin
      {$if declared(FC_CRYPTO_aligned_alloc)}
      CRYPTO_aligned_alloc := FC_CRYPTO_aligned_alloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_aligned_alloc_removed)}
    if CRYPTO_aligned_alloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_aligned_alloc)}
      CRYPTO_aligned_alloc := _CRYPTO_aligned_alloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_aligned_alloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_aligned_alloc');
    {$ifend}
  end;
  
  CRYPTO_aligned_alloc_array := LoadLibFunction(ADllHandle, CRYPTO_aligned_alloc_array_procname);
  FuncLoadError := not assigned(CRYPTO_aligned_alloc_array);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_aligned_alloc_array_allownil)}
    CRYPTO_aligned_alloc_array := ERR_CRYPTO_aligned_alloc_array;
    {$ifend}
    {$if declared(CRYPTO_aligned_alloc_array_introduced)}
    if LibVersion < CRYPTO_aligned_alloc_array_introduced then
    begin
      {$if declared(FC_CRYPTO_aligned_alloc_array)}
      CRYPTO_aligned_alloc_array := FC_CRYPTO_aligned_alloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_aligned_alloc_array_removed)}
    if CRYPTO_aligned_alloc_array_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_aligned_alloc_array)}
      CRYPTO_aligned_alloc_array := _CRYPTO_aligned_alloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_aligned_alloc_array_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_aligned_alloc_array');
    {$ifend}
  end;
  
  CRYPTO_memdup := LoadLibFunction(ADllHandle, CRYPTO_memdup_procname);
  FuncLoadError := not assigned(CRYPTO_memdup);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_memdup_allownil)}
    CRYPTO_memdup := ERR_CRYPTO_memdup;
    {$ifend}
    {$if declared(CRYPTO_memdup_introduced)}
    if LibVersion < CRYPTO_memdup_introduced then
    begin
      {$if declared(FC_CRYPTO_memdup)}
      CRYPTO_memdup := FC_CRYPTO_memdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_memdup_removed)}
    if CRYPTO_memdup_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_memdup)}
      CRYPTO_memdup := _CRYPTO_memdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_memdup_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_memdup');
    {$ifend}
  end;
  
  CRYPTO_strdup := LoadLibFunction(ADllHandle, CRYPTO_strdup_procname);
  FuncLoadError := not assigned(CRYPTO_strdup);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_strdup_allownil)}
    CRYPTO_strdup := ERR_CRYPTO_strdup;
    {$ifend}
    {$if declared(CRYPTO_strdup_introduced)}
    if LibVersion < CRYPTO_strdup_introduced then
    begin
      {$if declared(FC_CRYPTO_strdup)}
      CRYPTO_strdup := FC_CRYPTO_strdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_strdup_removed)}
    if CRYPTO_strdup_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_strdup)}
      CRYPTO_strdup := _CRYPTO_strdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_strdup_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_strdup');
    {$ifend}
  end;
  
  CRYPTO_strndup := LoadLibFunction(ADllHandle, CRYPTO_strndup_procname);
  FuncLoadError := not assigned(CRYPTO_strndup);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_strndup_allownil)}
    CRYPTO_strndup := ERR_CRYPTO_strndup;
    {$ifend}
    {$if declared(CRYPTO_strndup_introduced)}
    if LibVersion < CRYPTO_strndup_introduced then
    begin
      {$if declared(FC_CRYPTO_strndup)}
      CRYPTO_strndup := FC_CRYPTO_strndup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_strndup_removed)}
    if CRYPTO_strndup_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_strndup)}
      CRYPTO_strndup := _CRYPTO_strndup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_strndup_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_strndup');
    {$ifend}
  end;
  
  CRYPTO_free := LoadLibFunction(ADllHandle, CRYPTO_free_procname);
  FuncLoadError := not assigned(CRYPTO_free);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_free_allownil)}
    CRYPTO_free := ERR_CRYPTO_free;
    {$ifend}
    {$if declared(CRYPTO_free_introduced)}
    if LibVersion < CRYPTO_free_introduced then
    begin
      {$if declared(FC_CRYPTO_free)}
      CRYPTO_free := FC_CRYPTO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_free_removed)}
    if CRYPTO_free_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_free)}
      CRYPTO_free := _CRYPTO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_free');
    {$ifend}
  end;
  
  CRYPTO_clear_free := LoadLibFunction(ADllHandle, CRYPTO_clear_free_procname);
  FuncLoadError := not assigned(CRYPTO_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_clear_free_allownil)}
    CRYPTO_clear_free := ERR_CRYPTO_clear_free;
    {$ifend}
    {$if declared(CRYPTO_clear_free_introduced)}
    if LibVersion < CRYPTO_clear_free_introduced then
    begin
      {$if declared(FC_CRYPTO_clear_free)}
      CRYPTO_clear_free := FC_CRYPTO_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_clear_free_removed)}
    if CRYPTO_clear_free_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_clear_free)}
      CRYPTO_clear_free := _CRYPTO_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_clear_free');
    {$ifend}
  end;
  
  CRYPTO_realloc := LoadLibFunction(ADllHandle, CRYPTO_realloc_procname);
  FuncLoadError := not assigned(CRYPTO_realloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_realloc_allownil)}
    CRYPTO_realloc := ERR_CRYPTO_realloc;
    {$ifend}
    {$if declared(CRYPTO_realloc_introduced)}
    if LibVersion < CRYPTO_realloc_introduced then
    begin
      {$if declared(FC_CRYPTO_realloc)}
      CRYPTO_realloc := FC_CRYPTO_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_realloc_removed)}
    if CRYPTO_realloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_realloc)}
      CRYPTO_realloc := _CRYPTO_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_realloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_realloc');
    {$ifend}
  end;
  
  CRYPTO_clear_realloc := LoadLibFunction(ADllHandle, CRYPTO_clear_realloc_procname);
  FuncLoadError := not assigned(CRYPTO_clear_realloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_clear_realloc_allownil)}
    CRYPTO_clear_realloc := ERR_CRYPTO_clear_realloc;
    {$ifend}
    {$if declared(CRYPTO_clear_realloc_introduced)}
    if LibVersion < CRYPTO_clear_realloc_introduced then
    begin
      {$if declared(FC_CRYPTO_clear_realloc)}
      CRYPTO_clear_realloc := FC_CRYPTO_clear_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_clear_realloc_removed)}
    if CRYPTO_clear_realloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_clear_realloc)}
      CRYPTO_clear_realloc := _CRYPTO_clear_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_clear_realloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_clear_realloc');
    {$ifend}
  end;
  
  CRYPTO_realloc_array := LoadLibFunction(ADllHandle, CRYPTO_realloc_array_procname);
  FuncLoadError := not assigned(CRYPTO_realloc_array);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_realloc_array_allownil)}
    CRYPTO_realloc_array := ERR_CRYPTO_realloc_array;
    {$ifend}
    {$if declared(CRYPTO_realloc_array_introduced)}
    if LibVersion < CRYPTO_realloc_array_introduced then
    begin
      {$if declared(FC_CRYPTO_realloc_array)}
      CRYPTO_realloc_array := FC_CRYPTO_realloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_realloc_array_removed)}
    if CRYPTO_realloc_array_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_realloc_array)}
      CRYPTO_realloc_array := _CRYPTO_realloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_realloc_array_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_realloc_array');
    {$ifend}
  end;
  
  CRYPTO_clear_realloc_array := LoadLibFunction(ADllHandle, CRYPTO_clear_realloc_array_procname);
  FuncLoadError := not assigned(CRYPTO_clear_realloc_array);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_clear_realloc_array_allownil)}
    CRYPTO_clear_realloc_array := ERR_CRYPTO_clear_realloc_array;
    {$ifend}
    {$if declared(CRYPTO_clear_realloc_array_introduced)}
    if LibVersion < CRYPTO_clear_realloc_array_introduced then
    begin
      {$if declared(FC_CRYPTO_clear_realloc_array)}
      CRYPTO_clear_realloc_array := FC_CRYPTO_clear_realloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_clear_realloc_array_removed)}
    if CRYPTO_clear_realloc_array_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_clear_realloc_array)}
      CRYPTO_clear_realloc_array := _CRYPTO_clear_realloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_clear_realloc_array_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_clear_realloc_array');
    {$ifend}
  end;
  
  CRYPTO_secure_malloc_init := LoadLibFunction(ADllHandle, CRYPTO_secure_malloc_init_procname);
  FuncLoadError := not assigned(CRYPTO_secure_malloc_init);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_malloc_init_allownil)}
    CRYPTO_secure_malloc_init := ERR_CRYPTO_secure_malloc_init;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_init_introduced)}
    if LibVersion < CRYPTO_secure_malloc_init_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_malloc_init)}
      CRYPTO_secure_malloc_init := FC_CRYPTO_secure_malloc_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_init_removed)}
    if CRYPTO_secure_malloc_init_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_malloc_init)}
      CRYPTO_secure_malloc_init := _CRYPTO_secure_malloc_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_malloc_init_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_malloc_init');
    {$ifend}
  end;
  
  CRYPTO_secure_malloc_done := LoadLibFunction(ADllHandle, CRYPTO_secure_malloc_done_procname);
  FuncLoadError := not assigned(CRYPTO_secure_malloc_done);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_malloc_done_allownil)}
    CRYPTO_secure_malloc_done := ERR_CRYPTO_secure_malloc_done;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_done_introduced)}
    if LibVersion < CRYPTO_secure_malloc_done_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_malloc_done)}
      CRYPTO_secure_malloc_done := FC_CRYPTO_secure_malloc_done;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_done_removed)}
    if CRYPTO_secure_malloc_done_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_malloc_done)}
      CRYPTO_secure_malloc_done := _CRYPTO_secure_malloc_done;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_malloc_done_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_malloc_done');
    {$ifend}
  end;
  
  CRYPTO_secure_malloc := LoadLibFunction(ADllHandle, CRYPTO_secure_malloc_procname);
  FuncLoadError := not assigned(CRYPTO_secure_malloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_malloc_allownil)}
    CRYPTO_secure_malloc := ERR_CRYPTO_secure_malloc;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_introduced)}
    if LibVersion < CRYPTO_secure_malloc_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_malloc)}
      CRYPTO_secure_malloc := FC_CRYPTO_secure_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_removed)}
    if CRYPTO_secure_malloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_malloc)}
      CRYPTO_secure_malloc := _CRYPTO_secure_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_malloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_malloc');
    {$ifend}
  end;
  
  CRYPTO_secure_zalloc := LoadLibFunction(ADllHandle, CRYPTO_secure_zalloc_procname);
  FuncLoadError := not assigned(CRYPTO_secure_zalloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_zalloc_allownil)}
    CRYPTO_secure_zalloc := ERR_CRYPTO_secure_zalloc;
    {$ifend}
    {$if declared(CRYPTO_secure_zalloc_introduced)}
    if LibVersion < CRYPTO_secure_zalloc_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_zalloc)}
      CRYPTO_secure_zalloc := FC_CRYPTO_secure_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_zalloc_removed)}
    if CRYPTO_secure_zalloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_zalloc)}
      CRYPTO_secure_zalloc := _CRYPTO_secure_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_zalloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_zalloc');
    {$ifend}
  end;
  
  CRYPTO_secure_malloc_array := LoadLibFunction(ADllHandle, CRYPTO_secure_malloc_array_procname);
  FuncLoadError := not assigned(CRYPTO_secure_malloc_array);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_malloc_array_allownil)}
    CRYPTO_secure_malloc_array := ERR_CRYPTO_secure_malloc_array;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_array_introduced)}
    if LibVersion < CRYPTO_secure_malloc_array_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_malloc_array)}
      CRYPTO_secure_malloc_array := FC_CRYPTO_secure_malloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_array_removed)}
    if CRYPTO_secure_malloc_array_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_malloc_array)}
      CRYPTO_secure_malloc_array := _CRYPTO_secure_malloc_array;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_malloc_array_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_malloc_array');
    {$ifend}
  end;
  
  CRYPTO_secure_calloc := LoadLibFunction(ADllHandle, CRYPTO_secure_calloc_procname);
  FuncLoadError := not assigned(CRYPTO_secure_calloc);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_calloc_allownil)}
    CRYPTO_secure_calloc := ERR_CRYPTO_secure_calloc;
    {$ifend}
    {$if declared(CRYPTO_secure_calloc_introduced)}
    if LibVersion < CRYPTO_secure_calloc_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_calloc)}
      CRYPTO_secure_calloc := FC_CRYPTO_secure_calloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_calloc_removed)}
    if CRYPTO_secure_calloc_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_calloc)}
      CRYPTO_secure_calloc := _CRYPTO_secure_calloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_calloc_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_calloc');
    {$ifend}
  end;
  
  CRYPTO_secure_free := LoadLibFunction(ADllHandle, CRYPTO_secure_free_procname);
  FuncLoadError := not assigned(CRYPTO_secure_free);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_free_allownil)}
    CRYPTO_secure_free := ERR_CRYPTO_secure_free;
    {$ifend}
    {$if declared(CRYPTO_secure_free_introduced)}
    if LibVersion < CRYPTO_secure_free_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_free)}
      CRYPTO_secure_free := FC_CRYPTO_secure_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_free_removed)}
    if CRYPTO_secure_free_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_free)}
      CRYPTO_secure_free := _CRYPTO_secure_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_free');
    {$ifend}
  end;
  
  CRYPTO_secure_clear_free := LoadLibFunction(ADllHandle, CRYPTO_secure_clear_free_procname);
  FuncLoadError := not assigned(CRYPTO_secure_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_clear_free_allownil)}
    CRYPTO_secure_clear_free := ERR_CRYPTO_secure_clear_free;
    {$ifend}
    {$if declared(CRYPTO_secure_clear_free_introduced)}
    if LibVersion < CRYPTO_secure_clear_free_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_clear_free)}
      CRYPTO_secure_clear_free := FC_CRYPTO_secure_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_clear_free_removed)}
    if CRYPTO_secure_clear_free_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_clear_free)}
      CRYPTO_secure_clear_free := _CRYPTO_secure_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_clear_free');
    {$ifend}
  end;
  
  CRYPTO_secure_allocated := LoadLibFunction(ADllHandle, CRYPTO_secure_allocated_procname);
  FuncLoadError := not assigned(CRYPTO_secure_allocated);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_allocated_allownil)}
    CRYPTO_secure_allocated := ERR_CRYPTO_secure_allocated;
    {$ifend}
    {$if declared(CRYPTO_secure_allocated_introduced)}
    if LibVersion < CRYPTO_secure_allocated_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_allocated)}
      CRYPTO_secure_allocated := FC_CRYPTO_secure_allocated;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_allocated_removed)}
    if CRYPTO_secure_allocated_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_allocated)}
      CRYPTO_secure_allocated := _CRYPTO_secure_allocated;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_allocated_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_allocated');
    {$ifend}
  end;
  
  CRYPTO_secure_malloc_initialized := LoadLibFunction(ADllHandle, CRYPTO_secure_malloc_initialized_procname);
  FuncLoadError := not assigned(CRYPTO_secure_malloc_initialized);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_malloc_initialized_allownil)}
    CRYPTO_secure_malloc_initialized := ERR_CRYPTO_secure_malloc_initialized;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_initialized_introduced)}
    if LibVersion < CRYPTO_secure_malloc_initialized_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_malloc_initialized)}
      CRYPTO_secure_malloc_initialized := FC_CRYPTO_secure_malloc_initialized;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_malloc_initialized_removed)}
    if CRYPTO_secure_malloc_initialized_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_malloc_initialized)}
      CRYPTO_secure_malloc_initialized := _CRYPTO_secure_malloc_initialized;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_malloc_initialized_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_malloc_initialized');
    {$ifend}
  end;
  
  CRYPTO_secure_actual_size := LoadLibFunction(ADllHandle, CRYPTO_secure_actual_size_procname);
  FuncLoadError := not assigned(CRYPTO_secure_actual_size);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_actual_size_allownil)}
    CRYPTO_secure_actual_size := ERR_CRYPTO_secure_actual_size;
    {$ifend}
    {$if declared(CRYPTO_secure_actual_size_introduced)}
    if LibVersion < CRYPTO_secure_actual_size_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_actual_size)}
      CRYPTO_secure_actual_size := FC_CRYPTO_secure_actual_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_actual_size_removed)}
    if CRYPTO_secure_actual_size_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_actual_size)}
      CRYPTO_secure_actual_size := _CRYPTO_secure_actual_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_actual_size_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_actual_size');
    {$ifend}
  end;
  
  CRYPTO_secure_used := LoadLibFunction(ADllHandle, CRYPTO_secure_used_procname);
  FuncLoadError := not assigned(CRYPTO_secure_used);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_secure_used_allownil)}
    CRYPTO_secure_used := ERR_CRYPTO_secure_used;
    {$ifend}
    {$if declared(CRYPTO_secure_used_introduced)}
    if LibVersion < CRYPTO_secure_used_introduced then
    begin
      {$if declared(FC_CRYPTO_secure_used)}
      CRYPTO_secure_used := FC_CRYPTO_secure_used;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_secure_used_removed)}
    if CRYPTO_secure_used_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_secure_used)}
      CRYPTO_secure_used := _CRYPTO_secure_used;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_secure_used_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_secure_used');
    {$ifend}
  end;
  
  OPENSSL_cleanse := LoadLibFunction(ADllHandle, OPENSSL_cleanse_procname);
  FuncLoadError := not assigned(OPENSSL_cleanse);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_cleanse_allownil)}
    OPENSSL_cleanse := ERR_OPENSSL_cleanse;
    {$ifend}
    {$if declared(OPENSSL_cleanse_introduced)}
    if LibVersion < OPENSSL_cleanse_introduced then
    begin
      {$if declared(FC_OPENSSL_cleanse)}
      OPENSSL_cleanse := FC_OPENSSL_cleanse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_cleanse_removed)}
    if OPENSSL_cleanse_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_cleanse)}
      OPENSSL_cleanse := _OPENSSL_cleanse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_cleanse_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_cleanse');
    {$ifend}
  end;
  
  OPENSSL_die := LoadLibFunction(ADllHandle, OPENSSL_die_procname);
  FuncLoadError := not assigned(OPENSSL_die);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_die_allownil)}
    OPENSSL_die := ERR_OPENSSL_die;
    {$ifend}
    {$if declared(OPENSSL_die_introduced)}
    if LibVersion < OPENSSL_die_introduced then
    begin
      {$if declared(FC_OPENSSL_die)}
      OPENSSL_die := FC_OPENSSL_die;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_die_removed)}
    if OPENSSL_die_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_die)}
      OPENSSL_die := _OPENSSL_die;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_die_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_die');
    {$ifend}
  end;
  
  OPENSSL_isservice := LoadLibFunction(ADllHandle, OPENSSL_isservice_procname);
  FuncLoadError := not assigned(OPENSSL_isservice);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_isservice_allownil)}
    OPENSSL_isservice := ERR_OPENSSL_isservice;
    {$ifend}
    {$if declared(OPENSSL_isservice_introduced)}
    if LibVersion < OPENSSL_isservice_introduced then
    begin
      {$if declared(FC_OPENSSL_isservice)}
      OPENSSL_isservice := FC_OPENSSL_isservice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_isservice_removed)}
    if OPENSSL_isservice_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_isservice)}
      OPENSSL_isservice := _OPENSSL_isservice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_isservice_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_isservice');
    {$ifend}
  end;
  
  OPENSSL_init := LoadLibFunction(ADllHandle, OPENSSL_init_procname);
  FuncLoadError := not assigned(OPENSSL_init);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_init_allownil)}
    OPENSSL_init := ERR_OPENSSL_init;
    {$ifend}
    {$if declared(OPENSSL_init_introduced)}
    if LibVersion < OPENSSL_init_introduced then
    begin
      {$if declared(FC_OPENSSL_init)}
      OPENSSL_init := FC_OPENSSL_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_init_removed)}
    if OPENSSL_init_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_init)}
      OPENSSL_init := _OPENSSL_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_init_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_init');
    {$ifend}
  end;
  
  OPENSSL_fork_prepare := LoadLibFunction(ADllHandle, OPENSSL_fork_prepare_procname);
  FuncLoadError := not assigned(OPENSSL_fork_prepare);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_fork_prepare_allownil)}
    OPENSSL_fork_prepare := ERR_OPENSSL_fork_prepare;
    {$ifend}
    {$if declared(OPENSSL_fork_prepare_introduced)}
    if LibVersion < OPENSSL_fork_prepare_introduced then
    begin
      {$if declared(FC_OPENSSL_fork_prepare)}
      OPENSSL_fork_prepare := FC_OPENSSL_fork_prepare;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_fork_prepare_removed)}
    if OPENSSL_fork_prepare_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_fork_prepare)}
      OPENSSL_fork_prepare := _OPENSSL_fork_prepare;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_fork_prepare_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_fork_prepare');
    {$ifend}
  end;
  
  OPENSSL_fork_parent := LoadLibFunction(ADllHandle, OPENSSL_fork_parent_procname);
  FuncLoadError := not assigned(OPENSSL_fork_parent);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_fork_parent_allownil)}
    OPENSSL_fork_parent := ERR_OPENSSL_fork_parent;
    {$ifend}
    {$if declared(OPENSSL_fork_parent_introduced)}
    if LibVersion < OPENSSL_fork_parent_introduced then
    begin
      {$if declared(FC_OPENSSL_fork_parent)}
      OPENSSL_fork_parent := FC_OPENSSL_fork_parent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_fork_parent_removed)}
    if OPENSSL_fork_parent_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_fork_parent)}
      OPENSSL_fork_parent := _OPENSSL_fork_parent;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_fork_parent_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_fork_parent');
    {$ifend}
  end;
  
  OPENSSL_fork_child := LoadLibFunction(ADllHandle, OPENSSL_fork_child_procname);
  FuncLoadError := not assigned(OPENSSL_fork_child);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_fork_child_allownil)}
    OPENSSL_fork_child := ERR_OPENSSL_fork_child;
    {$ifend}
    {$if declared(OPENSSL_fork_child_introduced)}
    if LibVersion < OPENSSL_fork_child_introduced then
    begin
      {$if declared(FC_OPENSSL_fork_child)}
      OPENSSL_fork_child := FC_OPENSSL_fork_child;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_fork_child_removed)}
    if OPENSSL_fork_child_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_fork_child)}
      OPENSSL_fork_child := _OPENSSL_fork_child;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_fork_child_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_fork_child');
    {$ifend}
  end;
  
  OPENSSL_gmtime := LoadLibFunction(ADllHandle, OPENSSL_gmtime_procname);
  FuncLoadError := not assigned(OPENSSL_gmtime);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_gmtime_allownil)}
    OPENSSL_gmtime := ERR_OPENSSL_gmtime;
    {$ifend}
    {$if declared(OPENSSL_gmtime_introduced)}
    if LibVersion < OPENSSL_gmtime_introduced then
    begin
      {$if declared(FC_OPENSSL_gmtime)}
      OPENSSL_gmtime := FC_OPENSSL_gmtime;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_gmtime_removed)}
    if OPENSSL_gmtime_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_gmtime)}
      OPENSSL_gmtime := _OPENSSL_gmtime;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_gmtime_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_gmtime');
    {$ifend}
  end;
  
  OPENSSL_gmtime_adj := LoadLibFunction(ADllHandle, OPENSSL_gmtime_adj_procname);
  FuncLoadError := not assigned(OPENSSL_gmtime_adj);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_gmtime_adj_allownil)}
    OPENSSL_gmtime_adj := ERR_OPENSSL_gmtime_adj;
    {$ifend}
    {$if declared(OPENSSL_gmtime_adj_introduced)}
    if LibVersion < OPENSSL_gmtime_adj_introduced then
    begin
      {$if declared(FC_OPENSSL_gmtime_adj)}
      OPENSSL_gmtime_adj := FC_OPENSSL_gmtime_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_gmtime_adj_removed)}
    if OPENSSL_gmtime_adj_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_gmtime_adj)}
      OPENSSL_gmtime_adj := _OPENSSL_gmtime_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_gmtime_adj_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_gmtime_adj');
    {$ifend}
  end;
  
  OPENSSL_gmtime_diff := LoadLibFunction(ADllHandle, OPENSSL_gmtime_diff_procname);
  FuncLoadError := not assigned(OPENSSL_gmtime_diff);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_gmtime_diff_allownil)}
    OPENSSL_gmtime_diff := ERR_OPENSSL_gmtime_diff;
    {$ifend}
    {$if declared(OPENSSL_gmtime_diff_introduced)}
    if LibVersion < OPENSSL_gmtime_diff_introduced then
    begin
      {$if declared(FC_OPENSSL_gmtime_diff)}
      OPENSSL_gmtime_diff := FC_OPENSSL_gmtime_diff;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_gmtime_diff_removed)}
    if OPENSSL_gmtime_diff_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_gmtime_diff)}
      OPENSSL_gmtime_diff := _OPENSSL_gmtime_diff;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_gmtime_diff_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_gmtime_diff');
    {$ifend}
  end;
  
  CRYPTO_memcmp := LoadLibFunction(ADllHandle, CRYPTO_memcmp_procname);
  FuncLoadError := not assigned(CRYPTO_memcmp);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_memcmp_allownil)}
    CRYPTO_memcmp := ERR_CRYPTO_memcmp;
    {$ifend}
    {$if declared(CRYPTO_memcmp_introduced)}
    if LibVersion < CRYPTO_memcmp_introduced then
    begin
      {$if declared(FC_CRYPTO_memcmp)}
      CRYPTO_memcmp := FC_CRYPTO_memcmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_memcmp_removed)}
    if CRYPTO_memcmp_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_memcmp)}
      CRYPTO_memcmp := _CRYPTO_memcmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_memcmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_memcmp');
    {$ifend}
  end;
  
  OPENSSL_cleanup := LoadLibFunction(ADllHandle, OPENSSL_cleanup_procname);
  FuncLoadError := not assigned(OPENSSL_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_cleanup_allownil)}
    OPENSSL_cleanup := ERR_OPENSSL_cleanup;
    {$ifend}
    {$if declared(OPENSSL_cleanup_introduced)}
    if LibVersion < OPENSSL_cleanup_introduced then
    begin
      {$if declared(FC_OPENSSL_cleanup)}
      OPENSSL_cleanup := FC_OPENSSL_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_cleanup_removed)}
    if OPENSSL_cleanup_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_cleanup)}
      OPENSSL_cleanup := _OPENSSL_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_cleanup');
    {$ifend}
  end;
  
  OPENSSL_init_crypto := LoadLibFunction(ADllHandle, OPENSSL_init_crypto_procname);
  FuncLoadError := not assigned(OPENSSL_init_crypto);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_init_crypto_allownil)}
    OPENSSL_init_crypto := ERR_OPENSSL_init_crypto;
    {$ifend}
    {$if declared(OPENSSL_init_crypto_introduced)}
    if LibVersion < OPENSSL_init_crypto_introduced then
    begin
      {$if declared(FC_OPENSSL_init_crypto)}
      OPENSSL_init_crypto := FC_OPENSSL_init_crypto;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_init_crypto_removed)}
    if OPENSSL_init_crypto_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_init_crypto)}
      OPENSSL_init_crypto := _OPENSSL_init_crypto;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_init_crypto_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_init_crypto');
    {$ifend}
  end;
  
  OPENSSL_atexit := LoadLibFunction(ADllHandle, OPENSSL_atexit_procname);
  FuncLoadError := not assigned(OPENSSL_atexit);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_atexit_allownil)}
    OPENSSL_atexit := ERR_OPENSSL_atexit;
    {$ifend}
    {$if declared(OPENSSL_atexit_introduced)}
    if LibVersion < OPENSSL_atexit_introduced then
    begin
      {$if declared(FC_OPENSSL_atexit)}
      OPENSSL_atexit := FC_OPENSSL_atexit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_atexit_removed)}
    if OPENSSL_atexit_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_atexit)}
      OPENSSL_atexit := _OPENSSL_atexit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_atexit_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_atexit');
    {$ifend}
  end;
  
  OPENSSL_thread_stop := LoadLibFunction(ADllHandle, OPENSSL_thread_stop_procname);
  FuncLoadError := not assigned(OPENSSL_thread_stop);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_thread_stop_allownil)}
    OPENSSL_thread_stop := ERR_OPENSSL_thread_stop;
    {$ifend}
    {$if declared(OPENSSL_thread_stop_introduced)}
    if LibVersion < OPENSSL_thread_stop_introduced then
    begin
      {$if declared(FC_OPENSSL_thread_stop)}
      OPENSSL_thread_stop := FC_OPENSSL_thread_stop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_thread_stop_removed)}
    if OPENSSL_thread_stop_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_thread_stop)}
      OPENSSL_thread_stop := _OPENSSL_thread_stop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_thread_stop_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_thread_stop');
    {$ifend}
  end;
  
  OPENSSL_thread_stop_ex := LoadLibFunction(ADllHandle, OPENSSL_thread_stop_ex_procname);
  FuncLoadError := not assigned(OPENSSL_thread_stop_ex);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_thread_stop_ex_allownil)}
    OPENSSL_thread_stop_ex := ERR_OPENSSL_thread_stop_ex;
    {$ifend}
    {$if declared(OPENSSL_thread_stop_ex_introduced)}
    if LibVersion < OPENSSL_thread_stop_ex_introduced then
    begin
      {$if declared(FC_OPENSSL_thread_stop_ex)}
      OPENSSL_thread_stop_ex := FC_OPENSSL_thread_stop_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_thread_stop_ex_removed)}
    if OPENSSL_thread_stop_ex_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_thread_stop_ex)}
      OPENSSL_thread_stop_ex := _OPENSSL_thread_stop_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_thread_stop_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_thread_stop_ex');
    {$ifend}
  end;
  
  OPENSSL_INIT_new := LoadLibFunction(ADllHandle, OPENSSL_INIT_new_procname);
  FuncLoadError := not assigned(OPENSSL_INIT_new);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_INIT_new_allownil)}
    OPENSSL_INIT_new := ERR_OPENSSL_INIT_new;
    {$ifend}
    {$if declared(OPENSSL_INIT_new_introduced)}
    if LibVersion < OPENSSL_INIT_new_introduced then
    begin
      {$if declared(FC_OPENSSL_INIT_new)}
      OPENSSL_INIT_new := FC_OPENSSL_INIT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_INIT_new_removed)}
    if OPENSSL_INIT_new_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_INIT_new)}
      OPENSSL_INIT_new := _OPENSSL_INIT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_INIT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_INIT_new');
    {$ifend}
  end;
  
  OPENSSL_INIT_set_config_filename := LoadLibFunction(ADllHandle, OPENSSL_INIT_set_config_filename_procname);
  FuncLoadError := not assigned(OPENSSL_INIT_set_config_filename);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_INIT_set_config_filename_allownil)}
    OPENSSL_INIT_set_config_filename := ERR_OPENSSL_INIT_set_config_filename;
    {$ifend}
    {$if declared(OPENSSL_INIT_set_config_filename_introduced)}
    if LibVersion < OPENSSL_INIT_set_config_filename_introduced then
    begin
      {$if declared(FC_OPENSSL_INIT_set_config_filename)}
      OPENSSL_INIT_set_config_filename := FC_OPENSSL_INIT_set_config_filename;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_INIT_set_config_filename_removed)}
    if OPENSSL_INIT_set_config_filename_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_INIT_set_config_filename)}
      OPENSSL_INIT_set_config_filename := _OPENSSL_INIT_set_config_filename;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_INIT_set_config_filename_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_INIT_set_config_filename');
    {$ifend}
  end;
  
  OPENSSL_INIT_set_config_file_flags := LoadLibFunction(ADllHandle, OPENSSL_INIT_set_config_file_flags_procname);
  FuncLoadError := not assigned(OPENSSL_INIT_set_config_file_flags);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_INIT_set_config_file_flags_allownil)}
    OPENSSL_INIT_set_config_file_flags := ERR_OPENSSL_INIT_set_config_file_flags;
    {$ifend}
    {$if declared(OPENSSL_INIT_set_config_file_flags_introduced)}
    if LibVersion < OPENSSL_INIT_set_config_file_flags_introduced then
    begin
      {$if declared(FC_OPENSSL_INIT_set_config_file_flags)}
      OPENSSL_INIT_set_config_file_flags := FC_OPENSSL_INIT_set_config_file_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_INIT_set_config_file_flags_removed)}
    if OPENSSL_INIT_set_config_file_flags_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_INIT_set_config_file_flags)}
      OPENSSL_INIT_set_config_file_flags := _OPENSSL_INIT_set_config_file_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_INIT_set_config_file_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_INIT_set_config_file_flags');
    {$ifend}
  end;
  
  OPENSSL_INIT_set_config_appname := LoadLibFunction(ADllHandle, OPENSSL_INIT_set_config_appname_procname);
  FuncLoadError := not assigned(OPENSSL_INIT_set_config_appname);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_INIT_set_config_appname_allownil)}
    OPENSSL_INIT_set_config_appname := ERR_OPENSSL_INIT_set_config_appname;
    {$ifend}
    {$if declared(OPENSSL_INIT_set_config_appname_introduced)}
    if LibVersion < OPENSSL_INIT_set_config_appname_introduced then
    begin
      {$if declared(FC_OPENSSL_INIT_set_config_appname)}
      OPENSSL_INIT_set_config_appname := FC_OPENSSL_INIT_set_config_appname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_INIT_set_config_appname_removed)}
    if OPENSSL_INIT_set_config_appname_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_INIT_set_config_appname)}
      OPENSSL_INIT_set_config_appname := _OPENSSL_INIT_set_config_appname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_INIT_set_config_appname_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_INIT_set_config_appname');
    {$ifend}
  end;
  
  OPENSSL_INIT_free := LoadLibFunction(ADllHandle, OPENSSL_INIT_free_procname);
  FuncLoadError := not assigned(OPENSSL_INIT_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_INIT_free_allownil)}
    OPENSSL_INIT_free := ERR_OPENSSL_INIT_free;
    {$ifend}
    {$if declared(OPENSSL_INIT_free_introduced)}
    if LibVersion < OPENSSL_INIT_free_introduced then
    begin
      {$if declared(FC_OPENSSL_INIT_free)}
      OPENSSL_INIT_free := FC_OPENSSL_INIT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_INIT_free_removed)}
    if OPENSSL_INIT_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_INIT_free)}
      OPENSSL_INIT_free := _OPENSSL_INIT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_INIT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_INIT_free');
    {$ifend}
  end;
  
  CRYPTO_THREAD_run_once := LoadLibFunction(ADllHandle, CRYPTO_THREAD_run_once_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_run_once);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_run_once_allownil)}
    CRYPTO_THREAD_run_once := ERR_CRYPTO_THREAD_run_once;
    {$ifend}
    {$if declared(CRYPTO_THREAD_run_once_introduced)}
    if LibVersion < CRYPTO_THREAD_run_once_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_run_once)}
      CRYPTO_THREAD_run_once := FC_CRYPTO_THREAD_run_once;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_run_once_removed)}
    if CRYPTO_THREAD_run_once_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_run_once)}
      CRYPTO_THREAD_run_once := _CRYPTO_THREAD_run_once;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_run_once_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_run_once');
    {$ifend}
  end;
  
  CRYPTO_THREAD_init_local := LoadLibFunction(ADllHandle, CRYPTO_THREAD_init_local_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_init_local);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_init_local_allownil)}
    CRYPTO_THREAD_init_local := ERR_CRYPTO_THREAD_init_local;
    {$ifend}
    {$if declared(CRYPTO_THREAD_init_local_introduced)}
    if LibVersion < CRYPTO_THREAD_init_local_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_init_local)}
      CRYPTO_THREAD_init_local := FC_CRYPTO_THREAD_init_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_init_local_removed)}
    if CRYPTO_THREAD_init_local_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_init_local)}
      CRYPTO_THREAD_init_local := _CRYPTO_THREAD_init_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_init_local_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_init_local');
    {$ifend}
  end;
  
  CRYPTO_THREAD_get_local := LoadLibFunction(ADllHandle, CRYPTO_THREAD_get_local_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_get_local);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_get_local_allownil)}
    CRYPTO_THREAD_get_local := ERR_CRYPTO_THREAD_get_local;
    {$ifend}
    {$if declared(CRYPTO_THREAD_get_local_introduced)}
    if LibVersion < CRYPTO_THREAD_get_local_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_get_local)}
      CRYPTO_THREAD_get_local := FC_CRYPTO_THREAD_get_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_get_local_removed)}
    if CRYPTO_THREAD_get_local_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_get_local)}
      CRYPTO_THREAD_get_local := _CRYPTO_THREAD_get_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_get_local_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_get_local');
    {$ifend}
  end;
  
  CRYPTO_THREAD_set_local := LoadLibFunction(ADllHandle, CRYPTO_THREAD_set_local_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_set_local);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_set_local_allownil)}
    CRYPTO_THREAD_set_local := ERR_CRYPTO_THREAD_set_local;
    {$ifend}
    {$if declared(CRYPTO_THREAD_set_local_introduced)}
    if LibVersion < CRYPTO_THREAD_set_local_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_set_local)}
      CRYPTO_THREAD_set_local := FC_CRYPTO_THREAD_set_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_set_local_removed)}
    if CRYPTO_THREAD_set_local_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_set_local)}
      CRYPTO_THREAD_set_local := _CRYPTO_THREAD_set_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_set_local_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_set_local');
    {$ifend}
  end;
  
  CRYPTO_THREAD_cleanup_local := LoadLibFunction(ADllHandle, CRYPTO_THREAD_cleanup_local_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_cleanup_local);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_cleanup_local_allownil)}
    CRYPTO_THREAD_cleanup_local := ERR_CRYPTO_THREAD_cleanup_local;
    {$ifend}
    {$if declared(CRYPTO_THREAD_cleanup_local_introduced)}
    if LibVersion < CRYPTO_THREAD_cleanup_local_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_cleanup_local)}
      CRYPTO_THREAD_cleanup_local := FC_CRYPTO_THREAD_cleanup_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_cleanup_local_removed)}
    if CRYPTO_THREAD_cleanup_local_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_cleanup_local)}
      CRYPTO_THREAD_cleanup_local := _CRYPTO_THREAD_cleanup_local;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_cleanup_local_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_cleanup_local');
    {$ifend}
  end;
  
  CRYPTO_THREAD_get_current_id := LoadLibFunction(ADllHandle, CRYPTO_THREAD_get_current_id_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_get_current_id);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_get_current_id_allownil)}
    CRYPTO_THREAD_get_current_id := ERR_CRYPTO_THREAD_get_current_id;
    {$ifend}
    {$if declared(CRYPTO_THREAD_get_current_id_introduced)}
    if LibVersion < CRYPTO_THREAD_get_current_id_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_get_current_id)}
      CRYPTO_THREAD_get_current_id := FC_CRYPTO_THREAD_get_current_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_get_current_id_removed)}
    if CRYPTO_THREAD_get_current_id_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_get_current_id)}
      CRYPTO_THREAD_get_current_id := _CRYPTO_THREAD_get_current_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_get_current_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_get_current_id');
    {$ifend}
  end;
  
  CRYPTO_THREAD_compare_id := LoadLibFunction(ADllHandle, CRYPTO_THREAD_compare_id_procname);
  FuncLoadError := not assigned(CRYPTO_THREAD_compare_id);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREAD_compare_id_allownil)}
    CRYPTO_THREAD_compare_id := ERR_CRYPTO_THREAD_compare_id;
    {$ifend}
    {$if declared(CRYPTO_THREAD_compare_id_introduced)}
    if LibVersion < CRYPTO_THREAD_compare_id_introduced then
    begin
      {$if declared(FC_CRYPTO_THREAD_compare_id)}
      CRYPTO_THREAD_compare_id := FC_CRYPTO_THREAD_compare_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREAD_compare_id_removed)}
    if CRYPTO_THREAD_compare_id_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREAD_compare_id)}
      CRYPTO_THREAD_compare_id := _CRYPTO_THREAD_compare_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREAD_compare_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREAD_compare_id');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_new := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_new_allownil)}
    OSSL_LIB_CTX_new := ERR_OSSL_LIB_CTX_new;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_new_introduced)}
    if LibVersion < OSSL_LIB_CTX_new_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_new)}
      OSSL_LIB_CTX_new := FC_OSSL_LIB_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_new_removed)}
    if OSSL_LIB_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_new)}
      OSSL_LIB_CTX_new := _OSSL_LIB_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_new');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_new_from_dispatch := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_new_from_dispatch_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_new_from_dispatch);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_new_from_dispatch_allownil)}
    OSSL_LIB_CTX_new_from_dispatch := ERR_OSSL_LIB_CTX_new_from_dispatch;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_new_from_dispatch_introduced)}
    if LibVersion < OSSL_LIB_CTX_new_from_dispatch_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_new_from_dispatch)}
      OSSL_LIB_CTX_new_from_dispatch := FC_OSSL_LIB_CTX_new_from_dispatch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_new_from_dispatch_removed)}
    if OSSL_LIB_CTX_new_from_dispatch_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_new_from_dispatch)}
      OSSL_LIB_CTX_new_from_dispatch := _OSSL_LIB_CTX_new_from_dispatch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_new_from_dispatch_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_new_from_dispatch');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_new_child := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_new_child_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_new_child);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_new_child_allownil)}
    OSSL_LIB_CTX_new_child := ERR_OSSL_LIB_CTX_new_child;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_new_child_introduced)}
    if LibVersion < OSSL_LIB_CTX_new_child_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_new_child)}
      OSSL_LIB_CTX_new_child := FC_OSSL_LIB_CTX_new_child;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_new_child_removed)}
    if OSSL_LIB_CTX_new_child_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_new_child)}
      OSSL_LIB_CTX_new_child := _OSSL_LIB_CTX_new_child;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_new_child_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_new_child');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_load_config := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_load_config_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_load_config);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_load_config_allownil)}
    OSSL_LIB_CTX_load_config := ERR_OSSL_LIB_CTX_load_config;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_load_config_introduced)}
    if LibVersion < OSSL_LIB_CTX_load_config_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_load_config)}
      OSSL_LIB_CTX_load_config := FC_OSSL_LIB_CTX_load_config;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_load_config_removed)}
    if OSSL_LIB_CTX_load_config_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_load_config)}
      OSSL_LIB_CTX_load_config := _OSSL_LIB_CTX_load_config;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_load_config_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_load_config');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_free := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_free_allownil)}
    OSSL_LIB_CTX_free := ERR_OSSL_LIB_CTX_free;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_free_introduced)}
    if LibVersion < OSSL_LIB_CTX_free_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_free)}
      OSSL_LIB_CTX_free := FC_OSSL_LIB_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_free_removed)}
    if OSSL_LIB_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_free)}
      OSSL_LIB_CTX_free := _OSSL_LIB_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_free');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_get0_global_default := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_get0_global_default_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_get0_global_default);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_get0_global_default_allownil)}
    OSSL_LIB_CTX_get0_global_default := ERR_OSSL_LIB_CTX_get0_global_default;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_get0_global_default_introduced)}
    if LibVersion < OSSL_LIB_CTX_get0_global_default_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_get0_global_default)}
      OSSL_LIB_CTX_get0_global_default := FC_OSSL_LIB_CTX_get0_global_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_get0_global_default_removed)}
    if OSSL_LIB_CTX_get0_global_default_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_get0_global_default)}
      OSSL_LIB_CTX_get0_global_default := _OSSL_LIB_CTX_get0_global_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_get0_global_default_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_get0_global_default');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_set0_default := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_set0_default_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_set0_default);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_set0_default_allownil)}
    OSSL_LIB_CTX_set0_default := ERR_OSSL_LIB_CTX_set0_default;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_set0_default_introduced)}
    if LibVersion < OSSL_LIB_CTX_set0_default_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_set0_default)}
      OSSL_LIB_CTX_set0_default := FC_OSSL_LIB_CTX_set0_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_set0_default_removed)}
    if OSSL_LIB_CTX_set0_default_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_set0_default)}
      OSSL_LIB_CTX_set0_default := _OSSL_LIB_CTX_set0_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_set0_default_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_set0_default');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_get_conf_diagnostics := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_get_conf_diagnostics_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_get_conf_diagnostics);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_get_conf_diagnostics_allownil)}
    OSSL_LIB_CTX_get_conf_diagnostics := ERR_OSSL_LIB_CTX_get_conf_diagnostics;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_get_conf_diagnostics_introduced)}
    if LibVersion < OSSL_LIB_CTX_get_conf_diagnostics_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_get_conf_diagnostics)}
      OSSL_LIB_CTX_get_conf_diagnostics := FC_OSSL_LIB_CTX_get_conf_diagnostics;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_get_conf_diagnostics_removed)}
    if OSSL_LIB_CTX_get_conf_diagnostics_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_get_conf_diagnostics)}
      OSSL_LIB_CTX_get_conf_diagnostics := _OSSL_LIB_CTX_get_conf_diagnostics;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_get_conf_diagnostics_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_get_conf_diagnostics');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_set_conf_diagnostics := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_set_conf_diagnostics_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_set_conf_diagnostics);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_set_conf_diagnostics_allownil)}
    OSSL_LIB_CTX_set_conf_diagnostics := ERR_OSSL_LIB_CTX_set_conf_diagnostics;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_set_conf_diagnostics_introduced)}
    if LibVersion < OSSL_LIB_CTX_set_conf_diagnostics_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_set_conf_diagnostics)}
      OSSL_LIB_CTX_set_conf_diagnostics := FC_OSSL_LIB_CTX_set_conf_diagnostics;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_set_conf_diagnostics_removed)}
    if OSSL_LIB_CTX_set_conf_diagnostics_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_set_conf_diagnostics)}
      OSSL_LIB_CTX_set_conf_diagnostics := _OSSL_LIB_CTX_set_conf_diagnostics;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_set_conf_diagnostics_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_set_conf_diagnostics');
    {$ifend}
  end;
  
  OSSL_sleep := LoadLibFunction(ADllHandle, OSSL_sleep_procname);
  FuncLoadError := not assigned(OSSL_sleep);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_sleep_allownil)}
    OSSL_sleep := ERR_OSSL_sleep;
    {$ifend}
    {$if declared(OSSL_sleep_introduced)}
    if LibVersion < OSSL_sleep_introduced then
    begin
      {$if declared(FC_OSSL_sleep)}
      OSSL_sleep := FC_OSSL_sleep;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_sleep_removed)}
    if OSSL_sleep_removed <= LibVersion then
    begin
      {$if declared(_OSSL_sleep)}
      OSSL_sleep := _OSSL_sleep;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_sleep_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_sleep');
    {$ifend}
  end;
  
  OSSL_LIB_CTX_get_data := LoadLibFunction(ADllHandle, OSSL_LIB_CTX_get_data_procname);
  FuncLoadError := not assigned(OSSL_LIB_CTX_get_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_LIB_CTX_get_data_allownil)}
    OSSL_LIB_CTX_get_data := ERR_OSSL_LIB_CTX_get_data;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_get_data_introduced)}
    if LibVersion < OSSL_LIB_CTX_get_data_introduced then
    begin
      {$if declared(FC_OSSL_LIB_CTX_get_data)}
      OSSL_LIB_CTX_get_data := FC_OSSL_LIB_CTX_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_LIB_CTX_get_data_removed)}
    if OSSL_LIB_CTX_get_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_LIB_CTX_get_data)}
      OSSL_LIB_CTX_get_data := _OSSL_LIB_CTX_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_LIB_CTX_get_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_LIB_CTX_get_data');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  CRYPTO_THREAD_lock_new := nil;
  CRYPTO_THREAD_read_lock := nil;
  CRYPTO_THREAD_write_lock := nil;
  CRYPTO_THREAD_unlock := nil;
  CRYPTO_THREAD_lock_free := nil;
  CRYPTO_atomic_add := nil;
  CRYPTO_atomic_add64 := nil;
  CRYPTO_atomic_and := nil;
  CRYPTO_atomic_or := nil;
  CRYPTO_atomic_load := nil;
  CRYPTO_atomic_load_int := nil;
  CRYPTO_atomic_store := nil;
  OPENSSL_strlcpy := nil;
  OPENSSL_strlcat := nil;
  OPENSSL_strnlen := nil;
  OPENSSL_strtoul := nil;
  OPENSSL_buf2hexstr_ex := nil;
  OPENSSL_buf2hexstr := nil;
  OPENSSL_hexstr2buf_ex := nil;
  OPENSSL_hexstr2buf := nil;
  OPENSSL_hexchar2int := nil;
  OPENSSL_strcasecmp := nil;
  OPENSSL_strncasecmp := nil;
  OPENSSL_version_major := nil;
  OPENSSL_version_minor := nil;
  OPENSSL_version_patch := nil;
  OPENSSL_version_pre_release := nil;
  OPENSSL_version_build_metadata := nil;
  OpenSSL_version_num := nil;
  OpenSSL_version := nil;
  OPENSSL_info := nil;
  OPENSSL_issetugid := nil;
  CRYPTO_get_ex_new_index := nil;
  CRYPTO_free_ex_index := nil;
  CRYPTO_new_ex_data := nil;
  CRYPTO_dup_ex_data := nil;
  CRYPTO_free_ex_data := nil;
  CRYPTO_alloc_ex_data := nil;
  CRYPTO_set_ex_data := nil;
  CRYPTO_get_ex_data := nil;
  CRYPTO_set_mem_functions := nil;
  CRYPTO_get_mem_functions := nil;
  CRYPTO_malloc := nil;
  CRYPTO_zalloc := nil;
  CRYPTO_malloc_array := nil;
  CRYPTO_calloc := nil;
  CRYPTO_aligned_alloc := nil;
  CRYPTO_aligned_alloc_array := nil;
  CRYPTO_memdup := nil;
  CRYPTO_strdup := nil;
  CRYPTO_strndup := nil;
  CRYPTO_free := nil;
  CRYPTO_clear_free := nil;
  CRYPTO_realloc := nil;
  CRYPTO_clear_realloc := nil;
  CRYPTO_realloc_array := nil;
  CRYPTO_clear_realloc_array := nil;
  CRYPTO_secure_malloc_init := nil;
  CRYPTO_secure_malloc_done := nil;
  CRYPTO_secure_malloc := nil;
  CRYPTO_secure_zalloc := nil;
  CRYPTO_secure_malloc_array := nil;
  CRYPTO_secure_calloc := nil;
  CRYPTO_secure_free := nil;
  CRYPTO_secure_clear_free := nil;
  CRYPTO_secure_allocated := nil;
  CRYPTO_secure_malloc_initialized := nil;
  CRYPTO_secure_actual_size := nil;
  CRYPTO_secure_used := nil;
  OPENSSL_cleanse := nil;
  OPENSSL_die := nil;
  OPENSSL_isservice := nil;
  OPENSSL_init := nil;
  OPENSSL_fork_prepare := nil;
  OPENSSL_fork_parent := nil;
  OPENSSL_fork_child := nil;
  OPENSSL_gmtime := nil;
  OPENSSL_gmtime_adj := nil;
  OPENSSL_gmtime_diff := nil;
  CRYPTO_memcmp := nil;
  OPENSSL_cleanup := nil;
  OPENSSL_init_crypto := nil;
  OPENSSL_atexit := nil;
  OPENSSL_thread_stop := nil;
  OPENSSL_thread_stop_ex := nil;
  OPENSSL_INIT_new := nil;
  OPENSSL_INIT_set_config_filename := nil;
  OPENSSL_INIT_set_config_file_flags := nil;
  OPENSSL_INIT_set_config_appname := nil;
  OPENSSL_INIT_free := nil;
  CRYPTO_THREAD_run_once := nil;
  CRYPTO_THREAD_init_local := nil;
  CRYPTO_THREAD_get_local := nil;
  CRYPTO_THREAD_set_local := nil;
  CRYPTO_THREAD_cleanup_local := nil;
  CRYPTO_THREAD_get_current_id := nil;
  CRYPTO_THREAD_compare_id := nil;
  OSSL_LIB_CTX_new := nil;
  OSSL_LIB_CTX_new_from_dispatch := nil;
  OSSL_LIB_CTX_new_child := nil;
  OSSL_LIB_CTX_load_config := nil;
  OSSL_LIB_CTX_free := nil;
  OSSL_LIB_CTX_get0_global_default := nil;
  OSSL_LIB_CTX_set0_default := nil;
  OSSL_LIB_CTX_get_conf_diagnostics := nil;
  OSSL_LIB_CTX_set_conf_diagnostics := nil;
  OSSL_sleep := nil;
  OSSL_LIB_CTX_get_data := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.