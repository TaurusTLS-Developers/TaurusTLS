/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_crypto.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_crypto.h2pas
     and this file regenerated. TaurusTLSHeaders_crypto.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_crypto;

interface

// Headers for OpenSSL 1.1.1
// crypto.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_core,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_provider,
  {$IFDEF VCL_XE3_OR_ABOVE}System.Types{$ELSE}Types{$ENDIF};

{$MINENUMSIZE 4}

const
  {$EXTERNALSYM CRYPTO_MEM_CHECK_OFF}
  CRYPTO_MEM_CHECK_OFF = $0;   //* Control only */
  {$EXTERNALSYM CRYPTO_MEM_CHECK_ON}
  CRYPTO_MEM_CHECK_ON = $1;   //* Control and mode bit */
  {$EXTERNALSYM CRYPTO_MEM_CHECK_ENABLE}
  CRYPTO_MEM_CHECK_ENABLE = $2;   //* Control and mode bit */
  {$EXTERNALSYM CRYPTO_MEM_CHECK_DISABLE}
  CRYPTO_MEM_CHECK_DISABLE = $3;   //* Control only */

  {$EXTERNALSYM CRYPTO_EX_INDEX_SSL}
  CRYPTO_EX_INDEX_SSL = 0;
  {$EXTERNALSYM CRYPTO_EX_INDEX_SSL_CTX}
  CRYPTO_EX_INDEX_SSL_CTX = 1;
  {$EXTERNALSYM CRYPTO_EX_INDEX_SSL_SESSION}
  CRYPTO_EX_INDEX_SSL_SESSION = 2;
  {$EXTERNALSYM CRYPTO_EX_INDEX_X509}
  CRYPTO_EX_INDEX_X509 = 3;
  {$EXTERNALSYM CRYPTO_EX_INDEX_X509_STORE}
  CRYPTO_EX_INDEX_X509_STORE = 4;
  {$EXTERNALSYM CRYPTO_EX_INDEX_X509_STORE_CTX}
  CRYPTO_EX_INDEX_X509_STORE_CTX = 5;
  {$EXTERNALSYM CRYPTO_EX_INDEX_DH}
  CRYPTO_EX_INDEX_DH = 6;
  {$EXTERNALSYM CRYPTO_EX_INDEX_DSA}
  CRYPTO_EX_INDEX_DSA = 7;
  {$EXTERNALSYM CRYPTO_EX_INDEX_EC_KEY}
  CRYPTO_EX_INDEX_EC_KEY = 8;
  {$EXTERNALSYM CRYPTO_EX_INDEX_RSA}
  CRYPTO_EX_INDEX_RSA = 9;
  {$EXTERNALSYM CRYPTO_EX_INDEX_ENGINE}
  CRYPTO_EX_INDEX_ENGINE = 10;
  {$EXTERNALSYM CRYPTO_EX_INDEX_UI}
  CRYPTO_EX_INDEX_UI = 11;
  {$EXTERNALSYM CRYPTO_EX_INDEX_BIO}
  CRYPTO_EX_INDEX_BIO = 12;
  {$EXTERNALSYM CRYPTO_EX_INDEX_APP}
  CRYPTO_EX_INDEX_APP = 13;
  {$EXTERNALSYM CRYPTO_EX_INDEX_UI_METHOD}
  CRYPTO_EX_INDEX_UI_METHOD = 14;
  {$EXTERNALSYM CRYPTO_EX_INDEX_DRBG}
  CRYPTO_EX_INDEX_DRBG = 15;
  {$EXTERNALSYM CRYPTO_EX_INDEX__COUNT}
  CRYPTO_EX_INDEX__COUNT = 16;

  // Added _CONST to prevent nameclashes
  {$EXTERNALSYM OPENSSL_VERSION_CONST}
  OPENSSL_VERSION_CONST = 0;
  {$EXTERNALSYM OPENSSL_CFLAGS}
  OPENSSL_CFLAGS = 1;
  {$EXTERNALSYM OPENSSL_BUILT_ON}
  OPENSSL_BUILT_ON = 2;
  {$EXTERNALSYM OPENSSL_PLATFORM}
  OPENSSL_PLATFORM = 3;
  {$EXTERNALSYM OPENSSL_DIR}
  OPENSSL_DIR = 4;
  {$EXTERNALSYM OPENSSL_ENGINES_DIR}
  OPENSSL_ENGINES_DIR = 5;
  {$EXTERNALSYM SSLEAY_VERSION_CONST}
  SSLEAY_VERSION_CONST = OPENSSL_VERSION_CONST;
  {$EXTERNALSYM OPENSSL_VERSION_STRING}
  OPENSSL_VERSION_STRING = 6;
  {$EXTERNALSYM OPENSSL_FULL_VERSION_STRING}
  OPENSSL_FULL_VERSION_STRING = 7;
  {$EXTERNALSYM OPENSSL_MODULES_DIR}
  OPENSSL_MODULES_DIR = 8;
  {$EXTERNALSYM OPENSSL_CPU_INFO}
  OPENSSL_CPU_INFO = 9;

///*
// * The series starts at 1001 to avoid confusion with the OpenSSL_version
// * types.
// */
  {$EXTERNALSYM OPENSSL_INFO_CONFIG_DIR}
  OPENSSL_INFO_CONFIG_DIR               = 1001;
  {$EXTERNALSYM OPENSSL_INFO_ENGINES_DIR}
  OPENSSL_INFO_ENGINES_DIR              = 1002;
  {$EXTERNALSYM OPENSSL_INFO_MODULES_DIR}
  OPENSSL_INFO_MODULES_DIR              = 1003;
  {$EXTERNALSYM OPENSSL_INFO_DSO_EXTENSION}
  OPENSSL_INFO_DSO_EXTENSION            = 1004;
  {$EXTERNALSYM OPENSSL_INFO_DIR_FILENAME_SEPARATOR}
  OPENSSL_INFO_DIR_FILENAME_SEPARATOR   = 1005;
  {$EXTERNALSYM OPENSSL_INFO_LIST_SEPARATOR}
  OPENSSL_INFO_LIST_SEPARATOR           = 1006;
  {$EXTERNALSYM OPENSSL_INFO_SEED_SOURCE}
  OPENSSL_INFO_SEED_SOURCE              = 1007;
  {$EXTERNALSYM OPENSSL_INFO_CPU_SETTINGS}
  OPENSSL_INFO_CPU_SETTINGS             = 1008;

  (*
   * These defines where used in combination with the old locking callbacks,
   * they are not called anymore, but old code that's not called might still
   * use them.
   *)
  {$EXTERNALSYM CRYPTO_LOCK}
  CRYPTO_LOCK = 1;
  {$EXTERNALSYM CRYPTO_UNLOCK}
  CRYPTO_UNLOCK = 2;
  {$EXTERNALSYM CRYPTO_READ}
  CRYPTO_READ = 4;
  {$EXTERNALSYM CRYPTO_WRITE}
  CRYPTO_WRITE = 8;

  (* Standard initialisation options *)
  {$EXTERNALSYM OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS}
  OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = TIdC_Long($00000001);
  {$EXTERNALSYM OPENSSL_INIT_LOAD_CRYPTO_STRINGS}
  OPENSSL_INIT_LOAD_CRYPTO_STRINGS = TIdC_Long($00000002);
  {$EXTERNALSYM OPENSSL_INIT_ADD_ALL_CIPHERS}
  OPENSSL_INIT_ADD_ALL_CIPHERS = TIdC_Long($00000004);
  {$EXTERNALSYM OPENSSL_INIT_ADD_ALL_DIGESTS}
  OPENSSL_INIT_ADD_ALL_DIGESTS = TIdC_Long($00000008);
  {$EXTERNALSYM OPENSSL_INIT_NO_ADD_ALL_CIPHERS}
  OPENSSL_INIT_NO_ADD_ALL_CIPHERS = TIdC_Long($00000010);
  {$EXTERNALSYM OPENSSL_INIT_NO_ADD_ALL_DIGESTS}
  OPENSSL_INIT_NO_ADD_ALL_DIGESTS = TIdC_Long($00000020);
  {$EXTERNALSYM OPENSSL_INIT_LOAD_CONFIG}
  OPENSSL_INIT_LOAD_CONFIG = TIdC_Long($00000040);
  {$EXTERNALSYM OPENSSL_INIT_NO_LOAD_CONFIG}
  OPENSSL_INIT_NO_LOAD_CONFIG = TIdC_Long($00000080);
  {$EXTERNALSYM OPENSSL_INIT_ASYNC}
  OPENSSL_INIT_ASYNC = TIdC_Long($00000100);
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_RDRAND}
  OPENSSL_INIT_ENGINE_RDRAND = TIdC_Long($00000200);
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_DYNAMIC}
  OPENSSL_INIT_ENGINE_DYNAMIC = TIdC_Long($00000400);
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_OPENSSL}
  OPENSSL_INIT_ENGINE_OPENSSL = TIdC_Long($00000800);
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_CRYPTODEV}
  OPENSSL_INIT_ENGINE_CRYPTODEV = TIdC_Long($00001000);
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_CAPI}
  OPENSSL_INIT_ENGINE_CAPI = TIdC_Long($00002000);
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_PADLOCK}
  OPENSSL_INIT_ENGINE_PADLOCK = TIdC_Long($00004000);
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_AFALG}
  OPENSSL_INIT_ENGINE_AFALG = TIdC_Long($00008000);
  (* OPENSSL_INIT_ZLIB = TIdC_Long($00010000); *)
  {$EXTERNALSYM OPENSSL_INIT_ATFORK}
  OPENSSL_INIT_ATFORK = TIdC_Long(00020000);
  (* OPENSSL_INIT_BASE_ONLY = TIdC_Long(00040000); *)
  {$EXTERNALSYM OPENSSL_INIT_NO_ATEXIT}
  OPENSSL_INIT_NO_ATEXIT = TIdC_Long(00080000);
  (* OPENSSL_INIT flag range 0xfff00000 reserved for OPENSSL_init_ssl() *)
  (* Max OPENSSL_INIT flag value is 0x80000000 *)

  (* openssl and dasync not counted as builtin *)
  {$EXTERNALSYM OPENSSL_INIT_ENGINE_ALL_BUILTIN}
  OPENSSL_INIT_ENGINE_ALL_BUILTIN = OPENSSL_INIT_ENGINE_RDRAND
    or OPENSSL_INIT_ENGINE_DYNAMIC or OPENSSL_INIT_ENGINE_CRYPTODEV
    or OPENSSL_INIT_ENGINE_CAPI or OPENSSL_INIT_ENGINE_PADLOCK;

  {$EXTERNALSYM CRYPTO_ONCE_STATIC_INIT}
  CRYPTO_ONCE_STATIC_INIT = 0;

type
  {$EXTERNALSYM CRYPTO_THREADID}
  CRYPTO_THREADID = record {1.0.x only}
    _ptr : Pointer;
    _val : TIdC_ULONG;
  end;
  {$EXTERNALSYM PCRYPTO_THREADID}
  PCRYPTO_THREADID = ^CRYPTO_THREADID;
  {$EXTERNALSYM CRYPTO_RWLOCK}
  CRYPTO_RWLOCK = record end;
  {$EXTERNALSYM PCRYPTO_RWLOCK}
  PCRYPTO_RWLOCK = ^CRYPTO_RWLOCK;
  //crypto_ex_data_st = record
  //  sk: PStackOfVoid;
  //end;
  //DEFINE_STACK_OF(void)

  {$EXTERNALSYM Tthreadid_func}
  Tthreadid_func = procedure (id : PCRYPTO_THREADID) cdecl;


  // CRYPTO_EX_new = procedure(parent: Pointer; _ptr: Pointer; CRYPTO_EX_DATA *ad; idx: TIdC_INT; argl: TIdC_LONG; argp: Pointer);
  //  CRYPTO_EX_free = procedure(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
  //                             int idx, long argl, void *argp);
  //typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
  //                           void *from_d, int idx, long argl, void *argp);
  //__owur int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
  //                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
  //                            CRYPTO_EX_free *free_func);
  {$EXTERNALSYM CRYPTO_EX_new}
  CRYPTO_EX_new = procedure(parent, _ptr: Pointer; ad : PCRYPTO_EX_DATA;
                            idx: TIdC_INT; argl: TIdC_LONG; argp: Pointer); cdecl;
  {$EXTERNALSYM CRYPTO_EX_free}
  CRYPTO_EX_free = procedure(parent, _ptr: Pointer; ad : PCRYPTO_EX_DATA;
                             idx : TIdC_INT; argl : TIdC_LONG; argp : Pointer); cdecl;
  {$EXTERNALSYM CRYPTO_EX_dup}
  CRYPTO_EX_dup = function(_to : PCRYPTO_EX_DATA; const from : PCRYPTO_EX_DATA;
                           from_d : Pointer; idx : TIdC_INT; argl : TIdC_LONG; argo : Pointer) : TIdC_INT; cdecl;

  {$EXTERNALSYM CRYPTO_mem_leaks_cb_cb}
  CRYPTO_mem_leaks_cb_cb = function(const _str: PIdAnsiChar; len: TIdC_SIZET; u: Pointer): TIdC_INT; cdecl;
  {$EXTERNALSYM CRYPTO_THREAD_run_once_init}
  CRYPTO_THREAD_run_once_init = procedure; cdecl;

  {$EXTERNALSYM CRYPTO_THREAD_LOCAL}
  CRYPTO_THREAD_LOCAL = type DWORD;
  {$EXTERNALSYM PCRYPTO_THREAD_LOCAL}
  PCRYPTO_THREAD_LOCAL = ^CRYPTO_THREAD_LOCAL;
  {$EXTERNALSYM CRYPTO_THREAD_ID}
  CRYPTO_THREAD_ID = type DWORD;
  {$EXTERNALSYM CRYPTO_ONCE}
  CRYPTO_ONCE = type TIdC_LONG;
  {$EXTERNALSYM PCRYPTO_ONCE}
  PCRYPTO_ONCE = ^CRYPTO_ONCE;

  {$EXTERNALSYM CRYPTO_set_mem_functions_m}
  CRYPTO_set_mem_functions_m = function(size: TIdC_SIZET; const filename: PIdAnsiChar; linenumber: TIdC_INT): Pointer; cdecl;
  {$EXTERNALSYM CRYPTO_set_mem_functions_r}
  CRYPTO_set_mem_functions_r = function(buffer: Pointer; size: TIdC_SIZET; const filename: PIdAnsiChar; linenumber: TIdC_INT): Pointer; cdecl;
  {$EXTERNALSYM CRYPTO_set_mem_functions_f}
  CRYPTO_set_mem_functions_f = procedure(buffer: Pointer; const filename: PIdAnsiChar; const linenumber: TIdC_INT); cdecl;
  {$EXTERNALSYM TIdSslIdCallback}
  TIdSslIdCallback = function: TIdC_ULONG; cdecl;
  {$EXTERNALSYM TIdSslLockingCallback}
  TIdSslLockingCallback = procedure (mode, n : TIdC_INT; Afile : PIdAnsiChar; line : TIdC_INT); cdecl;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM OPENSSL_malloc}
  OPENSSL_malloc: function (num: TIdC_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_zalloc}
  OPENSSL_zalloc: function (num: TIdC_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_realloc}
  OPENSSL_realloc: function (address: Pointer; num: TIdC_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_clear_realloc}
  OPENSSL_clear_realloc: function (address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_clear_free}
  OPENSSL_clear_free: procedure (address: Pointer; num: TIdC_SIZET); cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_free}
  OPENSSL_free: procedure (address: Pointer); cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_memdup}
  OPENSSL_memdup: function (const _str: Pointer; s: TIdC_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_strdup}
  OPENSSL_strdup: function (const _str: PIdAnsiChar): PIdAnsiChar; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_strndup}
  OPENSSL_strndup: function (const _str: PIdAnsiChar; n: TIdC_SIZET): PIdAnsiChar; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_malloc}
  OPENSSL_secure_malloc: function (num: TIdC_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_zalloc}
  OPENSSL_secure_zalloc: function (num: TIdC_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_free}
  OPENSSL_secure_free: procedure (address: Pointer); cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_clear_free}
  OPENSSL_secure_clear_free: procedure (address: Pointer; num: TIdC_SIZET); cdecl = nil; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_actual_size}
  OPENSSL_secure_actual_size: function (_ptr: Pointer): TIdC_SIZET; cdecl = nil; {removed 1.0.0}

  {$EXTERNALSYM CRYPTO_THREAD_lock_new}
  CRYPTO_THREAD_lock_new: function : PCRYPTO_RWLOCK; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_read_lock}
  CRYPTO_THREAD_read_lock: function (lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_write_lock}
  CRYPTO_THREAD_write_lock: function (lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_unlock}
  CRYPTO_THREAD_unlock: function (lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_lock_free}
  CRYPTO_THREAD_lock_free: procedure (lock: PCRYPTO_RWLOCK); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_atomic_add}
  CRYPTO_atomic_add: function (_val: PIdC_INT; amount: TIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_mem_ctrl}
  CRYPTO_mem_ctrl: function (mode: TIdC_INT): TIdC_INT; cdecl = nil; {removed 3.0.0}

  {$EXTERNALSYM OPENSSL_strlcpy}
  OPENSSL_strlcpy: function (dst: PIdAnsiChar; const src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_strlcat}
  OPENSSL_strlcat: function (dst: PIdAnsiChar; const src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_strnlen}
  OPENSSL_strnlen: function (const _str: PIdAnsiChar; maxlen: TIdC_SIZET): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_buf2hexstr}
  OPENSSL_buf2hexstr: function (const buffer: PByte; len: TIdC_LONG): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_hexstr2buf}
  OPENSSL_hexstr2buf: function (const _str: PIdAnsiChar; len: PIdC_LONG): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_hexchar2int}
  OPENSSL_hexchar2int: function (c: Byte): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  // # define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))

  {$EXTERNALSYM OpenSSL_version_num}
  OpenSSL_version_num: function : TIdC_ULONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OpenSSL_version}
  OpenSSL_version: function (type_: TIdC_INT): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM OPENSSL_info}
  OPENSSL_info: function(type_: TIdC_INT): PIdAnsiChar; cdecl = nil; {introduced 3.0.0}

  {$EXTERNALSYM OPENSSL_issetugid}
  OPENSSL_issetugid: function : TIdC_INT; cdecl = nil;

  (* No longer use an index. *)
  //function CRYPTO_free_ex_index(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT;

  (*
   * Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a
   * given class (invokes whatever per-class callbacks are applicable)
   *)
  {$EXTERNALSYM CRYPTO_new_ex_data}
  CRYPTO_new_ex_data: function (class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_dup_ex_data}
  CRYPTO_dup_ex_data: function (class_index: TIdC_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM CRYPTO_free_ex_data}
  CRYPTO_free_ex_data: procedure (class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl = nil;

  (*
   * Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular
   * index (relative to the class type involved)
   *)
  {$EXTERNALSYM CRYPTO_set_ex_data}
  CRYPTO_set_ex_data: function (ad: PCRYPTO_EX_DATA; idx: TIdC_INT; _val: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_get_ex_data}
  CRYPTO_get_ex_data: function (const ad: PCRYPTO_EX_DATA; idx: TIdC_INT): Pointer; cdecl = nil;

  ///*
  // * The old locking functions have been removed completely without compatibility
  // * macros. This is because the old functions either could not properly report
  // * errors, or the returned error values were not clearly documented.
  // * Replacing the locking functions with no-ops would cause race condition
  // * issues in the affected applications. It is far better for them to fail at
  // * compile time.
  // * On the other hand, the locking callbacks are no longer used.  Consequently,
  // * the callback management functions can be safely replaced with no-op macros.
  // */
  //#  define CRYPTO_num_locks()            (1)
  {$EXTERNALSYM CRYPTO_num_locks}
  CRYPTO_num_locks: function : TIdC_INT; cdecl = nil; {removed 1.1.0}
  //#  define CRYPTO_set_locking_callback(func)
  //#  define CRYPTO_get_locking_callback()         (NULL)
  //#  define CRYPTO_set_add_lock_callback(func)
  //#  define CRYPTO_get_add_lock_callback()        (NULL)
  {$EXTERNALSYM CRYPTO_set_locking_callback}
  CRYPTO_set_locking_callback: procedure (func: TIdSslLockingCallback); cdecl = nil; {removed 1.1.0}

  ///* Only use CRYPTO_THREADID_set_[numeric|pointer]() within callbacks */
  //#  define CRYPTO_THREADID_set_numeric(id, val)
  {$EXTERNALSYM CRYPTO_THREADID_set_numeric}
  CRYPTO_THREADID_set_numeric: procedure (id : PCRYPTO_THREADID; _val: TIdC_ULONG); cdecl = nil; {removed 1.1.0}
  //#  define CRYPTO_THREADID_set_pointer(id, ptr)
  //#  define CRYPTO_THREADID_set_callback(threadid_func)   (0)
  {$EXTERNALSYM CRYPTO_THREADID_set_callback}
  CRYPTO_THREADID_set_callback: procedure (threadid_func: Tthreadid_func); cdecl = nil; {removed 1.1.0}
  //#  define CRYPTO_THREADID_get_callback()                (NULL)
  //#  define CRYPTO_THREADID_current(id)
  //#  define CRYPTO_THREADID_cmp(a, b)                     (-1)
  //#  define CRYPTO_THREADID_cpy(dest, src)
  //#  define CRYPTO_THREADID_hash(id)                      (0UL)

  {$EXTERNALSYM CRYPTO_set_id_callback}
  CRYPTO_set_id_callback: procedure (func: TIdSslIdCallback); cdecl = nil; {removed 1.1.0}
  //
  //#  define CRYPTO_set_dynlock_create_callback(dyn_create_function)
  //#  define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
  //#  define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
  //#  define CRYPTO_get_dynlock_create_callback()          (NULL)
  //#  define CRYPTO_get_dynlock_lock_callback()            (NULL)
  //#  define CRYPTO_get_dynlock_destroy_callback()         (NULL)
  //# endif /* OPENSSL_API_COMPAT < 0x10100000L */

  {$EXTERNALSYM CRYPTO_set_mem_functions}
  CRYPTO_set_mem_functions: function (m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CRYPTO_set_mem_debug}
  CRYPTO_set_mem_debug: function (flag: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
    //void CRYPTO_get_mem_functions(
  //        void *(**m) (TIdC_SIZET, const char *, int),
  //        void *(**r) (void *, TIdC_SIZET, const char *, int),
  //        void (**f) (void *, const char *, int));

  {$EXTERNALSYM CRYPTO_malloc}
  CRYPTO_malloc: function (num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_zalloc}
  CRYPTO_zalloc: function (num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_memdup}
  CRYPTO_memdup: function (const _str: Pointer; siz: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_strdup}
  CRYPTO_strdup: function (const _str: PIdAnsiChar; const file_: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CRYPTO_strndup}
  CRYPTO_strndup: function (const _str: PIdAnsiChar; s: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_free}
  CRYPTO_free: procedure (_ptr: Pointer; const file_: PIdAnsiChar; line: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM CRYPTO_clear_free}
  CRYPTO_clear_free: procedure (_ptr: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_realloc}
  CRYPTO_realloc: function (address: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CRYPTO_clear_realloc}
  CRYPTO_clear_realloc: function (address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_secure_malloc_init}
  CRYPTO_secure_malloc_init: function (sz: TIdC_SIZET; minsize: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_malloc_done}
  CRYPTO_secure_malloc_done: function : TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_malloc}
  CRYPTO_secure_malloc: function (num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_zalloc}
  CRYPTO_secure_zalloc: function (num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_free}
  CRYPTO_secure_free: procedure (_ptr: Pointer; const file_: PIdAnsiChar; line: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_clear_free}
  CRYPTO_secure_clear_free: procedure (_ptr: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_allocated}
  CRYPTO_secure_allocated: function (const _ptr: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_malloc_initialized}
  CRYPTO_secure_malloc_initialized: function : TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_actual_size}
  CRYPTO_secure_actual_size: function (_ptr: Pointer): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_used}
  CRYPTO_secure_used: function : TIdC_SIZET; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_get_ex_new_index}
  CRYPTO_get_ex_new_index : function(class_index : TIdC_INT; arg1 : TIdC_LONG; argp : Pointer;
                                     new_func : CRYPTO_EX_new; dup_func : CRYPTO_EX_dup;
                                     free_func : CRYPTO_EX_FREE) : TIdC_INT cdecl;

  {$EXTERNALSYM OPENSSL_cleanse}
  OPENSSL_cleanse: procedure (_ptr: Pointer; len: TIdC_SIZET); cdecl = nil;


  (* debug libraries only  *)
//  function CRYPTO_mem_debug_push(const info: PIdAnsiChar; const file_: PIdAnsiChar; line: TIdC_INT): TIdC_INT;
//  function CRYPTO_mem_debug_pop: TIdC_INT;
//  procedure CRYPTO_get_alloc_counts(mcount: PIdC_INT; rcount: PIdC_INT; fcount: PIdC_INT);

  (*
   * Debugging functions (enabled by CRYPTO_set_mem_debug(1))
   * The flag argument has the following significance:
   *   0:   called before the actual memory allocation has taken place
   *   1:   called after the actual memory allocation has taken place
   *)

//  procedure CRYPTO_mem_debug_malloc(address: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_realloc(addr1: Pointer; addr2: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_free(address: Pointer; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);

//  function CRYPTO_mem_leaks_cb(cb: CRYPTO_mem_leaks_cb_cb; u: Pointer): TIdC_INT;

//  function CRYPTO_mem_leaks_fp(&FILE: Pointer): TIdC_INT;
//  function CRYPTO_mem_leaks(BIO: PBIO): TIdC_INT;

  //* die if we have to */
  //ossl_noreturn void OPENSSL_die(const char *assertion, const char *file, int line);

  //# define OPENSSL_assert(e) \
  //    (void)((e) ? 0 : (OPENSSL_die("assertion failed: " #e, OPENSSL_FILE, OPENSSL_LINE), 1))

  {$EXTERNALSYM OPENSSL_isservice}
  OPENSSL_isservice: function : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM FIPS_mode}
  FIPS_mode: function : TIdC_INT; cdecl = nil; {removed 3.0.0}
  {$EXTERNALSYM FIPS_mode_set}
  FIPS_mode_set: function (r: TIdC_INT): TIdC_INT; cdecl = nil; {removed 3.0.0}

  {$EXTERNALSYM OPENSSL_init}
  OPENSSL_init: procedure ; cdecl = nil;

  // struct tm *OPENSSL_gmtime(const TIdC_TIMET *timer, struct tm *result);

  //function OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec): TIdC_INT;
  //function OPENSSL_gmtime_diff(int *pday, int *psec, const struct tm *from, const struct tm *to): TIdC_INT;

  (*
   * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
   * It takes an amount of time dependent on |len|, but independent of the
   * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
   * into a defined order as the return value when a != b is undefined, other
   * than to be non-zero.
   *)
  {$EXTERNALSYM CRYPTO_memcmp}
  CRYPTO_memcmp: function (const in_a: Pointer; const in_b: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;

  (* Library initialisation functions *)
  {$EXTERNALSYM OPENSSL_cleanup}
  OPENSSL_cleanup: procedure ; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_init_crypto}
  OPENSSL_init_crypto: function (opts: TIdC_UINT64; const settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  // int OPENSSL_atexit(void (*handler)(void));
  {$EXTERNALSYM OPENSSL_thread_stop}
  OPENSSL_thread_stop: procedure ; cdecl = nil; {introduced 1.1.0}

  (* Low-level control of initialization *)
  {$EXTERNALSYM OPENSSL_INIT_new}
  OPENSSL_INIT_new: function : POPENSSL_INIT_SETTINGS; cdecl = nil; {introduced 1.1.0}
  //int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings,
  //                                     const char *config_filename);
  //void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings,
  //                                        unsigned long flags);
  //int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings,
  //                                    const char *config_appname);
  {$EXTERNALSYM OPENSSL_INIT_free}
  OPENSSL_INIT_free: procedure (settings: POPENSSL_INIT_SETTINGS); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_THREAD_run_once}
  CRYPTO_THREAD_run_once: function (once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  //type
  //  CRYPTO_THREAD_init_local_cleanup = procedure(v1: Pointer);
  //
  //function CRYPTO_THREAD_init_local(key: PCRYPTO_THREAD_LOCAL; cleanup: CRYPTO_THREAD_init_local_cleanup): TIdC_INT;
  {$EXTERNALSYM CRYPTO_THREAD_get_local}
  CRYPTO_THREAD_get_local: function (key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_set_local}
  CRYPTO_THREAD_set_local: function (key: PCRYPTO_THREAD_LOCAL; _val: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_cleanup_local}
  CRYPTO_THREAD_cleanup_local: function (key: PCRYPTO_THREAD_LOCAL): TidC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_THREAD_get_current_id}
  CRYPTO_THREAD_get_current_id: function : CRYPTO_THREAD_ID; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_compare_id}
  CRYPTO_THREAD_compare_id: function (a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM SSLeay_version}
  SSLeay_version: function (type_ : TIdC_INT) : PIdAnsiChar; cdecl = nil; {removed 1.1.0}
  {$EXTERNALSYM SSLeay}
  SSLeay: function : TIdC_ULONG; cdecl = nil; {removed 1.1.0}

  {$EXTERNALSYM OSSL_LIB_CTX_new}
  OSSL_LIB_CTX_new : function : POSSL_LIB_CTX; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_new_from_dispatch}
  OSSL_LIB_CTX_new_from_dispatch : function(const handle : POSSL_CORE_HANDLE; const _in : POSSL_DISPATCH) : POSSL_LIB_CTX; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_new_child}
  OSSL_LIB_CTX_new_child : function(const handle : POSSL_CORE_HANDLE; const _in : POSSL_DISPATCH) : POSSL_LIB_CTX; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_load_config}
  OSSL_LIB_CTX_load_config : function(ctx : POSSL_LIB_CTX; const config_file : PIdAnsiChar) : TIdC_INT; cdecl = nil;  {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_free}
  OSSL_LIB_CTX_free : procedure(ctx : POSSL_LIB_CTX);  cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_get0_global_default}
  OSSL_LIB_CTX_get0_global_default : function : POSSL_LIB_CTX; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_set0_default}
  OSSL_LIB_CTX_set0_default : function(libctx : POSSL_LIB_CTX) : POSSL_LIB_CTX; cdecl = nil; {introduced 3.0.0}

{$ELSE}

  {$EXTERNALSYM CRYPTO_THREAD_lock_new}
  function CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_read_lock}
  function CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_write_lock}
  function CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_unlock}
  function CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_lock_free}
  procedure CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_atomic_add}
  function CRYPTO_atomic_add(_val: PIdC_INT; amount: TIdC_INT; ret: PIdC_INT; lock: PCRYPTO_RWLOCK): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}


  {$EXTERNALSYM OPENSSL_strlcpy}
  function OPENSSL_strlcpy(dst: PIdAnsiChar; const src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_strlcat}
  function OPENSSL_strlcat(dst: PIdAnsiChar; const src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_strnlen}
  function OPENSSL_strnlen(const _str: PIdAnsiChar; maxlen: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_buf2hexstr}
  function OPENSSL_buf2hexstr(const buffer: PByte; len: TIdC_LONG): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_hexstr2buf}
  function OPENSSL_hexstr2buf(const _str: PIdAnsiChar; len: PIdC_LONG): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_hexchar2int}
  function OPENSSL_hexchar2int(c: Byte): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  // # define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))

  {$EXTERNALSYM OpenSSL_version_num}
  function OpenSSL_version_num: TIdC_ULONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OpenSSL_version}
  function OpenSSL_version(type_: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_info}
  function OPENSSL_info(type_: TIdC_INT): PIdAnsiChar  cdecl; external CLibCrypto;  {introduced 3.0.0}

  {$EXTERNALSYM OPENSSL_issetugid}
  function OPENSSL_issetugid: TIdC_INT cdecl; external CLibCrypto;

  (* No longer use an index. *)
  //function CRYPTO_free_ex_index(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT;

  (*
   * Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a
   * given class (invokes whatever per-class callbacks are applicable)
   *)
  {$EXTERNALSYM CRYPTO_new_ex_data}
  function CRYPTO_new_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM CRYPTO_dup_ex_data}
  function CRYPTO_dup_ex_data(class_index: TIdC_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM CRYPTO_free_ex_data}
  procedure CRYPTO_free_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA) cdecl; external CLibCrypto;

  (*
   * Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular
   * index (relative to the class type involved)
   *)
  {$EXTERNALSYM CRYPTO_set_ex_data}
  function CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT; _val: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM CRYPTO_get_ex_data}
  function CRYPTO_get_ex_data(const ad: PCRYPTO_EX_DATA; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;

  ///*
  // * The old locking functions have been removed completely without compatibility
  // * macros. This is because the old functions either could not properly report
  // * errors, or the returned error values were not clearly documented.
  // * Replacing the locking functions with no-ops would cause race condition
  // * issues in the affected applications. It is far better for them to fail at
  // * compile time.
  // * On the other hand, the locking callbacks are no longer used.  Consequently,
  // * the callback management functions can be safely replaced with no-op macros.
  // */
  //#  define CRYPTO_num_locks()            (1)
  //#  define CRYPTO_set_locking_callback(func)
  //#  define CRYPTO_get_locking_callback()         (NULL)
  //#  define CRYPTO_set_add_lock_callback(func)
  //#  define CRYPTO_get_add_lock_callback()        (NULL)

  ///* Only use CRYPTO_THREADID_set_[numeric|pointer]() within callbacks */
  //#  define CRYPTO_THREADID_set_numeric(id, val)
  //#  define CRYPTO_THREADID_set_pointer(id, ptr)
  //#  define CRYPTO_THREADID_set_callback(threadid_func)   (0)
  //#  define CRYPTO_THREADID_get_callback()                (NULL)
  //#  define CRYPTO_THREADID_current(id)
  //#  define CRYPTO_THREADID_cmp(a, b)                     (-1)
  //#  define CRYPTO_THREADID_cpy(dest, src)
  //#  define CRYPTO_THREADID_hash(id)                      (0UL)

  //
  //#  define CRYPTO_set_dynlock_create_callback(dyn_create_function)
  //#  define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
  //#  define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
  //#  define CRYPTO_get_dynlock_create_callback()          (NULL)
  //#  define CRYPTO_get_dynlock_lock_callback()            (NULL)
  //#  define CRYPTO_get_dynlock_destroy_callback()         (NULL)
  //# endif /* OPENSSL_API_COMPAT < 0x10100000L */

  {$EXTERNALSYM CRYPTO_set_mem_functions}
  function CRYPTO_set_mem_functions(m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TIdC_INT cdecl; external CLibCrypto;
    //void CRYPTO_get_mem_functions(
  //        void *(**m) (TIdC_SIZET, const char *, int),
  //        void *(**r) (void *, TIdC_SIZET, const char *, int),
  //        void (**f) (void *, const char *, int));

  {$EXTERNALSYM CRYPTO_malloc}
  function CRYPTO_malloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM CRYPTO_zalloc}
  function CRYPTO_zalloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_memdup}
  function CRYPTO_memdup(const _str: Pointer; siz: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_strdup}
  function CRYPTO_strdup(const _str: PIdAnsiChar; const file_: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM CRYPTO_strndup}
  function CRYPTO_strndup(const _str: PIdAnsiChar; s: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_free}
  procedure CRYPTO_free(_ptr: Pointer; const file_: PIdAnsiChar; line: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM CRYPTO_clear_free}
  procedure CRYPTO_clear_free(_ptr: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_realloc}
  function CRYPTO_realloc(address: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM CRYPTO_clear_realloc}
  function CRYPTO_clear_realloc(address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_secure_malloc_init}
  function CRYPTO_secure_malloc_init(sz: TIdC_SIZET; minsize: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_malloc_done}
  function CRYPTO_secure_malloc_done: TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_malloc}
  function CRYPTO_secure_malloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_zalloc}
  function CRYPTO_secure_zalloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_free}
  procedure CRYPTO_secure_free(_ptr: Pointer; const file_: PIdAnsiChar; line: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_clear_free}
  procedure CRYPTO_secure_clear_free(_ptr: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_allocated}
  function CRYPTO_secure_allocated(const _ptr: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_malloc_initialized}
  function CRYPTO_secure_malloc_initialized: TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_actual_size}
  function CRYPTO_secure_actual_size(_ptr: Pointer): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_secure_used}
  function CRYPTO_secure_used: TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_get_ex_new_index}
  function CRYPTO_get_ex_new_index(class_index : TIdC_INT; arg1 : TIdC_LONG; argp : Pointer;
                                   new_func : CRYPTO_EX_new; dup_func : CRYPTO_EX_dup;
                                   free_func : CRYPTO_EX_FREE) : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM OPENSSL_cleanse}
  procedure OPENSSL_cleanse(_ptr: Pointer; len: TIdC_SIZET) cdecl; external CLibCrypto;

  (* debug libraries only  *)
//  function CRYPTO_mem_debug_push(const info: PIdAnsiChar; const file_: PIdAnsiChar; line: TIdC_INT): TIdC_INT;
//  function CRYPTO_mem_debug_pop: TIdC_INT;
//  procedure CRYPTO_get_alloc_counts(mcount: PIdC_INT; rcount: PIdC_INT; fcount: PIdC_INT);

  (*
   * Debugging functions (enabled by CRYPTO_set_mem_debug(1))
   * The flag argument has the following significance:
   *   0:   called before the actual memory allocation has taken place
   *   1:   called after the actual memory allocation has taken place
   *)

//  procedure CRYPTO_mem_debug_malloc(address: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_realloc(addr1: Pointer; addr2: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_free(address: Pointer; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);

//  function CRYPTO_mem_leaks_cb(cb: CRYPTO_mem_leaks_cb_cb; u: Pointer): TIdC_INT;

//  function CRYPTO_mem_leaks_fp(&FILE: Pointer): TIdC_INT;
//  function CRYPTO_mem_leaks(BIO: PBIO): TIdC_INT;

  //* die if we have to */
  //ossl_noreturn void OPENSSL_die(const char *assertion, const char *file, int line);

  //# define OPENSSL_assert(e) \
  //    (void)((e) ? 0 : (OPENSSL_die("assertion failed: " #e, OPENSSL_FILE, OPENSSL_LINE), 1))

  {$EXTERNALSYM OPENSSL_isservice}
  function OPENSSL_isservice: TIdC_INT cdecl; external CLibCrypto;


  {$EXTERNALSYM OPENSSL_init}
  procedure OPENSSL_init cdecl; external CLibCrypto;

  // struct tm *OPENSSL_gmtime(const TIdC_TIMET *timer, struct tm *result);

  //function OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec): TIdC_INT;
  //function OPENSSL_gmtime_diff(int *pday, int *psec, const struct tm *from, const struct tm *to): TIdC_INT;

  (*
   * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
   * It takes an amount of time dependent on |len|, but independent of the
   * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
   * into a defined order as the return value when a != b is undefined, other
   * than to be non-zero.
   *)
  {$EXTERNALSYM CRYPTO_memcmp}
  function CRYPTO_memcmp(const in_a: Pointer; const in_b: Pointer; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;

  (* Library initialisation functions *)
  {$EXTERNALSYM OPENSSL_cleanup}
  procedure OPENSSL_cleanup cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_init_crypto}
  function OPENSSL_init_crypto(opts: TIdC_UINT64; const settings: POPENSSL_INIT_SETTINGS): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0} //PALOFF functions called only as procedures
  // int OPENSSL_atexit(void (*handler)(void));
  {$EXTERNALSYM OPENSSL_thread_stop}
  procedure OPENSSL_thread_stop cdecl; external CLibCrypto; {introduced 1.1.0}

  (* Low-level control of initialization *)
  {$EXTERNALSYM OPENSSL_INIT_new}
  function OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS cdecl; external CLibCrypto; {introduced 1.1.0}
  //int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings,
  //                                     const char *config_filename);
  //void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings,
  //                                        unsigned long flags);
  //int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings,
  //                                    const char *config_appname);
  {$EXTERNALSYM OPENSSL_INIT_free}
  procedure OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_THREAD_run_once}
  function CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  //type
  //  CRYPTO_THREAD_init_local_cleanup = procedure(v1: Pointer);
  //
  //function CRYPTO_THREAD_init_local(key: PCRYPTO_THREAD_LOCAL; cleanup: CRYPTO_THREAD_init_local_cleanup): TIdC_INT;
  {$EXTERNALSYM CRYPTO_THREAD_get_local}
  function CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_set_local}
  function CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; _val: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_cleanup_local}
  function CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TidC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM CRYPTO_THREAD_get_current_id}
  function CRYPTO_THREAD_get_current_id: CRYPTO_THREAD_ID cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM CRYPTO_THREAD_compare_id}
  function CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OSSL_LIB_CTX_new}
  function OSSL_LIB_CTX_new : POSSL_LIB_CTX; cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_new_from_dispatch}
  function OSSL_LIB_CTX_new_from_dispatch(const handle : POSSL_CORE_HANDLE; const _in : POSSL_DISPATCH) : POSSL_LIB_CTX cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_new_child}
  function OSSL_LIB_CTX_new_child(const handle : POSSL_CORE_HANDLE; const _in : POSSL_DISPATCH) : POSSL_LIB_CTX cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_load_config}
  function OSSL_LIB_CTX_load_config(ctx : POSSL_LIB_CTX; const config_file : PIdAnsiChar) : TIdC_INT cdecl; external CLibCrypto;  {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_free}
  procedure OSSL_LIB_CTX_free(ctx : POSSL_LIB_CTX) cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_get0_global_default}
  function OSSL_LIB_CTX_get0_global_default : POSSL_LIB_CTX cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_LIB_CTX_set0_default}
  function OSSL_LIB_CTX_set0_default(libctx : POSSL_LIB_CTX) : POSSL_LIB_CTX cdecl; external CLibCrypto; {introduced 3.0.0}

  {$EXTERNALSYM OPENSSL_malloc}
  function OPENSSL_malloc(num: TIdC_SIZET): Pointer; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_zalloc}
function OPENSSL_zalloc(num: TIdC_SIZET): Pointer; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_realloc}
function OPENSSL_realloc(address: Pointer; num: TIdC_SIZET): Pointer; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_clear_realloc}
function OPENSSL_clear_realloc(address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET): Pointer; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_clear_free}
procedure OPENSSL_clear_free(address: Pointer; num: TIdC_SIZET); {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_free}
procedure OPENSSL_free(address: Pointer); {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_memdup}
function OPENSSL_memdup(const _str: Pointer; s: TIdC_SIZET): Pointer; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_strdup}
function OPENSSL_strdup(const _str: PIdAnsiChar): PIdAnsiChar; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_strndup}
function OPENSSL_strndup(const _str: PIdAnsiChar; n: TIdC_SIZET): PIdAnsiChar; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_malloc}
function OPENSSL_secure_malloc(num: TIdC_SIZET): Pointer; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_zalloc}
function OPENSSL_secure_zalloc(num: TIdC_SIZET): Pointer; {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_free}
procedure OPENSSL_secure_free(address: Pointer); {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_clear_free}
procedure OPENSSL_secure_clear_free(address: Pointer; num: TIdC_SIZET); {removed 1.0.0}
  {$EXTERNALSYM OPENSSL_secure_actual_size}
function OPENSSL_secure_actual_size(_ptr: Pointer): TIdC_SIZET; {removed 1.0.0}
  {$EXTERNALSYM CRYPTO_num_locks}
  function CRYPTO_num_locks: TIdC_INT; {removed 1.1.0}
  {$EXTERNALSYM CRYPTO_set_locking_callback}
  procedure CRYPTO_set_locking_callback(func: TIdSslLockingCallback); {removed 1.1.0}
  {$EXTERNALSYM CRYPTO_THREADID_set_numeric}
  procedure CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; _val: TIdC_ULONG); {removed 1.1.0}
  {$EXTERNALSYM CRYPTO_THREADID_set_callback}
  procedure CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); {removed 1.1.0}
  {$EXTERNALSYM CRYPTO_set_id_callback}
  procedure CRYPTO_set_id_callback(func: TIdSslIdCallback); {removed 1.1.0}
  {$EXTERNALSYM FIPS_mode}
  function FIPS_mode: TIdC_INT; {removed 3.0.0}
  {$EXTERNALSYM FIPS_mode_set}
  function FIPS_mode_set(r: TIdC_INT): TIdC_INT; {removed 3.0.0}
  {$EXTERNALSYM SSLeay_version}
  function SSLeay_version(type_ : TIdC_INT) : PIdAnsiChar; {removed 1.1.0}
  {$EXTERNALSYM SSLeay}
  function SSLeay: TIdC_ULONG; {removed 1.1.0}
{$ENDIF}

//Moved here to prevent circular unit depedency
  {$EXTERNALSYM BIO_get_ex_new_index}
function BIO_get_ex_new_index(l : TIdC_LONG; p : PBIO;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

//#define BIO_get_ex_new_index(l, p, newf, dupf, freef) \
//    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)

function BIO_get_ex_new_index(l : TIdC_LONG; p : PBIO;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef);
end;

const
  CRYPTO_THREAD_lock_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_read_lock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_write_lock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_unlock_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_lock_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_atomic_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_strlcpy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_strlcat_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_strnlen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_buf2hexstr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_hexstr2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_hexchar2int_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OpenSSL_version_num_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OpenSSL_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_info_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  CRYPTO_set_mem_debug_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_zalloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_memdup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_strndup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_clear_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_clear_realloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_malloc_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_malloc_done_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_malloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_zalloc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_clear_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_allocated_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_malloc_initialized_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_actual_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_secure_used_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_init_crypto_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_thread_stop_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_INIT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_INIT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_run_once_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_get_local_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_set_local_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_cleanup_local_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_get_current_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREAD_compare_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_malloc_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_zalloc_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_realloc_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_clear_realloc_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_clear_free_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_free_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_memdup_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_strdup_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_strndup_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_secure_malloc_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_secure_zalloc_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_secure_free_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_secure_clear_free_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  OPENSSL_secure_actual_size_removed = (byte(1) shl 8 or byte(0)) shl 8 or byte(0);
  CRYPTO_mem_ctrl_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  CRYPTO_num_locks_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_set_locking_callback_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREADID_set_numeric_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_THREADID_set_callback_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_set_id_callback_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CRYPTO_set_mem_debug_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  FIPS_mode_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  FIPS_mode_set_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  SSLeay_version_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SSLeay_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_LIB_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);  {removed 1.1.0}
  OSSL_LIB_CTX_new_from_dispatch_introduced  = (byte(3) shl 8 or byte(0)) shl 8 or byte(0); {removed 1.1.0}
  OSSL_LIB_CTX_new_child_introduced  = (byte(3) shl 8 or byte(0)) shl 8 or byte(0); {removed 1.1.0}
  OSSL_LIB_CTX_load_config_introduced  = (byte(3) shl 8 or byte(0)) shl 8 or byte(0); {removed 1.1.0}
  OSSL_LIB_CTX_free_introduced  = (byte(3) shl 8 or byte(0)) shl 8 or byte(0); {removed 1.1.0}
  OSSL_LIB_CTX_get0_global_default_introduced  = (byte(3) shl 8 or byte(0)) shl 8 or byte(0); {removed 1.1.0}
  OSSL_LIB_CTX_set0_default_introduced  = (byte(3) shl 8 or byte(0)) shl 8 or byte(0); {removed 1.1.0}

// OPENSSL_FILE = __FILE__ = C preprocessor macro
// OPENSSL_LINE = __LINE__ = C preprocessor macro
// FPC hase an equivalent with {$I %FILE%} and {$I %LINENUM%}, see https://www.freepascal.org/docs-html/prog/progsu41.html#x47-460001.1.41
// Delphi has nothing :(

//# define OPENSSL_malloc(num) CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  OPENSSL_malloc_procname = 'OPENSSL_malloc'; {removed 1.0.0}
  OPENSSL_zalloc_procname = 'OPENSSL_zalloc'; {removed 1.0.0}
  OPENSSL_realloc_procname = 'OPENSSL_realloc'; {removed 1.0.0}
  OPENSSL_clear_realloc_procname = 'OPENSSL_clear_realloc'; {removed 1.0.0}
  OPENSSL_clear_free_procname = 'OPENSSL_clear_free'; {removed 1.0.0}
  OPENSSL_free_procname = 'OPENSSL_free'; {removed 1.0.0}
  OPENSSL_memdup_procname = 'OPENSSL_memdup'; {removed 1.0.0}
  OPENSSL_strdup_procname = 'OPENSSL_strdup'; {removed 1.0.0}
  OPENSSL_strndup_procname = 'OPENSSL_strndup'; {removed 1.0.0}
  OPENSSL_secure_malloc_procname = 'OPENSSL_secure_malloc'; {removed 1.0.0}
  OPENSSL_secure_zalloc_procname = 'OPENSSL_secure_zalloc'; {removed 1.0.0}
  OPENSSL_secure_free_procname = 'OPENSSL_secure_free'; {removed 1.0.0}
  OPENSSL_secure_clear_free_procname = 'OPENSSL_secure_clear_free'; {removed 1.0.0}
  OPENSSL_secure_actual_size_procname = 'OPENSSL_secure_actual_size'; {removed 1.0.0}

  CRYPTO_THREAD_lock_new_procname = 'CRYPTO_THREAD_lock_new'; {introduced 1.1.0}
  CRYPTO_THREAD_read_lock_procname = 'CRYPTO_THREAD_read_lock'; {introduced 1.1.0}
  CRYPTO_THREAD_write_lock_procname = 'CRYPTO_THREAD_write_lock'; {introduced 1.1.0}
  CRYPTO_THREAD_unlock_procname = 'CRYPTO_THREAD_unlock'; {introduced 1.1.0}
  CRYPTO_THREAD_lock_free_procname = 'CRYPTO_THREAD_lock_free'; {introduced 1.1.0}

  CRYPTO_atomic_add_procname = 'CRYPTO_atomic_add'; {introduced 1.1.0}

  CRYPTO_mem_ctrl_procname = 'CRYPTO_mem_ctrl'; {removed 3.0.0}

  OPENSSL_strlcpy_procname = 'OPENSSL_strlcpy'; {introduced 1.1.0}
  OPENSSL_strlcat_procname = 'OPENSSL_strlcat'; {introduced 1.1.0}
  OPENSSL_strnlen_procname = 'OPENSSL_strnlen'; {introduced 1.1.0}
  OPENSSL_buf2hexstr_procname = 'OPENSSL_buf2hexstr'; {introduced 1.1.0}
  OPENSSL_hexstr2buf_procname = 'OPENSSL_hexstr2buf'; {introduced 1.1.0}
  OPENSSL_hexchar2int_procname = 'OPENSSL_hexchar2int'; {introduced 1.1.0}

  // # define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))

  OpenSSL_version_num_procname = 'OpenSSL_version_num'; {introduced 1.1.0}
  OpenSSL_version_procname = 'OpenSSL_version'; {introduced 1.1.0}
  OPENSSL_info_procname = 'OPENSSL_info'; {introduced 3.0.0}

  OPENSSL_issetugid_procname = 'OPENSSL_issetugid';

  (* No longer use an index. *)
  //function CRYPTO_free_ex_index(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT;

  (*
   * Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a
   * given class (invokes whatever per-class callbacks are applicable)
   *)
  CRYPTO_new_ex_data_procname = 'CRYPTO_new_ex_data';
  CRYPTO_dup_ex_data_procname = 'CRYPTO_dup_ex_data';

  CRYPTO_free_ex_data_procname = 'CRYPTO_free_ex_data';

  (*
   * Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular
   * index (relative to the class type involved)
   *)
  CRYPTO_set_ex_data_procname = 'CRYPTO_set_ex_data';
  CRYPTO_get_ex_data_procname = 'CRYPTO_get_ex_data';

  ///*
  // * The old locking functions have been removed completely without compatibility
  // * macros. This is because the old functions either could not properly report
  // * errors, or the returned error values were not clearly documented.
  // * Replacing the locking functions with no-ops would cause race condition
  // * issues in the affected applications. It is far better for them to fail at
  // * compile time.
  // * On the other hand, the locking callbacks are no longer used.  Consequently,
  // * the callback management functions can be safely replaced with no-op macros.
  // */
  //#  define CRYPTO_num_locks()            (1)
  CRYPTO_num_locks_procname = 'CRYPTO_num_locks'; {removed 1.1.0}
  //#  define CRYPTO_set_locking_callback(func)
  //#  define CRYPTO_get_locking_callback()         (NULL)
  //#  define CRYPTO_set_add_lock_callback(func)
  //#  define CRYPTO_get_add_lock_callback()        (NULL)
  CRYPTO_set_locking_callback_procname = 'CRYPTO_set_locking_callback'; {removed 1.1.0}

  ///* Only use CRYPTO_THREADID_set_[numeric|pointer]() within callbacks */
  //#  define CRYPTO_THREADID_set_numeric(id, val)
  CRYPTO_THREADID_set_numeric_procname = 'CRYPTO_THREADID_set_numeric'; {removed 1.1.0}
  //#  define CRYPTO_THREADID_set_pointer(id, ptr)
  //#  define CRYPTO_THREADID_set_callback(threadid_func)   (0)
  CRYPTO_THREADID_set_callback_procname = 'CRYPTO_THREADID_set_callback'; {removed 1.1.0}
  //#  define CRYPTO_THREADID_get_callback()                (NULL)
  //#  define CRYPTO_THREADID_current(id)
  //#  define CRYPTO_THREADID_cmp(a, b)                     (-1)
  //#  define CRYPTO_THREADID_cpy(dest, src)
  //#  define CRYPTO_THREADID_hash(id)                      (0UL)

  CRYPTO_set_id_callback_procname = 'CRYPTO_set_id_callback'; {removed 1.1.0}
  //
  //#  define CRYPTO_set_dynlock_create_callback(dyn_create_function)
  //#  define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
  //#  define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
  //#  define CRYPTO_get_dynlock_create_callback()          (NULL)
  //#  define CRYPTO_get_dynlock_lock_callback()            (NULL)
  //#  define CRYPTO_get_dynlock_destroy_callback()         (NULL)
  //# endif /* OPENSSL_API_COMPAT < 0x10100000L */

  CRYPTO_set_mem_functions_procname = 'CRYPTO_set_mem_functions';
  CRYPTO_set_mem_debug_procname = 'CRYPTO_set_mem_debug'; {introduced 1.1.0 removed 3.0.0}
    //void CRYPTO_get_mem_functions(
  //        void *(**m) (TIdC_SIZET, const char *, int),
  //        void *(**r) (void *, TIdC_SIZET, const char *, int),
  //        void (**f) (void *, const char *, int));

  CRYPTO_malloc_procname = 'CRYPTO_malloc';
  CRYPTO_zalloc_procname = 'CRYPTO_zalloc'; {introduced 1.1.0}
  CRYPTO_memdup_procname = 'CRYPTO_memdup'; {introduced 1.1.0}
  CRYPTO_strdup_procname = 'CRYPTO_strdup';
  CRYPTO_strndup_procname = 'CRYPTO_strndup'; {introduced 1.1.0}
  CRYPTO_free_procname = 'CRYPTO_free';
  CRYPTO_clear_free_procname = 'CRYPTO_clear_free'; {introduced 1.1.0}
  CRYPTO_realloc_procname = 'CRYPTO_realloc';
  CRYPTO_clear_realloc_procname = 'CRYPTO_clear_realloc'; {introduced 1.1.0}

  CRYPTO_secure_malloc_init_procname = 'CRYPTO_secure_malloc_init'; {introduced 1.1.0}
  CRYPTO_secure_malloc_done_procname = 'CRYPTO_secure_malloc_done'; {introduced 1.1.0}
  CRYPTO_secure_malloc_procname = 'CRYPTO_secure_malloc'; {introduced 1.1.0}
  CRYPTO_secure_zalloc_procname = 'CRYPTO_secure_zalloc'; {introduced 1.1.0}
  CRYPTO_secure_free_procname = 'CRYPTO_secure_free'; {introduced 1.1.0}
  CRYPTO_secure_clear_free_procname = 'CRYPTO_secure_clear_free'; {introduced 1.1.0}
  CRYPTO_secure_allocated_procname = 'CRYPTO_secure_allocated'; {introduced 1.1.0}
  CRYPTO_secure_malloc_initialized_procname = 'CRYPTO_secure_malloc_initialized'; {introduced 1.1.0}
  CRYPTO_secure_actual_size_procname = 'CRYPTO_secure_actual_size'; {introduced 1.1.0}
  CRYPTO_secure_used_procname = 'CRYPTO_secure_used'; {introduced 1.1.0}
  CRYPTO_get_ex_new_index_procname = 'CRYPTO_get_ex_new_index';

  OPENSSL_cleanse_procname = 'OPENSSL_cleanse';

  (* debug libraries only  *)
//  function CRYPTO_mem_debug_push(const info: PIdAnsiChar; const file_: PIdAnsiChar; line: TIdC_INT): TIdC_INT;
//  function CRYPTO_mem_debug_pop: TIdC_INT;
//  procedure CRYPTO_get_alloc_counts(mcount: PIdC_INT; rcount: PIdC_INT; fcount: PIdC_INT);

  (*
   * Debugging functions (enabled by CRYPTO_set_mem_debug(1))
   * The flag argument has the following significance:
   *   0:   called before the actual memory allocation has taken place
   *   1:   called after the actual memory allocation has taken place
   *)

//  procedure CRYPTO_mem_debug_malloc(address: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_realloc(addr1: Pointer; addr2: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_free(address: Pointer; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);

//  function CRYPTO_mem_leaks_cb(cb: CRYPTO_mem_leaks_cb_cb; u: Pointer): TIdC_INT;

//  function CRYPTO_mem_leaks_fp(&FILE: Pointer): TIdC_INT;
//  function CRYPTO_mem_leaks(BIO: PBIO): TIdC_INT;

  //* die if we have to */
  //ossl_noreturn void OPENSSL_die(const char *assertion, const char *file, int line);

  //# define OPENSSL_assert(e) \
  //    (void)((e) ? 0 : (OPENSSL_die("assertion failed: " #e, OPENSSL_FILE, OPENSSL_LINE), 1))

  OPENSSL_isservice_procname = 'OPENSSL_isservice';

  FIPS_mode_procname = 'FIPS_mode'; {removed 3.0.0}
  FIPS_mode_set_procname = 'FIPS_mode_set'; {removed 3.0.0}

  OPENSSL_init_procname = 'OPENSSL_init';

  // struct tm *OPENSSL_gmtime(const TIdC_TIMET *timer, struct tm *result);

  //function OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec): TIdC_INT;
  //function OPENSSL_gmtime_diff(int *pday, int *psec, const struct tm *from, const struct tm *to): TIdC_INT;

  (*
   * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
   * It takes an amount of time dependent on |len|, but independent of the
   * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
   * into a defined order as the return value when a != b is undefined, other
   * than to be non-zero.
   *)
  CRYPTO_memcmp_procname = 'CRYPTO_memcmp';

  (* Library initialisation functions *)
  OPENSSL_cleanup_procname = 'OPENSSL_cleanup'; {introduced 1.1.0}
  OPENSSL_init_crypto_procname = 'OPENSSL_init_crypto'; {introduced 1.1.0}
  // int OPENSSL_atexit(void (*handler)(void));
  OPENSSL_thread_stop_procname = 'OPENSSL_thread_stop'; {introduced 1.1.0}

  (* Low-level control of initialization *)
  OPENSSL_INIT_new_procname = 'OPENSSL_INIT_new'; {introduced 1.1.0}
  //int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings,
  //                                     const char *config_filename);
  //void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings,
  //                                        unsigned long flags);
  //int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings,
  //                                    const char *config_appname);
  OPENSSL_INIT_free_procname = 'OPENSSL_INIT_free'; {introduced 1.1.0}

  CRYPTO_THREAD_run_once_procname = 'CRYPTO_THREAD_run_once'; {introduced 1.1.0}

  //type
  //  CRYPTO_THREAD_init_local_cleanup = procedure(v1: Pointer);
  //
  //function CRYPTO_THREAD_init_local(key: PCRYPTO_THREAD_LOCAL; cleanup: CRYPTO_THREAD_init_local_cleanup): TIdC_INT;
  CRYPTO_THREAD_get_local_procname = 'CRYPTO_THREAD_get_local'; {introduced 1.1.0}
  CRYPTO_THREAD_set_local_procname = 'CRYPTO_THREAD_set_local'; {introduced 1.1.0}
  CRYPTO_THREAD_cleanup_local_procname = 'CRYPTO_THREAD_cleanup_local'; {introduced 1.1.0}

  CRYPTO_THREAD_get_current_id_procname = 'CRYPTO_THREAD_get_current_id'; {introduced 1.1.0}
  CRYPTO_THREAD_compare_id_procname = 'CRYPTO_THREAD_compare_id'; {introduced 1.1.0}

  SSLeay_version_procname = 'SSLeay_version'; {removed 1.1.0}
  SSLeay_procname = 'SSLeay'; {removed 1.1.0}

  OSSL_LIB_CTX_new_procname = 'OSSL_LIB_CTX_new';
  OSSL_LIB_CTX_new_from_dispatch_procname = 'OSSL_LIB_CTX_new_from_dispatch';
  OSSL_LIB_CTX_new_child_procname = 'OSSL_LIB_CTX_new_child';
  OSSL_LIB_CTX_load_config_procname = 'OSSL_LIB_CTX_load_config';
  OSSL_LIB_CTX_free_procname = 'OSSL_LIB_CTX_free';
  OSSL_LIB_CTX_get0_global_default_procname = 'OSSL_LIB_CTX_get0_global_default';
  OSSL_LIB_CTX_set0_default_procname = 'OSSL_LIB_CTX_set0_default';

  {$IFNDEF _FIXINSIGHT_}
// OPENSSL_FILE = __FILE__ = C preprocessor macro
// OPENSSL_LINE = __LINE__ = C preprocessor macro
// FPC hase an equivalent with {$I %FILE%} and {$I %LINENUM%}, see https://www.freepascal.org/docs-html/prog/progsu41.html#x47-460001.1.41
// Delphi has nothing :(

//# define OPENSSL_malloc(num) CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_malloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  Result := CRYPTO_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_zalloc(num) CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_zalloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  Result := CRYPTO_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_realloc(address, num) CRYPTO_realloc(address, num, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_realloc(address: Pointer; num: TIdC_SIZET): Pointer; cdecl;
begin
  Result := CRYPTO_realloc(address, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_realloc(address, old_num, num) CRYPTO_clear_realloc(address, old_num, num, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_clear_realloc(address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET): Pointer; cdecl;
begin
  Result := CRYPTO_clear_realloc(address, old_num, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_free(address, num) CRYPTO_clear_free(address, num, OPENSSL_FILE, OPENSSL_LINE)
procedure  _OPENSSL_clear_free(address: Pointer; num: TIdC_SIZET); cdecl;
begin
  CRYPTO_clear_free(address, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_free(addr) CRYPTO_free(address, OPENSSL_FILE, OPENSSL_LINE)
procedure  _OPENSSL_free(address: Pointer); cdecl;
begin
  CRYPTO_free(address, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_memdup(str, s) CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_memdup(const _str: Pointer; s: TIdC_SIZET): Pointer; cdecl;
begin
  Result := CRYPTO_memdup(_str, s, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strdup(str) CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_strdup(const _str: PIdAnsiChar): PIdAnsiChar; cdecl;
begin
  Result := CRYPTO_strdup(_str, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strndup(str, n) CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_strndup(const _str: PIdAnsiChar; n: TIdC_SIZET): PIdAnsiChar; cdecl;
begin
  Result := CRYPTO_strndup(_str, n, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_malloc(num) CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_secure_malloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  Result := CRYPTO_secure_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_zalloc(num) CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
function  _OPENSSL_secure_zalloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  Result := CRYPTO_secure_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_free(addr) CRYPTO_secure_free(address, OPENSSL_FILE, OPENSSL_LINE)
procedure  _OPENSSL_secure_free(address: Pointer); cdecl;
begin
  CRYPTO_secure_free(address, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_clear_free(address, num) CRYPTO_secure_clear_free(address, num, OPENSSL_FILE, OPENSSL_LINE)
procedure  _OPENSSL_secure_clear_free(address: Pointer; num: TIdC_SIZET); cdecl;
begin
  CRYPTO_secure_clear_free(address, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_actual_size(ptr) CRYPTO_secure_actual_size(ptr)
function  _OPENSSL_secure_actual_size(_ptr: Pointer): TIdC_SIZET; cdecl;
begin
  Result := CRYPTO_secure_actual_size(_ptr);
end;

function  _CRYPTO_num_locks: TIdC_INT; cdecl;
begin
  Result := 0;
end;

procedure  _CRYPTO_set_locking_callback(func: TIdSslLockingCallback); cdecl;
begin
end;  //PALOFF - Empty begin/end-blocks

{$I TaurusTLSUnusedParamOff.inc}
procedure  _CRYPTO_set_id_callback(func: TIdSslIdCallback); cdecl;
begin
end;  //PALOFF  - Empty begin/end-blocks

function  _SSLeay_version(type_ : TIdC_INT) : PIdAnsiChar; cdecl;
begin
  Result := OpenSSL_version(type_);
end;

function  _SSLeay: TIdC_ULONG; cdecl;
begin
  Result := OpenSSL_version_num();
end;

procedure  _CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; _val: TIdC_ULONG); cdecl;
begin
end;   //PALOFF Empty begin/end-blocks

procedure  _CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); cdecl;
begin
end;    //PALOFF - Empty begin/end-blocks

  {$I TaurusTLSUnusedParamOff.inc}

function  _FIPS_mode: TIdC_INT; cdecl;
begin
  Result := OSSL_PROVIDER_available(nil,PIdAnsiChar(AnsiString('fips')));
end;

var fips_provider: POSSL_PROVIDER;
    base_provider: POSSL_PROVIDER;

function  _FIPS_mode_set(r: TIdC_INT): TIdC_INT; cdecl;
begin
  if r = 0 then
  begin
    if base_provider <> nil then
    begin
      OSSL_PROVIDER_unload(base_provider); //PALOFF - Functions called as procedures
      base_provider := nil;
    end;

    if fips_provider <> nil then
    begin
       OSSL_PROVIDER_unload(fips_provider); //PALOFF - Functions called as procedures
       fips_provider := nil;
    end;
    Result := 1;
  end
  else
  begin
     Result := 0;
     fips_provider := OSSL_PROVIDER_load(nil, PIdAnsiChar(AnsiString('fips')));
     if fips_provider = nil then
       Exit;
     base_provider := OSSL_PROVIDER_load(nil, PIdAnsiChar(AnsiString('base')));
     if base_provider = nil then
     begin
       OSSL_PROVIDER_unload(fips_provider);  //PALOFF - Functions called as procedures
       fips_provider := nil;
       Exit;
     end;
     Result := 1;
  end;
end;

{forward_compatibility}

{$I TaurusTLSUnusedParamOff.inc}
function  FC_OPENSSL_init_crypto(opts: TIdC_UINT64; const settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl;
begin
  if opts and OPENSSL_INIT_ADD_ALL_CIPHERS <> 0 then
    OpenSSL_add_all_ciphers;
  if opts and OPENSSL_INIT_ADD_ALL_DIGESTS <> 0 then
    OpenSSL_add_all_digests;
  Result := 1;
end;

function FC_OPENSSL_info(type_: TIdC_INT): PIdAnsiChar; cdecl;
begin
  Result := PIdAnsiChar('');
end;

{$I TaurusTLSUnusedParamOn.inc}

procedure  FC_OPENSSL_cleanup; cdecl;
begin
 {nothing to do}
end;       //PALOFF

{/forward_compatibility}
  {$I TaurusTLSNoRetValOff.inc}
function  ERR_OPENSSL_malloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_malloc_procname);
end;


function  ERR_OPENSSL_zalloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_zalloc_procname);
end;


function  ERR_OPENSSL_realloc(address: Pointer; num: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_realloc_procname);
end;


function  ERR_OPENSSL_clear_realloc(address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_clear_realloc_procname);
end;


procedure  ERR_OPENSSL_clear_free(address: Pointer; num: TIdC_SIZET); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_clear_free_procname);
end;


procedure  ERR_OPENSSL_free(address: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_free_procname);
end;


function  ERR_OPENSSL_memdup(const _str: Pointer; s: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_memdup_procname);
end;

 
function  ERR_OPENSSL_strdup(const _str: PIdAnsiChar): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strdup_procname);
end;


function  ERR_OPENSSL_strndup(const _str: PIdAnsiChar; n: TIdC_SIZET): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strndup_procname);
end;


function  ERR_OPENSSL_secure_malloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_secure_malloc_procname);
end;


function  ERR_OPENSSL_secure_zalloc(num: TIdC_SIZET): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_secure_zalloc_procname);
end;


procedure  ERR_OPENSSL_secure_free(address: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_secure_free_procname);
end;


procedure  ERR_OPENSSL_secure_clear_free(address: Pointer; num: TIdC_SIZET); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_secure_clear_free_procname);
end;


function  ERR_OPENSSL_secure_actual_size(_ptr: Pointer): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_secure_actual_size_procname);
end;

 

function  ERR_CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_lock_new_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_read_lock_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_write_lock_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_unlock_procname);
end;

 {introduced 1.1.0}
procedure  ERR_CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_lock_free_procname);
end;

 {introduced 1.1.0}

function  ERR_CRYPTO_atomic_add(_val: PIdC_INT; amount: TIdC_INT; ret: PIdC_INT;
  lock: PCRYPTO_RWLOCK): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_atomic_add_procname);
end;

 {introduced 1.1.0}

function  ERR_CRYPTO_mem_ctrl(mode: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_mem_ctrl_procname);
end;



function  ERR_OPENSSL_strlcpy(dst: PIdAnsiChar; const src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strlcpy_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_strlcat(dst: PIdAnsiChar; const src: PIdAnsiChar; siz: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strlcat_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_strnlen(const _str: PIdAnsiChar; maxlen: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_strnlen_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_buf2hexstr(const buffer: PByte; len: TIdC_LONG): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_buf2hexstr_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_hexstr2buf(const _str: PIdAnsiChar; len: PIdC_LONG): PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_hexstr2buf_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_hexchar2int(c: Byte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_hexchar2int_procname);
end;

 {introduced 1.1.0}

  // # define OPENSSL_MALLOC_MAX_NELEMS(type)  (((1U<<(sizeof(int)*8-1))-1)/sizeof(type))

function  ERR_OpenSSL_version_num: TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OpenSSL_version_num_procname);
end;

 {introduced 1.1.0}
function  ERR_OpenSSL_version(type_: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OpenSSL_version_procname);
end;

function ERR_OPENSSL_info(type_: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_info_procname);
end;

 {introduced 1.1.0}

function  ERR_OPENSSL_issetugid: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_issetugid_procname);
end;



  (* No longer use an index. *)
  //function CRYPTO_free_ex_index(class_index: TIdC_INT; idx: TIdC_INT): TIdC_INT;

  (*
   * Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a
   * given class (invokes whatever per-class callbacks are applicable)
   *)
function  ERR_CRYPTO_new_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_new_ex_data_procname);
end;


function  ERR_CRYPTO_dup_ex_data(class_index: TIdC_INT; to_: PCRYPTO_EX_DATA;
  const from: PCRYPTO_EX_DATA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_dup_ex_data_procname);
end;



procedure  ERR_CRYPTO_free_ex_data(class_index: TIdC_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_free_ex_data_procname);
end;



  (*
   * Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular
   * index (relative to the class type involved)
   *)
function  ERR_CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TIdC_INT; _val: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_set_ex_data_procname);
end;


function  ERR_CRYPTO_get_ex_data(const ad: PCRYPTO_EX_DATA; idx: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_get_ex_data_procname);
end;



  ///*
  // * The old locking functions have been removed completely without compatibility
  // * macros. This is because the old functions either could not properly report
  // * errors, or the returned error values were not clearly documented.
  // * Replacing the locking functions with no-ops would cause race condition
  // * issues in the affected applications. It is far better for them to fail at
  // * compile time.
  // * On the other hand, the locking callbacks are no longer used.  Consequently,
  // * the callback management functions can be safely replaced with no-op macros.
  // */
  //#  define CRYPTO_num_locks()            (1)
function  ERR_CRYPTO_num_locks: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_num_locks_procname);
end;


  //#  define CRYPTO_set_locking_callback(func)
  //#  define CRYPTO_get_locking_callback()         (NULL)
  //#  define CRYPTO_set_add_lock_callback(func)
  //#  define CRYPTO_get_add_lock_callback()        (NULL)
procedure  ERR_CRYPTO_set_locking_callback(func: TIdSslLockingCallback); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_set_locking_callback_procname);
end;



  ///* Only use CRYPTO_THREADID_set_[numeric|pointer]() within callbacks */
  //#  define CRYPTO_THREADID_set_numeric(id, val)
procedure  ERR_CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; _val: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREADID_set_numeric_procname);
end;

 
  //#  define CRYPTO_THREADID_set_pointer(id, ptr)
  //#  define CRYPTO_THREADID_set_callback(threadid_func)   (0)
procedure  ERR_CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREADID_set_callback_procname);
end;


  //#  define CRYPTO_THREADID_get_callback()                (NULL)
  //#  define CRYPTO_THREADID_current(id)
  //#  define CRYPTO_THREADID_cmp(a, b)                     (-1)
  //#  define CRYPTO_THREADID_cpy(dest, src)
  //#  define CRYPTO_THREADID_hash(id)                      (0UL)

procedure  ERR_CRYPTO_set_id_callback(func: TIdSslIdCallback); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_set_id_callback_procname);
end;


  //
  //#  define CRYPTO_set_dynlock_create_callback(dyn_create_function)
  //#  define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
  //#  define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
  //#  define CRYPTO_get_dynlock_create_callback()          (NULL)
  //#  define CRYPTO_get_dynlock_lock_callback()            (NULL)
  //#  define CRYPTO_get_dynlock_destroy_callback()         (NULL)
  //# endif /* OPENSSL_API_COMPAT < 0x10100000L */

function  ERR_CRYPTO_set_mem_functions(m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r;
  f: CRYPTO_set_mem_functions_f): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_set_mem_functions_procname);
end;


function  ERR_CRYPTO_set_mem_debug(flag: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_set_mem_debug_procname);
end;


    //void CRYPTO_get_mem_functions(
  //        void *(**m) (TIdC_SIZET, const char *, int),
  //        void *(**r) (void *, TIdC_SIZET, const char *, int),
  //        void (**f) (void *, const char *, int));

function  ERR_CRYPTO_malloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_malloc_procname);
end;


function  ERR_CRYPTO_zalloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_zalloc_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_memdup(const _str: Pointer; siz: TIdC_SIZET; const file_: PIdAnsiChar;
  line: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_memdup_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_strdup(const _str: PIdAnsiChar; const file_: PIdAnsiChar;
  line: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_strdup_procname);
end;


function  ERR_CRYPTO_strndup(const _str: PIdAnsiChar; s: TIdC_SIZET; const file_: PIdAnsiChar;
  line: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_strndup_procname);
end;

 {introduced 1.1.0}
procedure  ERR_CRYPTO_free(_ptr: Pointer; const file_: PIdAnsiChar; line: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_free_procname);
end;


procedure  ERR_CRYPTO_clear_free(_ptr: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_clear_free_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_realloc(address: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar;
  line: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_realloc_procname);
end;


function  ERR_CRYPTO_clear_realloc(address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET;
  const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_clear_realloc_procname);
end;

 {introduced 1.1.0}

function  ERR_CRYPTO_secure_malloc_init(sz: TIdC_SIZET; minsize: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_init_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_secure_malloc_done: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_done_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_secure_malloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_secure_zalloc(num: TIdC_SIZET; const file_: PIdAnsiChar; line: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_zalloc_procname);
end;

 {introduced 1.1.0}
procedure  ERR_CRYPTO_secure_free(_ptr: Pointer; const file_: PIdAnsiChar; line: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_free_procname);
end;

 {introduced 1.1.0}
procedure  ERR_CRYPTO_secure_clear_free(_ptr: Pointer; num: TIdC_SIZET; const file_: PIdAnsiChar;
  line: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_clear_free_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_secure_allocated(const _ptr: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_allocated_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_secure_malloc_initialized: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_malloc_initialized_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_secure_actual_size(_ptr: Pointer): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_actual_size_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_secure_used: TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_secure_used_procname);
end;

function ERR_CRYPTO_get_ex_new_index(class_index : TIdC_INT; arg1 : TIdC_LONG; argp : Pointer;
                                 new_func : CRYPTO_EX_new; dup_func : CRYPTO_EX_dup;
                                 free_func : CRYPTO_EX_FREE) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_get_ex_new_index_procname);
end;

 {introduced 1.1.0}

procedure  ERR_OPENSSL_cleanse(_ptr: Pointer; len: TIdC_SIZET); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_cleanse_procname);
end;



  (* debug libraries only  *)
//  function CRYPTO_mem_debug_push(const info: PIdAnsiChar; const file_: PIdAnsiChar; line: TIdC_INT): TIdC_INT;
//  function CRYPTO_mem_debug_pop: TIdC_INT;
//  procedure CRYPTO_get_alloc_counts(mcount: PIdC_INT; rcount: PIdC_INT; fcount: PIdC_INT);

  (*
   * Debugging functions (enabled by CRYPTO_set_mem_debug(1))
   * The flag argument has the following significance:
   *   0:   called before the actual memory allocation has taken place
   *   1:   called after the actual memory allocation has taken place
   *)

//  procedure CRYPTO_mem_debug_malloc(address: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_realloc(addr1: Pointer; addr2: Pointer; num: TIdC_SIZET; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);
//  procedure CRYPTO_mem_debug_free(address: Pointer; flag: TIdC_INT; const file_: PIdAnsiChar; line: TIdC_INT);

//  function CRYPTO_mem_leaks_cb(cb: CRYPTO_mem_leaks_cb_cb; u: Pointer): TIdC_INT;

//  function CRYPTO_mem_leaks_fp(&FILE: Pointer): TIdC_INT;
//  function CRYPTO_mem_leaks(BIO: PBIO): TIdC_INT;

  //* die if we have to */
  //ossl_noreturn void OPENSSL_die(const char *assertion, const char *file, int line);

  //# define OPENSSL_assert(e) \
  //    (void)((e) ? 0 : (OPENSSL_die("assertion failed: " #e, OPENSSL_FILE, OPENSSL_LINE), 1))

function  ERR_OPENSSL_isservice: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_isservice_procname);
end;



function  ERR_FIPS_mode: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(FIPS_mode_procname);
end;


function  ERR_FIPS_mode_set(r: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(FIPS_mode_set_procname);
end;

 

procedure  ERR_OPENSSL_init; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_init_procname);
end;



  // struct tm *OPENSSL_gmtime(const TIdC_TIMET *timer, struct tm *result);

  //function OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec): TIdC_INT;
  //function OPENSSL_gmtime_diff(int *pday, int *psec, const struct tm *from, const struct tm *to): TIdC_INT;

  (*
   * CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
   * It takes an amount of time dependent on |len|, but independent of the
   * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
   * into a defined order as the return value when a != b is undefined, other
   * than to be non-zero.
   *)
function  ERR_CRYPTO_memcmp(const in_a: Pointer; const in_b: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_memcmp_procname);
end;



  (* Library initialisation functions *)
procedure  ERR_OPENSSL_cleanup; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_cleanup_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_init_crypto(opts: TIdC_UINT64; const settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_init_crypto_procname);
end;

 {introduced 1.1.0}
  // int OPENSSL_atexit(void (*handler)(void));
procedure  ERR_OPENSSL_thread_stop; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_thread_stop_procname);
end;

 {introduced 1.1.0}

  (* Low-level control of initialization *)
function  ERR_OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_INIT_new_procname);
end;

 {introduced 1.1.0}
  //int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings,
  //                                     const char *config_filename);
  //void OPENSSL_INIT_set_config_file_flags(OPENSSL_INIT_SETTINGS *settings,
  //                                        unsigned long flags);
  //int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings,
  //                                    const char *config_appname);
procedure  ERR_OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_INIT_free_procname);
end;

 {introduced 1.1.0}

function  ERR_CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_run_once_procname);
end;

 {introduced 1.1.0}

  //type
  //  CRYPTO_THREAD_init_local_cleanup = procedure(v1: Pointer);
  //
  //function CRYPTO_THREAD_init_local(key: PCRYPTO_THREAD_LOCAL; cleanup: CRYPTO_THREAD_init_local_cleanup): TIdC_INT;
function  ERR_CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_get_local_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; _val: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_set_local_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TidC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_cleanup_local_procname);
end;

 {introduced 1.1.0}

function  ERR_CRYPTO_THREAD_get_current_id: CRYPTO_THREAD_ID; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_get_current_id_procname);
end;

 {introduced 1.1.0}
function  ERR_CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CRYPTO_THREAD_compare_id_procname);
end;

 {introduced 1.1.0}

function  ERR_SSLeay_version(type_ : TIdC_INT) : PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSLeay_version_procname);
end;

 
function  ERR_SSLeay: TIdC_ULONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSLeay_procname);
end;

function ERR_OSSL_LIB_CTX_new : POSSL_LIB_CTX; cdecl;  {introduced 3.0.0}
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_new_procname);
end;

function ERR_OSSL_LIB_CTX_new_from_dispatch(const handle : POSSL_CORE_HANDLE;
  const _in : POSSL_DISPATCH) : POSSL_LIB_CTX; cdecl; {introduced 3.0.0}
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_new_from_dispatch_procname);
end;

function ERR_OSSL_LIB_CTX_new_child(const handle : POSSL_CORE_HANDLE;
  const _in : POSSL_DISPATCH) : POSSL_LIB_CTX; cdecl; {introduced 3.0.0}
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_new_child_procname);
end;

function ERR_OSSL_LIB_CTX_load_config(ctx : POSSL_LIB_CTX;
  const config_file : PIdAnsiChar) : TIdC_INT; cdecl;  {introduced 3.0.0}
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_load_config_procname);
end;

procedure ERR_OSSL_LIB_CTX_free(ctx : POSSL_LIB_CTX); cdecl; {introduced 3.0.0}
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_free_procname);
end;

function ERR_OSSL_LIB_CTX_get0_global_default : POSSL_LIB_CTX; cdecl; {introduced 3.0.0}
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_get0_global_default_procname);
end;

function ERR_OSSL_LIB_CTX_set0_default(libctx : POSSL_LIB_CTX) : POSSL_LIB_CTX; cdecl; {introduced 3.0.0}
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_LIB_CTX_set0_default_procname);
end;

  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  OPENSSL_malloc := LoadLibFunction(ADllHandle, OPENSSL_malloc_procname);
  FuncLoadError := not assigned(OPENSSL_malloc);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_malloc_allownil)}
    OPENSSL_malloc := ERR_OPENSSL_malloc;
    {$ifend}
    {$if declared(OPENSSL_malloc_introduced)}
    if LibVersion < OPENSSL_malloc_introduced then
    begin
      {$if declared(FC_OPENSSL_malloc)}
      OPENSSL_malloc := FC_OPENSSL_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_malloc_removed)}
    if OPENSSL_malloc_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_malloc)}
      OPENSSL_malloc := _OPENSSL_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_malloc_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_malloc');
    {$ifend}
  end;

 
  OPENSSL_zalloc := LoadLibFunction(ADllHandle, OPENSSL_zalloc_procname);
  FuncLoadError := not assigned(OPENSSL_zalloc);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_zalloc_allownil)}
    OPENSSL_zalloc := ERR_OPENSSL_zalloc;
    {$ifend}
    {$if declared(OPENSSL_zalloc_introduced)}
    if LibVersion < OPENSSL_zalloc_introduced then
    begin
      {$if declared(FC_OPENSSL_zalloc)}
      OPENSSL_zalloc := FC_OPENSSL_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_zalloc_removed)}
    if OPENSSL_zalloc_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_zalloc)}
      OPENSSL_zalloc := _OPENSSL_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_zalloc_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_zalloc');
    {$ifend}
  end;

 
  OPENSSL_realloc := LoadLibFunction(ADllHandle, OPENSSL_realloc_procname);
  FuncLoadError := not assigned(OPENSSL_realloc);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_realloc_allownil)}
    OPENSSL_realloc := ERR_OPENSSL_realloc;
    {$ifend}
    {$if declared(OPENSSL_realloc_introduced)}
    if LibVersion < OPENSSL_realloc_introduced then
    begin
      {$if declared(FC_OPENSSL_realloc)}
      OPENSSL_realloc := FC_OPENSSL_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_realloc_removed)}
    if OPENSSL_realloc_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_realloc)}
      OPENSSL_realloc := _OPENSSL_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_realloc_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_realloc');
    {$ifend}
  end;

 
  OPENSSL_clear_realloc := LoadLibFunction(ADllHandle, OPENSSL_clear_realloc_procname);
  FuncLoadError := not assigned(OPENSSL_clear_realloc);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_clear_realloc_allownil)}
    OPENSSL_clear_realloc := ERR_OPENSSL_clear_realloc;
    {$ifend}
    {$if declared(OPENSSL_clear_realloc_introduced)}
    if LibVersion < OPENSSL_clear_realloc_introduced then
    begin
      {$if declared(FC_OPENSSL_clear_realloc)}
      OPENSSL_clear_realloc := FC_OPENSSL_clear_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_clear_realloc_removed)}
    if OPENSSL_clear_realloc_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_clear_realloc)}
      OPENSSL_clear_realloc := _OPENSSL_clear_realloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_clear_realloc_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_clear_realloc');
    {$ifend}
  end;

 
  OPENSSL_clear_free := LoadLibFunction(ADllHandle, OPENSSL_clear_free_procname);
  FuncLoadError := not assigned(OPENSSL_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_clear_free_allownil)}
    OPENSSL_clear_free := ERR_OPENSSL_clear_free;
    {$ifend}
    {$if declared(OPENSSL_clear_free_introduced)}
    if LibVersion < OPENSSL_clear_free_introduced then
    begin
      {$if declared(FC_OPENSSL_clear_free)}
      OPENSSL_clear_free := FC_OPENSSL_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_clear_free_removed)}
    if OPENSSL_clear_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_clear_free)}
      OPENSSL_clear_free := _OPENSSL_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_clear_free');
    {$ifend}
  end;

 
  OPENSSL_free := LoadLibFunction(ADllHandle, OPENSSL_free_procname);
  FuncLoadError := not assigned(OPENSSL_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_free_allownil)}
    OPENSSL_free := ERR_OPENSSL_free;
    {$ifend}
    {$if declared(OPENSSL_free_introduced)}
    if LibVersion < OPENSSL_free_introduced then
    begin
      {$if declared(FC_OPENSSL_free)}
      OPENSSL_free := FC_OPENSSL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_free_removed)}
    if OPENSSL_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_free)}
      OPENSSL_free := _OPENSSL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_free');
    {$ifend}
  end;

 
  OPENSSL_memdup := LoadLibFunction(ADllHandle, OPENSSL_memdup_procname);
  FuncLoadError := not assigned(OPENSSL_memdup);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_memdup_allownil)}
    OPENSSL_memdup := ERR_OPENSSL_memdup;
    {$ifend}
    {$if declared(OPENSSL_memdup_introduced)}
    if LibVersion < OPENSSL_memdup_introduced then
    begin
      {$if declared(FC_OPENSSL_memdup)}
      OPENSSL_memdup := FC_OPENSSL_memdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_memdup_removed)}
    if OPENSSL_memdup_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_memdup)}
      OPENSSL_memdup := _OPENSSL_memdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_memdup_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_memdup');
    {$ifend}
  end;

 
  OPENSSL_strdup := LoadLibFunction(ADllHandle, OPENSSL_strdup_procname);
  FuncLoadError := not assigned(OPENSSL_strdup);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strdup_allownil)}
    OPENSSL_strdup := ERR_OPENSSL_strdup;
    {$ifend}
    {$if declared(OPENSSL_strdup_introduced)}
    if LibVersion < OPENSSL_strdup_introduced then
    begin
      {$if declared(FC_OPENSSL_strdup)}
      OPENSSL_strdup := FC_OPENSSL_strdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strdup_removed)}
    if OPENSSL_strdup_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strdup)}
      OPENSSL_strdup := _OPENSSL_strdup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strdup_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strdup');
    {$ifend}
  end;

 
  OPENSSL_strndup := LoadLibFunction(ADllHandle, OPENSSL_strndup_procname);
  FuncLoadError := not assigned(OPENSSL_strndup);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_strndup_allownil)}
    OPENSSL_strndup := ERR_OPENSSL_strndup;
    {$ifend}
    {$if declared(OPENSSL_strndup_introduced)}
    if LibVersion < OPENSSL_strndup_introduced then
    begin
      {$if declared(FC_OPENSSL_strndup)}
      OPENSSL_strndup := FC_OPENSSL_strndup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_strndup_removed)}
    if OPENSSL_strndup_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_strndup)}
      OPENSSL_strndup := _OPENSSL_strndup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_strndup_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_strndup');
    {$ifend}
  end;

 
  OPENSSL_secure_malloc := LoadLibFunction(ADllHandle, OPENSSL_secure_malloc_procname);
  FuncLoadError := not assigned(OPENSSL_secure_malloc);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_secure_malloc_allownil)}
    OPENSSL_secure_malloc := ERR_OPENSSL_secure_malloc;
    {$ifend}
    {$if declared(OPENSSL_secure_malloc_introduced)}
    if LibVersion < OPENSSL_secure_malloc_introduced then
    begin
      {$if declared(FC_OPENSSL_secure_malloc)}
      OPENSSL_secure_malloc := FC_OPENSSL_secure_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_secure_malloc_removed)}
    if OPENSSL_secure_malloc_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_secure_malloc)}
      OPENSSL_secure_malloc := _OPENSSL_secure_malloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_secure_malloc_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_malloc');
    {$ifend}
  end;

 
  OPENSSL_secure_zalloc := LoadLibFunction(ADllHandle, OPENSSL_secure_zalloc_procname);
  FuncLoadError := not assigned(OPENSSL_secure_zalloc);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_secure_zalloc_allownil)}
    OPENSSL_secure_zalloc := ERR_OPENSSL_secure_zalloc;
    {$ifend}
    {$if declared(OPENSSL_secure_zalloc_introduced)}
    if LibVersion < OPENSSL_secure_zalloc_introduced then
    begin
      {$if declared(FC_OPENSSL_secure_zalloc)}
      OPENSSL_secure_zalloc := FC_OPENSSL_secure_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_secure_zalloc_removed)}
    if OPENSSL_secure_zalloc_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_secure_zalloc)}
      OPENSSL_secure_zalloc := _OPENSSL_secure_zalloc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_secure_zalloc_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_zalloc');
    {$ifend}
  end;

 
  OPENSSL_secure_free := LoadLibFunction(ADllHandle, OPENSSL_secure_free_procname);
  FuncLoadError := not assigned(OPENSSL_secure_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_secure_free_allownil)}
    OPENSSL_secure_free := ERR_OPENSSL_secure_free;
    {$ifend}
    {$if declared(OPENSSL_secure_free_introduced)}
    if LibVersion < OPENSSL_secure_free_introduced then
    begin
      {$if declared(FC_OPENSSL_secure_free)}
      OPENSSL_secure_free := FC_OPENSSL_secure_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_secure_free_removed)}
    if OPENSSL_secure_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_secure_free)}
      OPENSSL_secure_free := _OPENSSL_secure_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_secure_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_free');
    {$ifend}
  end;

 
  OPENSSL_secure_clear_free := LoadLibFunction(ADllHandle, OPENSSL_secure_clear_free_procname);
  FuncLoadError := not assigned(OPENSSL_secure_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_secure_clear_free_allownil)}
    OPENSSL_secure_clear_free := ERR_OPENSSL_secure_clear_free;
    {$ifend}
    {$if declared(OPENSSL_secure_clear_free_introduced)}
    if LibVersion < OPENSSL_secure_clear_free_introduced then
    begin
      {$if declared(FC_OPENSSL_secure_clear_free)}
      OPENSSL_secure_clear_free := FC_OPENSSL_secure_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_secure_clear_free_removed)}
    if OPENSSL_secure_clear_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_secure_clear_free)}
      OPENSSL_secure_clear_free := _OPENSSL_secure_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_secure_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_clear_free');
    {$ifend}
  end;

 
  OPENSSL_secure_actual_size := LoadLibFunction(ADllHandle, OPENSSL_secure_actual_size_procname);
  FuncLoadError := not assigned(OPENSSL_secure_actual_size);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_secure_actual_size_allownil)}
    OPENSSL_secure_actual_size := ERR_OPENSSL_secure_actual_size;
    {$ifend}
    {$if declared(OPENSSL_secure_actual_size_introduced)}
    if LibVersion < OPENSSL_secure_actual_size_introduced then
    begin
      {$if declared(FC_OPENSSL_secure_actual_size)}
      OPENSSL_secure_actual_size := FC_OPENSSL_secure_actual_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_secure_actual_size_removed)}
    if OPENSSL_secure_actual_size_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_secure_actual_size)}
      OPENSSL_secure_actual_size := _OPENSSL_secure_actual_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_secure_actual_size_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_actual_size');
    {$ifend}
  end;

 
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
  CRYPTO_mem_ctrl := LoadLibFunction(ADllHandle, CRYPTO_mem_ctrl_procname);
  FuncLoadError := not assigned(CRYPTO_mem_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_mem_ctrl_allownil)}
    CRYPTO_mem_ctrl := ERR_CRYPTO_mem_ctrl;
    {$ifend}
    {$if declared(CRYPTO_mem_ctrl_introduced)}
    if LibVersion < CRYPTO_mem_ctrl_introduced then
    begin
      {$if declared(FC_CRYPTO_mem_ctrl)}
      CRYPTO_mem_ctrl := FC_CRYPTO_mem_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_mem_ctrl_removed)}
    if CRYPTO_mem_ctrl_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_mem_ctrl)}
      CRYPTO_mem_ctrl := _CRYPTO_mem_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_mem_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_mem_ctrl');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 3.0.0}
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

 {introduced 1.1.0}
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


  CRYPTO_num_locks := LoadLibFunction(ADllHandle, CRYPTO_num_locks_procname);
  FuncLoadError := not assigned(CRYPTO_num_locks);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_num_locks_allownil)}
    CRYPTO_num_locks := ERR_CRYPTO_num_locks;
    {$ifend}
    {$if declared(CRYPTO_num_locks_introduced)}
    if LibVersion < CRYPTO_num_locks_introduced then
    begin
      {$if declared(FC_CRYPTO_num_locks)}
      CRYPTO_num_locks := FC_CRYPTO_num_locks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_num_locks_removed)}
    if CRYPTO_num_locks_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_num_locks)}
      CRYPTO_num_locks := _CRYPTO_num_locks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_num_locks_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_num_locks');
    {$ifend}
  end;

 
  CRYPTO_set_locking_callback := LoadLibFunction(ADllHandle, CRYPTO_set_locking_callback_procname);
  FuncLoadError := not assigned(CRYPTO_set_locking_callback);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_set_locking_callback_allownil)}
    CRYPTO_set_locking_callback := ERR_CRYPTO_set_locking_callback;
    {$ifend}
    {$if declared(CRYPTO_set_locking_callback_introduced)}
    if LibVersion < CRYPTO_set_locking_callback_introduced then
    begin
      {$if declared(FC_CRYPTO_set_locking_callback)}
      CRYPTO_set_locking_callback := FC_CRYPTO_set_locking_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_set_locking_callback_removed)}
    if CRYPTO_set_locking_callback_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_set_locking_callback)}
      CRYPTO_set_locking_callback := _CRYPTO_set_locking_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_set_locking_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_locking_callback');
    {$ifend}
  end;

 
  CRYPTO_THREADID_set_numeric := LoadLibFunction(ADllHandle, CRYPTO_THREADID_set_numeric_procname);
  FuncLoadError := not assigned(CRYPTO_THREADID_set_numeric);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREADID_set_numeric_allownil)}
    CRYPTO_THREADID_set_numeric := ERR_CRYPTO_THREADID_set_numeric;
    {$ifend}
    {$if declared(CRYPTO_THREADID_set_numeric_introduced)}
    if LibVersion < CRYPTO_THREADID_set_numeric_introduced then
    begin
      {$if declared(FC_CRYPTO_THREADID_set_numeric)}
      CRYPTO_THREADID_set_numeric := FC_CRYPTO_THREADID_set_numeric;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREADID_set_numeric_removed)}
    if CRYPTO_THREADID_set_numeric_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREADID_set_numeric)}
      CRYPTO_THREADID_set_numeric := _CRYPTO_THREADID_set_numeric;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREADID_set_numeric_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREADID_set_numeric');
    {$ifend}
  end;

 
  CRYPTO_THREADID_set_callback := LoadLibFunction(ADllHandle, CRYPTO_THREADID_set_callback_procname);
  FuncLoadError := not assigned(CRYPTO_THREADID_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_THREADID_set_callback_allownil)}
    CRYPTO_THREADID_set_callback := ERR_CRYPTO_THREADID_set_callback;
    {$ifend}
    {$if declared(CRYPTO_THREADID_set_callback_introduced)}
    if LibVersion < CRYPTO_THREADID_set_callback_introduced then
    begin
      {$if declared(FC_CRYPTO_THREADID_set_callback)}
      CRYPTO_THREADID_set_callback := FC_CRYPTO_THREADID_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_THREADID_set_callback_removed)}
    if CRYPTO_THREADID_set_callback_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_THREADID_set_callback)}
      CRYPTO_THREADID_set_callback := _CRYPTO_THREADID_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_THREADID_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREADID_set_callback');
    {$ifend}
  end;

 
  CRYPTO_set_id_callback := LoadLibFunction(ADllHandle, CRYPTO_set_id_callback_procname);
  FuncLoadError := not assigned(CRYPTO_set_id_callback);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_set_id_callback_allownil)}
    CRYPTO_set_id_callback := ERR_CRYPTO_set_id_callback;
    {$ifend}
    {$if declared(CRYPTO_set_id_callback_introduced)}
    if LibVersion < CRYPTO_set_id_callback_introduced then
    begin
      {$if declared(FC_CRYPTO_set_id_callback)}
      CRYPTO_set_id_callback := FC_CRYPTO_set_id_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_set_id_callback_removed)}
    if CRYPTO_set_id_callback_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_set_id_callback)}
      CRYPTO_set_id_callback := _CRYPTO_set_id_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_set_id_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_id_callback');
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


  CRYPTO_set_mem_debug := LoadLibFunction(ADllHandle, CRYPTO_set_mem_debug_procname);
  FuncLoadError := not assigned(CRYPTO_set_mem_debug);
  if FuncLoadError then
  begin
    {$if not defined(CRYPTO_set_mem_debug_allownil)}
    CRYPTO_set_mem_debug := ERR_CRYPTO_set_mem_debug;
    {$ifend}
    {$if declared(CRYPTO_set_mem_debug_introduced)}
    if LibVersion < CRYPTO_set_mem_debug_introduced then
    begin
      {$if declared(FC_CRYPTO_set_mem_debug)}
      CRYPTO_set_mem_debug := FC_CRYPTO_set_mem_debug;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CRYPTO_set_mem_debug_removed)}
    if CRYPTO_set_mem_debug_removed <= LibVersion then
    begin
      {$if declared(_CRYPTO_set_mem_debug)}
      CRYPTO_set_mem_debug := _CRYPTO_set_mem_debug;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CRYPTO_set_mem_debug_allownil)}
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_mem_debug');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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


  FIPS_mode := LoadLibFunction(ADllHandle, FIPS_mode_procname);
  FuncLoadError := not assigned(FIPS_mode);
  if FuncLoadError then
  begin
    {$if not defined(FIPS_mode_allownil)}
    FIPS_mode := ERR_FIPS_mode;
    {$ifend}
    {$if declared(FIPS_mode_introduced)}
    if LibVersion < FIPS_mode_introduced then
    begin
      {$if declared(FC_FIPS_mode)}
      FIPS_mode := FC_FIPS_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(FIPS_mode_removed)}
    if FIPS_mode_removed <= LibVersion then
    begin
      {$if declared(_FIPS_mode)}
      FIPS_mode := _FIPS_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(FIPS_mode_allownil)}
    if FuncLoadError then
      AFailed.Add('FIPS_mode');
    {$ifend}
  end;

 
  FIPS_mode_set := LoadLibFunction(ADllHandle, FIPS_mode_set_procname);
  FuncLoadError := not assigned(FIPS_mode_set);
  if FuncLoadError then
  begin
    {$if not defined(FIPS_mode_set_allownil)}
    FIPS_mode_set := ERR_FIPS_mode_set;
    {$ifend}
    {$if declared(FIPS_mode_set_introduced)}
    if LibVersion < FIPS_mode_set_introduced then
    begin
      {$if declared(FC_FIPS_mode_set)}
      FIPS_mode_set := FC_FIPS_mode_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(FIPS_mode_set_removed)}
    if FIPS_mode_set_removed <= LibVersion then
    begin
      {$if declared(_FIPS_mode_set)}
      FIPS_mode_set := _FIPS_mode_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(FIPS_mode_set_allownil)}
    if FuncLoadError then
      AFailed.Add('FIPS_mode_set');
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
  SSLeay_version := LoadLibFunction(ADllHandle, SSLeay_version_procname);
  FuncLoadError := not assigned(SSLeay_version);
  if FuncLoadError then
  begin
    {$if not defined(SSLeay_version_allownil)}
    SSLeay_version := ERR_SSLeay_version;
    {$ifend}
    {$if declared(SSLeay_version_introduced)}
    if LibVersion < SSLeay_version_introduced then
    begin
      {$if declared(FC_SSLeay_version)}
      SSLeay_version := FC_SSLeay_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSLeay_version_removed)}
    if SSLeay_version_removed <= LibVersion then
    begin
      {$if declared(_SSLeay_version)}
      SSLeay_version := _SSLeay_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSLeay_version_allownil)}
    if FuncLoadError then
      AFailed.Add('SSLeay_version');
    {$ifend}
  end;

 
  SSLeay := LoadLibFunction(ADllHandle, SSLeay_procname);
  FuncLoadError := not assigned(SSLeay);
  if FuncLoadError then
  begin
    {$if not defined(SSLeay_allownil)}
    SSLeay := ERR_SSLeay;
    {$ifend}
    {$if declared(SSLeay_introduced)}
    if LibVersion < SSLeay_introduced then
    begin
      {$if declared(FC_SSLeay)}
      SSLeay := FC_SSLeay;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSLeay_removed)}
    if SSLeay_removed <= LibVersion then
    begin
      {$if declared(_SSLeay)}
      SSLeay := _SSLeay;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSLeay_allownil)}
    if FuncLoadError then
      AFailed.Add('SSLeay');
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
end;

procedure Unload;
begin
  OPENSSL_malloc := nil; {removed 1.0.0}
  OPENSSL_zalloc := nil; {removed 1.0.0}
  OPENSSL_realloc := nil; {removed 1.0.0}
  OPENSSL_clear_realloc := nil; {removed 1.0.0}
  OPENSSL_clear_free := nil; {removed 1.0.0}
  OPENSSL_free := nil; {removed 1.0.0}
  OPENSSL_memdup := nil; {removed 1.0.0}
  OPENSSL_strdup := nil; {removed 1.0.0}
  OPENSSL_strndup := nil; {removed 1.0.0}
  OPENSSL_secure_malloc := nil; {removed 1.0.0}
  OPENSSL_secure_zalloc := nil; {removed 1.0.0}
  OPENSSL_secure_free := nil; {removed 1.0.0}
  OPENSSL_secure_clear_free := nil; {removed 1.0.0}
  OPENSSL_secure_actual_size := nil; {removed 1.0.0}
  CRYPTO_THREAD_lock_new := nil; {introduced 1.1.0}
  CRYPTO_THREAD_read_lock := nil; {introduced 1.1.0}
  CRYPTO_THREAD_write_lock := nil; {introduced 1.1.0}
  CRYPTO_THREAD_unlock := nil; {introduced 1.1.0}
  CRYPTO_THREAD_lock_free := nil; {introduced 1.1.0}
  CRYPTO_atomic_add := nil; {introduced 1.1.0}
  CRYPTO_mem_ctrl := nil; {removed 3.0.0}
  OPENSSL_strlcpy := nil; {introduced 1.1.0}
  OPENSSL_strlcat := nil; {introduced 1.1.0}
  OPENSSL_strnlen := nil; {introduced 1.1.0}
  OPENSSL_buf2hexstr := nil; {introduced 1.1.0}
  OPENSSL_hexstr2buf := nil; {introduced 1.1.0}
  OPENSSL_hexchar2int := nil; {introduced 1.1.0}
  OpenSSL_version_num := nil; {introduced 1.1.0}
  OpenSSL_version := nil; {introduced 1.1.0}
  OPENSSL_info := nil; {introduced 3.0.0}
  OPENSSL_issetugid := nil;
  CRYPTO_new_ex_data := nil;
  CRYPTO_dup_ex_data := nil;
  CRYPTO_free_ex_data := nil;
  CRYPTO_set_ex_data := nil;
  CRYPTO_get_ex_data := nil;
  CRYPTO_num_locks := nil; {removed 1.1.0}
  CRYPTO_set_locking_callback := nil; {removed 1.1.0}
  CRYPTO_THREADID_set_numeric := nil; {removed 1.1.0}
  CRYPTO_THREADID_set_callback := nil; {removed 1.1.0}
  CRYPTO_set_id_callback := nil; {removed 1.1.0}
  CRYPTO_set_mem_functions := nil;
  CRYPTO_set_mem_debug := nil; {introduced 1.1.0 removed 3.0.0}
  CRYPTO_malloc := nil;
  CRYPTO_zalloc := nil; {introduced 1.1.0}
  CRYPTO_memdup := nil; {introduced 1.1.0}
  CRYPTO_strdup := nil;
  CRYPTO_strndup := nil; {introduced 1.1.0}
  CRYPTO_free := nil;
  CRYPTO_clear_free := nil; {introduced 1.1.0}
  CRYPTO_realloc := nil;
  CRYPTO_clear_realloc := nil; {introduced 1.1.0}
  CRYPTO_secure_malloc_init := nil; {introduced 1.1.0}
  CRYPTO_secure_malloc_done := nil; {introduced 1.1.0}
  CRYPTO_secure_malloc := nil; {introduced 1.1.0}
  CRYPTO_secure_zalloc := nil; {introduced 1.1.0}
  CRYPTO_secure_free := nil; {introduced 1.1.0}
  CRYPTO_secure_clear_free := nil; {introduced 1.1.0}
  CRYPTO_secure_allocated := nil; {introduced 1.1.0}
  CRYPTO_secure_malloc_initialized := nil; {introduced 1.1.0}
  CRYPTO_secure_actual_size := nil; {introduced 1.1.0}
  CRYPTO_secure_used := nil; {introduced 1.1.0}
  CRYPTO_get_ex_new_index := nil;
  OPENSSL_cleanse := nil;
  OPENSSL_isservice := nil;
  FIPS_mode := nil; {removed 3.0.0}
  FIPS_mode_set := nil; {removed 3.0.0}
  OPENSSL_init := nil;
  CRYPTO_memcmp := nil;
  OPENSSL_cleanup := nil; {introduced 1.1.0}
  OPENSSL_init_crypto := nil; {introduced 1.1.0}
  OPENSSL_thread_stop := nil; {introduced 1.1.0}
  OPENSSL_INIT_new := nil; {introduced 1.1.0}
  OPENSSL_INIT_free := nil; {introduced 1.1.0}
  CRYPTO_THREAD_run_once := nil; {introduced 1.1.0}
  CRYPTO_THREAD_get_local := nil; {introduced 1.1.0}
  CRYPTO_THREAD_set_local := nil; {introduced 1.1.0}
  CRYPTO_THREAD_cleanup_local := nil; {introduced 1.1.0}
  CRYPTO_THREAD_get_current_id := nil; {introduced 1.1.0}
  CRYPTO_THREAD_compare_id := nil; {introduced 1.1.0}
  SSLeay_version := nil; {removed 1.1.0}
  SSLeay := nil; {removed 1.1.0}

  OSSL_LIB_CTX_new := nil; {removed 1.1.0}
  OSSL_LIB_CTX_new_from_dispatch := nil; {removed 1.1.0}
  OSSL_LIB_CTX_new_child := nil; {removed 1.1.0}
  OSSL_LIB_CTX_load_config := nil; {removed 1.1.0}
  OSSL_LIB_CTX_free := nil; {removed 1.1.0}
  OSSL_LIB_CTX_get0_global_default := nil; {removed 1.1.0}
  OSSL_LIB_CTX_set0_default := nil; {removed 1.1.0}
end;
  {$ENDIF}
{$ELSE}
function OPENSSL_malloc(num: TIdC_SIZET): Pointer;
begin
  Result := CRYPTO_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_zalloc(num) CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_zalloc(num: TIdC_SIZET): Pointer;
begin
  Result := CRYPTO_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_realloc(address, num) CRYPTO_realloc(address, num, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_realloc(address: Pointer; num: TIdC_SIZET): Pointer;
begin
  Result := CRYPTO_realloc(address, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_realloc(address, old_num, num) CRYPTO_clear_realloc(address, old_num, num, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_clear_realloc(address: Pointer; old_num: TIdC_SIZET; num: TIdC_SIZET): Pointer;
begin
  Result := CRYPTO_clear_realloc(address, old_num, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_free(address, num) CRYPTO_clear_free(address, num, OPENSSL_FILE, OPENSSL_LINE)
procedure OPENSSL_clear_free(address: Pointer; num: TIdC_SIZET);
begin
  CRYPTO_clear_free(address, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_free(addr) CRYPTO_free(address, OPENSSL_FILE, OPENSSL_LINE)
procedure OPENSSL_free(address: Pointer);
begin
  CRYPTO_free(address, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_memdup(str, s) CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_memdup(const _str: Pointer; s: TIdC_SIZET): Pointer;
begin
  Result := CRYPTO_memdup(_str, s, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strdup(str) CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_strdup(const _str: PIdAnsiChar): PIdAnsiChar;
begin
   Result := CRYPTO_strdup(_str, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strndup(str, n) CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_strndup(const _str: PIdAnsiChar; n: TIdC_SIZET): PIdAnsiChar;
begin
  Result := CRYPTO_strndup(_str, n, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_malloc(num) CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_secure_malloc(num: TIdC_SIZET): Pointer;
begin
  Result := CRYPTO_secure_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_zalloc(num) CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)
function OPENSSL_secure_zalloc(num: TIdC_SIZET): Pointer;
begin
  Result := CRYPTO_secure_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_free(addr) CRYPTO_secure_free(address, OPENSSL_FILE, OPENSSL_LINE)
procedure OPENSSL_secure_free(address: Pointer);
begin
  CRYPTO_secure_free(address, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_clear_free(address, num) CRYPTO_secure_clear_free(address, num, OPENSSL_FILE, OPENSSL_LINE)
procedure OPENSSL_secure_clear_free(address: Pointer; num: TIdC_SIZET);
begin
  CRYPTO_secure_clear_free(address, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_actual_size(ptr) CRYPTO_secure_actual_size(ptr)
function OPENSSL_secure_actual_size(_ptr: Pointer): TIdC_SIZET;
begin
  Result := CRYPTO_secure_actual_size(_ptr);
end;

function CRYPTO_num_locks: TIdC_INT;
begin
  Result := 0;
end;

procedure CRYPTO_set_locking_callback;
begin
end;  //PALOFF  - Empty begin/end-blocks

procedure CRYPTO_set_id_callback(func: TIdSslIdCallback);
begin
end;  //PALOFF  - Empty begin/end-blocks

function SSLeay_version(type_ : TIdC_INT) : PIdAnsiChar;
begin
  Result := OpenSSL_version(type_);
end;

function SSLeay: TIdC_ULONG;
begin
  Result := OpenSSL_version_num();
end;

procedure CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; _val: TIdC_ULONG);
begin
end;  //PALOFF  - Empty begin/end-blocks

procedure CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func);
begin
end;  //PALOFF  - Empty begin/end-blocks

function FIPS_mode: TIdC_INT;
begin
  Result := OSSL_PROVIDER_available(nil,PIdAnsiChar('fips'));
end;

var fips_provider: POSSL_PROVIDER;
    base_provider: POSSL_PROVIDER;

function FIPS_mode_set(r: TIdC_INT): TIdC_INT;
begin
  if r = 0 then
  begin
    if base_provider <> nil then
    begin
      OSSL_PROVIDER_unload(base_provider);  //PALOFF - Functions called as procedures
      base_provider := nil;
    end;

    if fips_provider <> nil then
    begin
       OSSL_PROVIDER_unload(fips_provider);  //PALOFF - Functions called as procedures
       fips_provider := nil;
    end;
    Result := 1;
  end
  else
  begin
     Result := 0;
     fips_provider := OSSL_PROVIDER_load(nil, PIdAnsiChar('fips'));
     if fips_provider = nil then
       Exit;
     base_provider := OSSL_PROVIDER_load(nil, PIdAnsiChar('base'));
     if base_provider = nil then
     begin
       OSSL_PROVIDER_unload(fips_provider);   //PALOFF - Functions called as procedures
       fips_provider := nil;
       Exit;
     end;
     Result := 1;
  end;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
