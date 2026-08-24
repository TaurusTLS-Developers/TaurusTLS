/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_engine.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_engine.h2pas
     and this file regenerated. TaurusTLSHeaders_engine.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_engine;

interface

// Headers for OpenSSL 1.1.1
// engine.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_ec;

const
  (*
   * These flags are used to control combinations of algorithm (methods) by
   * bitwise "OR"ing.
   *)
  {$EXTERNALSYM ENGINE_METHOD_RSA}
  ENGINE_METHOD_RSA               = TIdC_UINT($0001);
  {$EXTERNALSYM ENGINE_METHOD_DSA}
  ENGINE_METHOD_DSA               = TIdC_UINT($0002);
  {$EXTERNALSYM ENGINE_METHOD_DH}
  ENGINE_METHOD_DH                = TIdC_UINT($0004);
  {$EXTERNALSYM ENGINE_METHOD_RAND}
  ENGINE_METHOD_RAND              = TIdC_UINT($0008);
  {$EXTERNALSYM ENGINE_METHOD_CIPHERS}
  ENGINE_METHOD_CIPHERS           = TIdC_UINT($0040);
  {$EXTERNALSYM ENGINE_METHOD_DIGESTS}
  ENGINE_METHOD_DIGESTS           = TIdC_UINT($0080);
  {$EXTERNALSYM ENGINE_METHOD_PKEY_METHS}
  ENGINE_METHOD_PKEY_METHS        = TIdC_UINT($0200);
  {$EXTERNALSYM ENGINE_METHOD_PKEY_ASN1_METHS}
  ENGINE_METHOD_PKEY_ASN1_METHS   = TIdC_UINT($0400);
  {$EXTERNALSYM ENGINE_METHOD_EC}
  ENGINE_METHOD_EC                = TIdC_UINT($0800);
  (* Obvious all-or-nothing cases. *)
  {$EXTERNALSYM ENGINE_METHOD_ALL}
  ENGINE_METHOD_ALL               = TIdC_UINT($FFFF);
  {$EXTERNALSYM ENGINE_METHOD_NONE}
  ENGINE_METHOD_NONE              = TIdC_UINT($0000);

  //
  // This(ese) flag(s) controls behaviour of the ENGINE_TABLE mechanism used
  // internally to control registration of ENGINE implementations, and can be
  // set by ENGINE_set_table_flags(). The "NOINIT" flag prevents attempts to
  // initialise registered ENGINEs if they are not already initialised.
  //
  {$EXTERNALSYM ENGINE_TABLE_FLAG_NOINIT}
  ENGINE_TABLE_FLAG_NOINIT        = TIdC_UINT($0001);

  //
  // This flag is for ENGINEs that wish to handle the various 'CMD'-related
  // control commands on their own. Without this flag, ENGINE_ctrl() handles
  // these control commands on behalf of the ENGINE using their "cmd_defns"
  // data.
  //
  {$EXTERNALSYM ENGINE_FLAGS_MANUAL_CMD_CTRL}
  ENGINE_FLAGS_MANUAL_CMD_CTRL    = TIdC_INT($0002);

  //
  // This flag is for ENGINEs who return new duplicate structures when found
  // via "ENGINE_by_id()". When an ENGINE must store state (eg. if
  // ENGINE_ctrl() commands are called in sequence as part of some stateful
  // process like key-generation setup and execution), it can set this flag -
  // then each attempt to obtain the ENGINE will result in it being copied intoo
  // a new structure. Normally, ENGINEs don't declare this flag so
  // ENGINE_by_id() just increments the existing ENGINE's structural reference
  // count.
  //
  {$EXTERNALSYM ENGINE_FLAGS_BY_ID_COPY}
  ENGINE_FLAGS_BY_ID_COPY         = TIdC_INT($0004);

  //
  // This flag if for an ENGINE that does not want its methods registered as
  // part of ENGINE_register_all_complete() for example if the methods are not
  // usable as default methods.
  //

  {$EXTERNALSYM ENGINE_FLAGS_NO_REGISTER_ALL}
  ENGINE_FLAGS_NO_REGISTER_ALL    = TIdC_INT($0008);

  //
  // ENGINEs can support their own command types, and these flags are used in
  // ENGINE_CTRL_GET_CMD_FLAGS to indicate to the caller what kind of input
  // each command expects. Currently only numeric and string input is
  // supported. If a control command supports none of the _NUMERIC, _STRING, or
  // _NO_INPUT options, then it is regarded as an "internal" control command -
  // and not for use in config setting situations. As such, they're not
  // available to the ENGINE_ctrl_cmd_string() function, only raw ENGINE_ctrl()
  // access. Changes to this list of 'command types' should be reflected
  // carefully in ENGINE_cmd_is_executable() and ENGINE_ctrl_cmd_string().
  //

  // accepts a 'long' input value (3rd parameter to ENGINE_ctrl) */
  {$EXTERNALSYM ENGINE_CMD_FLAG_NUMERIC}
  ENGINE_CMD_FLAG_NUMERIC         = TIdC_UINT($0001);
  //
  // accepts string input (cast from 'void*' to 'const char *', 4th parameter
  // to ENGINE_ctrl)
  //
  {$EXTERNALSYM ENGINE_CMD_FLAG_STRING}
  ENGINE_CMD_FLAG_STRING          = TIdC_UINT($0002);
  //
  // Indicates that the control command takes *no* input. Ie. the control
  // command is unparameterised.
  //
  {$EXTERNALSYM ENGINE_CMD_FLAG_NO_INPUT}
  ENGINE_CMD_FLAG_NO_INPUT        = TIdC_UINT($0004);
  //
  // Indicates that the control command is internal. This control command won't
  // be shown in any output, and is only usable through the ENGINE_ctrl_cmd()
  // function.
  //
  {$EXTERNALSYM ENGINE_CMD_FLAG_INTERNAL}
  ENGINE_CMD_FLAG_INTERNAL        = TIdC_UINT($0008);

  //
  // NB: These 3 control commands are deprecated and should not be used.
  // ENGINEs relying on these commands should compile conditional support for
  // compatibility (eg. if these symbols are defined) but should also migrate
  // the same functionality to their own ENGINE-specific control functions that
  // can be "discovered" by calling applications. The fact these control
  // commands wouldn't be "executable" (ie. usable by text-based config)
  // doesn't change the fact that application code can find and use them
  // without requiring per-ENGINE hacking.
  //

  //
  // These flags are used to tell the ctrl function what should be done. All
  // command numbers are shared between all engines, even if some don't make
  // sense to some engines.  In such a case, they do nothing but return the
  // error ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED.
  //
  {$EXTERNALSYM ENGINE_CTRL_SET_LOGSTREAM}
  ENGINE_CTRL_SET_LOGSTREAM              = 1;
  {$EXTERNALSYM ENGINE_CTRL_SET_PASSWORD_CALLBACK}
  ENGINE_CTRL_SET_PASSWORD_CALLBACK      = 2;
  {$EXTERNALSYM ENGINE_CTRL_HUP}
  ENGINE_CTRL_HUP                        = 3;// Close and reinitialise
                                             // any handles/connections
                                             // etc.
  {$EXTERNALSYM ENGINE_CTRL_SET_USER_INTERFACE}
  ENGINE_CTRL_SET_USER_INTERFACE         = 4;// Alternative to callback
  {$EXTERNALSYM ENGINE_CTRL_SET_CALLBACK_DATA}
  ENGINE_CTRL_SET_CALLBACK_DATA          = 5;// User-specific data, used
                                             // when calling the password
                                             // callback and the user
                                             // interface
  {$EXTERNALSYM ENGINE_CTRL_LOAD_CONFIGURATION}
  ENGINE_CTRL_LOAD_CONFIGURATION         = 6;// Load a configuration,
                                             // given a string that
                                             // represents a file name
                                             // or so
  {$EXTERNALSYM ENGINE_CTRL_LOAD_SECTION}
  ENGINE_CTRL_LOAD_SECTION               = 7;// Load data from a given
                                             // section in the already
                                             // loaded configuration

  //
  // These control commands allow an application to deal with an arbitrary
  // engine in a dynamic way. Warn: Negative return values indicate errors FOR
  // THESE COMMANDS because zero is used to indicate 'end-of-list'. Other
  // commands, including ENGINE-specific command types, return zero for an
  // error. An ENGINE can choose to implement these ctrl functions, and can
  // internally manage things however it chooses - it does so by setting the
  // ENGINE_FLAGS_MANUAL_CMD_CTRL flag (using ENGINE_set_flags()). Otherwise
  // the ENGINE_ctrl() code handles this on the ENGINE's behalf using the
  // cmd_defns data (set using ENGINE_set_cmd_defns()). This means an ENGINE's
  // ctrl() handler need only implement its own commands - the above "meta"
  // commands will be taken care of.
  //

  //
  // Returns non-zero if the supplied ENGINE has a ctrl() handler. If "not",
  // then all the remaining control commands will return failure, so it is
  // worth checking this first if the caller is trying to "discover" the
  // engine's capabilities and doesn't want errors generated unnecessarily.
  //
  {$EXTERNALSYM ENGINE_CTRL_HAS_CTRL_FUNCTION}
  ENGINE_CTRL_HAS_CTRL_FUNCTION          = 10;
  //
  // Returns a positive command number for the first command supported by the
  // engine. Returns zero if no ctrl commands are supported.
  //
  {$EXTERNALSYM ENGINE_CTRL_GET_FIRST_CMD_TYPE}
  ENGINE_CTRL_GET_FIRST_CMD_TYPE         = 11;
  //
  // The 'long' argument specifies a command implemented by the engine, and the
  // return value is the next command supported, or zero if there are no more.
  //
  {$EXTERNALSYM ENGINE_CTRL_GET_NEXT_CMD_TYPE}
  ENGINE_CTRL_GET_NEXT_CMD_TYPE          = 12;
  //
  // The 'void*' argument is a command name (cast from 'const char *'), and the
  // return value is the command that corresponds to it.
  //
  {$EXTERNALSYM ENGINE_CTRL_GET_CMD_FROM_NAME}
  ENGINE_CTRL_GET_CMD_FROM_NAME          = 13;
  //
  // The next two allow a command to be converted into its corresponding string
  // form. In each case, the 'long' argument supplies the command. In the
  // NAME_LEN case, the return value is the length of the command name (not
  // counting a trailing EOL). In the NAME case, the 'void*' argument must be a
  // string buffer large enough, and it will be populated with the name of the
  // command (WITH a trailing EOL).
  //
  {$EXTERNALSYM ENGINE_CTRL_GET_NAME_LEN_FROM_CMD}
  ENGINE_CTRL_GET_NAME_LEN_FROM_CMD      = 14;
  {$EXTERNALSYM ENGINE_CTRL_GET_NAME_FROM_CMD}
  ENGINE_CTRL_GET_NAME_FROM_CMD          = 15;
  // The next two are similar but give a "short description" of a command. */
  {$EXTERNALSYM ENGINE_CTRL_GET_DESC_LEN_FROM_CMD}
  ENGINE_CTRL_GET_DESC_LEN_FROM_CMD      = 16;
  {$EXTERNALSYM ENGINE_CTRL_GET_DESC_FROM_CMD}
  ENGINE_CTRL_GET_DESC_FROM_CMD          = 17;
  //
  // With this command, the return value is the OR'd combination of
  // ENGINE_CMD_FLAG_*** values that indicate what kind of input a given
  // engine-specific ctrl command expects.
  //
  {$EXTERNALSYM ENGINE_CTRL_GET_CMD_FLAGS}
  ENGINE_CTRL_GET_CMD_FLAGS              = 18;

  //
  // ENGINE implementations should start the numbering of their own control
  // commands from this value. (ie. ENGINE_CMD_BASE, ENGINE_CMD_BASE += 1, etc).
  //
  {$EXTERNALSYM ENGINE_CMD_BASE}
  ENGINE_CMD_BASE                        = 200;

  //
  // NB: These 2 nCipher "chil" control commands are deprecated, and their
  // functionality is now available through ENGINE-specific control commands
  // (exposed through the above-mentioned 'CMD'-handling). Code using these 2
  // commands should be migrated to the more general command handling before
  // these are removed.
  //

  // Flags specific to the nCipher "chil" engine */
  {$EXTERNALSYM ENGINE_CTRL_CHIL_SET_FORKCHECK}
  ENGINE_CTRL_CHIL_SET_FORKCHECK         = 100;
  //
  // Depending on the value of the (long)i argument, this sets or
  // unsets the SimpleForkCheck flag in the CHIL API to enable or
  // disable checking and workarounds for applications that fork().
  //
  {$EXTERNALSYM ENGINE_CTRL_CHIL_NO_LOCKING}
  ENGINE_CTRL_CHIL_NO_LOCKING            = 101;
  //
  // This prevents the initialisation function from providing mutex
  // callbacks to the nCipher library.
  //

type
  //
  // If an ENGINE supports its own specific control commands and wishes the
  // framework to handle the above 'ENGINE_CMD_***'-manipulation commands on
  // its behalf, it should supply a null-terminated array of ENGINE_CMD_DEFN
  // entries to ENGINE_set_cmd_defns(). It should also implement a ctrl()
  // handler that supports the stated commands (ie. the "cmd_num" entries as
  // described by the array). NB: The array must be ordered in increasing order
  // of cmd_num. "null-terminated" means that the last ENGINE_CMD_DEFN element
  // has cmd_num set to zero and/or cmd_name set to NULL.
  //
  {$EXTERNALSYM ENGINE_CMD_DEFN_st}
  ENGINE_CMD_DEFN_st = record
    cmd_num: TIdC_UINT;
    cmd_name: PIdAnsiChar;
    cmd_desc: PIdAnsiChar;
    cmd_flags: TIdC_UINT;
  end;
  {$EXTERNALSYM ENGINE_CMD_DEFN}
  ENGINE_CMD_DEFN = ENGINE_CMD_DEFN_st;
  {$EXTERNALSYM PENGINE_CMD_DEFN}
  PENGINE_CMD_DEFN = ^ENGINE_CMD_DEFN;

  // Generic function pointer */
  {$EXTERNALSYM ENGINE_GEN_FUNC_PTR}
  ENGINE_GEN_FUNC_PTR = function: TIdC_INT; cdecl;
  // Generic function pointer taking no arguments */
  {$EXTERNALSYM ENGINE_GEN_INT_FUNC_PTR}
  ENGINE_GEN_INT_FUNC_PTR = function(v1: PENGINE): TIdC_INT; cdecl;
  // Specific control function pointer */
  {$EXTERNALSYM f}
  f = procedure; cdecl;
  {$EXTERNALSYM ENGINE_CTRL_FUNC_PTR}
  ENGINE_CTRL_FUNC_PTR = function(v1: PENGINE; v2: TIdC_INT; v3: TIdC_LONG; v4: Pointer; v5: f): TIdC_INT; cdecl;
  // Generic load_key function pointer */
  {$EXTERNALSYM ENGINE_LOAD_KEY_PTR}
  ENGINE_LOAD_KEY_PTR = function(v1: PENGINE; const v2: PIdAnsiChar;
    ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl;
  //ENGINE_SSL_CLIENT_CERT_PTR = function(v1: PENGINE; ssl: PSSL;
  //  {STACK_OF(X509_NAME) *ca_dn;} pcert: PPX509; pkey: PPEVP_PKEY;
  //  {STACK_OF(X509) **pother;} ui_method: PUI_METHOD; callback_data: Pointer): TIdC_INT; cdecl;

  //
  // These callback types are for an ENGINE's handler for cipher and digest logic.
  // These handlers have these prototypes;
  //   int foo(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
  //   int foo(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
  // Looking at how to implement these handlers in the case of cipher support, if
  // the framework wants the EVP_CIPHER for 'nid', it will call;
  //   foo(e, &p_evp_cipher, NULL, nid);    (return zero for failure)
  // If the framework wants a list of supported 'nid's, it will call;
  //   foo(e, NULL, &p_nids, 0); (returns number of 'nids' or -1 for error)
  //
  //
  // Returns to a pointer to the array of supported cipher 'nid's. If the
  // second parameter is non-NULL it is set to the size of the returned array.
  //
  {$EXTERNALSYM ENGINE_CIPHERS_PTR}
  ENGINE_CIPHERS_PTR = function(v1: PENGINE; const v2: PPEVP_CIPHER;
    const v3: PPIdC_INT; v4: TIdC_INT): TIdC_INT; cdecl;
  {$EXTERNALSYM ENGINE_DIGESTS_PTR}
  ENGINE_DIGESTS_PTR = function(v1: PENGINE; const v2: PPEVP_MD;
    const v3: PPIdC_INT; v4: TIdC_INT): TIdC_INT; cdecl;
  {$EXTERNALSYM ENGINE_PKEY_METHS_PTR}
  ENGINE_PKEY_METHS_PTR = function(v1: PENGINE; v2: PPEVP_PKEY_METHOD;
    const v3: PPIdC_INT; v4: TIdC_INT): TIdC_INT; cdecl;
  {$EXTERNALSYM ENGINE_PKEY_ASN1_METHS_PTR}
  ENGINE_PKEY_ASN1_METHS_PTR = function(v1: PENGINE; v2: PPEVP_PKEY_ASN1_METHOD;
    const v3: PPIdC_INT; v4: TIdC_INT): TIdC_INT; cdecl;

  {$EXTERNALSYM dyn_MEM_malloc_fn}
  dyn_MEM_malloc_fn = function(v1: TIdC_SIZET; const v2: PIdAnsiChar; v3: TIdC_INT): Pointer; cdecl;
  {$EXTERNALSYM dyn_MEM_realloc_fn}
  dyn_MEM_realloc_fn = function(v1: Pointer; v2: TIdC_SIZET; const v3: PIdAnsiChar; v4: TIdC_INT): Pointer; cdecl;
  {$EXTERNALSYM dyn_MEM_free_fn}
  dyn_MEM_free_fn = procedure(v1: Pointer; const v2: PIdAnsiChar; v3: TIdC_INT); cdecl;

  {$EXTERNALSYM st_dynamic_MEM_fns}
  st_dynamic_MEM_fns = record
    malloc_fn: dyn_MEM_malloc_fn;
    realloc_fn: dyn_MEM_realloc_fn;
    free_fn: dyn_MEM_free_fn;
  end;
  {$EXTERNALSYM dynamic_MEM_fns}
  dynamic_MEM_fns = st_dynamic_MEM_fns;

  //*
  // * FIXME: Perhaps the memory and locking code (crypto.h) should declare and
  // * use these types so we (and any other dependent code) can simplify a bit??
  // */
  //* The top-level structure */
  {$EXTERNALSYM st_dynamic_fns}
  st_dynamic_fns = record
    static_state: Pointer;
    mem_fns: dynamic_MEM_fns;
  end;
  {$EXTERNALSYM dynamic_fns}
  dynamic_fns = st_dynamic_fns;

  //*
  // * The version checking function should be of this prototype. NB: The
  // * ossl_version value passed in is the OSSL_DYNAMIC_VERSION of the loading
  // * code. If this function returns zero, it indicates a (potential) version
  // * incompatibility and the loaded library doesn't believe it can proceed.
  // * Otherwise, the returned value is the (latest) version supported by the
  // * loading library. The loader may still decide that the loaded code's
  // * version is unsatisfactory and could veto the load. The function is
  // * expected to be implemented with the symbol name "v_check", and a default
  // * implementation can be fully instantiated with
  // * IMPLEMENT_DYNAMIC_CHECK_FN().
  // */
  {$EXTERNALSYM dynamic_v_check_fn}
  dynamic_v_check_fn = function(ossl_version: TIdC_ULONG): TIdC_ULONG; cdecl;
  //# define IMPLEMENT_DYNAMIC_CHECK_FN() \
  //        OPENSSL_EXPORT unsigned long v_check(unsigned long v); \
  //        OPENSSL_EXPORT unsigned long v_check(unsigned long v) { \
  //                if (v >= OSSL_DYNAMIC_OLDEST) return OSSL_DYNAMIC_VERSION; \
  //                return 0; }

  //*
  // * This function is passed the ENGINE structure to initialise with its own
  // * function and command settings. It should not adjust the structural or
  // * functional reference counts. If this function returns zero, (a) the load
  // * will be aborted, (b) the previous ENGINE state will be memcpy'd back onto
  // * the structure, and (c) the shared library will be unloaded. So
  // * implementations should do their own internal cleanup in failure
  // * circumstances otherwise they could leak. The 'id' parameter, if non-NULL,
  // * represents the ENGINE id that the loader is looking for. If this is NULL,
  // * the shared library can choose to return failure or to initialise a
  // * 'default' ENGINE. If non-NULL, the shared library must initialise only an
  // * ENGINE matching the passed 'id'. The function is expected to be
  // * implemented with the symbol name "bind_engine". A standard implementation
  // * can be instantiated with IMPLEMENT_DYNAMIC_BIND_FN(fn) where the parameter
  // * 'fn' is a callback function that populates the ENGINE structure and
  // * returns an int value (zero for failure). 'fn' should have prototype;
  // * [static] int fn(ENGINE *e, const char *id);
  // */
  {$EXTERNALSYM dynamic_bind_engine}
  dynamic_bind_engine = function(e: PENGINE; const id: PIdAnsiChar;
    const fns: dynamic_fns): TIdC_INT; cdecl;

  //
  // STRUCTURE functions ... all of these functions deal with pointers to
  // ENGINE structures where the pointers have a "structural reference". This
  // means that their reference is to allowed access to the structure but it
  // does not imply that the structure is functional. To simply increment or
  // decrement the structural reference count, use ENGINE_by_id and
  // ENGINE_free. NB: This is not required when iterating using ENGINE_get_next
  // as it will automatically decrement the structural reference count of the
  // "current" ENGINE and increment the structural reference count of the
  // ENGINE it returns (unless it is NULL).
  //
  // Get the first/last "ENGINE" type available. */
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ENGINE_get_first}
  ENGINE_get_first: function : PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_last}
  ENGINE_get_last: function : PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_next}
  ENGINE_get_next: function (e: PENGINE): PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_prev}
  ENGINE_get_prev: function (e: PENGINE): PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_add}
  ENGINE_add: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_remove}
  ENGINE_remove: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_by_id}
  ENGINE_by_id: function (const id: PIdAnsiChar): PENGINE; cdecl = nil;

  {$EXTERNALSYM ENGINE_load_builtin_engines}
  ENGINE_load_builtin_engines: procedure ; cdecl = nil;

  //
  // Get and set global flags (ENGINE_TABLE_FLAG_***) for the implementation
  // "registry" handling.
  //
  {$EXTERNALSYM ENGINE_get_table_flags}
  ENGINE_get_table_flags: function : TIdC_UINT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_table_flags}
  ENGINE_set_table_flags: procedure (flags: TIdC_UINT); cdecl = nil;

  //- Manage registration of ENGINEs per "table". For each type, there are 3
  // functions;
  //   ENGINE_register_***(e) - registers the implementation from 'e' (if it has one)
  //   ENGINE_unregister_***(e) - unregister the implementation from 'e'
  //   ENGINE_register_all_***() - call ENGINE_register_***() for each 'e' in the list
  // Cleanup is automatically registered from each table when required.
  //

  {$EXTERNALSYM ENGINE_register_RSA}
  ENGINE_register_RSA: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_RSA}
  ENGINE_unregister_RSA: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_RSA}
  ENGINE_register_all_RSA: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_DSA}
  ENGINE_register_DSA: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_DSA}
  ENGINE_unregister_DSA: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_DSA}
  ENGINE_register_all_DSA: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_EC}
  ENGINE_register_EC: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_EC}
  ENGINE_unregister_EC: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_EC}
  ENGINE_register_all_EC: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_DH}
  ENGINE_register_DH: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_DH}
  ENGINE_unregister_DH: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_DH}
  ENGINE_register_all_DH: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_RAND}
  ENGINE_register_RAND: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_RAND}
  ENGINE_unregister_RAND: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_RAND}
  ENGINE_register_all_RAND: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_ciphers}
  ENGINE_register_ciphers: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_ciphers}
  ENGINE_unregister_ciphers: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_ciphers}
  ENGINE_register_all_ciphers: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_digests}
  ENGINE_register_digests: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_digests}
  ENGINE_unregister_digests: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_digests}
  ENGINE_register_all_digests: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_pkey_meths}
  ENGINE_register_pkey_meths: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_pkey_meths}
  ENGINE_unregister_pkey_meths: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_pkey_meths}
  ENGINE_register_all_pkey_meths: procedure ; cdecl = nil;

  {$EXTERNALSYM ENGINE_register_pkey_asn1_meths}
  ENGINE_register_pkey_asn1_meths: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_unregister_pkey_asn1_meths}
  ENGINE_unregister_pkey_asn1_meths: procedure (e: PENGINE); cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_pkey_asn1_meths}
  ENGINE_register_all_pkey_asn1_meths: procedure ; cdecl = nil;

  //
  // These functions register all support from the above categories. Note, use
  // of these functions can result in static linkage of code your application
  // may not need. If you only need a subset of functionality, consider using
  // more selective initialisation.
  //
  {$EXTERNALSYM ENGINE_register_complete}
  ENGINE_register_complete: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_register_all_complete}
  ENGINE_register_all_complete: function : TIdC_INT; cdecl = nil;

  //
  // Send parameterised control commands to the engine. The possibilities to
  // send down an integer, a pointer to data or a function pointer are
  // provided. Any of the parameters may or may not be NULL, depending on the
  // command number. In actuality, this function only requires a structural
  // (rather than functional) reference to an engine, but many control commands
  // may require the engine be functional. The caller should be aware of trying
  // commands that require an operational ENGINE, and only use functional
  // references in such situations.
  //
  {$EXTERNALSYM ENGINE_ctrl}
  ENGINE_ctrl: function (e: PENGINE; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; v1: f): TIdC_INT; cdecl = nil;

  //
  // This function tests if an ENGINE-specific command is usable as a
  // "setting". Eg. in an application's config file that gets processed through
  // ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
  // ENGINE_ctrl_cmd_string(), only ENGINE_ctrl().
  //
  {$EXTERNALSYM ENGINE_cmd_is_executable}
  ENGINE_cmd_is_executable: function (e: PENGINE; cmd: TIdC_INT): TIdC_INT; cdecl = nil;

  //
  // This function works like ENGINE_ctrl() with the exception of taking a
  // command name instead of a command number, and can handle optional
  // commands. See the comment on ENGINE_ctrl_cmd_string() for an explanation
  // on how to use the cmd_name and cmd_optional.
  //
  {$EXTERNALSYM ENGINE_ctrl_cmd}
  ENGINE_ctrl_cmd: function (e: PENGINE; const cmd_name: PIdAnsiChar; i: TIdC_LONG; p: Pointer; v1: f; cmd_optional: TIdC_INT): TIdC_INT; cdecl = nil;

  //
  // This function passes a command-name and argument to an ENGINE. The
  // cmd_name is converted to a command number and the control command is
  // called using 'arg' as an argument (unless the ENGINE doesn't support such
  // a command, in which case no control command is called). The command is
  // checked for input flags, and if necessary the argument will be converted
  // to a numeric value. If cmd_optional is non-zero, then if the ENGINE
  // doesn't support the given cmd_name the return value will be success
  // anyway. This function is intended for applications to use so that users
  // (or config files) can supply engine-specific config data to the ENGINE at
  // run-time to control behaviour of specific engines. As such, it shouldn't
  // be used for calling ENGINE_ctrl() functions that return data, deal with
  // binary data, or that are otherwise supposed to be used directly through
  // ENGINE_ctrl() in application code. Any "return" data from an ENGINE_ctrl()
  // operation in this function will be lost - the return value is interpreted
  // as failure if the return value is zero, success otherwise, and this
  // function returns a boolean value as a result. In other words, vendors of
  // 'ENGINE'-enabled devices should write ENGINE implementations with
  // parameterisations that work in this scheme, so that compliant ENGINE-based
  // applications can work consistently with the same configuration for the
  // same ENGINE-enabled devices, across applications.
  //
  {$EXTERNALSYM ENGINE_ctrl_cmd_string}
  ENGINE_ctrl_cmd_string: function (e: PENGINE; const cmd_name: PIdAnsiChar; const arg: PIdAnsiChar; cmd_optional: TIdC_INT): TIdC_INT; cdecl = nil;

  //
  // These functions are useful for manufacturing new ENGINE structures. They
  // don't address reference counting at all - one uses them to populate an
  // ENGINE structure with personalised implementations of things prior to
  // using it directly or adding it to the builtin ENGINE list in TaurusTLS.
  // These are also here so that the ENGINE structure doesn't have to be
  // exposed and break binary compatibility!
  //
  {$EXTERNALSYM ENGINE_new}
  ENGINE_new: function : PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_free}
  ENGINE_free: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_up_ref}
  ENGINE_up_ref: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_id}
  ENGINE_set_id: function (e: PENGINE; const id: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_name}
  ENGINE_set_name: function (e: PENGINE; const name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_RSA}
  ENGINE_set_RSA: function (e: PENGINE; const rsa_meth: PRSA_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_DSA}
  ENGINE_set_DSA: function (e: PENGINE; const dsa_meth: PDSA_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_EC}
  ENGINE_set_EC: function (e: PENGINE; const ecdsa_meth: PEC_KEY_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_DH}
  ENGINE_set_DH: function (e: PENGINE; const dh_meth: PDH_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_RAND}
  ENGINE_set_RAND: function (e: PENGINE; const rand_meth: PRAND_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_destroy_function}
  ENGINE_set_destroy_function: function (e: PENGINE; destroy_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_init_function}
  ENGINE_set_init_function: function (e: PENGINE; init_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_finish_function}
  ENGINE_set_finish_function: function (e: PENGINE; finish_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_ctrl_function}
  ENGINE_set_ctrl_function: function (e: PENGINE; ctrl_f: ENGINE_CTRL_FUNC_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_load_privkey_function}
  ENGINE_set_load_privkey_function: function (e: PENGINE; loadpriv_f: ENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_load_pubkey_function}
  ENGINE_set_load_pubkey_function: function (e: PENGINE; loadpub_f: ENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl = nil;
  //function ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: ENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT;
  {$EXTERNALSYM ENGINE_set_ciphers}
  ENGINE_set_ciphers: function (e: PENGINE; f: ENGINE_CIPHERS_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_digests}
  ENGINE_set_digests: function (e: PENGINE; f: ENGINE_DIGESTS_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_pkey_meths}
  ENGINE_set_pkey_meths: function (e: PENGINE; f: ENGINE_PKEY_METHS_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_pkey_asn1_meths}
  ENGINE_set_pkey_asn1_meths: function (e: PENGINE; f: ENGINE_PKEY_ASN1_METHS_PTR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_flags}
  ENGINE_set_flags: function (e: PENGINE; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_cmd_defns}
  ENGINE_set_cmd_defns: function (e: PENGINE; const defns: PENGINE_CMD_DEFN): TIdC_INT; cdecl = nil;
  // These functions allow control over any per-structure ENGINE data. */
  //#define ENGINE_get_ex_new_index(l, p, newf, dupf, freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)
  {$EXTERNALSYM ENGINE_set_ex_data}
  ENGINE_set_ex_data: function (e: PENGINE; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_ex_data}
  ENGINE_get_ex_data: function (const e: PENGINE; idx: TIdC_INT): Pointer; cdecl = nil;

  //
  // These return values from within the ENGINE structure. These can be useful
  // with functional references as well as structural references - it depends
  // which you obtained. Using the result for functional purposes if you only
  // obtained a structural reference may be problematic!
  //
  {$EXTERNALSYM ENGINE_get_id}
  ENGINE_get_id: function (const e: PENGINE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_name}
  ENGINE_get_name: function (const e: PENGINE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_RSA}
  ENGINE_get_RSA: function (const e: PENGINE): PRSA_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_DSA}
  ENGINE_get_DSA: function (const e: PENGINE): PDSA_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_EC}
  ENGINE_get_EC: function (const e: PENGINE): PEC_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_DH}
  ENGINE_get_DH: function (const e: PENGINE): PDH_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_RAND}
  ENGINE_get_RAND: function (const e: PENGINE): PRAND_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_destroy_function}
  ENGINE_get_destroy_function: function (const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_init_function}
  ENGINE_get_init_function: function (const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_finish_function}
  ENGINE_get_finish_function: function (const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_ctrl_function}
  ENGINE_get_ctrl_function: function (const e: PENGINE): ENGINE_CTRL_FUNC_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_load_privkey_function}
  ENGINE_get_load_privkey_function: function (const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_load_pubkey_function}
  ENGINE_get_load_pubkey_function: function (const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl = nil;
  //function ENGINE_get_ssl_client_cert_function(const e: PENGINE): ENGINE_SSL_CLIENT_CERT_PTR;
  
  {$EXTERNALSYM ENGINE_get_ciphers}
  ENGINE_get_ciphers: function (const e: PENGINE): ENGINE_CIPHERS_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_digests}
  ENGINE_get_digests: function (const e: PENGINE): ENGINE_DIGESTS_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_pkey_meths}
  ENGINE_get_pkey_meths: function (const e: PENGINE): ENGINE_PKEY_METHS_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meths}
  ENGINE_get_pkey_asn1_meths: function (const e: PENGINE): ENGINE_PKEY_ASN1_METHS_PTR; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_cipher}
  ENGINE_get_cipher: function (e: PENGINE; nid: TIdC_INT): PEVP_CIPHER; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_digest}
  ENGINE_get_digest: function (e: PENGINE; nid: TIdC_INT): PEVP_MD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_pkey_meth}
  ENGINE_get_pkey_meth: function (e: PENGINE; nid: TIdC_INT): PEVP_PKEY_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth}
  ENGINE_get_pkey_asn1_meth: function (e: PENGINE; nid: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_str}
  ENGINE_get_pkey_asn1_meth_str: function (e: PENGINE; const _str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_pkey_asn1_find_str}
  ENGINE_pkey_asn1_find_str: function (pe: PPENGINE; const _str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_cmd_defns}
  ENGINE_get_cmd_defns: function (const e: PENGINE): PENGINE_CMD_DEFN; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_flags}
  ENGINE_get_flags: function (const e: PENGINE): TIdC_INT; cdecl = nil;

  ///*
  // * FUNCTIONAL functions. These functions deal with ENGINE structures that
  // * have (or will) be initialised for use. Broadly speaking, the structural
  // * functions are useful for iterating the list of available engine types,
  // * creating new engine types, and other "list" operations. These functions
  // * actually deal with ENGINEs that are to be used. As such these functions
  // * can fail (if applicable) when particular engines are unavailable - eg. if
  // * a hardware accelerator is not attached or not functioning correctly. Each
  // * ENGINE has 2 reference counts; structural and functional. Every time a
  // * functional reference is obtained or released, a corresponding structural
  // * reference is automatically obtained or released too.
  // */

  ///*
  // * Initialise a engine type for use (or up its reference count if it's
  // * already in use). This will fail if the engine is not currently operational
  // * and cannot initialise.
  // */
  {$EXTERNALSYM ENGINE_init}
  ENGINE_init: function (e: PENGINE): TIdC_INT; cdecl = nil;
  ///*
  // * Free a functional reference to a engine type. This does not require a
  // * corresponding call to ENGINE_free as it also releases a structural
  // * reference.
  // */
  {$EXTERNALSYM ENGINE_finish}
  ENGINE_finish: function (e: PENGINE): TIdC_INT; cdecl = nil;

  ///*
  // * The following functions handle keys that are stored in some secondary
  // * location, handled by the engine.  The storage may be on a card or
  // * whatever.
  // */
  {$EXTERNALSYM ENGINE_load_private_key}
  ENGINE_load_private_key: function (e: PENGINE; const key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM ENGINE_load_public_key}
  ENGINE_load_public_key: function (e: PENGINE; const key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl = nil;
  //function ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL;
  //  {STACK_OF(X509) *ca_dn;} {STACK_OF(X509) **pother;} ui_method: PUI_METHOD;
  //  callback_data: Pointer): TIdC_INT;

  ///*
  // * This returns a pointer for the current ENGINE structure that is (by
  // * default) performing any RSA operations. The value returned is an
  // * incremented reference, so it should be free'd (ENGINE_finish) before it is
  // * discarded.
  // */
  {$EXTERNALSYM ENGINE_get_default_RSA}
  ENGINE_get_default_RSA: function : PENGINE; cdecl = nil;
  //* Same for the other "methods" */
  {$EXTERNALSYM ENGINE_get_default_DSA}
  ENGINE_get_default_DSA: function : PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_default_EC}
  ENGINE_get_default_EC: function : PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_default_DH}
  ENGINE_get_default_DH: function : PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_default_RAND}
  ENGINE_get_default_RAND: function : PENGINE; cdecl = nil;
  ///*
  // * These functions can be used to get a functional reference to perform
  // * ciphering or digesting corresponding to "nid".
  // */
  {$EXTERNALSYM ENGINE_get_cipher_engine}
  ENGINE_get_cipher_engine: function (nid: TIdC_INT): PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_digest_engine}
  ENGINE_get_digest_engine: function (nid: TIdC_INT): PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_pkey_meth_engine}
  ENGINE_get_pkey_meth_engine: function (nid: TIdC_INT): PENGINE; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_engine}
  ENGINE_get_pkey_asn1_meth_engine: function (nid: TIdC_INT): PENGINE; cdecl = nil;
  ///*
  // * This sets a new default ENGINE structure for performing RSA operations. If
  // * the result is non-zero (success) then the ENGINE structure will have had
  // * its reference count up'd so the caller should still free their own
  // * reference 'e'.
  // */
  {$EXTERNALSYM ENGINE_set_default_RSA}
  ENGINE_set_default_RSA: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_string}
  ENGINE_set_default_string: function (e: PENGINE; const def_list: PIdAnsiChar): TIdC_INT; cdecl = nil;
  // Same for the other "methods"
  {$EXTERNALSYM ENGINE_set_default_DSA}
  ENGINE_set_default_DSA: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_EC}
  ENGINE_set_default_EC: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_DH}
  ENGINE_set_default_DH: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_RAND}
  ENGINE_set_default_RAND: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_ciphers}
  ENGINE_set_default_ciphers: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_digests}
  ENGINE_set_default_digests: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_pkey_meths}
  ENGINE_set_default_pkey_meths: function (e: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ENGINE_set_default_pkey_asn1_meths}
  ENGINE_set_default_pkey_asn1_meths: function (e: PENGINE): TIdC_INT; cdecl = nil;

  ///*
  // * The combination "set" - the flags are bitwise "OR"d from the
  // * ENGINE_METHOD_*** defines above. As with the "ENGINE_register_complete()"
  // * function, this function can result in unnecessary static linkage. If your
  // * application requires only specific functionality, consider using more
  // * selective functions.
  // */
  {$EXTERNALSYM ENGINE_set_default}
  ENGINE_set_default: function (e: PENGINE; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ENGINE_add_conf_module}
  ENGINE_add_conf_module: procedure ; cdecl = nil;

  ///* Deprecated functions ... */
  ///* int ENGINE_clear_defaults(void); */
  //
  //**************************/
  //* DYNAMIC ENGINE SUPPORT */
  //**************************/
  //
  //* Binary/behaviour compatibility levels */
  //# define OSSL_DYNAMIC_VERSION            (unsigned long)0x00030000
  //*
  // * Binary versions older than this are too old for us (whether we're a loader
  // * or a loadee)
  // */
  //# define OSSL_DYNAMIC_OLDEST             (unsigned long)0x00030000
  //
  //*
  // * When compiling an ENGINE entirely as an external shared library, loadable
  // * by the "dynamic" ENGINE, these types are needed. The 'dynamic_fns'
  // * structure type provides the calling application's (or library's) error
  // * functionality and memory management function pointers to the loaded
  // * library. These should be used/set in the loaded library code so that the
  // * loading application's 'state' will be used/changed in all operations. The
  // * 'static_state' pointer allows the loaded library to know if it shares the
  // * same static data as the calling application (or library), and thus whether
  // * these callbacks need to be set or not.
  // */


  //# define IMPLEMENT_DYNAMIC_BIND_FN(fn) \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \
  //            if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; \
  //            CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, \
  //                                     fns->mem_fns.realloc_fn, \
  //                                     fns->mem_fns.free_fn); \
  //        skip_cbs: \
  //            if (!fn(e, id)) return 0; \
  //            return 1; }
  //
  //*
  // * If the loading application (or library) and the loaded ENGINE library
  // * share the same static data (eg. they're both dynamically linked to the
  // * same libcrypto.so) we need a way to avoid trying to set system callbacks -
  // * this would fail, and for the same reason that it's unnecessary to try. If
  // * the loaded ENGINE has (or gets from through the loader) its own copy of
  // * the libcrypto static data, we will need to set the callbacks. The easiest
  // * way to detect this is to have a function that returns a pointer to some
  // * static data and let the loading application and loaded ENGINE compare
  // * their respective values.
  // */
  {$EXTERNALSYM ENGINE_get_static_state}
  ENGINE_get_static_state: function : Pointer; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ENGINE_get_first}
  function ENGINE_get_first: PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_last}
  function ENGINE_get_last: PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_next}
  function ENGINE_get_next(e: PENGINE): PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_prev}
  function ENGINE_get_prev(e: PENGINE): PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_add}
  function ENGINE_add(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_remove}
  function ENGINE_remove(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_by_id}
  function ENGINE_by_id(const id: PIdAnsiChar): PENGINE cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_load_builtin_engines}
  procedure ENGINE_load_builtin_engines cdecl; external CLibCrypto;

  //
  // Get and set global flags (ENGINE_TABLE_FLAG_***) for the implementation
  // "registry" handling.
  //
  {$EXTERNALSYM ENGINE_get_table_flags}
  function ENGINE_get_table_flags: TIdC_UINT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_table_flags}
  procedure ENGINE_set_table_flags(flags: TIdC_UINT) cdecl; external CLibCrypto;

  //- Manage registration of ENGINEs per "table". For each type, there are 3
  // functions;
  //   ENGINE_register_***(e) - registers the implementation from 'e' (if it has one)
  //   ENGINE_unregister_***(e) - unregister the implementation from 'e'
  //   ENGINE_register_all_***() - call ENGINE_register_***() for each 'e' in the list
  // Cleanup is automatically registered from each table when required.
  //

  {$EXTERNALSYM ENGINE_register_RSA}
  function ENGINE_register_RSA(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_RSA}
  procedure ENGINE_unregister_RSA(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_RSA}
  procedure ENGINE_register_all_RSA cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_DSA}
  function ENGINE_register_DSA(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_DSA}
  procedure ENGINE_unregister_DSA(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_DSA}
  procedure ENGINE_register_all_DSA cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_EC}
  function ENGINE_register_EC(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_EC}
  procedure ENGINE_unregister_EC(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_EC}
  procedure ENGINE_register_all_EC cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_DH}
  function ENGINE_register_DH(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_DH}
  procedure ENGINE_unregister_DH(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_DH}
  procedure ENGINE_register_all_DH cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_RAND}
  function ENGINE_register_RAND(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_RAND}
  procedure ENGINE_unregister_RAND(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_RAND}
  procedure ENGINE_register_all_RAND cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_ciphers}
  function ENGINE_register_ciphers(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_ciphers}
  procedure ENGINE_unregister_ciphers(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_ciphers}
  procedure ENGINE_register_all_ciphers cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_digests}
  function ENGINE_register_digests(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_digests}
  procedure ENGINE_unregister_digests(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_digests}
  procedure ENGINE_register_all_digests cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_pkey_meths}
  function ENGINE_register_pkey_meths(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_pkey_meths}
  procedure ENGINE_unregister_pkey_meths(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_pkey_meths}
  procedure ENGINE_register_all_pkey_meths cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_register_pkey_asn1_meths}
  function ENGINE_register_pkey_asn1_meths(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_unregister_pkey_asn1_meths}
  procedure ENGINE_unregister_pkey_asn1_meths(e: PENGINE) cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_pkey_asn1_meths}
  procedure ENGINE_register_all_pkey_asn1_meths cdecl; external CLibCrypto;

  //
  // These functions register all support from the above categories. Note, use
  // of these functions can result in static linkage of code your application
  // may not need. If you only need a subset of functionality, consider using
  // more selective initialisation.
  //
  {$EXTERNALSYM ENGINE_register_complete}
  function ENGINE_register_complete(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_register_all_complete}
  function ENGINE_register_all_complete: TIdC_INT cdecl; external CLibCrypto;

  //
  // Send parameterised control commands to the engine. The possibilities to
  // send down an integer, a pointer to data or a function pointer are
  // provided. Any of the parameters may or may not be NULL, depending on the
  // command number. In actuality, this function only requires a structural
  // (rather than functional) reference to an engine, but many control commands
  // may require the engine be functional. The caller should be aware of trying
  // commands that require an operational ENGINE, and only use functional
  // references in such situations.
  //
  {$EXTERNALSYM ENGINE_ctrl}
  function ENGINE_ctrl(e: PENGINE; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; v1: f): TIdC_INT cdecl; external CLibCrypto;

  //
  // This function tests if an ENGINE-specific command is usable as a
  // "setting". Eg. in an application's config file that gets processed through
  // ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
  // ENGINE_ctrl_cmd_string(), only ENGINE_ctrl().
  //
  {$EXTERNALSYM ENGINE_cmd_is_executable}
  function ENGINE_cmd_is_executable(e: PENGINE; cmd: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  //
  // This function works like ENGINE_ctrl() with the exception of taking a
  // command name instead of a command number, and can handle optional
  // commands. See the comment on ENGINE_ctrl_cmd_string() for an explanation
  // on how to use the cmd_name and cmd_optional.
  //
  {$EXTERNALSYM ENGINE_ctrl_cmd}
  function ENGINE_ctrl_cmd(e: PENGINE; const cmd_name: PIdAnsiChar; i: TIdC_LONG; p: Pointer; v1: f; cmd_optional: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  //
  // This function passes a command-name and argument to an ENGINE. The
  // cmd_name is converted to a command number and the control command is
  // called using 'arg' as an argument (unless the ENGINE doesn't support such
  // a command, in which case no control command is called). The command is
  // checked for input flags, and if necessary the argument will be converted
  // to a numeric value. If cmd_optional is non-zero, then if the ENGINE
  // doesn't support the given cmd_name the return value will be success
  // anyway. This function is intended for applications to use so that users
  // (or config files) can supply engine-specific config data to the ENGINE at
  // run-time to control behaviour of specific engines. As such, it shouldn't
  // be used for calling ENGINE_ctrl() functions that return data, deal with
  // binary data, or that are otherwise supposed to be used directly through
  // ENGINE_ctrl() in application code. Any "return" data from an ENGINE_ctrl()
  // operation in this function will be lost - the return value is interpreted
  // as failure if the return value is zero, success otherwise, and this
  // function returns a boolean value as a result. In other words, vendors of
  // 'ENGINE'-enabled devices should write ENGINE implementations with
  // parameterisations that work in this scheme, so that compliant ENGINE-based
  // applications can work consistently with the same configuration for the
  // same ENGINE-enabled devices, across applications.
  //
  {$EXTERNALSYM ENGINE_ctrl_cmd_string}
  function ENGINE_ctrl_cmd_string(e: PENGINE; const cmd_name: PIdAnsiChar; const arg: PIdAnsiChar; cmd_optional: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  //
  // These functions are useful for manufacturing new ENGINE structures. They
  // don't address reference counting at all - one uses them to populate an
  // ENGINE structure with personalised implementations of things prior to
  // using it directly or adding it to the builtin ENGINE list in TaurusTLS.
  // These are also here so that the ENGINE structure doesn't have to be
  // exposed and break binary compatibility!
  //
  {$EXTERNALSYM ENGINE_new}
  function ENGINE_new: PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_free}
  function ENGINE_free(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_up_ref}
  function ENGINE_up_ref(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_id}
  function ENGINE_set_id(e: PENGINE; const id: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_name}
  function ENGINE_set_name(e: PENGINE; const name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_RSA}
  function ENGINE_set_RSA(e: PENGINE; const rsa_meth: PRSA_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_DSA}
  function ENGINE_set_DSA(e: PENGINE; const dsa_meth: PDSA_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_EC}
  function ENGINE_set_EC(e: PENGINE; const ecdsa_meth: PEC_KEY_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_DH}
  function ENGINE_set_DH(e: PENGINE; const dh_meth: PDH_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_RAND}
  function ENGINE_set_RAND(e: PENGINE; const rand_meth: PRAND_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_destroy_function}
  function ENGINE_set_destroy_function(e: PENGINE; destroy_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_init_function}
  function ENGINE_set_init_function(e: PENGINE; init_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_finish_function}
  function ENGINE_set_finish_function(e: PENGINE; finish_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_ctrl_function}
  function ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: ENGINE_CTRL_FUNC_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_load_privkey_function}
  function ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: ENGINE_LOAD_KEY_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_load_pubkey_function}
  function ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: ENGINE_LOAD_KEY_PTR): TIdC_INT cdecl; external CLibCrypto;
  //function ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: ENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT;
  {$EXTERNALSYM ENGINE_set_ciphers}
  function ENGINE_set_ciphers(e: PENGINE; f: ENGINE_CIPHERS_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_digests}
  function ENGINE_set_digests(e: PENGINE; f: ENGINE_DIGESTS_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_pkey_meths}
  function ENGINE_set_pkey_meths(e: PENGINE; f: ENGINE_PKEY_METHS_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_pkey_asn1_meths}
  function ENGINE_set_pkey_asn1_meths(e: PENGINE; f: ENGINE_PKEY_ASN1_METHS_PTR): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_flags}
  function ENGINE_set_flags(e: PENGINE; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_cmd_defns}
  function ENGINE_set_cmd_defns(e: PENGINE; const defns: PENGINE_CMD_DEFN): TIdC_INT cdecl; external CLibCrypto;
  // These functions allow control over any per-structure ENGINE data. */
  //#define ENGINE_get_ex_new_index(l, p, newf, dupf, freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)
  {$EXTERNALSYM ENGINE_set_ex_data}
  function ENGINE_set_ex_data(e: PENGINE; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_ex_data}
  function ENGINE_get_ex_data(const e: PENGINE; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;

  //
  // These return values from within the ENGINE structure. These can be useful
  // with functional references as well as structural references - it depends
  // which you obtained. Using the result for functional purposes if you only
  // obtained a structural reference may be problematic!
  //
  {$EXTERNALSYM ENGINE_get_id}
  function ENGINE_get_id(const e: PENGINE): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_name}
  function ENGINE_get_name(const e: PENGINE): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_RSA}
  function ENGINE_get_RSA(const e: PENGINE): PRSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_DSA}
  function ENGINE_get_DSA(const e: PENGINE): PDSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_EC}
  function ENGINE_get_EC(const e: PENGINE): PEC_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_DH}
  function ENGINE_get_DH(const e: PENGINE): PDH_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_RAND}
  function ENGINE_get_RAND(const e: PENGINE): PRAND_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_destroy_function}
  function ENGINE_get_destroy_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_init_function}
  function ENGINE_get_init_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_finish_function}
  function ENGINE_get_finish_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_ctrl_function}
  function ENGINE_get_ctrl_function(const e: PENGINE): ENGINE_CTRL_FUNC_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_load_privkey_function}
  function ENGINE_get_load_privkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_load_pubkey_function}
  function ENGINE_get_load_pubkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR cdecl; external CLibCrypto;
  //function ENGINE_get_ssl_client_cert_function(const e: PENGINE): ENGINE_SSL_CLIENT_CERT_PTR;
  
  {$EXTERNALSYM ENGINE_get_ciphers}
  function ENGINE_get_ciphers(const e: PENGINE): ENGINE_CIPHERS_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_digests}
  function ENGINE_get_digests(const e: PENGINE): ENGINE_DIGESTS_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_pkey_meths}
  function ENGINE_get_pkey_meths(const e: PENGINE): ENGINE_PKEY_METHS_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meths}
  function ENGINE_get_pkey_asn1_meths(const e: PENGINE): ENGINE_PKEY_ASN1_METHS_PTR cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_cipher}
  function ENGINE_get_cipher(e: PENGINE; nid: TIdC_INT): PEVP_CIPHER cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_digest}
  function ENGINE_get_digest(e: PENGINE; nid: TIdC_INT): PEVP_MD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_pkey_meth}
  function ENGINE_get_pkey_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth}
  function ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_str}
  function ENGINE_get_pkey_asn1_meth_str(e: PENGINE; const _str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_pkey_asn1_find_str}
  function ENGINE_pkey_asn1_find_str(pe: PPENGINE; const _str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_cmd_defns}
  function ENGINE_get_cmd_defns(const e: PENGINE): PENGINE_CMD_DEFN cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_flags}
  function ENGINE_get_flags(const e: PENGINE): TIdC_INT cdecl; external CLibCrypto;

  ///*
  // * FUNCTIONAL functions. These functions deal with ENGINE structures that
  // * have (or will) be initialised for use. Broadly speaking, the structural
  // * functions are useful for iterating the list of available engine types,
  // * creating new engine types, and other "list" operations. These functions
  // * actually deal with ENGINEs that are to be used. As such these functions
  // * can fail (if applicable) when particular engines are unavailable - eg. if
  // * a hardware accelerator is not attached or not functioning correctly. Each
  // * ENGINE has 2 reference counts; structural and functional. Every time a
  // * functional reference is obtained or released, a corresponding structural
  // * reference is automatically obtained or released too.
  // */

  ///*
  // * Initialise a engine type for use (or up its reference count if it's
  // * already in use). This will fail if the engine is not currently operational
  // * and cannot initialise.
  // */
  {$EXTERNALSYM ENGINE_init}
  function ENGINE_init(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  ///*
  // * Free a functional reference to a engine type. This does not require a
  // * corresponding call to ENGINE_free as it also releases a structural
  // * reference.
  // */
  {$EXTERNALSYM ENGINE_finish}
  function ENGINE_finish(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;

  ///*
  // * The following functions handle keys that are stored in some secondary
  // * location, handled by the engine.  The storage may be on a card or
  // * whatever.
  // */
  {$EXTERNALSYM ENGINE_load_private_key}
  function ENGINE_load_private_key(e: PENGINE; const key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_load_public_key}
  function ENGINE_load_public_key(e: PENGINE; const key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY cdecl; external CLibCrypto;
  //function ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL;
  //  {STACK_OF(X509) *ca_dn;} {STACK_OF(X509) **pother;} ui_method: PUI_METHOD;
  //  callback_data: Pointer): TIdC_INT;

  ///*
  // * This returns a pointer for the current ENGINE structure that is (by
  // * default) performing any RSA operations. The value returned is an
  // * incremented reference, so it should be free'd (ENGINE_finish) before it is
  // * discarded.
  // */
  {$EXTERNALSYM ENGINE_get_default_RSA}
  function ENGINE_get_default_RSA: PENGINE cdecl; external CLibCrypto;
  //* Same for the other "methods" */
  {$EXTERNALSYM ENGINE_get_default_DSA}
  function ENGINE_get_default_DSA: PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_default_EC}
  function ENGINE_get_default_EC: PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_default_DH}
  function ENGINE_get_default_DH: PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_default_RAND}
  function ENGINE_get_default_RAND: PENGINE cdecl; external CLibCrypto;
  ///*
  // * These functions can be used to get a functional reference to perform
  // * ciphering or digesting corresponding to "nid".
  // */
  {$EXTERNALSYM ENGINE_get_cipher_engine}
  function ENGINE_get_cipher_engine(nid: TIdC_INT): PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_digest_engine}
  function ENGINE_get_digest_engine(nid: TIdC_INT): PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_pkey_meth_engine}
  function ENGINE_get_pkey_meth_engine(nid: TIdC_INT): PENGINE cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_engine}
  function ENGINE_get_pkey_asn1_meth_engine(nid: TIdC_INT): PENGINE cdecl; external CLibCrypto;
  ///*
  // * This sets a new default ENGINE structure for performing RSA operations. If
  // * the result is non-zero (success) then the ENGINE structure will have had
  // * its reference count up'd so the caller should still free their own
  // * reference 'e'.
  // */
  {$EXTERNALSYM ENGINE_set_default_RSA}
  function ENGINE_set_default_RSA(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_string}
  function ENGINE_set_default_string(e: PENGINE; const def_list: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  // Same for the other "methods"
  {$EXTERNALSYM ENGINE_set_default_DSA}
  function ENGINE_set_default_DSA(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_EC}
  function ENGINE_set_default_EC(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_DH}
  function ENGINE_set_default_DH(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_RAND}
  function ENGINE_set_default_RAND(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_ciphers}
  function ENGINE_set_default_ciphers(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_digests}
  function ENGINE_set_default_digests(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_pkey_meths}
  function ENGINE_set_default_pkey_meths(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ENGINE_set_default_pkey_asn1_meths}
  function ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TIdC_INT cdecl; external CLibCrypto;

  ///*
  // * The combination "set" - the flags are bitwise "OR"d from the
  // * ENGINE_METHOD_*** defines above. As with the "ENGINE_register_complete()"
  // * function, this function can result in unnecessary static linkage. If your
  // * application requires only specific functionality, consider using more
  // * selective functions.
  // */
  {$EXTERNALSYM ENGINE_set_default}
  function ENGINE_set_default(e: PENGINE; flags: TIdC_ULONG): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ENGINE_add_conf_module}
  procedure ENGINE_add_conf_module cdecl; external CLibCrypto;

  ///* Deprecated functions ... */
  ///* int ENGINE_clear_defaults(void); */
  //
  //**************************/
  //* DYNAMIC ENGINE SUPPORT */
  //**************************/
  //
  //* Binary/behaviour compatibility levels */
  //# define OSSL_DYNAMIC_VERSION            (unsigned long)0x00030000
  //*
  // * Binary versions older than this are too old for us (whether we're a loader
  // * or a loadee)
  // */
  //# define OSSL_DYNAMIC_OLDEST             (unsigned long)0x00030000
  //
  //*
  // * When compiling an ENGINE entirely as an external shared library, loadable
  // * by the "dynamic" ENGINE, these types are needed. The 'dynamic_fns'
  // * structure type provides the calling application's (or library's) error
  // * functionality and memory management function pointers to the loaded
  // * library. These should be used/set in the loaded library code so that the
  // * loading application's 'state' will be used/changed in all operations. The
  // * 'static_state' pointer allows the loaded library to know if it shares the
  // * same static data as the calling application (or library), and thus whether
  // * these callbacks need to be set or not.
  // */


  //# define IMPLEMENT_DYNAMIC_BIND_FN(fn) \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \
  //            if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; \
  //            CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, \
  //                                     fns->mem_fns.realloc_fn, \
  //                                     fns->mem_fns.free_fn); \
  //        skip_cbs: \
  //            if (!fn(e, id)) return 0; \
  //            return 1; }
  //
  //*
  // * If the loading application (or library) and the loaded ENGINE library
  // * share the same static data (eg. they're both dynamically linked to the
  // * same libcrypto.so) we need a way to avoid trying to set system callbacks -
  // * this would fail, and for the same reason that it's unnecessary to try. If
  // * the loaded ENGINE has (or gets from through the loader) its own copy of
  // * the libcrypto static data, we will need to set the callbacks. The easiest
  // * way to detect this is to have a function that returns a pointer to some
  // * static data and let the loading application and loaded ENGINE compare
  // * their respective values.
  // */
  {$EXTERNALSYM ENGINE_get_static_state}
  function ENGINE_get_static_state: Pointer cdecl; external CLibCrypto;

{$ENDIF}
  {$EXTERNALSYM ENGINE_get_ex_new_index}
function ENGINE_get_ex_new_index(l : TIdC_LONG; p : PENGINE;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
  // These functions allow control over any per-structure ENGINE data. */
  //#define ENGINE_get_ex_new_index(l, p, newf, dupf, freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)
function ENGINE_get_ex_new_index(l : TIdC_LONG; p : PENGINE;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef);
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  ENGINE_get_first_procname = 'ENGINE_get_first';
  ENGINE_get_last_procname = 'ENGINE_get_last';
  ENGINE_get_next_procname = 'ENGINE_get_next';
  ENGINE_get_prev_procname = 'ENGINE_get_prev';
  ENGINE_add_procname = 'ENGINE_add';
  ENGINE_remove_procname = 'ENGINE_remove';
  ENGINE_by_id_procname = 'ENGINE_by_id';

  ENGINE_load_builtin_engines_procname = 'ENGINE_load_builtin_engines';

  //
  // Get and set global flags (ENGINE_TABLE_FLAG_***) for the implementation
  // "registry" handling.
  //
  ENGINE_get_table_flags_procname = 'ENGINE_get_table_flags';
  ENGINE_set_table_flags_procname = 'ENGINE_set_table_flags';

  //- Manage registration of ENGINEs per "table". For each type, there are 3
  // functions;
  //   ENGINE_register_***(e) - registers the implementation from 'e' (if it has one)
  //   ENGINE_unregister_***(e) - unregister the implementation from 'e'
  //   ENGINE_register_all_***() - call ENGINE_register_***() for each 'e' in the list
  // Cleanup is automatically registered from each table when required.
  //

  ENGINE_register_RSA_procname = 'ENGINE_register_RSA';
  ENGINE_unregister_RSA_procname = 'ENGINE_unregister_RSA';
  ENGINE_register_all_RSA_procname = 'ENGINE_register_all_RSA';

  ENGINE_register_DSA_procname = 'ENGINE_register_DSA';
  ENGINE_unregister_DSA_procname = 'ENGINE_unregister_DSA';
  ENGINE_register_all_DSA_procname = 'ENGINE_register_all_DSA';

  ENGINE_register_EC_procname = 'ENGINE_register_EC';
  ENGINE_unregister_EC_procname = 'ENGINE_unregister_EC';
  ENGINE_register_all_EC_procname = 'ENGINE_register_all_EC';

  ENGINE_register_DH_procname = 'ENGINE_register_DH';
  ENGINE_unregister_DH_procname = 'ENGINE_unregister_DH';
  ENGINE_register_all_DH_procname = 'ENGINE_register_all_DH';

  ENGINE_register_RAND_procname = 'ENGINE_register_RAND';
  ENGINE_unregister_RAND_procname = 'ENGINE_unregister_RAND';
  ENGINE_register_all_RAND_procname = 'ENGINE_register_all_RAND';

  ENGINE_register_ciphers_procname = 'ENGINE_register_ciphers';
  ENGINE_unregister_ciphers_procname = 'ENGINE_unregister_ciphers';
  ENGINE_register_all_ciphers_procname = 'ENGINE_register_all_ciphers';

  ENGINE_register_digests_procname = 'ENGINE_register_digests';
  ENGINE_unregister_digests_procname = 'ENGINE_unregister_digests';
  ENGINE_register_all_digests_procname = 'ENGINE_register_all_digests';

  ENGINE_register_pkey_meths_procname = 'ENGINE_register_pkey_meths';
  ENGINE_unregister_pkey_meths_procname = 'ENGINE_unregister_pkey_meths';
  ENGINE_register_all_pkey_meths_procname = 'ENGINE_register_all_pkey_meths';

  ENGINE_register_pkey_asn1_meths_procname = 'ENGINE_register_pkey_asn1_meths';
  ENGINE_unregister_pkey_asn1_meths_procname = 'ENGINE_unregister_pkey_asn1_meths';
  ENGINE_register_all_pkey_asn1_meths_procname = 'ENGINE_register_all_pkey_asn1_meths';

  //
  // These functions register all support from the above categories. Note, use
  // of these functions can result in static linkage of code your application
  // may not need. If you only need a subset of functionality, consider using
  // more selective initialisation.
  //
  ENGINE_register_complete_procname = 'ENGINE_register_complete';
  ENGINE_register_all_complete_procname = 'ENGINE_register_all_complete';

  //
  // Send parameterised control commands to the engine. The possibilities to
  // send down an integer, a pointer to data or a function pointer are
  // provided. Any of the parameters may or may not be NULL, depending on the
  // command number. In actuality, this function only requires a structural
  // (rather than functional) reference to an engine, but many control commands
  // may require the engine be functional. The caller should be aware of trying
  // commands that require an operational ENGINE, and only use functional
  // references in such situations.
  //
  ENGINE_ctrl_procname = 'ENGINE_ctrl';

  //
  // This function tests if an ENGINE-specific command is usable as a
  // "setting". Eg. in an application's config file that gets processed through
  // ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
  // ENGINE_ctrl_cmd_string(), only ENGINE_ctrl().
  //
  ENGINE_cmd_is_executable_procname = 'ENGINE_cmd_is_executable';

  //
  // This function works like ENGINE_ctrl() with the exception of taking a
  // command name instead of a command number, and can handle optional
  // commands. See the comment on ENGINE_ctrl_cmd_string() for an explanation
  // on how to use the cmd_name and cmd_optional.
  //
  ENGINE_ctrl_cmd_procname = 'ENGINE_ctrl_cmd';

  //
  // This function passes a command-name and argument to an ENGINE. The
  // cmd_name is converted to a command number and the control command is
  // called using 'arg' as an argument (unless the ENGINE doesn't support such
  // a command, in which case no control command is called). The command is
  // checked for input flags, and if necessary the argument will be converted
  // to a numeric value. If cmd_optional is non-zero, then if the ENGINE
  // doesn't support the given cmd_name the return value will be success
  // anyway. This function is intended for applications to use so that users
  // (or config files) can supply engine-specific config data to the ENGINE at
  // run-time to control behaviour of specific engines. As such, it shouldn't
  // be used for calling ENGINE_ctrl() functions that return data, deal with
  // binary data, or that are otherwise supposed to be used directly through
  // ENGINE_ctrl() in application code. Any "return" data from an ENGINE_ctrl()
  // operation in this function will be lost - the return value is interpreted
  // as failure if the return value is zero, success otherwise, and this
  // function returns a boolean value as a result. In other words, vendors of
  // 'ENGINE'-enabled devices should write ENGINE implementations with
  // parameterisations that work in this scheme, so that compliant ENGINE-based
  // applications can work consistently with the same configuration for the
  // same ENGINE-enabled devices, across applications.
  //
  ENGINE_ctrl_cmd_string_procname = 'ENGINE_ctrl_cmd_string';

  //
  // These functions are useful for manufacturing new ENGINE structures. They
  // don't address reference counting at all - one uses them to populate an
  // ENGINE structure with personalised implementations of things prior to
  // using it directly or adding it to the builtin ENGINE list in TaurusTLS.
  // These are also here so that the ENGINE structure doesn't have to be
  // exposed and break binary compatibility!
  //
  ENGINE_new_procname = 'ENGINE_new';
  ENGINE_free_procname = 'ENGINE_free';
  ENGINE_up_ref_procname = 'ENGINE_up_ref';
  ENGINE_set_id_procname = 'ENGINE_set_id';
  ENGINE_set_name_procname = 'ENGINE_set_name';
  ENGINE_set_RSA_procname = 'ENGINE_set_RSA';
  ENGINE_set_DSA_procname = 'ENGINE_set_DSA';
  ENGINE_set_EC_procname = 'ENGINE_set_EC';
  ENGINE_set_DH_procname = 'ENGINE_set_DH';
  ENGINE_set_RAND_procname = 'ENGINE_set_RAND';
  ENGINE_set_destroy_function_procname = 'ENGINE_set_destroy_function';
  ENGINE_set_init_function_procname = 'ENGINE_set_init_function';
  ENGINE_set_finish_function_procname = 'ENGINE_set_finish_function';
  ENGINE_set_ctrl_function_procname = 'ENGINE_set_ctrl_function';
  ENGINE_set_load_privkey_function_procname = 'ENGINE_set_load_privkey_function';
  ENGINE_set_load_pubkey_function_procname = 'ENGINE_set_load_pubkey_function';
  //function ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: ENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT;
  ENGINE_set_ciphers_procname = 'ENGINE_set_ciphers';
  ENGINE_set_digests_procname = 'ENGINE_set_digests';
  ENGINE_set_pkey_meths_procname = 'ENGINE_set_pkey_meths';
  ENGINE_set_pkey_asn1_meths_procname = 'ENGINE_set_pkey_asn1_meths';
  ENGINE_set_flags_procname = 'ENGINE_set_flags';
  ENGINE_set_cmd_defns_procname = 'ENGINE_set_cmd_defns';
  // These functions allow control over any per-structure ENGINE data. */
  //#define ENGINE_get_ex_new_index(l, p, newf, dupf, freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)
  ENGINE_set_ex_data_procname = 'ENGINE_set_ex_data';
  ENGINE_get_ex_data_procname = 'ENGINE_get_ex_data';

  //
  // These return values from within the ENGINE structure. These can be useful
  // with functional references as well as structural references - it depends
  // which you obtained. Using the result for functional purposes if you only
  // obtained a structural reference may be problematic!
  //
  ENGINE_get_id_procname = 'ENGINE_get_id';
  ENGINE_get_name_procname = 'ENGINE_get_name';
  ENGINE_get_RSA_procname = 'ENGINE_get_RSA';
  ENGINE_get_DSA_procname = 'ENGINE_get_DSA';
  ENGINE_get_EC_procname = 'ENGINE_get_EC';
  ENGINE_get_DH_procname = 'ENGINE_get_DH';
  ENGINE_get_RAND_procname = 'ENGINE_get_RAND';
  ENGINE_get_destroy_function_procname = 'ENGINE_get_destroy_function';
  ENGINE_get_init_function_procname = 'ENGINE_get_init_function';
  ENGINE_get_finish_function_procname = 'ENGINE_get_finish_function';
  ENGINE_get_ctrl_function_procname = 'ENGINE_get_ctrl_function';
  ENGINE_get_load_privkey_function_procname = 'ENGINE_get_load_privkey_function';
  ENGINE_get_load_pubkey_function_procname = 'ENGINE_get_load_pubkey_function';
  //function ENGINE_get_ssl_client_cert_function(const e: PENGINE): ENGINE_SSL_CLIENT_CERT_PTR;
  
  ENGINE_get_ciphers_procname = 'ENGINE_get_ciphers';
  ENGINE_get_digests_procname = 'ENGINE_get_digests';
  ENGINE_get_pkey_meths_procname = 'ENGINE_get_pkey_meths';
  ENGINE_get_pkey_asn1_meths_procname = 'ENGINE_get_pkey_asn1_meths';
  ENGINE_get_cipher_procname = 'ENGINE_get_cipher';
  ENGINE_get_digest_procname = 'ENGINE_get_digest';
  ENGINE_get_pkey_meth_procname = 'ENGINE_get_pkey_meth';
  ENGINE_get_pkey_asn1_meth_procname = 'ENGINE_get_pkey_asn1_meth';
  ENGINE_get_pkey_asn1_meth_str_procname = 'ENGINE_get_pkey_asn1_meth_str';
  ENGINE_pkey_asn1_find_str_procname = 'ENGINE_pkey_asn1_find_str';
  ENGINE_get_cmd_defns_procname = 'ENGINE_get_cmd_defns';
  ENGINE_get_flags_procname = 'ENGINE_get_flags';

  ///*
  // * FUNCTIONAL functions. These functions deal with ENGINE structures that
  // * have (or will) be initialised for use. Broadly speaking, the structural
  // * functions are useful for iterating the list of available engine types,
  // * creating new engine types, and other "list" operations. These functions
  // * actually deal with ENGINEs that are to be used. As such these functions
  // * can fail (if applicable) when particular engines are unavailable - eg. if
  // * a hardware accelerator is not attached or not functioning correctly. Each
  // * ENGINE has 2 reference counts; structural and functional. Every time a
  // * functional reference is obtained or released, a corresponding structural
  // * reference is automatically obtained or released too.
  // */

  ///*
  // * Initialise a engine type for use (or up its reference count if it's
  // * already in use). This will fail if the engine is not currently operational
  // * and cannot initialise.
  // */
  ENGINE_init_procname = 'ENGINE_init';
  ///*
  // * Free a functional reference to a engine type. This does not require a
  // * corresponding call to ENGINE_free as it also releases a structural
  // * reference.
  // */
  ENGINE_finish_procname = 'ENGINE_finish';

  ///*
  // * The following functions handle keys that are stored in some secondary
  // * location, handled by the engine.  The storage may be on a card or
  // * whatever.
  // */
  ENGINE_load_private_key_procname = 'ENGINE_load_private_key';
  ENGINE_load_public_key_procname = 'ENGINE_load_public_key';
  //function ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL;
  //  {STACK_OF(X509) *ca_dn;} {STACK_OF(X509) **pother;} ui_method: PUI_METHOD;
  //  callback_data: Pointer): TIdC_INT;

  ///*
  // * This returns a pointer for the current ENGINE structure that is (by
  // * default) performing any RSA operations. The value returned is an
  // * incremented reference, so it should be free'd (ENGINE_finish) before it is
  // * discarded.
  // */
  ENGINE_get_default_RSA_procname = 'ENGINE_get_default_RSA';
  //* Same for the other "methods" */
  ENGINE_get_default_DSA_procname = 'ENGINE_get_default_DSA';
  ENGINE_get_default_EC_procname = 'ENGINE_get_default_EC';
  ENGINE_get_default_DH_procname = 'ENGINE_get_default_DH';
  ENGINE_get_default_RAND_procname = 'ENGINE_get_default_RAND';
  ///*
  // * These functions can be used to get a functional reference to perform
  // * ciphering or digesting corresponding to "nid".
  // */
  ENGINE_get_cipher_engine_procname = 'ENGINE_get_cipher_engine';
  ENGINE_get_digest_engine_procname = 'ENGINE_get_digest_engine';
  ENGINE_get_pkey_meth_engine_procname = 'ENGINE_get_pkey_meth_engine';
  ENGINE_get_pkey_asn1_meth_engine_procname = 'ENGINE_get_pkey_asn1_meth_engine';
  ///*
  // * This sets a new default ENGINE structure for performing RSA operations. If
  // * the result is non-zero (success) then the ENGINE structure will have had
  // * its reference count up'd so the caller should still free their own
  // * reference 'e'.
  // */
  ENGINE_set_default_RSA_procname = 'ENGINE_set_default_RSA';
  ENGINE_set_default_string_procname = 'ENGINE_set_default_string';
  // Same for the other "methods"
  ENGINE_set_default_DSA_procname = 'ENGINE_set_default_DSA';
  ENGINE_set_default_EC_procname = 'ENGINE_set_default_EC';
  ENGINE_set_default_DH_procname = 'ENGINE_set_default_DH';
  ENGINE_set_default_RAND_procname = 'ENGINE_set_default_RAND';
  ENGINE_set_default_ciphers_procname = 'ENGINE_set_default_ciphers';
  ENGINE_set_default_digests_procname = 'ENGINE_set_default_digests';
  ENGINE_set_default_pkey_meths_procname = 'ENGINE_set_default_pkey_meths';
  ENGINE_set_default_pkey_asn1_meths_procname = 'ENGINE_set_default_pkey_asn1_meths';

  ///*
  // * The combination "set" - the flags are bitwise "OR"d from the
  // * ENGINE_METHOD_*** defines above. As with the "ENGINE_register_complete()"
  // * function, this function can result in unnecessary static linkage. If your
  // * application requires only specific functionality, consider using more
  // * selective functions.
  // */
  ENGINE_set_default_procname = 'ENGINE_set_default';

  ENGINE_add_conf_module_procname = 'ENGINE_add_conf_module';

  ///* Deprecated functions ... */
  ///* int ENGINE_clear_defaults(void); */
  //
  //**************************/
  //* DYNAMIC ENGINE SUPPORT */
  //**************************/
  //
  //* Binary/behaviour compatibility levels */
  //# define OSSL_DYNAMIC_VERSION            (unsigned long)0x00030000
  //*
  // * Binary versions older than this are too old for us (whether we're a loader
  // * or a loadee)
  // */
  //# define OSSL_DYNAMIC_OLDEST             (unsigned long)0x00030000
  //
  //*
  // * When compiling an ENGINE entirely as an external shared library, loadable
  // * by the "dynamic" ENGINE, these types are needed. The 'dynamic_fns'
  // * structure type provides the calling application's (or library's) error
  // * functionality and memory management function pointers to the loaded
  // * library. These should be used/set in the loaded library code so that the
  // * loading application's 'state' will be used/changed in all operations. The
  // * 'static_state' pointer allows the loaded library to know if it shares the
  // * same static data as the calling application (or library), and thus whether
  // * these callbacks need to be set or not.
  // */


  //# define IMPLEMENT_DYNAMIC_BIND_FN(fn) \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \
  //            if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; \
  //            CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, \
  //                                     fns->mem_fns.realloc_fn, \
  //                                     fns->mem_fns.free_fn); \
  //        skip_cbs: \
  //            if (!fn(e, id)) return 0; \
  //            return 1; }
  //
  //*
  // * If the loading application (or library) and the loaded ENGINE library
  // * share the same static data (eg. they're both dynamically linked to the
  // * same libcrypto.so) we need a way to avoid trying to set system callbacks -
  // * this would fail, and for the same reason that it's unnecessary to try. If
  // * the loaded ENGINE has (or gets from through the loader) its own copy of
  // * the libcrypto static data, we will need to set the callbacks. The easiest
  // * way to detect this is to have a function that returns a pointer to some
  // * static data and let the loading application and loaded ENGINE compare
  // * their respective values.
  // */
  ENGINE_get_static_state_procname = 'ENGINE_get_static_state';

  // engines.h and engineerr.h were removed for OpenSSL 4.0.0.
  Removal_4_Engines =  (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  ENGINE_get_first_removed = Removal_4_Engines;
  ENGINE_get_last_removed =  Removal_4_Engines;
  ENGINE_get_next_removed = Removal_4_Engines;
  ENGINE_get_prev_removed = Removal_4_Engines;
  ENGINE_add_removed =  Removal_4_Engines;
  ENGINE_remove_removed = Removal_4_Engines;
  ENGINE_by_id_removed = Removal_4_Engines;
  ENGINE_load_builtin_engines_removed = Removal_4_Engines;
  ENGINE_get_table_flags_removed = Removal_4_Engines;
  ENGINE_set_table_flags_removed = Removal_4_Engines;
  ENGINE_register_RSA_removed = Removal_4_Engines;
  ENGINE_unregister_RSA_removed = Removal_4_Engines;
  ENGINE_register_all_RSA_removed = Removal_4_Engines;
  ENGINE_register_DSA_removed = Removal_4_Engines;
  ENGINE_unregister_DSA_removed = Removal_4_Engines;
  ENGINE_register_all_DSA_removed = Removal_4_Engines;
  ENGINE_register_EC_removed = Removal_4_Engines;
  ENGINE_unregister_EC_removed = Removal_4_Engines;
  ENGINE_register_all_EC_removed = Removal_4_Engines;
  ENGINE_register_DH_removed = Removal_4_Engines;
  ENGINE_unregister_DH_removed = Removal_4_Engines;
  ENGINE_register_all_DH_removed = Removal_4_Engines;
  ENGINE_register_RAND_removed = Removal_4_Engines;
  ENGINE_unregister_RAND_removed =  Removal_4_Engines;
  ENGINE_register_all_RAND_removed = Removal_4_Engines;
  ENGINE_register_ciphers_removed = Removal_4_Engines;
  ENGINE_unregister_ciphers_removed = Removal_4_Engines;
  ENGINE_register_all_ciphers_removed = Removal_4_Engines;
  ENGINE_register_digests_removed = Removal_4_Engines;
  ENGINE_unregister_digests_removed = Removal_4_Engines;
  ENGINE_register_all_digests_removed = Removal_4_Engines;
  ENGINE_register_pkey_meths_removed = Removal_4_Engines;
  ENGINE_unregister_pkey_meths_removed = Removal_4_Engines;
  ENGINE_register_all_pkey_meths_removed = Removal_4_Engines;
  ENGINE_register_pkey_asn1_meths_removed = Removal_4_Engines;
  ENGINE_unregister_pkey_asn1_meths_removed = Removal_4_Engines;
  ENGINE_register_all_pkey_asn1_meths_removed = Removal_4_Engines;
  ENGINE_register_complete_removed = Removal_4_Engines;
  ENGINE_register_all_complete_removed = Removal_4_Engines;
  ENGINE_ctrl_removed = Removal_4_Engines;
  ENGINE_cmd_is_executable_removed = Removal_4_Engines;
  ENGINE_ctrl_cmd_string_removed = Removal_4_Engines;
  ENGINE_ctrl_cmd_removed = Removal_4_Engines;

  ENGINE_new_removed = Removal_4_Engines;
  ENGINE_free_removed = Removal_4_Engines;
  ENGINE_up_ref_removed = Removal_4_Engines;
  ENGINE_set_id_removed = Removal_4_Engines;
  ENGINE_set_name_removed = Removal_4_Engines;
  ENGINE_set_RSA_removed = Removal_4_Engines;
  ENGINE_set_DSA_removed = Removal_4_Engines;
  ENGINE_set_EC_removed = Removal_4_Engines;
  ENGINE_set_DH_removed = Removal_4_Engines;
  ENGINE_set_RAND_removed = Removal_4_Engines;
  ENGINE_set_destroy_function_removed = Removal_4_Engines;
  ENGINE_set_init_function_removed = Removal_4_Engines;
  ENGINE_set_finish_function_removed = Removal_4_Engines;
  ENGINE_set_ctrl_function_removed = Removal_4_Engines;
  ENGINE_set_load_privkey_function_removed = Removal_4_Engines;
  ENGINE_set_load_pubkey_function_removed = Removal_4_Engines;
  ENGINE_set_ciphers_removed = Removal_4_Engines;
  ENGINE_set_digests_removed = Removal_4_Engines;
  ENGINE_set_pkey_meths_removed = Removal_4_Engines;
  ENGINE_set_pkey_asn1_meths_removed = Removal_4_Engines;
  ENGINE_set_flags_removed = Removal_4_Engines;
  ENGINE_set_cmd_defns_removed = Removal_4_Engines;
  ENGINE_set_ex_data_removed = Removal_4_Engines;
  ENGINE_get_ex_data_removed = Removal_4_Engines;
  ENGINE_get_id_removed = Removal_4_Engines;
  ENGINE_get_name_removed = Removal_4_Engines;
  ENGINE_get_RSA_removed = Removal_4_Engines;
  ENGINE_get_DSA_removed = Removal_4_Engines;
  ENGINE_get_EC_removed = Removal_4_Engines;
  ENGINE_get_DH_removed = Removal_4_Engines;
  ENGINE_get_RAND_removed = Removal_4_Engines;
  ENGINE_get_destroy_function_removed = Removal_4_Engines;
  ENGINE_get_init_function_removed = Removal_4_Engines;
  ENGINE_get_finish_function_removed = Removal_4_Engines;
  ENGINE_get_ctrl_function_removed = Removal_4_Engines;
  ENGINE_get_load_privkey_function_removed = Removal_4_Engines;
  ENGINE_get_load_pubkey_function_removed = Removal_4_Engines;
    ENGINE_get_ciphers_removed = Removal_4_Engines;
  ENGINE_get_digests_removed = Removal_4_Engines;
  ENGINE_get_cipher_removed = Removal_4_Engines;
  ENGINE_get_digest_removed = Removal_4_Engines;
  ENGINE_get_pkey_meth_removed = Removal_4_Engines;
  ENGINE_get_pkey_meths_removed = Removal_4_Engines;
  ENGINE_get_pkey_asn1_meth_removed = Removal_4_Engines;
  ENGINE_get_pkey_asn1_meth_str_removed = Removal_4_Engines;
  ENGINE_get_pkey_asn1_meths_removed = Removal_4_Engines;
  ENGINE_pkey_asn1_find_str_removed = Removal_4_Engines;
  ENGINE_get_cmd_defns_removed = Removal_4_Engines;
  ENGINE_get_flags_removed = Removal_4_Engines;
  ENGINE_init_removed = Removal_4_Engines;
  ENGINE_finish_removed = Removal_4_Engines;
  ENGINE_load_private_key_removed = Removal_4_Engines;
  ENGINE_load_public_key_removed = Removal_4_Engines;
  ENGINE_get_default_RSA_removed = Removal_4_Engines;
  ENGINE_get_default_DSA_removed = Removal_4_Engines;
  ENGINE_get_default_EC_removed = Removal_4_Engines;
  ENGINE_get_default_DH_removed = Removal_4_Engines;
  ENGINE_get_default_RAND_removed = Removal_4_Engines;
  ENGINE_get_cipher_engine_removed = Removal_4_Engines;
  ENGINE_get_digest_engine_removed = Removal_4_Engines;
  ENGINE_get_pkey_meth_engine_removed = Removal_4_Engines;
  ENGINE_get_pkey_asn1_meth_engine_removed = Removal_4_Engines;
  ENGINE_set_default_RSA_removed = Removal_4_Engines;
  ENGINE_set_default_string_removed = Removal_4_Engines;
  ENGINE_set_default_DSA_removed = Removal_4_Engines;
  ENGINE_set_default_EC_removed = Removal_4_Engines;
  ENGINE_set_default_DH_removed = Removal_4_Engines;
  ENGINE_set_default_RAND_removed = Removal_4_Engines;
  ENGINE_set_default_ciphers_removed = Removal_4_Engines;
  ENGINE_set_default_digests_removed = Removal_4_Engines;
  ENGINE_set_default_pkey_meths_removed = Removal_4_Engines;
  ENGINE_set_default_pkey_asn1_meths_removed = Removal_4_Engines;
  ENGINE_set_default_removed = Removal_4_Engines;
  ENGINE_add_conf_module_removed = Removal_4_Engines;
  ENGINE_get_static_state_removed = Removal_4_Engines;
  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ENGINE_get_first: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_first_procname);
end;


function  ERR_ENGINE_get_last: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_last_procname);
end;


function  ERR_ENGINE_get_next(e: PENGINE): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_next_procname);
end;


function  ERR_ENGINE_get_prev(e: PENGINE): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_prev_procname);
end;


function  ERR_ENGINE_add(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_add_procname);
end;


function  ERR_ENGINE_remove(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_remove_procname);
end;


function  ERR_ENGINE_by_id(const id: PIdAnsiChar): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_by_id_procname);
end;



procedure  ERR_ENGINE_load_builtin_engines; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_load_builtin_engines_procname);
end;



  //
  // Get and set global flags (ENGINE_TABLE_FLAG_***) for the implementation
  // "registry" handling.
  //
function  ERR_ENGINE_get_table_flags: TIdC_UINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_table_flags_procname);
end;


procedure  ERR_ENGINE_set_table_flags(flags: TIdC_UINT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_table_flags_procname);
end;



  //- Manage registration of ENGINEs per "table". For each type, there are 3
  // functions;
  //   ENGINE_register_***(e) - registers the implementation from 'e' (if it has one)
  //   ENGINE_unregister_***(e) - unregister the implementation from 'e'
  //   ENGINE_register_all_***() - call ENGINE_register_***() for each 'e' in the list
  // Cleanup is automatically registered from each table when required.
  //

function  ERR_ENGINE_register_RSA(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_RSA_procname);
end;


procedure  ERR_ENGINE_unregister_RSA(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_RSA_procname);
end;


procedure  ERR_ENGINE_register_all_RSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_RSA_procname);
end;



function  ERR_ENGINE_register_DSA(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_DSA_procname);
end;


procedure  ERR_ENGINE_unregister_DSA(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_DSA_procname);
end;


procedure  ERR_ENGINE_register_all_DSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_DSA_procname);
end;



function  ERR_ENGINE_register_EC(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_EC_procname);
end;


procedure  ERR_ENGINE_unregister_EC(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_EC_procname);
end;


procedure  ERR_ENGINE_register_all_EC; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_EC_procname);
end;



function  ERR_ENGINE_register_DH(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_DH_procname);
end;


procedure  ERR_ENGINE_unregister_DH(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_DH_procname);
end;


procedure  ERR_ENGINE_register_all_DH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_DH_procname);
end;



function  ERR_ENGINE_register_RAND(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_RAND_procname);
end;


procedure  ERR_ENGINE_unregister_RAND(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_RAND_procname);
end;


procedure  ERR_ENGINE_register_all_RAND; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_RAND_procname);
end;



function  ERR_ENGINE_register_ciphers(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_ciphers_procname);
end;


procedure  ERR_ENGINE_unregister_ciphers(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_ciphers_procname);
end;


procedure  ERR_ENGINE_register_all_ciphers; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_ciphers_procname);
end;



function  ERR_ENGINE_register_digests(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_digests_procname);
end;


procedure  ERR_ENGINE_unregister_digests(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_digests_procname);
end;


procedure  ERR_ENGINE_register_all_digests; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_digests_procname);
end;



function  ERR_ENGINE_register_pkey_meths(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_pkey_meths_procname);
end;


procedure  ERR_ENGINE_unregister_pkey_meths(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_pkey_meths_procname);
end;


procedure  ERR_ENGINE_register_all_pkey_meths; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_pkey_meths_procname);
end;



function  ERR_ENGINE_register_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_pkey_asn1_meths_procname);
end;


procedure  ERR_ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_pkey_asn1_meths_procname);
end;


procedure  ERR_ENGINE_register_all_pkey_asn1_meths; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_pkey_asn1_meths_procname);
end;



  //
  // These functions register all support from the above categories. Note, use
  // of these functions can result in static linkage of code your application
  // may not need. If you only need a subset of functionality, consider using
  // more selective initialisation.
  //
function  ERR_ENGINE_register_complete(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_complete_procname);
end;


function  ERR_ENGINE_register_all_complete: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_complete_procname);
end;



  //
  // Send parameterised control commands to the engine. The possibilities to
  // send down an integer, a pointer to data or a function pointer are
  // provided. Any of the parameters may or may not be NULL, depending on the
  // command number. In actuality, this function only requires a structural
  // (rather than functional) reference to an engine, but many control commands
  // may require the engine be functional. The caller should be aware of trying
  // commands that require an operational ENGINE, and only use functional
  // references in such situations.
  //
function  ERR_ENGINE_ctrl(e: PENGINE; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; v1: f): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_ctrl_procname);
end;



  //
  // This function tests if an ENGINE-specific command is usable as a
  // "setting". Eg. in an application's config file that gets processed through
  // ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
  // ENGINE_ctrl_cmd_string(), only ENGINE_ctrl().
  //
function  ERR_ENGINE_cmd_is_executable(e: PENGINE; cmd: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_cmd_is_executable_procname);
end;



  //
  // This function works like ENGINE_ctrl() with the exception of taking a
  // command name instead of a command number, and can handle optional
  // commands. See the comment on ENGINE_ctrl_cmd_string() for an explanation
  // on how to use the cmd_name and cmd_optional.
  //
function  ERR_ENGINE_ctrl_cmd(e: PENGINE; const cmd_name: PIdAnsiChar; i: TIdC_LONG; p: Pointer; v1: f;
  cmd_optional: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_ctrl_cmd_procname);
end;



  //
  // This function passes a command-name and argument to an ENGINE. The
  // cmd_name is converted to a command number and the control command is
  // called using 'arg' as an argument (unless the ENGINE doesn't support such
  // a command, in which case no control command is called). The command is
  // checked for input flags, and if necessary the argument will be converted
  // to a numeric value. If cmd_optional is non-zero, then if the ENGINE
  // doesn't support the given cmd_name the return value will be success
  // anyway. This function is intended for applications to use so that users
  // (or config files) can supply engine-specific config data to the ENGINE at
  // run-time to control behaviour of specific engines. As such, it shouldn't
  // be used for calling ENGINE_ctrl() functions that return data, deal with
  // binary data, or that are otherwise supposed to be used directly through
  // ENGINE_ctrl() in application code. Any "return" data from an ENGINE_ctrl()
  // operation in this function will be lost - the return value is interpreted
  // as failure if the return value is zero, success otherwise, and this
  // function returns a boolean value as a result. In other words, vendors of
  // 'ENGINE'-enabled devices should write ENGINE implementations with
  // parameterisations that work in this scheme, so that compliant ENGINE-based
  // applications can work consistently with the same configuration for the
  // same ENGINE-enabled devices, across applications.
  //
function  ERR_ENGINE_ctrl_cmd_string(e: PENGINE; const cmd_name: PIdAnsiChar; const arg: PIdAnsiChar;
  cmd_optional: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_ctrl_cmd_string_procname);
end;



  //
  // These functions are useful for manufacturing new ENGINE structures. They
  // don't address reference counting at all - one uses them to populate an
  // ENGINE structure with personalised implementations of things prior to
  // using it directly or adding it to the builtin ENGINE list in TaurusTLS.
  // These are also here so that the ENGINE structure doesn't have to be
  // exposed and break binary compatibility!
  //
function  ERR_ENGINE_new: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_new_procname);
end;


function  ERR_ENGINE_free(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_free_procname);
end;


function  ERR_ENGINE_up_ref(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_up_ref_procname);
end;


function  ERR_ENGINE_set_id(e: PENGINE; const id: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_id_procname);
end;


function  ERR_ENGINE_set_name(e: PENGINE; const name: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_name_procname);
end;


function  ERR_ENGINE_set_RSA(e: PENGINE; const rsa_meth: PRSA_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_RSA_procname);
end;


function  ERR_ENGINE_set_DSA(e: PENGINE; const dsa_meth: PDSA_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_DSA_procname);
end;


function  ERR_ENGINE_set_EC(e: PENGINE; const ecdsa_meth: PEC_KEY_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_EC_procname);
end;


function  ERR_ENGINE_set_DH(e: PENGINE; const dh_meth: PDH_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_DH_procname);
end;


function  ERR_ENGINE_set_RAND(e: PENGINE; const rand_meth: PRAND_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_RAND_procname);
end;


function  ERR_ENGINE_set_destroy_function(e: PENGINE; destroy_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_destroy_function_procname);
end;


function  ERR_ENGINE_set_init_function(e: PENGINE; init_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_init_function_procname);
end;


function  ERR_ENGINE_set_finish_function(e: PENGINE; finish_f: ENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_finish_function_procname);
end;


function  ERR_ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: ENGINE_CTRL_FUNC_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_ctrl_function_procname);
end;


function  ERR_ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: ENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_load_privkey_function_procname);
end;


function  ERR_ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: ENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_load_pubkey_function_procname);
end;


  //function ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: ENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT; cdecl;
function  ERR_ENGINE_set_ciphers(e: PENGINE; f: ENGINE_CIPHERS_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_ciphers_procname);
end;


function  ERR_ENGINE_set_digests(e: PENGINE; f: ENGINE_DIGESTS_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_digests_procname);
end;


function  ERR_ENGINE_set_pkey_meths(e: PENGINE; f: ENGINE_PKEY_METHS_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_pkey_meths_procname);
end;


function  ERR_ENGINE_set_pkey_asn1_meths(e: PENGINE; f: ENGINE_PKEY_ASN1_METHS_PTR): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_pkey_asn1_meths_procname);
end;


function  ERR_ENGINE_set_flags(e: PENGINE; flags: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_flags_procname);
end;


function  ERR_ENGINE_set_cmd_defns(e: PENGINE; const defns: PENGINE_CMD_DEFN): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_cmd_defns_procname);
end;

function  ERR_ENGINE_set_ex_data(e: PENGINE; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_ex_data_procname);
end;


function  ERR_ENGINE_get_ex_data(const e: PENGINE; idx: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_ex_data_procname);
end;



  //
  // These return values from within the ENGINE structure. These can be useful
  // with functional references as well as structural references - it depends
  // which you obtained. Using the result for functional purposes if you only
  // obtained a structural reference may be problematic!
  //
function  ERR_ENGINE_get_id(const e: PENGINE): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_id_procname);
end;


function  ERR_ENGINE_get_name(const e: PENGINE): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_name_procname);
end;


function  ERR_ENGINE_get_RSA(const e: PENGINE): PRSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_RSA_procname);
end;


function  ERR_ENGINE_get_DSA(const e: PENGINE): PDSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_DSA_procname);
end;


function  ERR_ENGINE_get_EC(const e: PENGINE): PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_EC_procname);
end;


function  ERR_ENGINE_get_DH(const e: PENGINE): PDH_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_DH_procname);
end;


function  ERR_ENGINE_get_RAND(const e: PENGINE): PRAND_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_RAND_procname);
end;


function  ERR_ENGINE_get_destroy_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_destroy_function_procname);
end;


function  ERR_ENGINE_get_init_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_init_function_procname);
end;


function  ERR_ENGINE_get_finish_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_finish_function_procname);
end;


function  ERR_ENGINE_get_ctrl_function(const e: PENGINE): ENGINE_CTRL_FUNC_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_ctrl_function_procname);
end;


function  ERR_ENGINE_get_load_privkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_load_privkey_function_procname);
end;


function  ERR_ENGINE_get_load_pubkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_load_pubkey_function_procname);
end;


  //function ENGINE_get_ssl_client_cert_function(const e: PENGINE): ENGINE_SSL_CLIENT_CERT_PTR; cdecl;

function  ERR_ENGINE_get_ciphers(const e: PENGINE): ENGINE_CIPHERS_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_ciphers_procname);
end;


function  ERR_ENGINE_get_digests(const e: PENGINE): ENGINE_DIGESTS_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_digests_procname);
end;


function  ERR_ENGINE_get_pkey_meths(const e: PENGINE): ENGINE_PKEY_METHS_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_meths_procname);
end;


function  ERR_ENGINE_get_pkey_asn1_meths(const e: PENGINE): ENGINE_PKEY_ASN1_METHS_PTR; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meths_procname);
end;


function  ERR_ENGINE_get_cipher(e: PENGINE; nid: TIdC_INT): PEVP_CIPHER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_cipher_procname);
end;


function  ERR_ENGINE_get_digest(e: PENGINE; nid: TIdC_INT): PEVP_MD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_digest_procname);
end;


function  ERR_ENGINE_get_pkey_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_meth_procname);
end;


function  ERR_ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meth_procname);
end;


function  ERR_ENGINE_get_pkey_asn1_meth_str(e: PENGINE; const _str: PIdAnsiChar;
  len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meth_str_procname);
end;


function  ERR_ENGINE_pkey_asn1_find_str(pe: PPENGINE; const _str: PIdAnsiChar;
  len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_pkey_asn1_find_str_procname);
end;


function  ERR_ENGINE_get_cmd_defns(const e: PENGINE): PENGINE_CMD_DEFN; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_cmd_defns_procname);
end;


function  ERR_ENGINE_get_flags(const e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_flags_procname);
end;



  ///*
  // * FUNCTIONAL functions. These functions deal with ENGINE structures that
  // * have (or will) be initialised for use. Broadly speaking, the structural
  // * functions are useful for iterating the list of available engine types,
  // * creating new engine types, and other "list" operations. These functions
  // * actually deal with ENGINEs that are to be used. As such these functions
  // * can fail (if applicable) when particular engines are unavailable - eg. if
  // * a hardware accelerator is not attached or not functioning correctly. Each
  // * ENGINE has 2 reference counts; structural and functional. Every time a
  // * functional reference is obtained or released, a corresponding structural
  // * reference is automatically obtained or released too.
  // */

  ///*
  // * Initialise a engine type for use (or up its reference count if it's
  // * already in use). This will fail if the engine is not currently operational
  // * and cannot initialise.
  // */
function  ERR_ENGINE_init(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_init_procname);
end;


  ///*
  // * Free a functional reference to a engine type. This does not require a
  // * corresponding call to ENGINE_free as it also releases a structural
  // * reference.
  // */
function  ERR_ENGINE_finish(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_finish_procname);
end;



  ///*
  // * The following functions handle keys that are stored in some secondary
  // * location, handled by the engine.  The storage may be on a card or
  // * whatever.
  // */
function  ERR_ENGINE_load_private_key(e: PENGINE; const key_id: PIdAnsiChar; ui_method: PUI_METHOD;
  callback_data: Pointer): PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_load_private_key_procname);
end;


function  ERR_ENGINE_load_public_key(e: PENGINE; const key_id: PIdAnsiChar; ui_method: PUI_METHOD;
  callback_data: Pointer): PEVP_PKEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_load_public_key_procname);
end;


  //function ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL;
  //  {STACK_OF(X509) *ca_dn;} {STACK_OF(X509) **pother;} ui_method: PUI_METHOD;
  //  callback_data: Pointer): TIdC_INT;

  ///*
  // * This returns a pointer for the current ENGINE structure that is (by
  // * default) performing any RSA operations. The value returned is an
  // * incremented reference, so it should be free'd (ENGINE_finish) before it is
  // * discarded.
  // */
function  ERR_ENGINE_get_default_RSA: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_RSA_procname);
end;


  //* Same for the other "methods" */
function  ERR_ENGINE_get_default_DSA: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_DSA_procname);
end;


function  ERR_ENGINE_get_default_EC: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_EC_procname);
end;


function  ERR_ENGINE_get_default_DH: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_DH_procname);
end;


function  ERR_ENGINE_get_default_RAND: PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_RAND_procname);
end;


  ///*
  // * These functions can be used to get a functional reference to perform
  // * ciphering or digesting corresponding to "nid".
  // */
function  ERR_ENGINE_get_cipher_engine(nid: TIdC_INT): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_cipher_engine_procname);
end;


function  ERR_ENGINE_get_digest_engine(nid: TIdC_INT): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_digest_engine_procname);
end;


function  ERR_ENGINE_get_pkey_meth_engine(nid: TIdC_INT): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_meth_engine_procname);
end;


function  ERR_ENGINE_get_pkey_asn1_meth_engine(nid: TIdC_INT): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meth_engine_procname);
end;


  ///*
  // * This sets a new default ENGINE structure for performing RSA operations. If
  // * the result is non-zero (success) then the ENGINE structure will have had
  // * its reference count up'd so the caller should still free their own
  // * reference 'e'.
  // */
function  ERR_ENGINE_set_default_RSA(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_RSA_procname);
end;


function  ERR_ENGINE_set_default_string(e: PENGINE; const def_list: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_string_procname);
end;


  // Same for the other "methods"
function  ERR_ENGINE_set_default_DSA(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_DSA_procname);
end;


function  ERR_ENGINE_set_default_EC(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_EC_procname);
end;


function  ERR_ENGINE_set_default_DH(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_DH_procname);
end;


function  ERR_ENGINE_set_default_RAND(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_RAND_procname);
end;


function  ERR_ENGINE_set_default_ciphers(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_ciphers_procname);
end;


function  ERR_ENGINE_set_default_digests(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_digests_procname);
end;


function  ERR_ENGINE_set_default_pkey_meths(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_pkey_meths_procname);
end;


function  ERR_ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_pkey_asn1_meths_procname);
end;



  ///*
  // * The combination "set" - the flags are bitwise "OR"d from the
  // * ENGINE_METHOD_*** defines above. As with the "ENGINE_register_complete()"
  // * function, this function can result in unnecessary static linkage. If your
  // * application requires only specific functionality, consider using more
  // * selective functions.
  // */
function  ERR_ENGINE_set_default(e: PENGINE; flags: TIdC_ULONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_procname);
end;



procedure  ERR_ENGINE_add_conf_module; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_add_conf_module_procname);
end;



  ///* Deprecated functions ... */
  ///* int ENGINE_clear_defaults(void); */
  //
  //**************************/
  //* DYNAMIC ENGINE SUPPORT */
  //**************************/
  //
  //* Binary/behaviour compatibility levels */
  //# define OSSL_DYNAMIC_VERSION            (unsigned long)0x00030000
  //*
  // * Binary versions older than this are too old for us (whether we're a loader
  // * or a loadee)
  // */
  //# define OSSL_DYNAMIC_OLDEST             (unsigned long)0x00030000
  //
  //*
  // * When compiling an ENGINE entirely as an external shared library, loadable
  // * by the "dynamic" ENGINE, these types are needed. The 'dynamic_fns'
  // * structure type provides the calling application's (or library's) error
  // * functionality and memory management function pointers to the loaded
  // * library. These should be used/set in the loaded library code so that the
  // * loading application's 'state' will be used/changed in all operations. The
  // * 'static_state' pointer allows the loaded library to know if it shares the
  // * same static data as the calling application (or library), and thus whether
  // * these callbacks need to be set or not.
  // */


  //# define IMPLEMENT_DYNAMIC_BIND_FN(fn) \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); \
  //        OPENSSL_EXPORT \
  //        int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \
  //            if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; \
  //            CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, \
  //                                     fns->mem_fns.realloc_fn, \
  //                                     fns->mem_fns.free_fn); \
  //        skip_cbs: \
  //            if (!fn(e, id)) return 0; \
  //            return 1; }
  //
  //*
  // * If the loading application (or library) and the loaded ENGINE library
  // * share the same static data (eg. they're both dynamically linked to the
  // * same libcrypto.so) we need a way to avoid trying to set system callbacks -
  // * this would fail, and for the same reason that it's unnecessary to try. If
  // * the loaded ENGINE has (or gets from through the loader) its own copy of
  // * the libcrypto static data, we will need to set the callbacks. The easiest
  // * way to detect this is to have a function that returns a pointer to some
  // * static data and let the loading application and loaded ENGINE compare
  // * their respective values.
  // */
function  ERR_ENGINE_get_static_state: Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_static_state_procname);
end;



  {$I TaurusTLSNoRetValOn.inc}
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ENGINE_get_first := LoadLibFunction(ADllHandle, ENGINE_get_first_procname);
  FuncLoadError := not assigned(ENGINE_get_first);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_first_allownil)}
    ENGINE_get_first := ERR_ENGINE_get_first;
    {$ifend}
    {$if declared(ENGINE_get_first_introduced)}
    if LibVersion < ENGINE_get_first_introduced then
    begin
      {$if declared(FC_ENGINE_get_first)}
      ENGINE_get_first := FC_ENGINE_get_first;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_first_removed)}
    if ENGINE_get_first_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_first)}
      ENGINE_get_first := _ENGINE_get_first;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_first_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_first');
    {$ifend}
  end;


  ENGINE_get_last := LoadLibFunction(ADllHandle, ENGINE_get_last_procname);
  FuncLoadError := not assigned(ENGINE_get_last);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_last_allownil)}
    ENGINE_get_last := ERR_ENGINE_get_last;
    {$ifend}
    {$if declared(ENGINE_get_last_introduced)}
    if LibVersion < ENGINE_get_last_introduced then
    begin
      {$if declared(FC_ENGINE_get_last)}
      ENGINE_get_last := FC_ENGINE_get_last;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_last_removed)}
    if ENGINE_get_last_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_last)}
      ENGINE_get_last := _ENGINE_get_last;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_last_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_last');
    {$ifend}
  end;


  ENGINE_get_next := LoadLibFunction(ADllHandle, ENGINE_get_next_procname);
  FuncLoadError := not assigned(ENGINE_get_next);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_next_allownil)}
    ENGINE_get_next := ERR_ENGINE_get_next;
    {$ifend}
    {$if declared(ENGINE_get_next_introduced)}
    if LibVersion < ENGINE_get_next_introduced then
    begin
      {$if declared(FC_ENGINE_get_next)}
      ENGINE_get_next := FC_ENGINE_get_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_next_removed)}
    if ENGINE_get_next_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_next)}
      ENGINE_get_next := _ENGINE_get_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_next_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_next');
    {$ifend}
  end;


  ENGINE_get_prev := LoadLibFunction(ADllHandle, ENGINE_get_prev_procname);
  FuncLoadError := not assigned(ENGINE_get_prev);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_prev_allownil)}
    ENGINE_get_prev := ERR_ENGINE_get_prev;
    {$ifend}
    {$if declared(ENGINE_get_prev_introduced)}
    if LibVersion < ENGINE_get_prev_introduced then
    begin
      {$if declared(FC_ENGINE_get_prev)}
      ENGINE_get_prev := FC_ENGINE_get_prev;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_prev_removed)}
    if ENGINE_get_prev_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_prev)}
      ENGINE_get_prev := _ENGINE_get_prev;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_prev_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_prev');
    {$ifend}
  end;


  ENGINE_add := LoadLibFunction(ADllHandle, ENGINE_add_procname);
  FuncLoadError := not assigned(ENGINE_add);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_add_allownil)}
    ENGINE_add := ERR_ENGINE_add;
    {$ifend}
    {$if declared(ENGINE_add_introduced)}
    if LibVersion < ENGINE_add_introduced then
    begin
      {$if declared(FC_ENGINE_add)}
      ENGINE_add := FC_ENGINE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_add_removed)}
    if ENGINE_add_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_add)}
      ENGINE_add := _ENGINE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_add_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_add');
    {$ifend}
  end;


  ENGINE_remove := LoadLibFunction(ADllHandle, ENGINE_remove_procname);
  FuncLoadError := not assigned(ENGINE_remove);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_remove_allownil)}
    ENGINE_remove := ERR_ENGINE_remove;
    {$ifend}
    {$if declared(ENGINE_remove_introduced)}
    if LibVersion < ENGINE_remove_introduced then
    begin
      {$if declared(FC_ENGINE_remove)}
      ENGINE_remove := FC_ENGINE_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_remove_removed)}
    if ENGINE_remove_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_remove)}
      ENGINE_remove := _ENGINE_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_remove_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_remove');
    {$ifend}
  end;


  ENGINE_by_id := LoadLibFunction(ADllHandle, ENGINE_by_id_procname);
  FuncLoadError := not assigned(ENGINE_by_id);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_by_id_allownil)}
    ENGINE_by_id := ERR_ENGINE_by_id;
    {$ifend}
    {$if declared(ENGINE_by_id_introduced)}
    if LibVersion < ENGINE_by_id_introduced then
    begin
      {$if declared(FC_ENGINE_by_id)}
      ENGINE_by_id := FC_ENGINE_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_by_id_removed)}
    if ENGINE_by_id_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_by_id)}
      ENGINE_by_id := _ENGINE_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_by_id');
    {$ifend}
  end;


  ENGINE_load_builtin_engines := LoadLibFunction(ADllHandle, ENGINE_load_builtin_engines_procname);
  FuncLoadError := not assigned(ENGINE_load_builtin_engines);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_load_builtin_engines_allownil)}
    ENGINE_load_builtin_engines := ERR_ENGINE_load_builtin_engines;
    {$ifend}
    {$if declared(ENGINE_load_builtin_engines_introduced)}
    if LibVersion < ENGINE_load_builtin_engines_introduced then
    begin
      {$if declared(FC_ENGINE_load_builtin_engines)}
      ENGINE_load_builtin_engines := FC_ENGINE_load_builtin_engines;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_load_builtin_engines_removed)}
    if ENGINE_load_builtin_engines_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_load_builtin_engines)}
      ENGINE_load_builtin_engines := _ENGINE_load_builtin_engines;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_load_builtin_engines_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_load_builtin_engines');
    {$ifend}
  end;


  ENGINE_get_table_flags := LoadLibFunction(ADllHandle, ENGINE_get_table_flags_procname);
  FuncLoadError := not assigned(ENGINE_get_table_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_table_flags_allownil)}
    ENGINE_get_table_flags := ERR_ENGINE_get_table_flags;
    {$ifend}
    {$if declared(ENGINE_get_table_flags_introduced)}
    if LibVersion < ENGINE_get_table_flags_introduced then
    begin
      {$if declared(FC_ENGINE_get_table_flags)}
      ENGINE_get_table_flags := FC_ENGINE_get_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_table_flags_removed)}
    if ENGINE_get_table_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_table_flags)}
      ENGINE_get_table_flags := _ENGINE_get_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_table_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_table_flags');
    {$ifend}
  end;


  ENGINE_set_table_flags := LoadLibFunction(ADllHandle, ENGINE_set_table_flags_procname);
  FuncLoadError := not assigned(ENGINE_set_table_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_table_flags_allownil)}
    ENGINE_set_table_flags := ERR_ENGINE_set_table_flags;
    {$ifend}
    {$if declared(ENGINE_set_table_flags_introduced)}
    if LibVersion < ENGINE_set_table_flags_introduced then
    begin
      {$if declared(FC_ENGINE_set_table_flags)}
      ENGINE_set_table_flags := FC_ENGINE_set_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_table_flags_removed)}
    if ENGINE_set_table_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_table_flags)}
      ENGINE_set_table_flags := _ENGINE_set_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_table_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_table_flags');
    {$ifend}
  end;


  ENGINE_register_RSA := LoadLibFunction(ADllHandle, ENGINE_register_RSA_procname);
  FuncLoadError := not assigned(ENGINE_register_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_RSA_allownil)}
    ENGINE_register_RSA := ERR_ENGINE_register_RSA;
    {$ifend}
    {$if declared(ENGINE_register_RSA_introduced)}
    if LibVersion < ENGINE_register_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_RSA)}
      ENGINE_register_RSA := FC_ENGINE_register_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_RSA_removed)}
    if ENGINE_register_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_RSA)}
      ENGINE_register_RSA := _ENGINE_register_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_RSA');
    {$ifend}
  end;


  ENGINE_unregister_RSA := LoadLibFunction(ADllHandle, ENGINE_unregister_RSA_procname);
  FuncLoadError := not assigned(ENGINE_unregister_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_RSA_allownil)}
    ENGINE_unregister_RSA := ERR_ENGINE_unregister_RSA;
    {$ifend}
    {$if declared(ENGINE_unregister_RSA_introduced)}
    if LibVersion < ENGINE_unregister_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_RSA)}
      ENGINE_unregister_RSA := FC_ENGINE_unregister_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_RSA_removed)}
    if ENGINE_unregister_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_RSA)}
      ENGINE_unregister_RSA := _ENGINE_unregister_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_RSA');
    {$ifend}
  end;


  ENGINE_register_all_RSA := LoadLibFunction(ADllHandle, ENGINE_register_all_RSA_procname);
  FuncLoadError := not assigned(ENGINE_register_all_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_RSA_allownil)}
    ENGINE_register_all_RSA := ERR_ENGINE_register_all_RSA;
    {$ifend}
    {$if declared(ENGINE_register_all_RSA_introduced)}
    if LibVersion < ENGINE_register_all_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_RSA)}
      ENGINE_register_all_RSA := FC_ENGINE_register_all_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_RSA_removed)}
    if ENGINE_register_all_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_RSA)}
      ENGINE_register_all_RSA := _ENGINE_register_all_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_RSA');
    {$ifend}
  end;


  ENGINE_register_DSA := LoadLibFunction(ADllHandle, ENGINE_register_DSA_procname);
  FuncLoadError := not assigned(ENGINE_register_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_DSA_allownil)}
    ENGINE_register_DSA := ERR_ENGINE_register_DSA;
    {$ifend}
    {$if declared(ENGINE_register_DSA_introduced)}
    if LibVersion < ENGINE_register_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_DSA)}
      ENGINE_register_DSA := FC_ENGINE_register_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_DSA_removed)}
    if ENGINE_register_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_DSA)}
      ENGINE_register_DSA := _ENGINE_register_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_DSA');
    {$ifend}
  end;


  ENGINE_unregister_DSA := LoadLibFunction(ADllHandle, ENGINE_unregister_DSA_procname);
  FuncLoadError := not assigned(ENGINE_unregister_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_DSA_allownil)}
    ENGINE_unregister_DSA := ERR_ENGINE_unregister_DSA;
    {$ifend}
    {$if declared(ENGINE_unregister_DSA_introduced)}
    if LibVersion < ENGINE_unregister_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_DSA)}
      ENGINE_unregister_DSA := FC_ENGINE_unregister_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_DSA_removed)}
    if ENGINE_unregister_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_DSA)}
      ENGINE_unregister_DSA := _ENGINE_unregister_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_DSA');
    {$ifend}
  end;


  ENGINE_register_all_DSA := LoadLibFunction(ADllHandle, ENGINE_register_all_DSA_procname);
  FuncLoadError := not assigned(ENGINE_register_all_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_DSA_allownil)}
    ENGINE_register_all_DSA := ERR_ENGINE_register_all_DSA;
    {$ifend}
    {$if declared(ENGINE_register_all_DSA_introduced)}
    if LibVersion < ENGINE_register_all_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_DSA)}
      ENGINE_register_all_DSA := FC_ENGINE_register_all_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_DSA_removed)}
    if ENGINE_register_all_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_DSA)}
      ENGINE_register_all_DSA := _ENGINE_register_all_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_DSA');
    {$ifend}
  end;


  ENGINE_register_EC := LoadLibFunction(ADllHandle, ENGINE_register_EC_procname);
  FuncLoadError := not assigned(ENGINE_register_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_EC_allownil)}
    ENGINE_register_EC := ERR_ENGINE_register_EC;
    {$ifend}
    {$if declared(ENGINE_register_EC_introduced)}
    if LibVersion < ENGINE_register_EC_introduced then
    begin
      {$if declared(FC_ENGINE_register_EC)}
      ENGINE_register_EC := FC_ENGINE_register_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_EC_removed)}
    if ENGINE_register_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_EC)}
      ENGINE_register_EC := _ENGINE_register_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_EC');
    {$ifend}
  end;


  ENGINE_unregister_EC := LoadLibFunction(ADllHandle, ENGINE_unregister_EC_procname);
  FuncLoadError := not assigned(ENGINE_unregister_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_EC_allownil)}
    ENGINE_unregister_EC := ERR_ENGINE_unregister_EC;
    {$ifend}
    {$if declared(ENGINE_unregister_EC_introduced)}
    if LibVersion < ENGINE_unregister_EC_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_EC)}
      ENGINE_unregister_EC := FC_ENGINE_unregister_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_EC_removed)}
    if ENGINE_unregister_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_EC)}
      ENGINE_unregister_EC := _ENGINE_unregister_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_EC');
    {$ifend}
  end;


  ENGINE_register_all_EC := LoadLibFunction(ADllHandle, ENGINE_register_all_EC_procname);
  FuncLoadError := not assigned(ENGINE_register_all_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_EC_allownil)}
    ENGINE_register_all_EC := ERR_ENGINE_register_all_EC;
    {$ifend}
    {$if declared(ENGINE_register_all_EC_introduced)}
    if LibVersion < ENGINE_register_all_EC_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_EC)}
      ENGINE_register_all_EC := FC_ENGINE_register_all_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_EC_removed)}
    if ENGINE_register_all_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_EC)}
      ENGINE_register_all_EC := _ENGINE_register_all_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_EC');
    {$ifend}
  end;


  ENGINE_register_DH := LoadLibFunction(ADllHandle, ENGINE_register_DH_procname);
  FuncLoadError := not assigned(ENGINE_register_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_DH_allownil)}
    ENGINE_register_DH := ERR_ENGINE_register_DH;
    {$ifend}
    {$if declared(ENGINE_register_DH_introduced)}
    if LibVersion < ENGINE_register_DH_introduced then
    begin
      {$if declared(FC_ENGINE_register_DH)}
      ENGINE_register_DH := FC_ENGINE_register_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_DH_removed)}
    if ENGINE_register_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_DH)}
      ENGINE_register_DH := _ENGINE_register_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_DH');
    {$ifend}
  end;


  ENGINE_unregister_DH := LoadLibFunction(ADllHandle, ENGINE_unregister_DH_procname);
  FuncLoadError := not assigned(ENGINE_unregister_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_DH_allownil)}
    ENGINE_unregister_DH := ERR_ENGINE_unregister_DH;
    {$ifend}
    {$if declared(ENGINE_unregister_DH_introduced)}
    if LibVersion < ENGINE_unregister_DH_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_DH)}
      ENGINE_unregister_DH := FC_ENGINE_unregister_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_DH_removed)}
    if ENGINE_unregister_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_DH)}
      ENGINE_unregister_DH := _ENGINE_unregister_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_DH');
    {$ifend}
  end;


  ENGINE_register_all_DH := LoadLibFunction(ADllHandle, ENGINE_register_all_DH_procname);
  FuncLoadError := not assigned(ENGINE_register_all_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_DH_allownil)}
    ENGINE_register_all_DH := ERR_ENGINE_register_all_DH;
    {$ifend}
    {$if declared(ENGINE_register_all_DH_introduced)}
    if LibVersion < ENGINE_register_all_DH_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_DH)}
      ENGINE_register_all_DH := FC_ENGINE_register_all_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_DH_removed)}
    if ENGINE_register_all_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_DH)}
      ENGINE_register_all_DH := _ENGINE_register_all_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_DH');
    {$ifend}
  end;


  ENGINE_register_RAND := LoadLibFunction(ADllHandle, ENGINE_register_RAND_procname);
  FuncLoadError := not assigned(ENGINE_register_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_RAND_allownil)}
    ENGINE_register_RAND := ERR_ENGINE_register_RAND;
    {$ifend}
    {$if declared(ENGINE_register_RAND_introduced)}
    if LibVersion < ENGINE_register_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_register_RAND)}
      ENGINE_register_RAND := FC_ENGINE_register_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_RAND_removed)}
    if ENGINE_register_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_RAND)}
      ENGINE_register_RAND := _ENGINE_register_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_RAND');
    {$ifend}
  end;


  ENGINE_unregister_RAND := LoadLibFunction(ADllHandle, ENGINE_unregister_RAND_procname);
  FuncLoadError := not assigned(ENGINE_unregister_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_RAND_allownil)}
    ENGINE_unregister_RAND := ERR_ENGINE_unregister_RAND;
    {$ifend}
    {$if declared(ENGINE_unregister_RAND_introduced)}
    if LibVersion < ENGINE_unregister_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_RAND)}
      ENGINE_unregister_RAND := FC_ENGINE_unregister_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_RAND_removed)}
    if ENGINE_unregister_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_RAND)}
      ENGINE_unregister_RAND := _ENGINE_unregister_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_RAND');
    {$ifend}
  end;


  ENGINE_register_all_RAND := LoadLibFunction(ADllHandle, ENGINE_register_all_RAND_procname);
  FuncLoadError := not assigned(ENGINE_register_all_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_RAND_allownil)}
    ENGINE_register_all_RAND := ERR_ENGINE_register_all_RAND;
    {$ifend}
    {$if declared(ENGINE_register_all_RAND_introduced)}
    if LibVersion < ENGINE_register_all_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_RAND)}
      ENGINE_register_all_RAND := FC_ENGINE_register_all_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_RAND_removed)}
    if ENGINE_register_all_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_RAND)}
      ENGINE_register_all_RAND := _ENGINE_register_all_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_RAND');
    {$ifend}
  end;


  ENGINE_register_ciphers := LoadLibFunction(ADllHandle, ENGINE_register_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_register_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_ciphers_allownil)}
    ENGINE_register_ciphers := ERR_ENGINE_register_ciphers;
    {$ifend}
    {$if declared(ENGINE_register_ciphers_introduced)}
    if LibVersion < ENGINE_register_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_register_ciphers)}
      ENGINE_register_ciphers := FC_ENGINE_register_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_ciphers_removed)}
    if ENGINE_register_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_ciphers)}
      ENGINE_register_ciphers := _ENGINE_register_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_ciphers');
    {$ifend}
  end;


  ENGINE_unregister_ciphers := LoadLibFunction(ADllHandle, ENGINE_unregister_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_unregister_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_ciphers_allownil)}
    ENGINE_unregister_ciphers := ERR_ENGINE_unregister_ciphers;
    {$ifend}
    {$if declared(ENGINE_unregister_ciphers_introduced)}
    if LibVersion < ENGINE_unregister_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_ciphers)}
      ENGINE_unregister_ciphers := FC_ENGINE_unregister_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_ciphers_removed)}
    if ENGINE_unregister_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_ciphers)}
      ENGINE_unregister_ciphers := _ENGINE_unregister_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_ciphers');
    {$ifend}
  end;


  ENGINE_register_all_ciphers := LoadLibFunction(ADllHandle, ENGINE_register_all_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_register_all_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_ciphers_allownil)}
    ENGINE_register_all_ciphers := ERR_ENGINE_register_all_ciphers;
    {$ifend}
    {$if declared(ENGINE_register_all_ciphers_introduced)}
    if LibVersion < ENGINE_register_all_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_ciphers)}
      ENGINE_register_all_ciphers := FC_ENGINE_register_all_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_ciphers_removed)}
    if ENGINE_register_all_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_ciphers)}
      ENGINE_register_all_ciphers := _ENGINE_register_all_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_ciphers');
    {$ifend}
  end;


  ENGINE_register_digests := LoadLibFunction(ADllHandle, ENGINE_register_digests_procname);
  FuncLoadError := not assigned(ENGINE_register_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_digests_allownil)}
    ENGINE_register_digests := ERR_ENGINE_register_digests;
    {$ifend}
    {$if declared(ENGINE_register_digests_introduced)}
    if LibVersion < ENGINE_register_digests_introduced then
    begin
      {$if declared(FC_ENGINE_register_digests)}
      ENGINE_register_digests := FC_ENGINE_register_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_digests_removed)}
    if ENGINE_register_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_digests)}
      ENGINE_register_digests := _ENGINE_register_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_digests');
    {$ifend}
  end;


  ENGINE_unregister_digests := LoadLibFunction(ADllHandle, ENGINE_unregister_digests_procname);
  FuncLoadError := not assigned(ENGINE_unregister_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_digests_allownil)}
    ENGINE_unregister_digests := ERR_ENGINE_unregister_digests;
    {$ifend}
    {$if declared(ENGINE_unregister_digests_introduced)}
    if LibVersion < ENGINE_unregister_digests_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_digests)}
      ENGINE_unregister_digests := FC_ENGINE_unregister_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_digests_removed)}
    if ENGINE_unregister_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_digests)}
      ENGINE_unregister_digests := _ENGINE_unregister_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_digests');
    {$ifend}
  end;


  ENGINE_register_all_digests := LoadLibFunction(ADllHandle, ENGINE_register_all_digests_procname);
  FuncLoadError := not assigned(ENGINE_register_all_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_digests_allownil)}
    ENGINE_register_all_digests := ERR_ENGINE_register_all_digests;
    {$ifend}
    {$if declared(ENGINE_register_all_digests_introduced)}
    if LibVersion < ENGINE_register_all_digests_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_digests)}
      ENGINE_register_all_digests := FC_ENGINE_register_all_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_digests_removed)}
    if ENGINE_register_all_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_digests)}
      ENGINE_register_all_digests := _ENGINE_register_all_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_digests');
    {$ifend}
  end;


  ENGINE_register_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_register_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_pkey_meths_allownil)}
    ENGINE_register_pkey_meths := ERR_ENGINE_register_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_register_pkey_meths_introduced)}
    if LibVersion < ENGINE_register_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_pkey_meths)}
      ENGINE_register_pkey_meths := FC_ENGINE_register_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_pkey_meths_removed)}
    if ENGINE_register_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_pkey_meths)}
      ENGINE_register_pkey_meths := _ENGINE_register_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_pkey_meths');
    {$ifend}
  end;


  ENGINE_unregister_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_unregister_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_unregister_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_pkey_meths_allownil)}
    ENGINE_unregister_pkey_meths := ERR_ENGINE_unregister_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_meths_introduced)}
    if LibVersion < ENGINE_unregister_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_pkey_meths)}
      ENGINE_unregister_pkey_meths := FC_ENGINE_unregister_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_meths_removed)}
    if ENGINE_unregister_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_pkey_meths)}
      ENGINE_unregister_pkey_meths := _ENGINE_unregister_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_pkey_meths');
    {$ifend}
  end;


  ENGINE_register_all_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_register_all_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_all_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_pkey_meths_allownil)}
    ENGINE_register_all_pkey_meths := ERR_ENGINE_register_all_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_meths_introduced)}
    if LibVersion < ENGINE_register_all_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_pkey_meths)}
      ENGINE_register_all_pkey_meths := FC_ENGINE_register_all_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_meths_removed)}
    if ENGINE_register_all_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_pkey_meths)}
      ENGINE_register_all_pkey_meths := _ENGINE_register_all_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_pkey_meths');
    {$ifend}
  end;


  ENGINE_register_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_register_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_pkey_asn1_meths_allownil)}
    ENGINE_register_pkey_asn1_meths := ERR_ENGINE_register_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_register_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_register_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_pkey_asn1_meths)}
      ENGINE_register_pkey_asn1_meths := FC_ENGINE_register_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_pkey_asn1_meths_removed)}
    if ENGINE_register_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_pkey_asn1_meths)}
      ENGINE_register_pkey_asn1_meths := _ENGINE_register_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_pkey_asn1_meths');
    {$ifend}
  end;


  ENGINE_unregister_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_unregister_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_unregister_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_pkey_asn1_meths_allownil)}
    ENGINE_unregister_pkey_asn1_meths := ERR_ENGINE_unregister_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_unregister_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_pkey_asn1_meths)}
      ENGINE_unregister_pkey_asn1_meths := FC_ENGINE_unregister_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_asn1_meths_removed)}
    if ENGINE_unregister_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_pkey_asn1_meths)}
      ENGINE_unregister_pkey_asn1_meths := _ENGINE_unregister_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_pkey_asn1_meths');
    {$ifend}
  end;


  ENGINE_register_all_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_register_all_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_all_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_pkey_asn1_meths_allownil)}
    ENGINE_register_all_pkey_asn1_meths := ERR_ENGINE_register_all_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_register_all_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_pkey_asn1_meths)}
      ENGINE_register_all_pkey_asn1_meths := FC_ENGINE_register_all_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_asn1_meths_removed)}
    if ENGINE_register_all_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_pkey_asn1_meths)}
      ENGINE_register_all_pkey_asn1_meths := _ENGINE_register_all_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_pkey_asn1_meths');
    {$ifend}
  end;


  ENGINE_register_complete := LoadLibFunction(ADllHandle, ENGINE_register_complete_procname);
  FuncLoadError := not assigned(ENGINE_register_complete);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_complete_allownil)}
    ENGINE_register_complete := ERR_ENGINE_register_complete;
    {$ifend}
    {$if declared(ENGINE_register_complete_introduced)}
    if LibVersion < ENGINE_register_complete_introduced then
    begin
      {$if declared(FC_ENGINE_register_complete)}
      ENGINE_register_complete := FC_ENGINE_register_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_complete_removed)}
    if ENGINE_register_complete_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_complete)}
      ENGINE_register_complete := _ENGINE_register_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_complete_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_complete');
    {$ifend}
  end;


  ENGINE_register_all_complete := LoadLibFunction(ADllHandle, ENGINE_register_all_complete_procname);
  FuncLoadError := not assigned(ENGINE_register_all_complete);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_complete_allownil)}
    ENGINE_register_all_complete := ERR_ENGINE_register_all_complete;
    {$ifend}
    {$if declared(ENGINE_register_all_complete_introduced)}
    if LibVersion < ENGINE_register_all_complete_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_complete)}
      ENGINE_register_all_complete := FC_ENGINE_register_all_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_complete_removed)}
    if ENGINE_register_all_complete_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_complete)}
      ENGINE_register_all_complete := _ENGINE_register_all_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_complete_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_complete');
    {$ifend}
  end;


  ENGINE_ctrl := LoadLibFunction(ADllHandle, ENGINE_ctrl_procname);
  FuncLoadError := not assigned(ENGINE_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_ctrl_allownil)}
    ENGINE_ctrl := ERR_ENGINE_ctrl;
    {$ifend}
    {$if declared(ENGINE_ctrl_introduced)}
    if LibVersion < ENGINE_ctrl_introduced then
    begin
      {$if declared(FC_ENGINE_ctrl)}
      ENGINE_ctrl := FC_ENGINE_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_ctrl_removed)}
    if ENGINE_ctrl_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_ctrl)}
      ENGINE_ctrl := _ENGINE_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_ctrl');
    {$ifend}
  end;


  ENGINE_cmd_is_executable := LoadLibFunction(ADllHandle, ENGINE_cmd_is_executable_procname);
  FuncLoadError := not assigned(ENGINE_cmd_is_executable);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_cmd_is_executable_allownil)}
    ENGINE_cmd_is_executable := ERR_ENGINE_cmd_is_executable;
    {$ifend}
    {$if declared(ENGINE_cmd_is_executable_introduced)}
    if LibVersion < ENGINE_cmd_is_executable_introduced then
    begin
      {$if declared(FC_ENGINE_cmd_is_executable)}
      ENGINE_cmd_is_executable := FC_ENGINE_cmd_is_executable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_cmd_is_executable_removed)}
    if ENGINE_cmd_is_executable_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_cmd_is_executable)}
      ENGINE_cmd_is_executable := _ENGINE_cmd_is_executable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_cmd_is_executable_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_cmd_is_executable');
    {$ifend}
  end;


  ENGINE_ctrl_cmd := LoadLibFunction(ADllHandle, ENGINE_ctrl_cmd_procname);
  FuncLoadError := not assigned(ENGINE_ctrl_cmd);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_ctrl_cmd_allownil)}
    ENGINE_ctrl_cmd := ERR_ENGINE_ctrl_cmd;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_introduced)}
    if LibVersion < ENGINE_ctrl_cmd_introduced then
    begin
      {$if declared(FC_ENGINE_ctrl_cmd)}
      ENGINE_ctrl_cmd := FC_ENGINE_ctrl_cmd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_removed)}
    if ENGINE_ctrl_cmd_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_ctrl_cmd)}
      ENGINE_ctrl_cmd := _ENGINE_ctrl_cmd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_ctrl_cmd_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_ctrl_cmd');
    {$ifend}
  end;


  ENGINE_ctrl_cmd_string := LoadLibFunction(ADllHandle, ENGINE_ctrl_cmd_string_procname);
  FuncLoadError := not assigned(ENGINE_ctrl_cmd_string);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_ctrl_cmd_string_allownil)}
    ENGINE_ctrl_cmd_string := ERR_ENGINE_ctrl_cmd_string;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_string_introduced)}
    if LibVersion < ENGINE_ctrl_cmd_string_introduced then
    begin
      {$if declared(FC_ENGINE_ctrl_cmd_string)}
      ENGINE_ctrl_cmd_string := FC_ENGINE_ctrl_cmd_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_string_removed)}
    if ENGINE_ctrl_cmd_string_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_ctrl_cmd_string)}
      ENGINE_ctrl_cmd_string := _ENGINE_ctrl_cmd_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_ctrl_cmd_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_ctrl_cmd_string');
    {$ifend}
  end;


  ENGINE_new := LoadLibFunction(ADllHandle, ENGINE_new_procname);
  FuncLoadError := not assigned(ENGINE_new);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_new_allownil)}
    ENGINE_new := ERR_ENGINE_new;
    {$ifend}
    {$if declared(ENGINE_new_introduced)}
    if LibVersion < ENGINE_new_introduced then
    begin
      {$if declared(FC_ENGINE_new)}
      ENGINE_new := FC_ENGINE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_new_removed)}
    if ENGINE_new_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_new)}
      ENGINE_new := _ENGINE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_new');
    {$ifend}
  end;


  ENGINE_free := LoadLibFunction(ADllHandle, ENGINE_free_procname);
  FuncLoadError := not assigned(ENGINE_free);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_free_allownil)}
    ENGINE_free := ERR_ENGINE_free;
    {$ifend}
    {$if declared(ENGINE_free_introduced)}
    if LibVersion < ENGINE_free_introduced then
    begin
      {$if declared(FC_ENGINE_free)}
      ENGINE_free := FC_ENGINE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_free_removed)}
    if ENGINE_free_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_free)}
      ENGINE_free := _ENGINE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_free');
    {$ifend}
  end;


  ENGINE_up_ref := LoadLibFunction(ADllHandle, ENGINE_up_ref_procname);
  FuncLoadError := not assigned(ENGINE_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_up_ref_allownil)}
    ENGINE_up_ref := ERR_ENGINE_up_ref;
    {$ifend}
    {$if declared(ENGINE_up_ref_introduced)}
    if LibVersion < ENGINE_up_ref_introduced then
    begin
      {$if declared(FC_ENGINE_up_ref)}
      ENGINE_up_ref := FC_ENGINE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_up_ref_removed)}
    if ENGINE_up_ref_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_up_ref)}
      ENGINE_up_ref := _ENGINE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_up_ref');
    {$ifend}
  end;


  ENGINE_set_id := LoadLibFunction(ADllHandle, ENGINE_set_id_procname);
  FuncLoadError := not assigned(ENGINE_set_id);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_id_allownil)}
    ENGINE_set_id := ERR_ENGINE_set_id;
    {$ifend}
    {$if declared(ENGINE_set_id_introduced)}
    if LibVersion < ENGINE_set_id_introduced then
    begin
      {$if declared(FC_ENGINE_set_id)}
      ENGINE_set_id := FC_ENGINE_set_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_id_removed)}
    if ENGINE_set_id_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_id)}
      ENGINE_set_id := _ENGINE_set_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_id_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_id');
    {$ifend}
  end;


  ENGINE_set_name := LoadLibFunction(ADllHandle, ENGINE_set_name_procname);
  FuncLoadError := not assigned(ENGINE_set_name);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_name_allownil)}
    ENGINE_set_name := ERR_ENGINE_set_name;
    {$ifend}
    {$if declared(ENGINE_set_name_introduced)}
    if LibVersion < ENGINE_set_name_introduced then
    begin
      {$if declared(FC_ENGINE_set_name)}
      ENGINE_set_name := FC_ENGINE_set_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_name_removed)}
    if ENGINE_set_name_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_name)}
      ENGINE_set_name := _ENGINE_set_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_name_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_name');
    {$ifend}
  end;


  ENGINE_set_RSA := LoadLibFunction(ADllHandle, ENGINE_set_RSA_procname);
  FuncLoadError := not assigned(ENGINE_set_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_RSA_allownil)}
    ENGINE_set_RSA := ERR_ENGINE_set_RSA;
    {$ifend}
    {$if declared(ENGINE_set_RSA_introduced)}
    if LibVersion < ENGINE_set_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_RSA)}
      ENGINE_set_RSA := FC_ENGINE_set_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_RSA_removed)}
    if ENGINE_set_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_RSA)}
      ENGINE_set_RSA := _ENGINE_set_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_RSA');
    {$ifend}
  end;


  ENGINE_set_DSA := LoadLibFunction(ADllHandle, ENGINE_set_DSA_procname);
  FuncLoadError := not assigned(ENGINE_set_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_DSA_allownil)}
    ENGINE_set_DSA := ERR_ENGINE_set_DSA;
    {$ifend}
    {$if declared(ENGINE_set_DSA_introduced)}
    if LibVersion < ENGINE_set_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_DSA)}
      ENGINE_set_DSA := FC_ENGINE_set_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_DSA_removed)}
    if ENGINE_set_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_DSA)}
      ENGINE_set_DSA := _ENGINE_set_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_DSA');
    {$ifend}
  end;


  ENGINE_set_EC := LoadLibFunction(ADllHandle, ENGINE_set_EC_procname);
  FuncLoadError := not assigned(ENGINE_set_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_EC_allownil)}
    ENGINE_set_EC := ERR_ENGINE_set_EC;
    {$ifend}
    {$if declared(ENGINE_set_EC_introduced)}
    if LibVersion < ENGINE_set_EC_introduced then
    begin
      {$if declared(FC_ENGINE_set_EC)}
      ENGINE_set_EC := FC_ENGINE_set_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_EC_removed)}
    if ENGINE_set_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_EC)}
      ENGINE_set_EC := _ENGINE_set_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_EC');
    {$ifend}
  end;


  ENGINE_set_DH := LoadLibFunction(ADllHandle, ENGINE_set_DH_procname);
  FuncLoadError := not assigned(ENGINE_set_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_DH_allownil)}
    ENGINE_set_DH := ERR_ENGINE_set_DH;
    {$ifend}
    {$if declared(ENGINE_set_DH_introduced)}
    if LibVersion < ENGINE_set_DH_introduced then
    begin
      {$if declared(FC_ENGINE_set_DH)}
      ENGINE_set_DH := FC_ENGINE_set_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_DH_removed)}
    if ENGINE_set_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_DH)}
      ENGINE_set_DH := _ENGINE_set_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_DH');
    {$ifend}
  end;


  ENGINE_set_RAND := LoadLibFunction(ADllHandle, ENGINE_set_RAND_procname);
  FuncLoadError := not assigned(ENGINE_set_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_RAND_allownil)}
    ENGINE_set_RAND := ERR_ENGINE_set_RAND;
    {$ifend}
    {$if declared(ENGINE_set_RAND_introduced)}
    if LibVersion < ENGINE_set_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_set_RAND)}
      ENGINE_set_RAND := FC_ENGINE_set_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_RAND_removed)}
    if ENGINE_set_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_RAND)}
      ENGINE_set_RAND := _ENGINE_set_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_RAND');
    {$ifend}
  end;


  ENGINE_set_destroy_function := LoadLibFunction(ADllHandle, ENGINE_set_destroy_function_procname);
  FuncLoadError := not assigned(ENGINE_set_destroy_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_destroy_function_allownil)}
    ENGINE_set_destroy_function := ERR_ENGINE_set_destroy_function;
    {$ifend}
    {$if declared(ENGINE_set_destroy_function_introduced)}
    if LibVersion < ENGINE_set_destroy_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_destroy_function)}
      ENGINE_set_destroy_function := FC_ENGINE_set_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_destroy_function_removed)}
    if ENGINE_set_destroy_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_destroy_function)}
      ENGINE_set_destroy_function := _ENGINE_set_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_destroy_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_destroy_function');
    {$ifend}
  end;


  ENGINE_set_init_function := LoadLibFunction(ADllHandle, ENGINE_set_init_function_procname);
  FuncLoadError := not assigned(ENGINE_set_init_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_init_function_allownil)}
    ENGINE_set_init_function := ERR_ENGINE_set_init_function;
    {$ifend}
    {$if declared(ENGINE_set_init_function_introduced)}
    if LibVersion < ENGINE_set_init_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_init_function)}
      ENGINE_set_init_function := FC_ENGINE_set_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_init_function_removed)}
    if ENGINE_set_init_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_init_function)}
      ENGINE_set_init_function := _ENGINE_set_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_init_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_init_function');
    {$ifend}
  end;


  ENGINE_set_finish_function := LoadLibFunction(ADllHandle, ENGINE_set_finish_function_procname);
  FuncLoadError := not assigned(ENGINE_set_finish_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_finish_function_allownil)}
    ENGINE_set_finish_function := ERR_ENGINE_set_finish_function;
    {$ifend}
    {$if declared(ENGINE_set_finish_function_introduced)}
    if LibVersion < ENGINE_set_finish_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_finish_function)}
      ENGINE_set_finish_function := FC_ENGINE_set_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_finish_function_removed)}
    if ENGINE_set_finish_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_finish_function)}
      ENGINE_set_finish_function := _ENGINE_set_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_finish_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_finish_function');
    {$ifend}
  end;


  ENGINE_set_ctrl_function := LoadLibFunction(ADllHandle, ENGINE_set_ctrl_function_procname);
  FuncLoadError := not assigned(ENGINE_set_ctrl_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_ctrl_function_allownil)}
    ENGINE_set_ctrl_function := ERR_ENGINE_set_ctrl_function;
    {$ifend}
    {$if declared(ENGINE_set_ctrl_function_introduced)}
    if LibVersion < ENGINE_set_ctrl_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_ctrl_function)}
      ENGINE_set_ctrl_function := FC_ENGINE_set_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_ctrl_function_removed)}
    if ENGINE_set_ctrl_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_ctrl_function)}
      ENGINE_set_ctrl_function := _ENGINE_set_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_ctrl_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_ctrl_function');
    {$ifend}
  end;


  ENGINE_set_load_privkey_function := LoadLibFunction(ADllHandle, ENGINE_set_load_privkey_function_procname);
  FuncLoadError := not assigned(ENGINE_set_load_privkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_load_privkey_function_allownil)}
    ENGINE_set_load_privkey_function := ERR_ENGINE_set_load_privkey_function;
    {$ifend}
    {$if declared(ENGINE_set_load_privkey_function_introduced)}
    if LibVersion < ENGINE_set_load_privkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_load_privkey_function)}
      ENGINE_set_load_privkey_function := FC_ENGINE_set_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_load_privkey_function_removed)}
    if ENGINE_set_load_privkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_load_privkey_function)}
      ENGINE_set_load_privkey_function := _ENGINE_set_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_load_privkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_load_privkey_function');
    {$ifend}
  end;


  ENGINE_set_load_pubkey_function := LoadLibFunction(ADllHandle, ENGINE_set_load_pubkey_function_procname);
  FuncLoadError := not assigned(ENGINE_set_load_pubkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_load_pubkey_function_allownil)}
    ENGINE_set_load_pubkey_function := ERR_ENGINE_set_load_pubkey_function;
    {$ifend}
    {$if declared(ENGINE_set_load_pubkey_function_introduced)}
    if LibVersion < ENGINE_set_load_pubkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_load_pubkey_function)}
      ENGINE_set_load_pubkey_function := FC_ENGINE_set_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_load_pubkey_function_removed)}
    if ENGINE_set_load_pubkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_load_pubkey_function)}
      ENGINE_set_load_pubkey_function := _ENGINE_set_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_load_pubkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_load_pubkey_function');
    {$ifend}
  end;


  ENGINE_set_ciphers := LoadLibFunction(ADllHandle, ENGINE_set_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_set_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_ciphers_allownil)}
    ENGINE_set_ciphers := ERR_ENGINE_set_ciphers;
    {$ifend}
    {$if declared(ENGINE_set_ciphers_introduced)}
    if LibVersion < ENGINE_set_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_set_ciphers)}
      ENGINE_set_ciphers := FC_ENGINE_set_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_ciphers_removed)}
    if ENGINE_set_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_ciphers)}
      ENGINE_set_ciphers := _ENGINE_set_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_ciphers');
    {$ifend}
  end;


  ENGINE_set_digests := LoadLibFunction(ADllHandle, ENGINE_set_digests_procname);
  FuncLoadError := not assigned(ENGINE_set_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_digests_allownil)}
    ENGINE_set_digests := ERR_ENGINE_set_digests;
    {$ifend}
    {$if declared(ENGINE_set_digests_introduced)}
    if LibVersion < ENGINE_set_digests_introduced then
    begin
      {$if declared(FC_ENGINE_set_digests)}
      ENGINE_set_digests := FC_ENGINE_set_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_digests_removed)}
    if ENGINE_set_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_digests)}
      ENGINE_set_digests := _ENGINE_set_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_digests');
    {$ifend}
  end;


  ENGINE_set_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_set_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_pkey_meths_allownil)}
    ENGINE_set_pkey_meths := ERR_ENGINE_set_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_set_pkey_meths_introduced)}
    if LibVersion < ENGINE_set_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_pkey_meths)}
      ENGINE_set_pkey_meths := FC_ENGINE_set_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_pkey_meths_removed)}
    if ENGINE_set_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_pkey_meths)}
      ENGINE_set_pkey_meths := _ENGINE_set_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_pkey_meths');
    {$ifend}
  end;


  ENGINE_set_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_set_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_pkey_asn1_meths_allownil)}
    ENGINE_set_pkey_asn1_meths := ERR_ENGINE_set_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_set_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_set_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_pkey_asn1_meths)}
      ENGINE_set_pkey_asn1_meths := FC_ENGINE_set_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_pkey_asn1_meths_removed)}
    if ENGINE_set_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_pkey_asn1_meths)}
      ENGINE_set_pkey_asn1_meths := _ENGINE_set_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_pkey_asn1_meths');
    {$ifend}
  end;


  ENGINE_set_flags := LoadLibFunction(ADllHandle, ENGINE_set_flags_procname);
  FuncLoadError := not assigned(ENGINE_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_flags_allownil)}
    ENGINE_set_flags := ERR_ENGINE_set_flags;
    {$ifend}
    {$if declared(ENGINE_set_flags_introduced)}
    if LibVersion < ENGINE_set_flags_introduced then
    begin
      {$if declared(FC_ENGINE_set_flags)}
      ENGINE_set_flags := FC_ENGINE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_flags_removed)}
    if ENGINE_set_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_flags)}
      ENGINE_set_flags := _ENGINE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_flags');
    {$ifend}
  end;


  ENGINE_set_cmd_defns := LoadLibFunction(ADllHandle, ENGINE_set_cmd_defns_procname);
  FuncLoadError := not assigned(ENGINE_set_cmd_defns);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_cmd_defns_allownil)}
    ENGINE_set_cmd_defns := ERR_ENGINE_set_cmd_defns;
    {$ifend}
    {$if declared(ENGINE_set_cmd_defns_introduced)}
    if LibVersion < ENGINE_set_cmd_defns_introduced then
    begin
      {$if declared(FC_ENGINE_set_cmd_defns)}
      ENGINE_set_cmd_defns := FC_ENGINE_set_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_cmd_defns_removed)}
    if ENGINE_set_cmd_defns_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_cmd_defns)}
      ENGINE_set_cmd_defns := _ENGINE_set_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_cmd_defns_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_cmd_defns');
    {$ifend}
  end;


  ENGINE_set_ex_data := LoadLibFunction(ADllHandle, ENGINE_set_ex_data_procname);
  FuncLoadError := not assigned(ENGINE_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_ex_data_allownil)}
    ENGINE_set_ex_data := ERR_ENGINE_set_ex_data;
    {$ifend}
    {$if declared(ENGINE_set_ex_data_introduced)}
    if LibVersion < ENGINE_set_ex_data_introduced then
    begin
      {$if declared(FC_ENGINE_set_ex_data)}
      ENGINE_set_ex_data := FC_ENGINE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_ex_data_removed)}
    if ENGINE_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_ex_data)}
      ENGINE_set_ex_data := _ENGINE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_ex_data');
    {$ifend}
  end;


  ENGINE_get_ex_data := LoadLibFunction(ADllHandle, ENGINE_get_ex_data_procname);
  FuncLoadError := not assigned(ENGINE_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_ex_data_allownil)}
    ENGINE_get_ex_data := ERR_ENGINE_get_ex_data;
    {$ifend}
    {$if declared(ENGINE_get_ex_data_introduced)}
    if LibVersion < ENGINE_get_ex_data_introduced then
    begin
      {$if declared(FC_ENGINE_get_ex_data)}
      ENGINE_get_ex_data := FC_ENGINE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_ex_data_removed)}
    if ENGINE_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_ex_data)}
      ENGINE_get_ex_data := _ENGINE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_ex_data');
    {$ifend}
  end;


  ENGINE_get_id := LoadLibFunction(ADllHandle, ENGINE_get_id_procname);
  FuncLoadError := not assigned(ENGINE_get_id);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_id_allownil)}
    ENGINE_get_id := ERR_ENGINE_get_id;
    {$ifend}
    {$if declared(ENGINE_get_id_introduced)}
    if LibVersion < ENGINE_get_id_introduced then
    begin
      {$if declared(FC_ENGINE_get_id)}
      ENGINE_get_id := FC_ENGINE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_id_removed)}
    if ENGINE_get_id_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_id)}
      ENGINE_get_id := _ENGINE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_id_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_id');
    {$ifend}
  end;


  ENGINE_get_name := LoadLibFunction(ADllHandle, ENGINE_get_name_procname);
  FuncLoadError := not assigned(ENGINE_get_name);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_name_allownil)}
    ENGINE_get_name := ERR_ENGINE_get_name;
    {$ifend}
    {$if declared(ENGINE_get_name_introduced)}
    if LibVersion < ENGINE_get_name_introduced then
    begin
      {$if declared(FC_ENGINE_get_name)}
      ENGINE_get_name := FC_ENGINE_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_name_removed)}
    if ENGINE_get_name_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_name)}
      ENGINE_get_name := _ENGINE_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_name_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_name');
    {$ifend}
  end;


  ENGINE_get_RSA := LoadLibFunction(ADllHandle, ENGINE_get_RSA_procname);
  FuncLoadError := not assigned(ENGINE_get_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_RSA_allownil)}
    ENGINE_get_RSA := ERR_ENGINE_get_RSA;
    {$ifend}
    {$if declared(ENGINE_get_RSA_introduced)}
    if LibVersion < ENGINE_get_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_RSA)}
      ENGINE_get_RSA := FC_ENGINE_get_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_RSA_removed)}
    if ENGINE_get_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_RSA)}
      ENGINE_get_RSA := _ENGINE_get_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_RSA');
    {$ifend}
  end;


  ENGINE_get_DSA := LoadLibFunction(ADllHandle, ENGINE_get_DSA_procname);
  FuncLoadError := not assigned(ENGINE_get_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_DSA_allownil)}
    ENGINE_get_DSA := ERR_ENGINE_get_DSA;
    {$ifend}
    {$if declared(ENGINE_get_DSA_introduced)}
    if LibVersion < ENGINE_get_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_DSA)}
      ENGINE_get_DSA := FC_ENGINE_get_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_DSA_removed)}
    if ENGINE_get_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_DSA)}
      ENGINE_get_DSA := _ENGINE_get_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_DSA');
    {$ifend}
  end;


  ENGINE_get_EC := LoadLibFunction(ADllHandle, ENGINE_get_EC_procname);
  FuncLoadError := not assigned(ENGINE_get_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_EC_allownil)}
    ENGINE_get_EC := ERR_ENGINE_get_EC;
    {$ifend}
    {$if declared(ENGINE_get_EC_introduced)}
    if LibVersion < ENGINE_get_EC_introduced then
    begin
      {$if declared(FC_ENGINE_get_EC)}
      ENGINE_get_EC := FC_ENGINE_get_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_EC_removed)}
    if ENGINE_get_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_EC)}
      ENGINE_get_EC := _ENGINE_get_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_EC');
    {$ifend}
  end;


  ENGINE_get_DH := LoadLibFunction(ADllHandle, ENGINE_get_DH_procname);
  FuncLoadError := not assigned(ENGINE_get_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_DH_allownil)}
    ENGINE_get_DH := ERR_ENGINE_get_DH;
    {$ifend}
    {$if declared(ENGINE_get_DH_introduced)}
    if LibVersion < ENGINE_get_DH_introduced then
    begin
      {$if declared(FC_ENGINE_get_DH)}
      ENGINE_get_DH := FC_ENGINE_get_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_DH_removed)}
    if ENGINE_get_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_DH)}
      ENGINE_get_DH := _ENGINE_get_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_DH');
    {$ifend}
  end;


  ENGINE_get_RAND := LoadLibFunction(ADllHandle, ENGINE_get_RAND_procname);
  FuncLoadError := not assigned(ENGINE_get_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_RAND_allownil)}
    ENGINE_get_RAND := ERR_ENGINE_get_RAND;
    {$ifend}
    {$if declared(ENGINE_get_RAND_introduced)}
    if LibVersion < ENGINE_get_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_get_RAND)}
      ENGINE_get_RAND := FC_ENGINE_get_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_RAND_removed)}
    if ENGINE_get_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_RAND)}
      ENGINE_get_RAND := _ENGINE_get_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_RAND');
    {$ifend}
  end;


  ENGINE_get_destroy_function := LoadLibFunction(ADllHandle, ENGINE_get_destroy_function_procname);
  FuncLoadError := not assigned(ENGINE_get_destroy_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_destroy_function_allownil)}
    ENGINE_get_destroy_function := ERR_ENGINE_get_destroy_function;
    {$ifend}
    {$if declared(ENGINE_get_destroy_function_introduced)}
    if LibVersion < ENGINE_get_destroy_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_destroy_function)}
      ENGINE_get_destroy_function := FC_ENGINE_get_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_destroy_function_removed)}
    if ENGINE_get_destroy_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_destroy_function)}
      ENGINE_get_destroy_function := _ENGINE_get_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_destroy_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_destroy_function');
    {$ifend}
  end;


  ENGINE_get_init_function := LoadLibFunction(ADllHandle, ENGINE_get_init_function_procname);
  FuncLoadError := not assigned(ENGINE_get_init_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_init_function_allownil)}
    ENGINE_get_init_function := ERR_ENGINE_get_init_function;
    {$ifend}
    {$if declared(ENGINE_get_init_function_introduced)}
    if LibVersion < ENGINE_get_init_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_init_function)}
      ENGINE_get_init_function := FC_ENGINE_get_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_init_function_removed)}
    if ENGINE_get_init_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_init_function)}
      ENGINE_get_init_function := _ENGINE_get_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_init_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_init_function');
    {$ifend}
  end;


  ENGINE_get_finish_function := LoadLibFunction(ADllHandle, ENGINE_get_finish_function_procname);
  FuncLoadError := not assigned(ENGINE_get_finish_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_finish_function_allownil)}
    ENGINE_get_finish_function := ERR_ENGINE_get_finish_function;
    {$ifend}
    {$if declared(ENGINE_get_finish_function_introduced)}
    if LibVersion < ENGINE_get_finish_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_finish_function)}
      ENGINE_get_finish_function := FC_ENGINE_get_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_finish_function_removed)}
    if ENGINE_get_finish_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_finish_function)}
      ENGINE_get_finish_function := _ENGINE_get_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_finish_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_finish_function');
    {$ifend}
  end;


  ENGINE_get_ctrl_function := LoadLibFunction(ADllHandle, ENGINE_get_ctrl_function_procname);
  FuncLoadError := not assigned(ENGINE_get_ctrl_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_ctrl_function_allownil)}
    ENGINE_get_ctrl_function := ERR_ENGINE_get_ctrl_function;
    {$ifend}
    {$if declared(ENGINE_get_ctrl_function_introduced)}
    if LibVersion < ENGINE_get_ctrl_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_ctrl_function)}
      ENGINE_get_ctrl_function := FC_ENGINE_get_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_ctrl_function_removed)}
    if ENGINE_get_ctrl_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_ctrl_function)}
      ENGINE_get_ctrl_function := _ENGINE_get_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_ctrl_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_ctrl_function');
    {$ifend}
  end;


  ENGINE_get_load_privkey_function := LoadLibFunction(ADllHandle, ENGINE_get_load_privkey_function_procname);
  FuncLoadError := not assigned(ENGINE_get_load_privkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_load_privkey_function_allownil)}
    ENGINE_get_load_privkey_function := ERR_ENGINE_get_load_privkey_function;
    {$ifend}
    {$if declared(ENGINE_get_load_privkey_function_introduced)}
    if LibVersion < ENGINE_get_load_privkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_load_privkey_function)}
      ENGINE_get_load_privkey_function := FC_ENGINE_get_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_load_privkey_function_removed)}
    if ENGINE_get_load_privkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_load_privkey_function)}
      ENGINE_get_load_privkey_function := _ENGINE_get_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_load_privkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_load_privkey_function');
    {$ifend}
  end;


  ENGINE_get_load_pubkey_function := LoadLibFunction(ADllHandle, ENGINE_get_load_pubkey_function_procname);
  FuncLoadError := not assigned(ENGINE_get_load_pubkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_load_pubkey_function_allownil)}
    ENGINE_get_load_pubkey_function := ERR_ENGINE_get_load_pubkey_function;
    {$ifend}
    {$if declared(ENGINE_get_load_pubkey_function_introduced)}
    if LibVersion < ENGINE_get_load_pubkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_load_pubkey_function)}
      ENGINE_get_load_pubkey_function := FC_ENGINE_get_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_load_pubkey_function_removed)}
    if ENGINE_get_load_pubkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_load_pubkey_function)}
      ENGINE_get_load_pubkey_function := _ENGINE_get_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_load_pubkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_load_pubkey_function');
    {$ifend}
  end;


  ENGINE_get_ciphers := LoadLibFunction(ADllHandle, ENGINE_get_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_get_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_ciphers_allownil)}
    ENGINE_get_ciphers := ERR_ENGINE_get_ciphers;
    {$ifend}
    {$if declared(ENGINE_get_ciphers_introduced)}
    if LibVersion < ENGINE_get_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_get_ciphers)}
      ENGINE_get_ciphers := FC_ENGINE_get_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_ciphers_removed)}
    if ENGINE_get_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_ciphers)}
      ENGINE_get_ciphers := _ENGINE_get_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_ciphers');
    {$ifend}
  end;


  ENGINE_get_digests := LoadLibFunction(ADllHandle, ENGINE_get_digests_procname);
  FuncLoadError := not assigned(ENGINE_get_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_digests_allownil)}
    ENGINE_get_digests := ERR_ENGINE_get_digests;
    {$ifend}
    {$if declared(ENGINE_get_digests_introduced)}
    if LibVersion < ENGINE_get_digests_introduced then
    begin
      {$if declared(FC_ENGINE_get_digests)}
      ENGINE_get_digests := FC_ENGINE_get_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_digests_removed)}
    if ENGINE_get_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_digests)}
      ENGINE_get_digests := _ENGINE_get_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_digests');
    {$ifend}
  end;


  ENGINE_get_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_get_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_meths_allownil)}
    ENGINE_get_pkey_meths := ERR_ENGINE_get_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meths_introduced)}
    if LibVersion < ENGINE_get_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_meths)}
      ENGINE_get_pkey_meths := FC_ENGINE_get_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meths_removed)}
    if ENGINE_get_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_meths)}
      ENGINE_get_pkey_meths := _ENGINE_get_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_meths');
    {$ifend}
  end;


  ENGINE_get_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meths_allownil)}
    ENGINE_get_pkey_asn1_meths := ERR_ENGINE_get_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meths)}
      ENGINE_get_pkey_asn1_meths := FC_ENGINE_get_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meths_removed)}
    if ENGINE_get_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meths)}
      ENGINE_get_pkey_asn1_meths := _ENGINE_get_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meths');
    {$ifend}
  end;


  ENGINE_get_cipher := LoadLibFunction(ADllHandle, ENGINE_get_cipher_procname);
  FuncLoadError := not assigned(ENGINE_get_cipher);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_cipher_allownil)}
    ENGINE_get_cipher := ERR_ENGINE_get_cipher;
    {$ifend}
    {$if declared(ENGINE_get_cipher_introduced)}
    if LibVersion < ENGINE_get_cipher_introduced then
    begin
      {$if declared(FC_ENGINE_get_cipher)}
      ENGINE_get_cipher := FC_ENGINE_get_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_cipher_removed)}
    if ENGINE_get_cipher_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_cipher)}
      ENGINE_get_cipher := _ENGINE_get_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_cipher');
    {$ifend}
  end;


  ENGINE_get_digest := LoadLibFunction(ADllHandle, ENGINE_get_digest_procname);
  FuncLoadError := not assigned(ENGINE_get_digest);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_digest_allownil)}
    ENGINE_get_digest := ERR_ENGINE_get_digest;
    {$ifend}
    {$if declared(ENGINE_get_digest_introduced)}
    if LibVersion < ENGINE_get_digest_introduced then
    begin
      {$if declared(FC_ENGINE_get_digest)}
      ENGINE_get_digest := FC_ENGINE_get_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_digest_removed)}
    if ENGINE_get_digest_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_digest)}
      ENGINE_get_digest := _ENGINE_get_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_digest');
    {$ifend}
  end;


  ENGINE_get_pkey_meth := LoadLibFunction(ADllHandle, ENGINE_get_pkey_meth_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_meth);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_meth_allownil)}
    ENGINE_get_pkey_meth := ERR_ENGINE_get_pkey_meth;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_introduced)}
    if LibVersion < ENGINE_get_pkey_meth_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_meth)}
      ENGINE_get_pkey_meth := FC_ENGINE_get_pkey_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_removed)}
    if ENGINE_get_pkey_meth_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_meth)}
      ENGINE_get_pkey_meth := _ENGINE_get_pkey_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_meth_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_meth');
    {$ifend}
  end;


  ENGINE_get_pkey_asn1_meth := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meth_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meth_allownil)}
    ENGINE_get_pkey_asn1_meth := ERR_ENGINE_get_pkey_asn1_meth;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meth_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meth)}
      ENGINE_get_pkey_asn1_meth := FC_ENGINE_get_pkey_asn1_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_removed)}
    if ENGINE_get_pkey_asn1_meth_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meth)}
      ENGINE_get_pkey_asn1_meth := _ENGINE_get_pkey_asn1_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meth_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meth');
    {$ifend}
  end;


  ENGINE_get_pkey_asn1_meth_str := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meth_str_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth_str);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meth_str_allownil)}
    ENGINE_get_pkey_asn1_meth_str := ERR_ENGINE_get_pkey_asn1_meth_str;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_str_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meth_str_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meth_str)}
      ENGINE_get_pkey_asn1_meth_str := FC_ENGINE_get_pkey_asn1_meth_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_str_removed)}
    if ENGINE_get_pkey_asn1_meth_str_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meth_str)}
      ENGINE_get_pkey_asn1_meth_str := _ENGINE_get_pkey_asn1_meth_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meth_str_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meth_str');
    {$ifend}
  end;


  ENGINE_pkey_asn1_find_str := LoadLibFunction(ADllHandle, ENGINE_pkey_asn1_find_str_procname);
  FuncLoadError := not assigned(ENGINE_pkey_asn1_find_str);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_pkey_asn1_find_str_allownil)}
    ENGINE_pkey_asn1_find_str := ERR_ENGINE_pkey_asn1_find_str;
    {$ifend}
    {$if declared(ENGINE_pkey_asn1_find_str_introduced)}
    if LibVersion < ENGINE_pkey_asn1_find_str_introduced then
    begin
      {$if declared(FC_ENGINE_pkey_asn1_find_str)}
      ENGINE_pkey_asn1_find_str := FC_ENGINE_pkey_asn1_find_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_pkey_asn1_find_str_removed)}
    if ENGINE_pkey_asn1_find_str_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_pkey_asn1_find_str)}
      ENGINE_pkey_asn1_find_str := _ENGINE_pkey_asn1_find_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_pkey_asn1_find_str_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_pkey_asn1_find_str');
    {$ifend}
  end;


  ENGINE_get_cmd_defns := LoadLibFunction(ADllHandle, ENGINE_get_cmd_defns_procname);
  FuncLoadError := not assigned(ENGINE_get_cmd_defns);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_cmd_defns_allownil)}
    ENGINE_get_cmd_defns := ERR_ENGINE_get_cmd_defns;
    {$ifend}
    {$if declared(ENGINE_get_cmd_defns_introduced)}
    if LibVersion < ENGINE_get_cmd_defns_introduced then
    begin
      {$if declared(FC_ENGINE_get_cmd_defns)}
      ENGINE_get_cmd_defns := FC_ENGINE_get_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_cmd_defns_removed)}
    if ENGINE_get_cmd_defns_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_cmd_defns)}
      ENGINE_get_cmd_defns := _ENGINE_get_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_cmd_defns_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_cmd_defns');
    {$ifend}
  end;


  ENGINE_get_flags := LoadLibFunction(ADllHandle, ENGINE_get_flags_procname);
  FuncLoadError := not assigned(ENGINE_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_flags_allownil)}
    ENGINE_get_flags := ERR_ENGINE_get_flags;
    {$ifend}
    {$if declared(ENGINE_get_flags_introduced)}
    if LibVersion < ENGINE_get_flags_introduced then
    begin
      {$if declared(FC_ENGINE_get_flags)}
      ENGINE_get_flags := FC_ENGINE_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_flags_removed)}
    if ENGINE_get_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_flags)}
      ENGINE_get_flags := _ENGINE_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_flags');
    {$ifend}
  end;


  ENGINE_init := LoadLibFunction(ADllHandle, ENGINE_init_procname);
  FuncLoadError := not assigned(ENGINE_init);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_init_allownil)}
    ENGINE_init := ERR_ENGINE_init;
    {$ifend}
    {$if declared(ENGINE_init_introduced)}
    if LibVersion < ENGINE_init_introduced then
    begin
      {$if declared(FC_ENGINE_init)}
      ENGINE_init := FC_ENGINE_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_init_removed)}
    if ENGINE_init_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_init)}
      ENGINE_init := _ENGINE_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_init_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_init');
    {$ifend}
  end;


  ENGINE_finish := LoadLibFunction(ADllHandle, ENGINE_finish_procname);
  FuncLoadError := not assigned(ENGINE_finish);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_finish_allownil)}
    ENGINE_finish := ERR_ENGINE_finish;
    {$ifend}
    {$if declared(ENGINE_finish_introduced)}
    if LibVersion < ENGINE_finish_introduced then
    begin
      {$if declared(FC_ENGINE_finish)}
      ENGINE_finish := FC_ENGINE_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_finish_removed)}
    if ENGINE_finish_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_finish)}
      ENGINE_finish := _ENGINE_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_finish');
    {$ifend}
  end;


  ENGINE_load_private_key := LoadLibFunction(ADllHandle, ENGINE_load_private_key_procname);
  FuncLoadError := not assigned(ENGINE_load_private_key);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_load_private_key_allownil)}
    ENGINE_load_private_key := ERR_ENGINE_load_private_key;
    {$ifend}
    {$if declared(ENGINE_load_private_key_introduced)}
    if LibVersion < ENGINE_load_private_key_introduced then
    begin
      {$if declared(FC_ENGINE_load_private_key)}
      ENGINE_load_private_key := FC_ENGINE_load_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_load_private_key_removed)}
    if ENGINE_load_private_key_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_load_private_key)}
      ENGINE_load_private_key := _ENGINE_load_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_load_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_load_private_key');
    {$ifend}
  end;


  ENGINE_load_public_key := LoadLibFunction(ADllHandle, ENGINE_load_public_key_procname);
  FuncLoadError := not assigned(ENGINE_load_public_key);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_load_public_key_allownil)}
    ENGINE_load_public_key := ERR_ENGINE_load_public_key;
    {$ifend}
    {$if declared(ENGINE_load_public_key_introduced)}
    if LibVersion < ENGINE_load_public_key_introduced then
    begin
      {$if declared(FC_ENGINE_load_public_key)}
      ENGINE_load_public_key := FC_ENGINE_load_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_load_public_key_removed)}
    if ENGINE_load_public_key_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_load_public_key)}
      ENGINE_load_public_key := _ENGINE_load_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_load_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_load_public_key');
    {$ifend}
  end;


  ENGINE_get_default_RSA := LoadLibFunction(ADllHandle, ENGINE_get_default_RSA_procname);
  FuncLoadError := not assigned(ENGINE_get_default_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_RSA_allownil)}
    ENGINE_get_default_RSA := ERR_ENGINE_get_default_RSA;
    {$ifend}
    {$if declared(ENGINE_get_default_RSA_introduced)}
    if LibVersion < ENGINE_get_default_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_RSA)}
      ENGINE_get_default_RSA := FC_ENGINE_get_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_RSA_removed)}
    if ENGINE_get_default_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_RSA)}
      ENGINE_get_default_RSA := _ENGINE_get_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_RSA');
    {$ifend}
  end;


  ENGINE_get_default_DSA := LoadLibFunction(ADllHandle, ENGINE_get_default_DSA_procname);
  FuncLoadError := not assigned(ENGINE_get_default_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_DSA_allownil)}
    ENGINE_get_default_DSA := ERR_ENGINE_get_default_DSA;
    {$ifend}
    {$if declared(ENGINE_get_default_DSA_introduced)}
    if LibVersion < ENGINE_get_default_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_DSA)}
      ENGINE_get_default_DSA := FC_ENGINE_get_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_DSA_removed)}
    if ENGINE_get_default_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_DSA)}
      ENGINE_get_default_DSA := _ENGINE_get_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_DSA');
    {$ifend}
  end;


  ENGINE_get_default_EC := LoadLibFunction(ADllHandle, ENGINE_get_default_EC_procname);
  FuncLoadError := not assigned(ENGINE_get_default_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_EC_allownil)}
    ENGINE_get_default_EC := ERR_ENGINE_get_default_EC;
    {$ifend}
    {$if declared(ENGINE_get_default_EC_introduced)}
    if LibVersion < ENGINE_get_default_EC_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_EC)}
      ENGINE_get_default_EC := FC_ENGINE_get_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_EC_removed)}
    if ENGINE_get_default_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_EC)}
      ENGINE_get_default_EC := _ENGINE_get_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_EC');
    {$ifend}
  end;


  ENGINE_get_default_DH := LoadLibFunction(ADllHandle, ENGINE_get_default_DH_procname);
  FuncLoadError := not assigned(ENGINE_get_default_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_DH_allownil)}
    ENGINE_get_default_DH := ERR_ENGINE_get_default_DH;
    {$ifend}
    {$if declared(ENGINE_get_default_DH_introduced)}
    if LibVersion < ENGINE_get_default_DH_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_DH)}
      ENGINE_get_default_DH := FC_ENGINE_get_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_DH_removed)}
    if ENGINE_get_default_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_DH)}
      ENGINE_get_default_DH := _ENGINE_get_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_DH');
    {$ifend}
  end;


  ENGINE_get_default_RAND := LoadLibFunction(ADllHandle, ENGINE_get_default_RAND_procname);
  FuncLoadError := not assigned(ENGINE_get_default_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_RAND_allownil)}
    ENGINE_get_default_RAND := ERR_ENGINE_get_default_RAND;
    {$ifend}
    {$if declared(ENGINE_get_default_RAND_introduced)}
    if LibVersion < ENGINE_get_default_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_RAND)}
      ENGINE_get_default_RAND := FC_ENGINE_get_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_RAND_removed)}
    if ENGINE_get_default_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_RAND)}
      ENGINE_get_default_RAND := _ENGINE_get_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_RAND');
    {$ifend}
  end;


  ENGINE_get_cipher_engine := LoadLibFunction(ADllHandle, ENGINE_get_cipher_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_cipher_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_cipher_engine_allownil)}
    ENGINE_get_cipher_engine := ERR_ENGINE_get_cipher_engine;
    {$ifend}
    {$if declared(ENGINE_get_cipher_engine_introduced)}
    if LibVersion < ENGINE_get_cipher_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_cipher_engine)}
      ENGINE_get_cipher_engine := FC_ENGINE_get_cipher_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_cipher_engine_removed)}
    if ENGINE_get_cipher_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_cipher_engine)}
      ENGINE_get_cipher_engine := _ENGINE_get_cipher_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_cipher_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_cipher_engine');
    {$ifend}
  end;


  ENGINE_get_digest_engine := LoadLibFunction(ADllHandle, ENGINE_get_digest_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_digest_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_digest_engine_allownil)}
    ENGINE_get_digest_engine := ERR_ENGINE_get_digest_engine;
    {$ifend}
    {$if declared(ENGINE_get_digest_engine_introduced)}
    if LibVersion < ENGINE_get_digest_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_digest_engine)}
      ENGINE_get_digest_engine := FC_ENGINE_get_digest_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_digest_engine_removed)}
    if ENGINE_get_digest_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_digest_engine)}
      ENGINE_get_digest_engine := _ENGINE_get_digest_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_digest_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_digest_engine');
    {$ifend}
  end;


  ENGINE_get_pkey_meth_engine := LoadLibFunction(ADllHandle, ENGINE_get_pkey_meth_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_meth_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_meth_engine_allownil)}
    ENGINE_get_pkey_meth_engine := ERR_ENGINE_get_pkey_meth_engine;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_engine_introduced)}
    if LibVersion < ENGINE_get_pkey_meth_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_meth_engine)}
      ENGINE_get_pkey_meth_engine := FC_ENGINE_get_pkey_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_engine_removed)}
    if ENGINE_get_pkey_meth_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_meth_engine)}
      ENGINE_get_pkey_meth_engine := _ENGINE_get_pkey_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_meth_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_meth_engine');
    {$ifend}
  end;


  ENGINE_get_pkey_asn1_meth_engine := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meth_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meth_engine_allownil)}
    ENGINE_get_pkey_asn1_meth_engine := ERR_ENGINE_get_pkey_asn1_meth_engine;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_engine_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meth_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meth_engine)}
      ENGINE_get_pkey_asn1_meth_engine := FC_ENGINE_get_pkey_asn1_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_engine_removed)}
    if ENGINE_get_pkey_asn1_meth_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meth_engine)}
      ENGINE_get_pkey_asn1_meth_engine := _ENGINE_get_pkey_asn1_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meth_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meth_engine');
    {$ifend}
  end;


  ENGINE_set_default_RSA := LoadLibFunction(ADllHandle, ENGINE_set_default_RSA_procname);
  FuncLoadError := not assigned(ENGINE_set_default_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_RSA_allownil)}
    ENGINE_set_default_RSA := ERR_ENGINE_set_default_RSA;
    {$ifend}
    {$if declared(ENGINE_set_default_RSA_introduced)}
    if LibVersion < ENGINE_set_default_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_RSA)}
      ENGINE_set_default_RSA := FC_ENGINE_set_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_RSA_removed)}
    if ENGINE_set_default_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_RSA)}
      ENGINE_set_default_RSA := _ENGINE_set_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_RSA');
    {$ifend}
  end;


  ENGINE_set_default_string := LoadLibFunction(ADllHandle, ENGINE_set_default_string_procname);
  FuncLoadError := not assigned(ENGINE_set_default_string);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_string_allownil)}
    ENGINE_set_default_string := ERR_ENGINE_set_default_string;
    {$ifend}
    {$if declared(ENGINE_set_default_string_introduced)}
    if LibVersion < ENGINE_set_default_string_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_string)}
      ENGINE_set_default_string := FC_ENGINE_set_default_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_string_removed)}
    if ENGINE_set_default_string_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_string)}
      ENGINE_set_default_string := _ENGINE_set_default_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_string');
    {$ifend}
  end;


  ENGINE_set_default_DSA := LoadLibFunction(ADllHandle, ENGINE_set_default_DSA_procname);
  FuncLoadError := not assigned(ENGINE_set_default_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_DSA_allownil)}
    ENGINE_set_default_DSA := ERR_ENGINE_set_default_DSA;
    {$ifend}
    {$if declared(ENGINE_set_default_DSA_introduced)}
    if LibVersion < ENGINE_set_default_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_DSA)}
      ENGINE_set_default_DSA := FC_ENGINE_set_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_DSA_removed)}
    if ENGINE_set_default_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_DSA)}
      ENGINE_set_default_DSA := _ENGINE_set_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_DSA');
    {$ifend}
  end;


  ENGINE_set_default_EC := LoadLibFunction(ADllHandle, ENGINE_set_default_EC_procname);
  FuncLoadError := not assigned(ENGINE_set_default_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_EC_allownil)}
    ENGINE_set_default_EC := ERR_ENGINE_set_default_EC;
    {$ifend}
    {$if declared(ENGINE_set_default_EC_introduced)}
    if LibVersion < ENGINE_set_default_EC_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_EC)}
      ENGINE_set_default_EC := FC_ENGINE_set_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_EC_removed)}
    if ENGINE_set_default_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_EC)}
      ENGINE_set_default_EC := _ENGINE_set_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_EC');
    {$ifend}
  end;


  ENGINE_set_default_DH := LoadLibFunction(ADllHandle, ENGINE_set_default_DH_procname);
  FuncLoadError := not assigned(ENGINE_set_default_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_DH_allownil)}
    ENGINE_set_default_DH := ERR_ENGINE_set_default_DH;
    {$ifend}
    {$if declared(ENGINE_set_default_DH_introduced)}
    if LibVersion < ENGINE_set_default_DH_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_DH)}
      ENGINE_set_default_DH := FC_ENGINE_set_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_DH_removed)}
    if ENGINE_set_default_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_DH)}
      ENGINE_set_default_DH := _ENGINE_set_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_DH');
    {$ifend}
  end;


  ENGINE_set_default_RAND := LoadLibFunction(ADllHandle, ENGINE_set_default_RAND_procname);
  FuncLoadError := not assigned(ENGINE_set_default_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_RAND_allownil)}
    ENGINE_set_default_RAND := ERR_ENGINE_set_default_RAND;
    {$ifend}
    {$if declared(ENGINE_set_default_RAND_introduced)}
    if LibVersion < ENGINE_set_default_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_RAND)}
      ENGINE_set_default_RAND := FC_ENGINE_set_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_RAND_removed)}
    if ENGINE_set_default_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_RAND)}
      ENGINE_set_default_RAND := _ENGINE_set_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_RAND');
    {$ifend}
  end;


  ENGINE_set_default_ciphers := LoadLibFunction(ADllHandle, ENGINE_set_default_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_set_default_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_ciphers_allownil)}
    ENGINE_set_default_ciphers := ERR_ENGINE_set_default_ciphers;
    {$ifend}
    {$if declared(ENGINE_set_default_ciphers_introduced)}
    if LibVersion < ENGINE_set_default_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_ciphers)}
      ENGINE_set_default_ciphers := FC_ENGINE_set_default_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_ciphers_removed)}
    if ENGINE_set_default_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_ciphers)}
      ENGINE_set_default_ciphers := _ENGINE_set_default_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_ciphers');
    {$ifend}
  end;


  ENGINE_set_default_digests := LoadLibFunction(ADllHandle, ENGINE_set_default_digests_procname);
  FuncLoadError := not assigned(ENGINE_set_default_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_digests_allownil)}
    ENGINE_set_default_digests := ERR_ENGINE_set_default_digests;
    {$ifend}
    {$if declared(ENGINE_set_default_digests_introduced)}
    if LibVersion < ENGINE_set_default_digests_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_digests)}
      ENGINE_set_default_digests := FC_ENGINE_set_default_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_digests_removed)}
    if ENGINE_set_default_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_digests)}
      ENGINE_set_default_digests := _ENGINE_set_default_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_digests');
    {$ifend}
  end;


  ENGINE_set_default_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_set_default_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_default_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_pkey_meths_allownil)}
    ENGINE_set_default_pkey_meths := ERR_ENGINE_set_default_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_meths_introduced)}
    if LibVersion < ENGINE_set_default_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_pkey_meths)}
      ENGINE_set_default_pkey_meths := FC_ENGINE_set_default_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_meths_removed)}
    if ENGINE_set_default_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_pkey_meths)}
      ENGINE_set_default_pkey_meths := _ENGINE_set_default_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_pkey_meths');
    {$ifend}
  end;


  ENGINE_set_default_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_set_default_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_default_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_pkey_asn1_meths_allownil)}
    ENGINE_set_default_pkey_asn1_meths := ERR_ENGINE_set_default_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_set_default_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_pkey_asn1_meths)}
      ENGINE_set_default_pkey_asn1_meths := FC_ENGINE_set_default_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_asn1_meths_removed)}
    if ENGINE_set_default_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_pkey_asn1_meths)}
      ENGINE_set_default_pkey_asn1_meths := _ENGINE_set_default_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_pkey_asn1_meths');
    {$ifend}
  end;


  ENGINE_set_default := LoadLibFunction(ADllHandle, ENGINE_set_default_procname);
  FuncLoadError := not assigned(ENGINE_set_default);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_allownil)}
    ENGINE_set_default := ERR_ENGINE_set_default;
    {$ifend}
    {$if declared(ENGINE_set_default_introduced)}
    if LibVersion < ENGINE_set_default_introduced then
    begin
      {$if declared(FC_ENGINE_set_default)}
      ENGINE_set_default := FC_ENGINE_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_removed)}
    if ENGINE_set_default_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default)}
      ENGINE_set_default := _ENGINE_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default');
    {$ifend}
  end;


  ENGINE_add_conf_module := LoadLibFunction(ADllHandle, ENGINE_add_conf_module_procname);
  FuncLoadError := not assigned(ENGINE_add_conf_module);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_add_conf_module_allownil)}
    ENGINE_add_conf_module := ERR_ENGINE_add_conf_module;
    {$ifend}
    {$if declared(ENGINE_add_conf_module_introduced)}
    if LibVersion < ENGINE_add_conf_module_introduced then
    begin
      {$if declared(FC_ENGINE_add_conf_module)}
      ENGINE_add_conf_module := FC_ENGINE_add_conf_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_add_conf_module_removed)}
    if ENGINE_add_conf_module_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_add_conf_module)}
      ENGINE_add_conf_module := _ENGINE_add_conf_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_add_conf_module_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_add_conf_module');
    {$ifend}
  end;


  ENGINE_get_static_state := LoadLibFunction(ADllHandle, ENGINE_get_static_state_procname);
  FuncLoadError := not assigned(ENGINE_get_static_state);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_static_state_allownil)}
    ENGINE_get_static_state := ERR_ENGINE_get_static_state;
    {$ifend}
    {$if declared(ENGINE_get_static_state_introduced)}
    if LibVersion < ENGINE_get_static_state_introduced then
    begin
      {$if declared(FC_ENGINE_get_static_state)}
      ENGINE_get_static_state := FC_ENGINE_get_static_state;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_static_state_removed)}
    if ENGINE_get_static_state_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_static_state)}
      ENGINE_get_static_state := _ENGINE_get_static_state;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_static_state_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_static_state');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ENGINE_get_first := nil;
  ENGINE_get_last := nil;
  ENGINE_get_next := nil;
  ENGINE_get_prev := nil;
  ENGINE_add := nil;
  ENGINE_remove := nil;
  ENGINE_by_id := nil;
  ENGINE_load_builtin_engines := nil;
  ENGINE_get_table_flags := nil;
  ENGINE_set_table_flags := nil;
  ENGINE_register_RSA := nil;
  ENGINE_unregister_RSA := nil;
  ENGINE_register_all_RSA := nil;
  ENGINE_register_DSA := nil;
  ENGINE_unregister_DSA := nil;
  ENGINE_register_all_DSA := nil;
  ENGINE_register_EC := nil;
  ENGINE_unregister_EC := nil;
  ENGINE_register_all_EC := nil;
  ENGINE_register_DH := nil;
  ENGINE_unregister_DH := nil;
  ENGINE_register_all_DH := nil;
  ENGINE_register_RAND := nil;
  ENGINE_unregister_RAND := nil;
  ENGINE_register_all_RAND := nil;
  ENGINE_register_ciphers := nil;
  ENGINE_unregister_ciphers := nil;
  ENGINE_register_all_ciphers := nil;
  ENGINE_register_digests := nil;
  ENGINE_unregister_digests := nil;
  ENGINE_register_all_digests := nil;
  ENGINE_register_pkey_meths := nil;
  ENGINE_unregister_pkey_meths := nil;
  ENGINE_register_all_pkey_meths := nil;
  ENGINE_register_pkey_asn1_meths := nil;
  ENGINE_unregister_pkey_asn1_meths := nil;
  ENGINE_register_all_pkey_asn1_meths := nil;
  ENGINE_register_complete := nil;
  ENGINE_register_all_complete := nil;
  ENGINE_ctrl := nil;
  ENGINE_cmd_is_executable := nil;
  ENGINE_ctrl_cmd := nil;
  ENGINE_ctrl_cmd_string := nil;
  ENGINE_new := nil;
  ENGINE_free := nil;
  ENGINE_up_ref := nil;
  ENGINE_set_id := nil;
  ENGINE_set_name := nil;
  ENGINE_set_RSA := nil;
  ENGINE_set_DSA := nil;
  ENGINE_set_EC := nil;
  ENGINE_set_DH := nil;
  ENGINE_set_RAND := nil;
  ENGINE_set_destroy_function := nil;
  ENGINE_set_init_function := nil;
  ENGINE_set_finish_function := nil;
  ENGINE_set_ctrl_function := nil;
  ENGINE_set_load_privkey_function := nil;
  ENGINE_set_load_pubkey_function := nil;
  ENGINE_set_ciphers := nil;
  ENGINE_set_digests := nil;
  ENGINE_set_pkey_meths := nil;
  ENGINE_set_pkey_asn1_meths := nil;
  ENGINE_set_flags := nil;
  ENGINE_set_cmd_defns := nil;
  ENGINE_set_ex_data := nil;
  ENGINE_get_ex_data := nil;
  ENGINE_get_id := nil;
  ENGINE_get_name := nil;
  ENGINE_get_RSA := nil;
  ENGINE_get_DSA := nil;
  ENGINE_get_EC := nil;
  ENGINE_get_DH := nil;
  ENGINE_get_RAND := nil;
  ENGINE_get_destroy_function := nil;
  ENGINE_get_init_function := nil;
  ENGINE_get_finish_function := nil;
  ENGINE_get_ctrl_function := nil;
  ENGINE_get_load_privkey_function := nil;
  ENGINE_get_load_pubkey_function := nil;
  ENGINE_get_ciphers := nil;
  ENGINE_get_digests := nil;
  ENGINE_get_pkey_meths := nil;
  ENGINE_get_pkey_asn1_meths := nil;
  ENGINE_get_cipher := nil;
  ENGINE_get_digest := nil;
  ENGINE_get_pkey_meth := nil;
  ENGINE_get_pkey_asn1_meth := nil;
  ENGINE_get_pkey_asn1_meth_str := nil;
  ENGINE_pkey_asn1_find_str := nil;
  ENGINE_get_cmd_defns := nil;
  ENGINE_get_flags := nil;
  ENGINE_init := nil;
  ENGINE_finish := nil;
  ENGINE_load_private_key := nil;
  ENGINE_load_public_key := nil;
  ENGINE_get_default_RSA := nil;
  ENGINE_get_default_DSA := nil;
  ENGINE_get_default_EC := nil;
  ENGINE_get_default_DH := nil;
  ENGINE_get_default_RAND := nil;
  ENGINE_get_cipher_engine := nil;
  ENGINE_get_digest_engine := nil;
  ENGINE_get_pkey_meth_engine := nil;
  ENGINE_get_pkey_asn1_meth_engine := nil;
  ENGINE_set_default_RSA := nil;
  ENGINE_set_default_string := nil;
  ENGINE_set_default_DSA := nil;
  ENGINE_set_default_EC := nil;
  ENGINE_set_default_DH := nil;
  ENGINE_set_default_RAND := nil;
  ENGINE_set_default_ciphers := nil;
  ENGINE_set_default_digests := nil;
  ENGINE_set_default_pkey_meths := nil;
  ENGINE_set_default_pkey_asn1_meths := nil;
  ENGINE_set_default := nil;
  ENGINE_add_conf_module := nil;
  ENGINE_get_static_state := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
