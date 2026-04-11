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

unit TaurusTLSHeaders_lhash;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core,
  ossl_types;



// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  Plhash_node_st = ^Tlhash_node_st;
  Tlhash_node_st =   record end;
  {$EXTERNALSYM Plhash_node_st}

  Plhash_st = ^Tlhash_st;
  Tlhash_st =   record end;
  {$EXTERNALSYM Plhash_st}

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // DEFINE_LHASH_OF_INTERNAL(OPENSSL_STRING)

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // DEFINE_LHASH_OF_INTERNAL(OPENSSL_CSTRING)

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // DEFINE_LHASH_OF_INTERNAL(OPENSSL_CSTRING)


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOPENSSL_LH_COMPFUNC = function(arg1: Pointer; arg2: Pointer): TIdC_INT; cdecl;
  TOPENSSL_LH_COMPFUNCTHUNK = function(arg1: Pointer; arg2: Pointer; cfn: TOPENSSL_LH_COMPFUNC): TIdC_INT; cdecl;
  TOPENSSL_LH_HASHFUNC = function(arg1: Pointer): TIdC_ULONG; cdecl;
  TOPENSSL_LH_HASHFUNCTHUNK = function(arg1: Pointer; hfn: TOPENSSL_LH_HASHFUNC): TIdC_ULONG; cdecl;
  TOPENSSL_LH_DOALL_FUNC = procedure(arg1: Pointer); cdecl;
  TOPENSSL_LH_DOALL_FUNC_THUNK = procedure(arg1: Pointer; doall: TOPENSSL_LH_DOALL_FUNC); cdecl;
  TOPENSSL_LH_DOALL_FUNCARG = procedure(arg1: Pointer; arg2: Pointer); cdecl;
  TOPENSSL_LH_DOALL_FUNCARG_THUNK = procedure(arg1: Pointer; arg2: Pointer; doall: TOPENSSL_LH_DOALL_FUNCARG); cdecl;
  Tlh_OPENSSL_STRING_compfunc = function(a: POPENSSL_STRING; b: POPENSSL_STRING): TIdC_INT; cdecl;
  Tlh_OPENSSL_STRING_hashfunc = function(a: POPENSSL_STRING): TIdC_ULONG; cdecl;
  Tlh_OPENSSL_STRING_doallfunc = procedure(a: POPENSSL_STRING); cdecl;
  Tlh_OPENSSL_CSTRING_compfunc = function(a: POPENSSL_CSTRING; b: POPENSSL_CSTRING): TIdC_INT; cdecl;
  Tlh_OPENSSL_CSTRING_hashfunc = function(a: POPENSSL_CSTRING): TIdC_ULONG; cdecl;
  Tlh_OPENSSL_CSTRING_doallfunc = procedure(a: POPENSSL_CSTRING); cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  LH_LOAD_MULT = 256;
  _LHASH = OPENSSL_LHASH;
  LHASH_NODE = OPENSSL_LH_NODE;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OPENSSL_LH_error: function(lh: POPENSSL_LHASH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_error}

  OPENSSL_LH_new: function(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_new}

  OPENSSL_LH_set_thunks: function(lh: POPENSSL_LHASH; hw: TOPENSSL_LH_HASHFUNCTHUNK; cw: TOPENSSL_LH_COMPFUNCTHUNK; daw: TOPENSSL_LH_DOALL_FUNC_THUNK; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK): POPENSSL_LHASH; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_set_thunks}

  OPENSSL_LH_free: procedure(lh: POPENSSL_LHASH); cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_free}

  OPENSSL_LH_flush: procedure(lh: POPENSSL_LHASH); cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_flush}

  OPENSSL_LH_insert: function(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_insert}

  OPENSSL_LH_delete: function(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_delete}

  OPENSSL_LH_retrieve: function(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_retrieve}

  OPENSSL_LH_doall: procedure(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_doall}

  OPENSSL_LH_doall_arg: procedure(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_doall_arg}

  OPENSSL_LH_doall_arg_thunk: procedure(lh: POPENSSL_LHASH; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK; fn: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_doall_arg_thunk}

  OPENSSL_LH_strhash: function(c: PIdAnsiChar): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_strhash}

  OPENSSL_LH_num_items: function(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_num_items}

  OPENSSL_LH_get_down_load: function(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_get_down_load}

  OPENSSL_LH_set_down_load: procedure(lh: POPENSSL_LHASH; down_load: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM OPENSSL_LH_set_down_load}

  OPENSSL_LH_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = nil; // Deprecated in 3_1_0
  {$EXTERNALSYM OPENSSL_LH_stats}

  OPENSSL_LH_node_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = nil; // Deprecated in 3_1_0
  {$EXTERNALSYM OPENSSL_LH_node_stats}

  OPENSSL_LH_node_usage_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = nil; // Deprecated in 3_1_0
  {$EXTERNALSYM OPENSSL_LH_node_usage_stats}

  OPENSSL_LH_stats_bio: procedure(lh: POPENSSL_LHASH; _out: PBIO); cdecl = nil; // Deprecated in 3_1_0
  {$EXTERNALSYM OPENSSL_LH_stats_bio}

  OPENSSL_LH_node_stats_bio: procedure(lh: POPENSSL_LHASH; _out: PBIO); cdecl = nil; // Deprecated in 3_1_0
  {$EXTERNALSYM OPENSSL_LH_node_stats_bio}

  OPENSSL_LH_node_usage_stats_bio: procedure(lh: POPENSSL_LHASH; _out: PBIO); cdecl = nil; // Deprecated in 3_1_0
  {$EXTERNALSYM OPENSSL_LH_node_usage_stats_bio}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OPENSSL_LH_error(lh: POPENSSL_LHASH): TIdC_INT; cdecl;
function OPENSSL_LH_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl;
function OPENSSL_LH_set_thunks(lh: POPENSSL_LHASH; hw: TOPENSSL_LH_HASHFUNCTHUNK; cw: TOPENSSL_LH_COMPFUNCTHUNK; daw: TOPENSSL_LH_DOALL_FUNC_THUNK; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK): POPENSSL_LHASH; cdecl;
procedure OPENSSL_LH_free(lh: POPENSSL_LHASH); cdecl;
procedure OPENSSL_LH_flush(lh: POPENSSL_LHASH); cdecl;
function OPENSSL_LH_insert(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl;
function OPENSSL_LH_delete(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl;
function OPENSSL_LH_retrieve(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl;
procedure OPENSSL_LH_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl;
procedure OPENSSL_LH_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl;
procedure OPENSSL_LH_doall_arg_thunk(lh: POPENSSL_LHASH; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK; fn: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl;
function OPENSSL_LH_strhash(c: PIdAnsiChar): TIdC_ULONG; cdecl;
function OPENSSL_LH_num_items(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl;
function OPENSSL_LH_get_down_load(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl;
procedure OPENSSL_LH_set_down_load(lh: POPENSSL_LHASH; down_load: TIdC_ULONG); cdecl;
procedure OPENSSL_LH_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; deprecated 'In OpenSSL 3_1_0';
procedure OPENSSL_LH_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; deprecated 'In OpenSSL 3_1_0';
procedure OPENSSL_LH_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; deprecated 'In OpenSSL 3_1_0';
procedure OPENSSL_LH_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl; deprecated 'In OpenSSL 3_1_0';
procedure OPENSSL_LH_node_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl; deprecated 'In OpenSSL 3_1_0';
procedure OPENSSL_LH_node_usage_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl; deprecated 'In OpenSSL 3_1_0';
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function lh_error(lh: POPENSSL_LHASH): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function lh_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_free(lh: POPENSSL_LHASH); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function lh_insert(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function lh_delete(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function lh_retrieve(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function lh_strhash(c: PIdAnsiChar): TIdC_ULONG; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function lh_num_items(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_node_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure lh_node_usage_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl;


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

function OPENSSL_LH_error(lh: POPENSSL_LHASH): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_LH_error';
function OPENSSL_LH_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl external CLibCrypto name 'OPENSSL_LH_new';
function OPENSSL_LH_set_thunks(lh: POPENSSL_LHASH; hw: TOPENSSL_LH_HASHFUNCTHUNK; cw: TOPENSSL_LH_COMPFUNCTHUNK; daw: TOPENSSL_LH_DOALL_FUNC_THUNK; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK): POPENSSL_LHASH; cdecl external CLibCrypto name 'OPENSSL_LH_set_thunks';
procedure OPENSSL_LH_free(lh: POPENSSL_LHASH); cdecl external CLibCrypto name 'OPENSSL_LH_free';
procedure OPENSSL_LH_flush(lh: POPENSSL_LHASH); cdecl external CLibCrypto name 'OPENSSL_LH_flush';
function OPENSSL_LH_insert(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl external CLibCrypto name 'OPENSSL_LH_insert';
function OPENSSL_LH_delete(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl external CLibCrypto name 'OPENSSL_LH_delete';
function OPENSSL_LH_retrieve(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl external CLibCrypto name 'OPENSSL_LH_retrieve';
procedure OPENSSL_LH_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl external CLibCrypto name 'OPENSSL_LH_doall';
procedure OPENSSL_LH_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl external CLibCrypto name 'OPENSSL_LH_doall_arg';
procedure OPENSSL_LH_doall_arg_thunk(lh: POPENSSL_LHASH; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK; fn: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl external CLibCrypto name 'OPENSSL_LH_doall_arg_thunk';
function OPENSSL_LH_strhash(c: PIdAnsiChar): TIdC_ULONG; cdecl external CLibCrypto name 'OPENSSL_LH_strhash';
function OPENSSL_LH_num_items(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl external CLibCrypto name 'OPENSSL_LH_num_items';
function OPENSSL_LH_get_down_load(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl external CLibCrypto name 'OPENSSL_LH_get_down_load';
procedure OPENSSL_LH_set_down_load(lh: POPENSSL_LHASH; down_load: TIdC_ULONG); cdecl external CLibCrypto name 'OPENSSL_LH_set_down_load';
procedure OPENSSL_LH_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl external CLibCrypto name 'OPENSSL_LH_stats';
procedure OPENSSL_LH_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl external CLibCrypto name 'OPENSSL_LH_node_stats';
procedure OPENSSL_LH_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl external CLibCrypto name 'OPENSSL_LH_node_usage_stats';
procedure OPENSSL_LH_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl external CLibCrypto name 'OPENSSL_LH_stats_bio';
procedure OPENSSL_LH_node_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl external CLibCrypto name 'OPENSSL_LH_node_stats_bio';
procedure OPENSSL_LH_node_usage_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl external CLibCrypto name 'OPENSSL_LH_node_usage_stats_bio';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OPENSSL_LH_error_procname = 'OPENSSL_LH_error';
  OPENSSL_LH_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_new_procname = 'OPENSSL_LH_new';
  OPENSSL_LH_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_set_thunks_procname = 'OPENSSL_LH_set_thunks';
  OPENSSL_LH_set_thunks_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OPENSSL_LH_free_procname = 'OPENSSL_LH_free';
  OPENSSL_LH_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_flush_procname = 'OPENSSL_LH_flush';
  OPENSSL_LH_flush_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_LH_insert_procname = 'OPENSSL_LH_insert';
  OPENSSL_LH_insert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_delete_procname = 'OPENSSL_LH_delete';
  OPENSSL_LH_delete_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_retrieve_procname = 'OPENSSL_LH_retrieve';
  OPENSSL_LH_retrieve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_doall_procname = 'OPENSSL_LH_doall';
  OPENSSL_LH_doall_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_doall_arg_procname = 'OPENSSL_LH_doall_arg';
  OPENSSL_LH_doall_arg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_doall_arg_thunk_procname = 'OPENSSL_LH_doall_arg_thunk';
  OPENSSL_LH_doall_arg_thunk_introduced = (byte(3) shl 8 or byte(3)) shl 8 or byte(0);

  OPENSSL_LH_strhash_procname = 'OPENSSL_LH_strhash';
  OPENSSL_LH_strhash_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_num_items_procname = 'OPENSSL_LH_num_items';
  OPENSSL_LH_num_items_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_get_down_load_procname = 'OPENSSL_LH_get_down_load';
  OPENSSL_LH_get_down_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_set_down_load_procname = 'OPENSSL_LH_set_down_load';
  OPENSSL_LH_set_down_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_stats_procname = 'OPENSSL_LH_stats';
  OPENSSL_LH_stats_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_LH_stats_removed = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_node_stats_procname = 'OPENSSL_LH_node_stats';
  OPENSSL_LH_node_stats_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_LH_node_stats_removed = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_node_usage_stats_procname = 'OPENSSL_LH_node_usage_stats';
  OPENSSL_LH_node_usage_stats_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_LH_node_usage_stats_removed = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_stats_bio_procname = 'OPENSSL_LH_stats_bio';
  OPENSSL_LH_stats_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_LH_stats_bio_removed = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_node_stats_bio_procname = 'OPENSSL_LH_node_stats_bio';
  OPENSSL_LH_node_stats_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_LH_node_stats_bio_removed = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_LH_node_usage_stats_bio_procname = 'OPENSSL_LH_node_usage_stats_bio';
  OPENSSL_LH_node_usage_stats_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_LH_node_usage_stats_bio_removed = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function lh_error(lh: POPENSSL_LHASH): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_error OPENSSL_LH_error
  }
end;

function lh_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_new OPENSSL_LH_new
  }
end;

procedure lh_free(lh: POPENSSL_LHASH); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_free OPENSSL_LH_free
  }
end;

function lh_insert(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_insert OPENSSL_LH_insert
  }
end;

function lh_delete(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_delete OPENSSL_LH_delete
  }
end;

function lh_retrieve(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_retrieve OPENSSL_LH_retrieve
  }
end;

procedure lh_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_doall OPENSSL_LH_doall
  }
end;

procedure lh_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_doall_arg OPENSSL_LH_doall_arg
  }
end;

function lh_strhash(c: PIdAnsiChar): TIdC_ULONG; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_strhash OPENSSL_LH_strhash
  }
end;

function lh_num_items(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_num_items OPENSSL_LH_num_items
  }
end;

procedure lh_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_stats OPENSSL_LH_stats
  }
end;

procedure lh_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_node_stats OPENSSL_LH_node_stats
  }
end;

procedure lh_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_node_usage_stats OPENSSL_LH_node_usage_stats
  }
end;

procedure lh_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_stats_bio OPENSSL_LH_stats_bio
  }
end;

procedure lh_node_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_node_stats_bio OPENSSL_LH_node_stats_bio
  }
end;

procedure lh_node_usage_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    lh_node_usage_stats_bio OPENSSL_LH_node_usage_stats_bio
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OPENSSL_LH_error(lh: POPENSSL_LHASH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_error_procname);
end;

function ERR_OPENSSL_LH_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_new_procname);
end;

function ERR_OPENSSL_LH_set_thunks(lh: POPENSSL_LHASH; hw: TOPENSSL_LH_HASHFUNCTHUNK; cw: TOPENSSL_LH_COMPFUNCTHUNK; daw: TOPENSSL_LH_DOALL_FUNC_THUNK; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK): POPENSSL_LHASH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_set_thunks_procname);
end;

procedure ERR_OPENSSL_LH_free(lh: POPENSSL_LHASH); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_free_procname);
end;

procedure ERR_OPENSSL_LH_flush(lh: POPENSSL_LHASH); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_flush_procname);
end;

function ERR_OPENSSL_LH_insert(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_insert_procname);
end;

function ERR_OPENSSL_LH_delete(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_delete_procname);
end;

function ERR_OPENSSL_LH_retrieve(lh: POPENSSL_LHASH; data: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_retrieve_procname);
end;

procedure ERR_OPENSSL_LH_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_doall_procname);
end;

procedure ERR_OPENSSL_LH_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_doall_arg_procname);
end;

procedure ERR_OPENSSL_LH_doall_arg_thunk(lh: POPENSSL_LHASH; daaw: TOPENSSL_LH_DOALL_FUNCARG_THUNK; fn: TOPENSSL_LH_DOALL_FUNCARG; arg: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_doall_arg_thunk_procname);
end;

function ERR_OPENSSL_LH_strhash(c: PIdAnsiChar): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_strhash_procname);
end;

function ERR_OPENSSL_LH_num_items(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_num_items_procname);
end;

function ERR_OPENSSL_LH_get_down_load(lh: POPENSSL_LHASH): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_get_down_load_procname);
end;

procedure ERR_OPENSSL_LH_set_down_load(lh: POPENSSL_LHASH; down_load: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_set_down_load_procname);
end;

procedure ERR_OPENSSL_LH_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_stats_procname);
end;

procedure ERR_OPENSSL_LH_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_node_stats_procname);
end;

procedure ERR_OPENSSL_LH_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_node_usage_stats_procname);
end;

procedure ERR_OPENSSL_LH_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_stats_bio_procname);
end;

procedure ERR_OPENSSL_LH_node_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_node_stats_bio_procname);
end;

procedure ERR_OPENSSL_LH_node_usage_stats_bio(lh: POPENSSL_LHASH; _out: PBIO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_LH_node_usage_stats_bio_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OPENSSL_LH_error := LoadLibFunction(ADllHandle, OPENSSL_LH_error_procname);
  FuncLoadError := not assigned(OPENSSL_LH_error);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_error_allownil)}
    OPENSSL_LH_error := ERR_OPENSSL_LH_error;
    {$ifend}
    {$if declared(OPENSSL_LH_error_introduced)}
    if LibVersion < OPENSSL_LH_error_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_error)}
      OPENSSL_LH_error := FC_OPENSSL_LH_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_error_removed)}
    if OPENSSL_LH_error_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_error)}
      OPENSSL_LH_error := _OPENSSL_LH_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_error_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_error');
    {$ifend}
  end;
  
  OPENSSL_LH_new := LoadLibFunction(ADllHandle, OPENSSL_LH_new_procname);
  FuncLoadError := not assigned(OPENSSL_LH_new);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_new_allownil)}
    OPENSSL_LH_new := ERR_OPENSSL_LH_new;
    {$ifend}
    {$if declared(OPENSSL_LH_new_introduced)}
    if LibVersion < OPENSSL_LH_new_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_new)}
      OPENSSL_LH_new := FC_OPENSSL_LH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_new_removed)}
    if OPENSSL_LH_new_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_new)}
      OPENSSL_LH_new := _OPENSSL_LH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_new');
    {$ifend}
  end;
  
  OPENSSL_LH_set_thunks := LoadLibFunction(ADllHandle, OPENSSL_LH_set_thunks_procname);
  FuncLoadError := not assigned(OPENSSL_LH_set_thunks);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_set_thunks_allownil)}
    OPENSSL_LH_set_thunks := ERR_OPENSSL_LH_set_thunks;
    {$ifend}
    {$if declared(OPENSSL_LH_set_thunks_introduced)}
    if LibVersion < OPENSSL_LH_set_thunks_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_set_thunks)}
      OPENSSL_LH_set_thunks := FC_OPENSSL_LH_set_thunks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_set_thunks_removed)}
    if OPENSSL_LH_set_thunks_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_set_thunks)}
      OPENSSL_LH_set_thunks := _OPENSSL_LH_set_thunks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_set_thunks_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_set_thunks');
    {$ifend}
  end;
  
  OPENSSL_LH_free := LoadLibFunction(ADllHandle, OPENSSL_LH_free_procname);
  FuncLoadError := not assigned(OPENSSL_LH_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_free_allownil)}
    OPENSSL_LH_free := ERR_OPENSSL_LH_free;
    {$ifend}
    {$if declared(OPENSSL_LH_free_introduced)}
    if LibVersion < OPENSSL_LH_free_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_free)}
      OPENSSL_LH_free := FC_OPENSSL_LH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_free_removed)}
    if OPENSSL_LH_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_free)}
      OPENSSL_LH_free := _OPENSSL_LH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_free');
    {$ifend}
  end;
  
  OPENSSL_LH_flush := LoadLibFunction(ADllHandle, OPENSSL_LH_flush_procname);
  FuncLoadError := not assigned(OPENSSL_LH_flush);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_flush_allownil)}
    OPENSSL_LH_flush := ERR_OPENSSL_LH_flush;
    {$ifend}
    {$if declared(OPENSSL_LH_flush_introduced)}
    if LibVersion < OPENSSL_LH_flush_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_flush)}
      OPENSSL_LH_flush := FC_OPENSSL_LH_flush;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_flush_removed)}
    if OPENSSL_LH_flush_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_flush)}
      OPENSSL_LH_flush := _OPENSSL_LH_flush;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_flush_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_flush');
    {$ifend}
  end;
  
  OPENSSL_LH_insert := LoadLibFunction(ADllHandle, OPENSSL_LH_insert_procname);
  FuncLoadError := not assigned(OPENSSL_LH_insert);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_insert_allownil)}
    OPENSSL_LH_insert := ERR_OPENSSL_LH_insert;
    {$ifend}
    {$if declared(OPENSSL_LH_insert_introduced)}
    if LibVersion < OPENSSL_LH_insert_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_insert)}
      OPENSSL_LH_insert := FC_OPENSSL_LH_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_insert_removed)}
    if OPENSSL_LH_insert_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_insert)}
      OPENSSL_LH_insert := _OPENSSL_LH_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_insert_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_insert');
    {$ifend}
  end;
  
  OPENSSL_LH_delete := LoadLibFunction(ADllHandle, OPENSSL_LH_delete_procname);
  FuncLoadError := not assigned(OPENSSL_LH_delete);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_delete_allownil)}
    OPENSSL_LH_delete := ERR_OPENSSL_LH_delete;
    {$ifend}
    {$if declared(OPENSSL_LH_delete_introduced)}
    if LibVersion < OPENSSL_LH_delete_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_delete)}
      OPENSSL_LH_delete := FC_OPENSSL_LH_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_delete_removed)}
    if OPENSSL_LH_delete_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_delete)}
      OPENSSL_LH_delete := _OPENSSL_LH_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_delete_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_delete');
    {$ifend}
  end;
  
  OPENSSL_LH_retrieve := LoadLibFunction(ADllHandle, OPENSSL_LH_retrieve_procname);
  FuncLoadError := not assigned(OPENSSL_LH_retrieve);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_retrieve_allownil)}
    OPENSSL_LH_retrieve := ERR_OPENSSL_LH_retrieve;
    {$ifend}
    {$if declared(OPENSSL_LH_retrieve_introduced)}
    if LibVersion < OPENSSL_LH_retrieve_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_retrieve)}
      OPENSSL_LH_retrieve := FC_OPENSSL_LH_retrieve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_retrieve_removed)}
    if OPENSSL_LH_retrieve_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_retrieve)}
      OPENSSL_LH_retrieve := _OPENSSL_LH_retrieve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_retrieve_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_retrieve');
    {$ifend}
  end;
  
  OPENSSL_LH_doall := LoadLibFunction(ADllHandle, OPENSSL_LH_doall_procname);
  FuncLoadError := not assigned(OPENSSL_LH_doall);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_doall_allownil)}
    OPENSSL_LH_doall := ERR_OPENSSL_LH_doall;
    {$ifend}
    {$if declared(OPENSSL_LH_doall_introduced)}
    if LibVersion < OPENSSL_LH_doall_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_doall)}
      OPENSSL_LH_doall := FC_OPENSSL_LH_doall;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_doall_removed)}
    if OPENSSL_LH_doall_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_doall)}
      OPENSSL_LH_doall := _OPENSSL_LH_doall;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_doall_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_doall');
    {$ifend}
  end;
  
  OPENSSL_LH_doall_arg := LoadLibFunction(ADllHandle, OPENSSL_LH_doall_arg_procname);
  FuncLoadError := not assigned(OPENSSL_LH_doall_arg);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_doall_arg_allownil)}
    OPENSSL_LH_doall_arg := ERR_OPENSSL_LH_doall_arg;
    {$ifend}
    {$if declared(OPENSSL_LH_doall_arg_introduced)}
    if LibVersion < OPENSSL_LH_doall_arg_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_doall_arg)}
      OPENSSL_LH_doall_arg := FC_OPENSSL_LH_doall_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_doall_arg_removed)}
    if OPENSSL_LH_doall_arg_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_doall_arg)}
      OPENSSL_LH_doall_arg := _OPENSSL_LH_doall_arg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_doall_arg_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_doall_arg');
    {$ifend}
  end;
  
  OPENSSL_LH_doall_arg_thunk := LoadLibFunction(ADllHandle, OPENSSL_LH_doall_arg_thunk_procname);
  FuncLoadError := not assigned(OPENSSL_LH_doall_arg_thunk);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_doall_arg_thunk_allownil)}
    OPENSSL_LH_doall_arg_thunk := ERR_OPENSSL_LH_doall_arg_thunk;
    {$ifend}
    {$if declared(OPENSSL_LH_doall_arg_thunk_introduced)}
    if LibVersion < OPENSSL_LH_doall_arg_thunk_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_doall_arg_thunk)}
      OPENSSL_LH_doall_arg_thunk := FC_OPENSSL_LH_doall_arg_thunk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_doall_arg_thunk_removed)}
    if OPENSSL_LH_doall_arg_thunk_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_doall_arg_thunk)}
      OPENSSL_LH_doall_arg_thunk := _OPENSSL_LH_doall_arg_thunk;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_doall_arg_thunk_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_doall_arg_thunk');
    {$ifend}
  end;
  
  OPENSSL_LH_strhash := LoadLibFunction(ADllHandle, OPENSSL_LH_strhash_procname);
  FuncLoadError := not assigned(OPENSSL_LH_strhash);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_strhash_allownil)}
    OPENSSL_LH_strhash := ERR_OPENSSL_LH_strhash;
    {$ifend}
    {$if declared(OPENSSL_LH_strhash_introduced)}
    if LibVersion < OPENSSL_LH_strhash_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_strhash)}
      OPENSSL_LH_strhash := FC_OPENSSL_LH_strhash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_strhash_removed)}
    if OPENSSL_LH_strhash_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_strhash)}
      OPENSSL_LH_strhash := _OPENSSL_LH_strhash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_strhash_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_strhash');
    {$ifend}
  end;
  
  OPENSSL_LH_num_items := LoadLibFunction(ADllHandle, OPENSSL_LH_num_items_procname);
  FuncLoadError := not assigned(OPENSSL_LH_num_items);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_num_items_allownil)}
    OPENSSL_LH_num_items := ERR_OPENSSL_LH_num_items;
    {$ifend}
    {$if declared(OPENSSL_LH_num_items_introduced)}
    if LibVersion < OPENSSL_LH_num_items_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_num_items)}
      OPENSSL_LH_num_items := FC_OPENSSL_LH_num_items;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_num_items_removed)}
    if OPENSSL_LH_num_items_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_num_items)}
      OPENSSL_LH_num_items := _OPENSSL_LH_num_items;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_num_items_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_num_items');
    {$ifend}
  end;
  
  OPENSSL_LH_get_down_load := LoadLibFunction(ADllHandle, OPENSSL_LH_get_down_load_procname);
  FuncLoadError := not assigned(OPENSSL_LH_get_down_load);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_get_down_load_allownil)}
    OPENSSL_LH_get_down_load := ERR_OPENSSL_LH_get_down_load;
    {$ifend}
    {$if declared(OPENSSL_LH_get_down_load_introduced)}
    if LibVersion < OPENSSL_LH_get_down_load_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_get_down_load)}
      OPENSSL_LH_get_down_load := FC_OPENSSL_LH_get_down_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_get_down_load_removed)}
    if OPENSSL_LH_get_down_load_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_get_down_load)}
      OPENSSL_LH_get_down_load := _OPENSSL_LH_get_down_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_get_down_load_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_get_down_load');
    {$ifend}
  end;
  
  OPENSSL_LH_set_down_load := LoadLibFunction(ADllHandle, OPENSSL_LH_set_down_load_procname);
  FuncLoadError := not assigned(OPENSSL_LH_set_down_load);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_set_down_load_allownil)}
    OPENSSL_LH_set_down_load := ERR_OPENSSL_LH_set_down_load;
    {$ifend}
    {$if declared(OPENSSL_LH_set_down_load_introduced)}
    if LibVersion < OPENSSL_LH_set_down_load_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_set_down_load)}
      OPENSSL_LH_set_down_load := FC_OPENSSL_LH_set_down_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_set_down_load_removed)}
    if OPENSSL_LH_set_down_load_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_set_down_load)}
      OPENSSL_LH_set_down_load := _OPENSSL_LH_set_down_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_set_down_load_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_set_down_load');
    {$ifend}
  end;
  
  OPENSSL_LH_stats := LoadLibFunction(ADllHandle, OPENSSL_LH_stats_procname);
  FuncLoadError := not assigned(OPENSSL_LH_stats);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_stats_allownil)}
    OPENSSL_LH_stats := ERR_OPENSSL_LH_stats;
    {$ifend}
    {$if declared(OPENSSL_LH_stats_introduced)}
    if LibVersion < OPENSSL_LH_stats_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_stats)}
      OPENSSL_LH_stats := FC_OPENSSL_LH_stats;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_stats_removed)}
    if OPENSSL_LH_stats_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_stats)}
      OPENSSL_LH_stats := _OPENSSL_LH_stats;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_stats_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_stats');
    {$ifend}
  end;
  
  OPENSSL_LH_node_stats := LoadLibFunction(ADllHandle, OPENSSL_LH_node_stats_procname);
  FuncLoadError := not assigned(OPENSSL_LH_node_stats);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_node_stats_allownil)}
    OPENSSL_LH_node_stats := ERR_OPENSSL_LH_node_stats;
    {$ifend}
    {$if declared(OPENSSL_LH_node_stats_introduced)}
    if LibVersion < OPENSSL_LH_node_stats_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_node_stats)}
      OPENSSL_LH_node_stats := FC_OPENSSL_LH_node_stats;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_node_stats_removed)}
    if OPENSSL_LH_node_stats_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_node_stats)}
      OPENSSL_LH_node_stats := _OPENSSL_LH_node_stats;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_node_stats_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_node_stats');
    {$ifend}
  end;
  
  OPENSSL_LH_node_usage_stats := LoadLibFunction(ADllHandle, OPENSSL_LH_node_usage_stats_procname);
  FuncLoadError := not assigned(OPENSSL_LH_node_usage_stats);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_node_usage_stats_allownil)}
    OPENSSL_LH_node_usage_stats := ERR_OPENSSL_LH_node_usage_stats;
    {$ifend}
    {$if declared(OPENSSL_LH_node_usage_stats_introduced)}
    if LibVersion < OPENSSL_LH_node_usage_stats_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_node_usage_stats)}
      OPENSSL_LH_node_usage_stats := FC_OPENSSL_LH_node_usage_stats;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_node_usage_stats_removed)}
    if OPENSSL_LH_node_usage_stats_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_node_usage_stats)}
      OPENSSL_LH_node_usage_stats := _OPENSSL_LH_node_usage_stats;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_node_usage_stats_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_node_usage_stats');
    {$ifend}
  end;
  
  OPENSSL_LH_stats_bio := LoadLibFunction(ADllHandle, OPENSSL_LH_stats_bio_procname);
  FuncLoadError := not assigned(OPENSSL_LH_stats_bio);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_stats_bio_allownil)}
    OPENSSL_LH_stats_bio := ERR_OPENSSL_LH_stats_bio;
    {$ifend}
    {$if declared(OPENSSL_LH_stats_bio_introduced)}
    if LibVersion < OPENSSL_LH_stats_bio_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_stats_bio)}
      OPENSSL_LH_stats_bio := FC_OPENSSL_LH_stats_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_stats_bio_removed)}
    if OPENSSL_LH_stats_bio_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_stats_bio)}
      OPENSSL_LH_stats_bio := _OPENSSL_LH_stats_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_stats_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_stats_bio');
    {$ifend}
  end;
  
  OPENSSL_LH_node_stats_bio := LoadLibFunction(ADllHandle, OPENSSL_LH_node_stats_bio_procname);
  FuncLoadError := not assigned(OPENSSL_LH_node_stats_bio);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_node_stats_bio_allownil)}
    OPENSSL_LH_node_stats_bio := ERR_OPENSSL_LH_node_stats_bio;
    {$ifend}
    {$if declared(OPENSSL_LH_node_stats_bio_introduced)}
    if LibVersion < OPENSSL_LH_node_stats_bio_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_node_stats_bio)}
      OPENSSL_LH_node_stats_bio := FC_OPENSSL_LH_node_stats_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_node_stats_bio_removed)}
    if OPENSSL_LH_node_stats_bio_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_node_stats_bio)}
      OPENSSL_LH_node_stats_bio := _OPENSSL_LH_node_stats_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_node_stats_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_node_stats_bio');
    {$ifend}
  end;
  
  OPENSSL_LH_node_usage_stats_bio := LoadLibFunction(ADllHandle, OPENSSL_LH_node_usage_stats_bio_procname);
  FuncLoadError := not assigned(OPENSSL_LH_node_usage_stats_bio);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_LH_node_usage_stats_bio_allownil)}
    OPENSSL_LH_node_usage_stats_bio := ERR_OPENSSL_LH_node_usage_stats_bio;
    {$ifend}
    {$if declared(OPENSSL_LH_node_usage_stats_bio_introduced)}
    if LibVersion < OPENSSL_LH_node_usage_stats_bio_introduced then
    begin
      {$if declared(FC_OPENSSL_LH_node_usage_stats_bio)}
      OPENSSL_LH_node_usage_stats_bio := FC_OPENSSL_LH_node_usage_stats_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_LH_node_usage_stats_bio_removed)}
    if OPENSSL_LH_node_usage_stats_bio_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_LH_node_usage_stats_bio)}
      OPENSSL_LH_node_usage_stats_bio := _OPENSSL_LH_node_usage_stats_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_LH_node_usage_stats_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_LH_node_usage_stats_bio');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OPENSSL_LH_error := nil;
  OPENSSL_LH_new := nil;
  OPENSSL_LH_set_thunks := nil;
  OPENSSL_LH_free := nil;
  OPENSSL_LH_flush := nil;
  OPENSSL_LH_insert := nil;
  OPENSSL_LH_delete := nil;
  OPENSSL_LH_retrieve := nil;
  OPENSSL_LH_doall := nil;
  OPENSSL_LH_doall_arg := nil;
  OPENSSL_LH_doall_arg_thunk := nil;
  OPENSSL_LH_strhash := nil;
  OPENSSL_LH_num_items := nil;
  OPENSSL_LH_get_down_load := nil;
  OPENSSL_LH_set_down_load := nil;
  OPENSSL_LH_stats := nil;
  OPENSSL_LH_node_stats := nil;
  OPENSSL_LH_node_usage_stats := nil;
  OPENSSL_LH_stats_bio := nil;
  OPENSSL_LH_node_stats_bio := nil;
  OPENSSL_LH_node_usage_stats_bio := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.