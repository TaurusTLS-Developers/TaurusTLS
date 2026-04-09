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

unit TaurusTLSHeaders_rand;

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
  Prand_meth_st = ^Trand_meth_st;
  Trand_meth_st = record end;
  {$EXTERNALSYM Prand_meth_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  RAND_DRBG_STRENGTH = 256;
  OSSL_PROV_RANDOM_PUBLIC = 0;
  OSSL_PROV_RANDOM_PRIVATE = 1;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  RAND_set_rand_method: function(meth: PRAND_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RAND_set_rand_method}

  RAND_get_rand_method: function: PRAND_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RAND_get_rand_method}

  RAND_set_rand_engine: function(engine: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RAND_set_rand_engine}

  RAND_OpenSSL: function: PRAND_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RAND_OpenSSL}

  RAND_bytes: function(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_bytes}

  RAND_priv_bytes: function(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_priv_bytes}

  RAND_priv_bytes_ex: function(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_priv_bytes_ex}

  RAND_bytes_ex: function(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_bytes_ex}

  RAND_get0_primary: function(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl = nil;
  {$EXTERNALSYM RAND_get0_primary}

  RAND_get0_public: function(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl = nil;
  {$EXTERNALSYM RAND_get0_public}

  RAND_get0_private: function(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl = nil;
  {$EXTERNALSYM RAND_get0_private}

  RAND_set0_public: function(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_set0_public}

  RAND_set0_private: function(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_set0_private}

  RAND_set_DRBG_type: function(ctx: POSSL_LIB_CTX; drbg: PIdAnsiChar; propq: PIdAnsiChar; cipher: PIdAnsiChar; digest: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_set_DRBG_type}

  RAND_set_seed_source_type: function(ctx: POSSL_LIB_CTX; seed: PIdAnsiChar; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_set_seed_source_type}

  RAND_seed: procedure(buf: Pointer; num: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM RAND_seed}

  RAND_keep_random_devices_open: procedure(keep: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM RAND_keep_random_devices_open}

  RAND_add: procedure(buf: Pointer; num: TIdC_INT; randomness: Double); cdecl = nil;
  {$EXTERNALSYM RAND_add}

  RAND_load_file: function(_file: PIdAnsiChar; max_bytes: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_load_file}

  RAND_write_file: function(_file: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_write_file}

  RAND_file_name: function(_file: PIdAnsiChar; num: TIdC_SIZET): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM RAND_file_name}

  RAND_status: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_status}

  RAND_poll: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_poll}

  RAND_set1_random_provider: function(ctx: POSSL_LIB_CTX; p: POSSL_PROVIDER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RAND_set1_random_provider}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function RAND_set_rand_method(meth: PRAND_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RAND_get_rand_method: PRAND_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function RAND_set_rand_engine(engine: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RAND_OpenSSL: PRAND_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function RAND_bytes(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl;
function RAND_priv_bytes(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl;
function RAND_priv_bytes_ex(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl;
function RAND_bytes_ex(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl;
function RAND_get0_primary(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
function RAND_get0_public(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
function RAND_get0_private(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
function RAND_set0_public(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl;
function RAND_set0_private(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl;
function RAND_set_DRBG_type(ctx: POSSL_LIB_CTX; drbg: PIdAnsiChar; propq: PIdAnsiChar; cipher: PIdAnsiChar; digest: PIdAnsiChar): TIdC_INT; cdecl;
function RAND_set_seed_source_type(ctx: POSSL_LIB_CTX; seed: PIdAnsiChar; propq: PIdAnsiChar): TIdC_INT; cdecl;
procedure RAND_seed(buf: Pointer; num: TIdC_INT); cdecl;
procedure RAND_keep_random_devices_open(keep: TIdC_INT); cdecl;
procedure RAND_add(buf: Pointer; num: TIdC_INT; randomness: Double); cdecl;
function RAND_load_file(_file: PIdAnsiChar; max_bytes: TIdC_LONG): TIdC_INT; cdecl;
function RAND_write_file(_file: PIdAnsiChar): TIdC_INT; cdecl;
function RAND_file_name(_file: PIdAnsiChar; num: TIdC_SIZET): PIdAnsiChar; cdecl;
function RAND_status: TIdC_INT; cdecl;
function RAND_poll: TIdC_INT; cdecl;
function RAND_set1_random_provider(ctx: POSSL_LIB_CTX; p: POSSL_PROVIDER): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function RAND_cleanup: TIdC_INT; cdecl; deprecated 'In OpenSSL 1_1_0';
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

function RAND_set_rand_method(meth: PRAND_METHOD): TIdC_INT; cdecl external CLibCrypto name 'RAND_set_rand_method';
function RAND_get_rand_method: PRAND_METHOD; cdecl external CLibCrypto name 'RAND_get_rand_method';
function RAND_set_rand_engine(engine: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'RAND_set_rand_engine';
function RAND_OpenSSL: PRAND_METHOD; cdecl external CLibCrypto name 'RAND_OpenSSL';
function RAND_bytes(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RAND_bytes';
function RAND_priv_bytes(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RAND_priv_bytes';
function RAND_priv_bytes_ex(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'RAND_priv_bytes_ex';
function RAND_bytes_ex(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'RAND_bytes_ex';
function RAND_get0_primary(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl external CLibCrypto name 'RAND_get0_primary';
function RAND_get0_public(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl external CLibCrypto name 'RAND_get0_public';
function RAND_get0_private(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl external CLibCrypto name 'RAND_get0_private';
function RAND_set0_public(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl external CLibCrypto name 'RAND_set0_public';
function RAND_set0_private(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl external CLibCrypto name 'RAND_set0_private';
function RAND_set_DRBG_type(ctx: POSSL_LIB_CTX; drbg: PIdAnsiChar; propq: PIdAnsiChar; cipher: PIdAnsiChar; digest: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'RAND_set_DRBG_type';
function RAND_set_seed_source_type(ctx: POSSL_LIB_CTX; seed: PIdAnsiChar; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'RAND_set_seed_source_type';
procedure RAND_seed(buf: Pointer; num: TIdC_INT); cdecl external CLibCrypto name 'RAND_seed';
procedure RAND_keep_random_devices_open(keep: TIdC_INT); cdecl external CLibCrypto name 'RAND_keep_random_devices_open';
procedure RAND_add(buf: Pointer; num: TIdC_INT; randomness: Double); cdecl external CLibCrypto name 'RAND_add';
function RAND_load_file(_file: PIdAnsiChar; max_bytes: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'RAND_load_file';
function RAND_write_file(_file: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'RAND_write_file';
function RAND_file_name(_file: PIdAnsiChar; num: TIdC_SIZET): PIdAnsiChar; cdecl external CLibCrypto name 'RAND_file_name';
function RAND_status: TIdC_INT; cdecl external CLibCrypto name 'RAND_status';
function RAND_poll: TIdC_INT; cdecl external CLibCrypto name 'RAND_poll';
function RAND_set1_random_provider(ctx: POSSL_LIB_CTX; p: POSSL_PROVIDER): TIdC_INT; cdecl external CLibCrypto name 'RAND_set1_random_provider';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  RAND_set_rand_method_procname = 'RAND_set_rand_method';
  RAND_set_rand_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RAND_set_rand_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_get_rand_method_procname = 'RAND_get_rand_method';
  RAND_get_rand_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RAND_get_rand_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_set_rand_engine_procname = 'RAND_set_rand_engine';
  RAND_set_rand_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RAND_set_rand_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_OpenSSL_procname = 'RAND_OpenSSL';
  RAND_OpenSSL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RAND_OpenSSL_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_bytes_procname = 'RAND_bytes';
  RAND_bytes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_priv_bytes_procname = 'RAND_priv_bytes';
  RAND_priv_bytes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  RAND_priv_bytes_ex_procname = 'RAND_priv_bytes_ex';
  RAND_priv_bytes_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_bytes_ex_procname = 'RAND_bytes_ex';
  RAND_bytes_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_get0_primary_procname = 'RAND_get0_primary';
  RAND_get0_primary_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_get0_public_procname = 'RAND_get0_public';
  RAND_get0_public_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_get0_private_procname = 'RAND_get0_private';
  RAND_get0_private_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_set0_public_procname = 'RAND_set0_public';
  RAND_set0_public_introduced = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_set0_private_procname = 'RAND_set0_private';
  RAND_set0_private_introduced = (byte(3) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_set_DRBG_type_procname = 'RAND_set_DRBG_type';
  RAND_set_DRBG_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_set_seed_source_type_procname = 'RAND_set_seed_source_type';
  RAND_set_seed_source_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RAND_seed_procname = 'RAND_seed';
  RAND_seed_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_keep_random_devices_open_procname = 'RAND_keep_random_devices_open';
  RAND_keep_random_devices_open_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  RAND_add_procname = 'RAND_add';
  RAND_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_load_file_procname = 'RAND_load_file';
  RAND_load_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_write_file_procname = 'RAND_write_file';
  RAND_write_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_file_name_procname = 'RAND_file_name';
  RAND_file_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_status_procname = 'RAND_status';
  RAND_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_poll_procname = 'RAND_poll';
  RAND_poll_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RAND_set1_random_provider_procname = 'RAND_set1_random_provider';
  RAND_set1_random_provider_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function RAND_cleanup: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    RAND_cleanup() \
    while (0)          \
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

function ERR_RAND_set_rand_method(meth: PRAND_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set_rand_method_procname);
end;

function ERR_RAND_get_rand_method: PRAND_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_get_rand_method_procname);
end;

function ERR_RAND_set_rand_engine(engine: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set_rand_engine_procname);
end;

function ERR_RAND_OpenSSL: PRAND_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_OpenSSL_procname);
end;

function ERR_RAND_bytes(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_bytes_procname);
end;

function ERR_RAND_priv_bytes(buf: PIdAnsiChar; num: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_priv_bytes_procname);
end;

function ERR_RAND_priv_bytes_ex(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_priv_bytes_ex_procname);
end;

function ERR_RAND_bytes_ex(ctx: POSSL_LIB_CTX; buf: PIdAnsiChar; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_bytes_ex_procname);
end;

function ERR_RAND_get0_primary(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_get0_primary_procname);
end;

function ERR_RAND_get0_public(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_get0_public_procname);
end;

function ERR_RAND_get0_private(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_get0_private_procname);
end;

function ERR_RAND_set0_public(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set0_public_procname);
end;

function ERR_RAND_set0_private(ctx: POSSL_LIB_CTX; rand: PEVP_RAND_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set0_private_procname);
end;

function ERR_RAND_set_DRBG_type(ctx: POSSL_LIB_CTX; drbg: PIdAnsiChar; propq: PIdAnsiChar; cipher: PIdAnsiChar; digest: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set_DRBG_type_procname);
end;

function ERR_RAND_set_seed_source_type(ctx: POSSL_LIB_CTX; seed: PIdAnsiChar; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set_seed_source_type_procname);
end;

procedure ERR_RAND_seed(buf: Pointer; num: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_seed_procname);
end;

procedure ERR_RAND_keep_random_devices_open(keep: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_keep_random_devices_open_procname);
end;

procedure ERR_RAND_add(buf: Pointer; num: TIdC_INT; randomness: Double); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_add_procname);
end;

function ERR_RAND_load_file(_file: PIdAnsiChar; max_bytes: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_load_file_procname);
end;

function ERR_RAND_write_file(_file: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_write_file_procname);
end;

function ERR_RAND_file_name(_file: PIdAnsiChar; num: TIdC_SIZET): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_file_name_procname);
end;

function ERR_RAND_status: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_status_procname);
end;

function ERR_RAND_poll: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_poll_procname);
end;

function ERR_RAND_set1_random_provider(ctx: POSSL_LIB_CTX; p: POSSL_PROVIDER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set1_random_provider_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  RAND_set_rand_method := LoadLibFunction(ADllHandle, RAND_set_rand_method_procname);
  FuncLoadError := not assigned(RAND_set_rand_method);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set_rand_method_allownil)}
    RAND_set_rand_method := ERR_RAND_set_rand_method;
    {$ifend}
    {$if declared(RAND_set_rand_method_introduced)}
    if LibVersion < RAND_set_rand_method_introduced then
    begin
      {$if declared(FC_RAND_set_rand_method)}
      RAND_set_rand_method := FC_RAND_set_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set_rand_method_removed)}
    if RAND_set_rand_method_removed <= LibVersion then
    begin
      {$if declared(_RAND_set_rand_method)}
      RAND_set_rand_method := _RAND_set_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set_rand_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set_rand_method');
    {$ifend}
  end;
  
  RAND_get_rand_method := LoadLibFunction(ADllHandle, RAND_get_rand_method_procname);
  FuncLoadError := not assigned(RAND_get_rand_method);
  if FuncLoadError then
  begin
    {$if not defined(RAND_get_rand_method_allownil)}
    RAND_get_rand_method := ERR_RAND_get_rand_method;
    {$ifend}
    {$if declared(RAND_get_rand_method_introduced)}
    if LibVersion < RAND_get_rand_method_introduced then
    begin
      {$if declared(FC_RAND_get_rand_method)}
      RAND_get_rand_method := FC_RAND_get_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_get_rand_method_removed)}
    if RAND_get_rand_method_removed <= LibVersion then
    begin
      {$if declared(_RAND_get_rand_method)}
      RAND_get_rand_method := _RAND_get_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_get_rand_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_get_rand_method');
    {$ifend}
  end;
  
  RAND_set_rand_engine := LoadLibFunction(ADllHandle, RAND_set_rand_engine_procname);
  FuncLoadError := not assigned(RAND_set_rand_engine);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set_rand_engine_allownil)}
    RAND_set_rand_engine := ERR_RAND_set_rand_engine;
    {$ifend}
    {$if declared(RAND_set_rand_engine_introduced)}
    if LibVersion < RAND_set_rand_engine_introduced then
    begin
      {$if declared(FC_RAND_set_rand_engine)}
      RAND_set_rand_engine := FC_RAND_set_rand_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set_rand_engine_removed)}
    if RAND_set_rand_engine_removed <= LibVersion then
    begin
      {$if declared(_RAND_set_rand_engine)}
      RAND_set_rand_engine := _RAND_set_rand_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set_rand_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set_rand_engine');
    {$ifend}
  end;
  
  RAND_OpenSSL := LoadLibFunction(ADllHandle, RAND_OpenSSL_procname);
  FuncLoadError := not assigned(RAND_OpenSSL);
  if FuncLoadError then
  begin
    {$if not defined(RAND_OpenSSL_allownil)}
    RAND_OpenSSL := ERR_RAND_OpenSSL;
    {$ifend}
    {$if declared(RAND_OpenSSL_introduced)}
    if LibVersion < RAND_OpenSSL_introduced then
    begin
      {$if declared(FC_RAND_OpenSSL)}
      RAND_OpenSSL := FC_RAND_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_OpenSSL_removed)}
    if RAND_OpenSSL_removed <= LibVersion then
    begin
      {$if declared(_RAND_OpenSSL)}
      RAND_OpenSSL := _RAND_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_OpenSSL_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_OpenSSL');
    {$ifend}
  end;
  
  RAND_bytes := LoadLibFunction(ADllHandle, RAND_bytes_procname);
  FuncLoadError := not assigned(RAND_bytes);
  if FuncLoadError then
  begin
    {$if not defined(RAND_bytes_allownil)}
    RAND_bytes := ERR_RAND_bytes;
    {$ifend}
    {$if declared(RAND_bytes_introduced)}
    if LibVersion < RAND_bytes_introduced then
    begin
      {$if declared(FC_RAND_bytes)}
      RAND_bytes := FC_RAND_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_bytes_removed)}
    if RAND_bytes_removed <= LibVersion then
    begin
      {$if declared(_RAND_bytes)}
      RAND_bytes := _RAND_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_bytes');
    {$ifend}
  end;
  
  RAND_priv_bytes := LoadLibFunction(ADllHandle, RAND_priv_bytes_procname);
  FuncLoadError := not assigned(RAND_priv_bytes);
  if FuncLoadError then
  begin
    {$if not defined(RAND_priv_bytes_allownil)}
    RAND_priv_bytes := ERR_RAND_priv_bytes;
    {$ifend}
    {$if declared(RAND_priv_bytes_introduced)}
    if LibVersion < RAND_priv_bytes_introduced then
    begin
      {$if declared(FC_RAND_priv_bytes)}
      RAND_priv_bytes := FC_RAND_priv_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_priv_bytes_removed)}
    if RAND_priv_bytes_removed <= LibVersion then
    begin
      {$if declared(_RAND_priv_bytes)}
      RAND_priv_bytes := _RAND_priv_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_priv_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_priv_bytes');
    {$ifend}
  end;
  
  RAND_priv_bytes_ex := LoadLibFunction(ADllHandle, RAND_priv_bytes_ex_procname);
  FuncLoadError := not assigned(RAND_priv_bytes_ex);
  if FuncLoadError then
  begin
    {$if not defined(RAND_priv_bytes_ex_allownil)}
    RAND_priv_bytes_ex := ERR_RAND_priv_bytes_ex;
    {$ifend}
    {$if declared(RAND_priv_bytes_ex_introduced)}
    if LibVersion < RAND_priv_bytes_ex_introduced then
    begin
      {$if declared(FC_RAND_priv_bytes_ex)}
      RAND_priv_bytes_ex := FC_RAND_priv_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_priv_bytes_ex_removed)}
    if RAND_priv_bytes_ex_removed <= LibVersion then
    begin
      {$if declared(_RAND_priv_bytes_ex)}
      RAND_priv_bytes_ex := _RAND_priv_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_priv_bytes_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_priv_bytes_ex');
    {$ifend}
  end;
  
  RAND_bytes_ex := LoadLibFunction(ADllHandle, RAND_bytes_ex_procname);
  FuncLoadError := not assigned(RAND_bytes_ex);
  if FuncLoadError then
  begin
    {$if not defined(RAND_bytes_ex_allownil)}
    RAND_bytes_ex := ERR_RAND_bytes_ex;
    {$ifend}
    {$if declared(RAND_bytes_ex_introduced)}
    if LibVersion < RAND_bytes_ex_introduced then
    begin
      {$if declared(FC_RAND_bytes_ex)}
      RAND_bytes_ex := FC_RAND_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_bytes_ex_removed)}
    if RAND_bytes_ex_removed <= LibVersion then
    begin
      {$if declared(_RAND_bytes_ex)}
      RAND_bytes_ex := _RAND_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_bytes_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_bytes_ex');
    {$ifend}
  end;
  
  
  RAND_get0_primary := LoadLibFunction(ADllHandle, RAND_get0_primary_procname);
  FuncLoadError := not assigned(RAND_get0_primary);
  if FuncLoadError then
  begin
    {$if not defined(RAND_get0_primary_allownil)}
    RAND_get0_primary := ERR_RAND_get0_primary;
    {$ifend}
    {$if declared(RAND_get0_primary_introduced)}
    if LibVersion < RAND_get0_primary_introduced then
    begin
      {$if declared(FC_RAND_get0_primary)}
      RAND_get0_primary := FC_RAND_get0_primary;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_get0_primary_removed)}
    if RAND_get0_primary_removed <= LibVersion then
    begin
      {$if declared(_RAND_get0_primary)}
      RAND_get0_primary := _RAND_get0_primary;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_get0_primary_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_get0_primary');
    {$ifend}
  end;
  
  RAND_get0_public := LoadLibFunction(ADllHandle, RAND_get0_public_procname);
  FuncLoadError := not assigned(RAND_get0_public);
  if FuncLoadError then
  begin
    {$if not defined(RAND_get0_public_allownil)}
    RAND_get0_public := ERR_RAND_get0_public;
    {$ifend}
    {$if declared(RAND_get0_public_introduced)}
    if LibVersion < RAND_get0_public_introduced then
    begin
      {$if declared(FC_RAND_get0_public)}
      RAND_get0_public := FC_RAND_get0_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_get0_public_removed)}
    if RAND_get0_public_removed <= LibVersion then
    begin
      {$if declared(_RAND_get0_public)}
      RAND_get0_public := _RAND_get0_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_get0_public_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_get0_public');
    {$ifend}
  end;
  
  RAND_get0_private := LoadLibFunction(ADllHandle, RAND_get0_private_procname);
  FuncLoadError := not assigned(RAND_get0_private);
  if FuncLoadError then
  begin
    {$if not defined(RAND_get0_private_allownil)}
    RAND_get0_private := ERR_RAND_get0_private;
    {$ifend}
    {$if declared(RAND_get0_private_introduced)}
    if LibVersion < RAND_get0_private_introduced then
    begin
      {$if declared(FC_RAND_get0_private)}
      RAND_get0_private := FC_RAND_get0_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_get0_private_removed)}
    if RAND_get0_private_removed <= LibVersion then
    begin
      {$if declared(_RAND_get0_private)}
      RAND_get0_private := _RAND_get0_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_get0_private_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_get0_private');
    {$ifend}
  end;
  
  RAND_set0_public := LoadLibFunction(ADllHandle, RAND_set0_public_procname);
  FuncLoadError := not assigned(RAND_set0_public);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set0_public_allownil)}
    RAND_set0_public := ERR_RAND_set0_public;
    {$ifend}
    {$if declared(RAND_set0_public_introduced)}
    if LibVersion < RAND_set0_public_introduced then
    begin
      {$if declared(FC_RAND_set0_public)}
      RAND_set0_public := FC_RAND_set0_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set0_public_removed)}
    if RAND_set0_public_removed <= LibVersion then
    begin
      {$if declared(_RAND_set0_public)}
      RAND_set0_public := _RAND_set0_public;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set0_public_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set0_public');
    {$ifend}
  end;
  
  RAND_set0_private := LoadLibFunction(ADllHandle, RAND_set0_private_procname);
  FuncLoadError := not assigned(RAND_set0_private);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set0_private_allownil)}
    RAND_set0_private := ERR_RAND_set0_private;
    {$ifend}
    {$if declared(RAND_set0_private_introduced)}
    if LibVersion < RAND_set0_private_introduced then
    begin
      {$if declared(FC_RAND_set0_private)}
      RAND_set0_private := FC_RAND_set0_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set0_private_removed)}
    if RAND_set0_private_removed <= LibVersion then
    begin
      {$if declared(_RAND_set0_private)}
      RAND_set0_private := _RAND_set0_private;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set0_private_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set0_private');
    {$ifend}
  end;
  
  RAND_set_DRBG_type := LoadLibFunction(ADllHandle, RAND_set_DRBG_type_procname);
  FuncLoadError := not assigned(RAND_set_DRBG_type);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set_DRBG_type_allownil)}
    RAND_set_DRBG_type := ERR_RAND_set_DRBG_type;
    {$ifend}
    {$if declared(RAND_set_DRBG_type_introduced)}
    if LibVersion < RAND_set_DRBG_type_introduced then
    begin
      {$if declared(FC_RAND_set_DRBG_type)}
      RAND_set_DRBG_type := FC_RAND_set_DRBG_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set_DRBG_type_removed)}
    if RAND_set_DRBG_type_removed <= LibVersion then
    begin
      {$if declared(_RAND_set_DRBG_type)}
      RAND_set_DRBG_type := _RAND_set_DRBG_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set_DRBG_type_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set_DRBG_type');
    {$ifend}
  end;
  
  RAND_set_seed_source_type := LoadLibFunction(ADllHandle, RAND_set_seed_source_type_procname);
  FuncLoadError := not assigned(RAND_set_seed_source_type);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set_seed_source_type_allownil)}
    RAND_set_seed_source_type := ERR_RAND_set_seed_source_type;
    {$ifend}
    {$if declared(RAND_set_seed_source_type_introduced)}
    if LibVersion < RAND_set_seed_source_type_introduced then
    begin
      {$if declared(FC_RAND_set_seed_source_type)}
      RAND_set_seed_source_type := FC_RAND_set_seed_source_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set_seed_source_type_removed)}
    if RAND_set_seed_source_type_removed <= LibVersion then
    begin
      {$if declared(_RAND_set_seed_source_type)}
      RAND_set_seed_source_type := _RAND_set_seed_source_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set_seed_source_type_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set_seed_source_type');
    {$ifend}
  end;
  
  RAND_seed := LoadLibFunction(ADllHandle, RAND_seed_procname);
  FuncLoadError := not assigned(RAND_seed);
  if FuncLoadError then
  begin
    {$if not defined(RAND_seed_allownil)}
    RAND_seed := ERR_RAND_seed;
    {$ifend}
    {$if declared(RAND_seed_introduced)}
    if LibVersion < RAND_seed_introduced then
    begin
      {$if declared(FC_RAND_seed)}
      RAND_seed := FC_RAND_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_seed_removed)}
    if RAND_seed_removed <= LibVersion then
    begin
      {$if declared(_RAND_seed)}
      RAND_seed := _RAND_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_seed_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_seed');
    {$ifend}
  end;
  
  RAND_keep_random_devices_open := LoadLibFunction(ADllHandle, RAND_keep_random_devices_open_procname);
  FuncLoadError := not assigned(RAND_keep_random_devices_open);
  if FuncLoadError then
  begin
    {$if not defined(RAND_keep_random_devices_open_allownil)}
    RAND_keep_random_devices_open := ERR_RAND_keep_random_devices_open;
    {$ifend}
    {$if declared(RAND_keep_random_devices_open_introduced)}
    if LibVersion < RAND_keep_random_devices_open_introduced then
    begin
      {$if declared(FC_RAND_keep_random_devices_open)}
      RAND_keep_random_devices_open := FC_RAND_keep_random_devices_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_keep_random_devices_open_removed)}
    if RAND_keep_random_devices_open_removed <= LibVersion then
    begin
      {$if declared(_RAND_keep_random_devices_open)}
      RAND_keep_random_devices_open := _RAND_keep_random_devices_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_keep_random_devices_open_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_keep_random_devices_open');
    {$ifend}
  end;
  
  RAND_add := LoadLibFunction(ADllHandle, RAND_add_procname);
  FuncLoadError := not assigned(RAND_add);
  if FuncLoadError then
  begin
    {$if not defined(RAND_add_allownil)}
    RAND_add := ERR_RAND_add;
    {$ifend}
    {$if declared(RAND_add_introduced)}
    if LibVersion < RAND_add_introduced then
    begin
      {$if declared(FC_RAND_add)}
      RAND_add := FC_RAND_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_add_removed)}
    if RAND_add_removed <= LibVersion then
    begin
      {$if declared(_RAND_add)}
      RAND_add := _RAND_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_add_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_add');
    {$ifend}
  end;
  
  RAND_load_file := LoadLibFunction(ADllHandle, RAND_load_file_procname);
  FuncLoadError := not assigned(RAND_load_file);
  if FuncLoadError then
  begin
    {$if not defined(RAND_load_file_allownil)}
    RAND_load_file := ERR_RAND_load_file;
    {$ifend}
    {$if declared(RAND_load_file_introduced)}
    if LibVersion < RAND_load_file_introduced then
    begin
      {$if declared(FC_RAND_load_file)}
      RAND_load_file := FC_RAND_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_load_file_removed)}
    if RAND_load_file_removed <= LibVersion then
    begin
      {$if declared(_RAND_load_file)}
      RAND_load_file := _RAND_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_load_file_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_load_file');
    {$ifend}
  end;
  
  RAND_write_file := LoadLibFunction(ADllHandle, RAND_write_file_procname);
  FuncLoadError := not assigned(RAND_write_file);
  if FuncLoadError then
  begin
    {$if not defined(RAND_write_file_allownil)}
    RAND_write_file := ERR_RAND_write_file;
    {$ifend}
    {$if declared(RAND_write_file_introduced)}
    if LibVersion < RAND_write_file_introduced then
    begin
      {$if declared(FC_RAND_write_file)}
      RAND_write_file := FC_RAND_write_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_write_file_removed)}
    if RAND_write_file_removed <= LibVersion then
    begin
      {$if declared(_RAND_write_file)}
      RAND_write_file := _RAND_write_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_write_file_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_write_file');
    {$ifend}
  end;
  
  RAND_file_name := LoadLibFunction(ADllHandle, RAND_file_name_procname);
  FuncLoadError := not assigned(RAND_file_name);
  if FuncLoadError then
  begin
    {$if not defined(RAND_file_name_allownil)}
    RAND_file_name := ERR_RAND_file_name;
    {$ifend}
    {$if declared(RAND_file_name_introduced)}
    if LibVersion < RAND_file_name_introduced then
    begin
      {$if declared(FC_RAND_file_name)}
      RAND_file_name := FC_RAND_file_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_file_name_removed)}
    if RAND_file_name_removed <= LibVersion then
    begin
      {$if declared(_RAND_file_name)}
      RAND_file_name := _RAND_file_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_file_name_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_file_name');
    {$ifend}
  end;
  
  RAND_status := LoadLibFunction(ADllHandle, RAND_status_procname);
  FuncLoadError := not assigned(RAND_status);
  if FuncLoadError then
  begin
    {$if not defined(RAND_status_allownil)}
    RAND_status := ERR_RAND_status;
    {$ifend}
    {$if declared(RAND_status_introduced)}
    if LibVersion < RAND_status_introduced then
    begin
      {$if declared(FC_RAND_status)}
      RAND_status := FC_RAND_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_status_removed)}
    if RAND_status_removed <= LibVersion then
    begin
      {$if declared(_RAND_status)}
      RAND_status := _RAND_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_status_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_status');
    {$ifend}
  end;
  
  RAND_poll := LoadLibFunction(ADllHandle, RAND_poll_procname);
  FuncLoadError := not assigned(RAND_poll);
  if FuncLoadError then
  begin
    {$if not defined(RAND_poll_allownil)}
    RAND_poll := ERR_RAND_poll;
    {$ifend}
    {$if declared(RAND_poll_introduced)}
    if LibVersion < RAND_poll_introduced then
    begin
      {$if declared(FC_RAND_poll)}
      RAND_poll := FC_RAND_poll;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_poll_removed)}
    if RAND_poll_removed <= LibVersion then
    begin
      {$if declared(_RAND_poll)}
      RAND_poll := _RAND_poll;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_poll_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_poll');
    {$ifend}
  end;
  
  RAND_set1_random_provider := LoadLibFunction(ADllHandle, RAND_set1_random_provider_procname);
  FuncLoadError := not assigned(RAND_set1_random_provider);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set1_random_provider_allownil)}
    RAND_set1_random_provider := ERR_RAND_set1_random_provider;
    {$ifend}
    {$if declared(RAND_set1_random_provider_introduced)}
    if LibVersion < RAND_set1_random_provider_introduced then
    begin
      {$if declared(FC_RAND_set1_random_provider)}
      RAND_set1_random_provider := FC_RAND_set1_random_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set1_random_provider_removed)}
    if RAND_set1_random_provider_removed <= LibVersion then
    begin
      {$if declared(_RAND_set1_random_provider)}
      RAND_set1_random_provider := _RAND_set1_random_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set1_random_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set1_random_provider');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  RAND_set_rand_method := nil;
  RAND_get_rand_method := nil;
  RAND_set_rand_engine := nil;
  RAND_OpenSSL := nil;
  RAND_bytes := nil;
  RAND_priv_bytes := nil;
  RAND_priv_bytes_ex := nil;
  RAND_bytes_ex := nil;
  RAND_get0_primary := nil;
  RAND_get0_public := nil;
  RAND_get0_private := nil;
  RAND_set0_public := nil;
  RAND_set0_private := nil;
  RAND_set_DRBG_type := nil;
  RAND_set_seed_source_type := nil;
  RAND_seed := nil;
  RAND_keep_random_devices_open := nil;
  RAND_add := nil;
  RAND_load_file := nil;
  RAND_write_file := nil;
  RAND_file_name := nil;
  RAND_status := nil;
  RAND_poll := nil;
  RAND_set1_random_provider := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.