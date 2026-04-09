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

unit TaurusTLSHeaders_thread;

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
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL = (1 shl 0);
  OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN = (1 shl 1);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_get_thread_support_flags: function: UInt32; cdecl = nil;
  {$EXTERNALSYM OSSL_get_thread_support_flags}

  OSSL_set_max_threads: function(ctx: POSSL_LIB_CTX; max_threads: UInt64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_set_max_threads}

  OSSL_get_max_threads: function(ctx: POSSL_LIB_CTX): UInt64; cdecl = nil;
  {$EXTERNALSYM OSSL_get_max_threads}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_get_thread_support_flags: UInt32; cdecl;
function OSSL_set_max_threads(ctx: POSSL_LIB_CTX; max_threads: UInt64): TIdC_INT; cdecl;
function OSSL_get_max_threads(ctx: POSSL_LIB_CTX): UInt64; cdecl;
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

function OSSL_get_thread_support_flags: UInt32; cdecl external CLibCrypto name 'OSSL_get_thread_support_flags';
function OSSL_set_max_threads(ctx: POSSL_LIB_CTX; max_threads: UInt64): TIdC_INT; cdecl external CLibCrypto name 'OSSL_set_max_threads';
function OSSL_get_max_threads(ctx: POSSL_LIB_CTX): UInt64; cdecl external CLibCrypto name 'OSSL_get_max_threads';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_get_thread_support_flags_procname = 'OSSL_get_thread_support_flags';
  OSSL_get_thread_support_flags_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_set_max_threads_procname = 'OSSL_set_max_threads';
  OSSL_set_max_threads_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_get_max_threads_procname = 'OSSL_get_max_threads';
  OSSL_get_max_threads_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_get_thread_support_flags: UInt32; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_get_thread_support_flags_procname);
end;

function ERR_OSSL_set_max_threads(ctx: POSSL_LIB_CTX; max_threads: UInt64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_set_max_threads_procname);
end;

function ERR_OSSL_get_max_threads(ctx: POSSL_LIB_CTX): UInt64; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_get_max_threads_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_get_thread_support_flags := LoadLibFunction(ADllHandle, OSSL_get_thread_support_flags_procname);
  FuncLoadError := not assigned(OSSL_get_thread_support_flags);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_get_thread_support_flags_allownil)}
    OSSL_get_thread_support_flags := ERR_OSSL_get_thread_support_flags;
    {$ifend}
    {$if declared(OSSL_get_thread_support_flags_introduced)}
    if LibVersion < OSSL_get_thread_support_flags_introduced then
    begin
      {$if declared(FC_OSSL_get_thread_support_flags)}
      OSSL_get_thread_support_flags := FC_OSSL_get_thread_support_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_get_thread_support_flags_removed)}
    if OSSL_get_thread_support_flags_removed <= LibVersion then
    begin
      {$if declared(_OSSL_get_thread_support_flags)}
      OSSL_get_thread_support_flags := _OSSL_get_thread_support_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_get_thread_support_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_get_thread_support_flags');
    {$ifend}
  end;
  
  OSSL_set_max_threads := LoadLibFunction(ADllHandle, OSSL_set_max_threads_procname);
  FuncLoadError := not assigned(OSSL_set_max_threads);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_set_max_threads_allownil)}
    OSSL_set_max_threads := ERR_OSSL_set_max_threads;
    {$ifend}
    {$if declared(OSSL_set_max_threads_introduced)}
    if LibVersion < OSSL_set_max_threads_introduced then
    begin
      {$if declared(FC_OSSL_set_max_threads)}
      OSSL_set_max_threads := FC_OSSL_set_max_threads;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_set_max_threads_removed)}
    if OSSL_set_max_threads_removed <= LibVersion then
    begin
      {$if declared(_OSSL_set_max_threads)}
      OSSL_set_max_threads := _OSSL_set_max_threads;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_set_max_threads_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_set_max_threads');
    {$ifend}
  end;
  
  OSSL_get_max_threads := LoadLibFunction(ADllHandle, OSSL_get_max_threads_procname);
  FuncLoadError := not assigned(OSSL_get_max_threads);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_get_max_threads_allownil)}
    OSSL_get_max_threads := ERR_OSSL_get_max_threads;
    {$ifend}
    {$if declared(OSSL_get_max_threads_introduced)}
    if LibVersion < OSSL_get_max_threads_introduced then
    begin
      {$if declared(FC_OSSL_get_max_threads)}
      OSSL_get_max_threads := FC_OSSL_get_max_threads;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_get_max_threads_removed)}
    if OSSL_get_max_threads_removed <= LibVersion then
    begin
      {$if declared(_OSSL_get_max_threads)}
      OSSL_get_max_threads := _OSSL_get_max_threads;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_get_max_threads_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_get_max_threads');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_get_thread_support_flags := nil;
  OSSL_set_max_threads := nil;
  OSSL_get_max_threads := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.