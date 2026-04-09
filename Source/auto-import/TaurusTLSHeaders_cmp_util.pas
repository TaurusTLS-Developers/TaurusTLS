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

unit TaurusTLSHeaders_cmp_util;

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
  POSSL_CMP_severity = ^TOSSL_CMP_severity;
  TOSSL_CMP_severity = TIdC_INT;
  {$EXTERNALSYM POSSL_CMP_severity}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_CMP_log_cb_t_func_cb = function(arg1: PIdAnsiChar; arg2: PIdAnsiChar; arg3: TIdC_INT; arg4: TOSSL_CMP_severity; arg5: PIdAnsiChar): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_CMP_LOG_PREFIX = 'CMP ';
  OSSL_CMP_LOG_EMERG = 0;
  OSSL_CMP_LOG_ALERT = 1;
  OSSL_CMP_LOG_CRIT = 2;
  OSSL_CMP_LOG_ERR = 3;
  OSSL_CMP_LOG_WARNING = 4;
  OSSL_CMP_LOG_NOTICE = 5;
  OSSL_CMP_LOG_INFO = 6;
  OSSL_CMP_LOG_DEBUG = 7;
  OSSL_CMP_LOG_TRACE = 8;
  OSSL_CMP_LOG_MAX = OSSL_CMP_LOG_TRACE;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_CMP_log_open: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_log_open}

  OSSL_CMP_log_close: procedure; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_log_close}

  OSSL_CMP_print_to_bio: function(bio: PBIO; component: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT; level: TOSSL_CMP_severity; msg: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_print_to_bio}

  OSSL_CMP_print_errors_cb: procedure(log_fn: TOSSL_CMP_log_cb_t_func_cb); cdecl = nil;
  {$EXTERNALSYM OSSL_CMP_print_errors_cb}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_CMP_log_open: TIdC_INT; cdecl;
procedure OSSL_CMP_log_close; cdecl;
function OSSL_CMP_print_to_bio(bio: PBIO; component: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT; level: TOSSL_CMP_severity; msg: PIdAnsiChar): TIdC_INT; cdecl;
procedure OSSL_CMP_print_errors_cb(log_fn: TOSSL_CMP_log_cb_t_func_cb); cdecl;
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

function OSSL_CMP_log_open: TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_log_open';
procedure OSSL_CMP_log_close; cdecl external CLibCrypto name 'OSSL_CMP_log_close';
function OSSL_CMP_print_to_bio(bio: PBIO; component: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT; level: TOSSL_CMP_severity; msg: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_CMP_print_to_bio';
procedure OSSL_CMP_print_errors_cb(log_fn: TOSSL_CMP_log_cb_t_func_cb); cdecl external CLibCrypto name 'OSSL_CMP_print_errors_cb';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_CMP_log_open_procname = 'OSSL_CMP_log_open';
  OSSL_CMP_log_open_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_log_close_procname = 'OSSL_CMP_log_close';
  OSSL_CMP_log_close_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_print_to_bio_procname = 'OSSL_CMP_print_to_bio';
  OSSL_CMP_print_to_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_CMP_print_errors_cb_procname = 'OSSL_CMP_print_errors_cb';
  OSSL_CMP_print_errors_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_CMP_log_open: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_log_open_procname);
end;

procedure ERR_OSSL_CMP_log_close; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_log_close_procname);
end;

function ERR_OSSL_CMP_print_to_bio(bio: PBIO; component: PIdAnsiChar; _file: PIdAnsiChar; line: TIdC_INT; level: TOSSL_CMP_severity; msg: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_print_to_bio_procname);
end;

procedure ERR_OSSL_CMP_print_errors_cb(log_fn: TOSSL_CMP_log_cb_t_func_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_CMP_print_errors_cb_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_CMP_log_open := LoadLibFunction(ADllHandle, OSSL_CMP_log_open_procname);
  FuncLoadError := not assigned(OSSL_CMP_log_open);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_log_open_allownil)}
    OSSL_CMP_log_open := ERR_OSSL_CMP_log_open;
    {$ifend}
    {$if declared(OSSL_CMP_log_open_introduced)}
    if LibVersion < OSSL_CMP_log_open_introduced then
    begin
      {$if declared(FC_OSSL_CMP_log_open)}
      OSSL_CMP_log_open := FC_OSSL_CMP_log_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_log_open_removed)}
    if OSSL_CMP_log_open_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_log_open)}
      OSSL_CMP_log_open := _OSSL_CMP_log_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_log_open_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_log_open');
    {$ifend}
  end;
  
  OSSL_CMP_log_close := LoadLibFunction(ADllHandle, OSSL_CMP_log_close_procname);
  FuncLoadError := not assigned(OSSL_CMP_log_close);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_log_close_allownil)}
    OSSL_CMP_log_close := ERR_OSSL_CMP_log_close;
    {$ifend}
    {$if declared(OSSL_CMP_log_close_introduced)}
    if LibVersion < OSSL_CMP_log_close_introduced then
    begin
      {$if declared(FC_OSSL_CMP_log_close)}
      OSSL_CMP_log_close := FC_OSSL_CMP_log_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_log_close_removed)}
    if OSSL_CMP_log_close_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_log_close)}
      OSSL_CMP_log_close := _OSSL_CMP_log_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_log_close_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_log_close');
    {$ifend}
  end;
  
  OSSL_CMP_print_to_bio := LoadLibFunction(ADllHandle, OSSL_CMP_print_to_bio_procname);
  FuncLoadError := not assigned(OSSL_CMP_print_to_bio);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_print_to_bio_allownil)}
    OSSL_CMP_print_to_bio := ERR_OSSL_CMP_print_to_bio;
    {$ifend}
    {$if declared(OSSL_CMP_print_to_bio_introduced)}
    if LibVersion < OSSL_CMP_print_to_bio_introduced then
    begin
      {$if declared(FC_OSSL_CMP_print_to_bio)}
      OSSL_CMP_print_to_bio := FC_OSSL_CMP_print_to_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_print_to_bio_removed)}
    if OSSL_CMP_print_to_bio_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_print_to_bio)}
      OSSL_CMP_print_to_bio := _OSSL_CMP_print_to_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_print_to_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_print_to_bio');
    {$ifend}
  end;
  
  OSSL_CMP_print_errors_cb := LoadLibFunction(ADllHandle, OSSL_CMP_print_errors_cb_procname);
  FuncLoadError := not assigned(OSSL_CMP_print_errors_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_CMP_print_errors_cb_allownil)}
    OSSL_CMP_print_errors_cb := ERR_OSSL_CMP_print_errors_cb;
    {$ifend}
    {$if declared(OSSL_CMP_print_errors_cb_introduced)}
    if LibVersion < OSSL_CMP_print_errors_cb_introduced then
    begin
      {$if declared(FC_OSSL_CMP_print_errors_cb)}
      OSSL_CMP_print_errors_cb := FC_OSSL_CMP_print_errors_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_CMP_print_errors_cb_removed)}
    if OSSL_CMP_print_errors_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_CMP_print_errors_cb)}
      OSSL_CMP_print_errors_cb := _OSSL_CMP_print_errors_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_CMP_print_errors_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_CMP_print_errors_cb');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_CMP_log_open := nil;
  OSSL_CMP_log_close := nil;
  OSSL_CMP_print_to_bio := nil;
  OSSL_CMP_print_errors_cb := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.