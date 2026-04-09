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

unit TaurusTLSHeaders_indicator;

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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_INDICATOR_CALLBACK_func_cb = function(arg1: PIdAnsiChar; arg2: PIdAnsiChar; arg3: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_INDICATOR_set_callback: procedure(libctx: POSSL_LIB_CTX; cb: TOSSL_INDICATOR_CALLBACK_func_cb); cdecl = nil;
  {$EXTERNALSYM OSSL_INDICATOR_set_callback}

  OSSL_INDICATOR_get_callback: procedure(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl = nil;
  {$EXTERNALSYM OSSL_INDICATOR_get_callback}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

procedure OSSL_INDICATOR_set_callback(libctx: POSSL_LIB_CTX; cb: TOSSL_INDICATOR_CALLBACK_func_cb); cdecl;
procedure OSSL_INDICATOR_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl;
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

procedure OSSL_INDICATOR_set_callback(libctx: POSSL_LIB_CTX; cb: TOSSL_INDICATOR_CALLBACK_func_cb); cdecl external CLibCrypto name 'OSSL_INDICATOR_set_callback';
procedure OSSL_INDICATOR_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl external CLibCrypto name 'OSSL_INDICATOR_get_callback';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_INDICATOR_set_callback_procname = 'OSSL_INDICATOR_set_callback';
  OSSL_INDICATOR_set_callback_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_INDICATOR_get_callback_procname = 'OSSL_INDICATOR_get_callback';
  OSSL_INDICATOR_get_callback_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

procedure ERR_OSSL_INDICATOR_set_callback(libctx: POSSL_LIB_CTX; cb: TOSSL_INDICATOR_CALLBACK_func_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INDICATOR_set_callback_procname);
end;

procedure ERR_OSSL_INDICATOR_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_INDICATOR_get_callback_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_INDICATOR_set_callback := LoadLibFunction(ADllHandle, OSSL_INDICATOR_set_callback_procname);
  FuncLoadError := not assigned(OSSL_INDICATOR_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INDICATOR_set_callback_allownil)}
    OSSL_INDICATOR_set_callback := ERR_OSSL_INDICATOR_set_callback;
    {$ifend}
    {$if declared(OSSL_INDICATOR_set_callback_introduced)}
    if LibVersion < OSSL_INDICATOR_set_callback_introduced then
    begin
      {$if declared(FC_OSSL_INDICATOR_set_callback)}
      OSSL_INDICATOR_set_callback := FC_OSSL_INDICATOR_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INDICATOR_set_callback_removed)}
    if OSSL_INDICATOR_set_callback_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INDICATOR_set_callback)}
      OSSL_INDICATOR_set_callback := _OSSL_INDICATOR_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INDICATOR_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INDICATOR_set_callback');
    {$ifend}
  end;
  
  OSSL_INDICATOR_get_callback := LoadLibFunction(ADllHandle, OSSL_INDICATOR_get_callback_procname);
  FuncLoadError := not assigned(OSSL_INDICATOR_get_callback);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_INDICATOR_get_callback_allownil)}
    OSSL_INDICATOR_get_callback := ERR_OSSL_INDICATOR_get_callback;
    {$ifend}
    {$if declared(OSSL_INDICATOR_get_callback_introduced)}
    if LibVersion < OSSL_INDICATOR_get_callback_introduced then
    begin
      {$if declared(FC_OSSL_INDICATOR_get_callback)}
      OSSL_INDICATOR_get_callback := FC_OSSL_INDICATOR_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_INDICATOR_get_callback_removed)}
    if OSSL_INDICATOR_get_callback_removed <= LibVersion then
    begin
      {$if declared(_OSSL_INDICATOR_get_callback)}
      OSSL_INDICATOR_get_callback := _OSSL_INDICATOR_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_INDICATOR_get_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_INDICATOR_get_callback');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_INDICATOR_set_callback := nil;
  OSSL_INDICATOR_get_callback := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.