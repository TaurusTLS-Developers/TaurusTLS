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

unit TaurusTLSHeaders_buffer;

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
  Pbuf_mem_st = ^Tbuf_mem_st;
  Tbuf_mem_st = record end;
  {$EXTERNALSYM Pbuf_mem_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  BUF_MEM_FLAG_SECURE = $01;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  BUF_MEM_new: function: PBUF_MEM; cdecl = nil;
  {$EXTERNALSYM BUF_MEM_new}

  BUF_MEM_new_ex: function(flags: TIdC_ULONG): PBUF_MEM; cdecl = nil;
  {$EXTERNALSYM BUF_MEM_new_ex}

  BUF_MEM_free: procedure(a: PBUF_MEM); cdecl = nil;
  {$EXTERNALSYM BUF_MEM_free}

  BUF_MEM_grow: function(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BUF_MEM_grow}

  BUF_MEM_grow_clean: function(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BUF_MEM_grow_clean}

  BUF_reverse: procedure(_out: PIdAnsiChar; _in: PIdAnsiChar; siz: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM BUF_reverse}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function BUF_MEM_new: PBUF_MEM; cdecl;
function BUF_MEM_new_ex(flags: TIdC_ULONG): PBUF_MEM; cdecl;
procedure BUF_MEM_free(a: PBUF_MEM); cdecl;
function BUF_MEM_grow(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl;
function BUF_MEM_grow_clean(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl;
procedure BUF_reverse(_out: PIdAnsiChar; _in: PIdAnsiChar; siz: TIdC_SIZET); cdecl;
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

function BUF_MEM_new: PBUF_MEM; cdecl external CLibCrypto name 'BUF_MEM_new';
function BUF_MEM_new_ex(flags: TIdC_ULONG): PBUF_MEM; cdecl external CLibCrypto name 'BUF_MEM_new_ex';
procedure BUF_MEM_free(a: PBUF_MEM); cdecl external CLibCrypto name 'BUF_MEM_free';
function BUF_MEM_grow(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'BUF_MEM_grow';
function BUF_MEM_grow_clean(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'BUF_MEM_grow_clean';
procedure BUF_reverse(_out: PIdAnsiChar; _in: PIdAnsiChar; siz: TIdC_SIZET); cdecl external CLibCrypto name 'BUF_reverse';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  BUF_MEM_new_procname = 'BUF_MEM_new';
  BUF_MEM_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BUF_MEM_new_ex_procname = 'BUF_MEM_new_ex';
  BUF_MEM_new_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BUF_MEM_free_procname = 'BUF_MEM_free';
  BUF_MEM_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BUF_MEM_grow_procname = 'BUF_MEM_grow';
  BUF_MEM_grow_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BUF_MEM_grow_clean_procname = 'BUF_MEM_grow_clean';
  BUF_MEM_grow_clean_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BUF_reverse_procname = 'BUF_reverse';
  BUF_reverse_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_BUF_MEM_new: PBUF_MEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_new_procname);
end;

function ERR_BUF_MEM_new_ex(flags: TIdC_ULONG): PBUF_MEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_new_ex_procname);
end;

procedure ERR_BUF_MEM_free(a: PBUF_MEM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_free_procname);
end;

function ERR_BUF_MEM_grow(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_grow_procname);
end;

function ERR_BUF_MEM_grow_clean(str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_grow_clean_procname);
end;

procedure ERR_BUF_reverse(_out: PIdAnsiChar; _in: PIdAnsiChar; siz: TIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_reverse_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  BUF_MEM_new := LoadLibFunction(ADllHandle, BUF_MEM_new_procname);
  FuncLoadError := not assigned(BUF_MEM_new);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_new_allownil)}
    BUF_MEM_new := ERR_BUF_MEM_new;
    {$ifend}
    {$if declared(BUF_MEM_new_introduced)}
    if LibVersion < BUF_MEM_new_introduced then
    begin
      {$if declared(FC_BUF_MEM_new)}
      BUF_MEM_new := FC_BUF_MEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_new_removed)}
    if BUF_MEM_new_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_new)}
      BUF_MEM_new := _BUF_MEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_new');
    {$ifend}
  end;
  
  BUF_MEM_new_ex := LoadLibFunction(ADllHandle, BUF_MEM_new_ex_procname);
  FuncLoadError := not assigned(BUF_MEM_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_new_ex_allownil)}
    BUF_MEM_new_ex := ERR_BUF_MEM_new_ex;
    {$ifend}
    {$if declared(BUF_MEM_new_ex_introduced)}
    if LibVersion < BUF_MEM_new_ex_introduced then
    begin
      {$if declared(FC_BUF_MEM_new_ex)}
      BUF_MEM_new_ex := FC_BUF_MEM_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_new_ex_removed)}
    if BUF_MEM_new_ex_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_new_ex)}
      BUF_MEM_new_ex := _BUF_MEM_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_new_ex');
    {$ifend}
  end;
  
  BUF_MEM_free := LoadLibFunction(ADllHandle, BUF_MEM_free_procname);
  FuncLoadError := not assigned(BUF_MEM_free);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_free_allownil)}
    BUF_MEM_free := ERR_BUF_MEM_free;
    {$ifend}
    {$if declared(BUF_MEM_free_introduced)}
    if LibVersion < BUF_MEM_free_introduced then
    begin
      {$if declared(FC_BUF_MEM_free)}
      BUF_MEM_free := FC_BUF_MEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_free_removed)}
    if BUF_MEM_free_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_free)}
      BUF_MEM_free := _BUF_MEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_free');
    {$ifend}
  end;
  
  BUF_MEM_grow := LoadLibFunction(ADllHandle, BUF_MEM_grow_procname);
  FuncLoadError := not assigned(BUF_MEM_grow);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_grow_allownil)}
    BUF_MEM_grow := ERR_BUF_MEM_grow;
    {$ifend}
    {$if declared(BUF_MEM_grow_introduced)}
    if LibVersion < BUF_MEM_grow_introduced then
    begin
      {$if declared(FC_BUF_MEM_grow)}
      BUF_MEM_grow := FC_BUF_MEM_grow;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_grow_removed)}
    if BUF_MEM_grow_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_grow)}
      BUF_MEM_grow := _BUF_MEM_grow;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_grow_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_grow');
    {$ifend}
  end;
  
  BUF_MEM_grow_clean := LoadLibFunction(ADllHandle, BUF_MEM_grow_clean_procname);
  FuncLoadError := not assigned(BUF_MEM_grow_clean);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_grow_clean_allownil)}
    BUF_MEM_grow_clean := ERR_BUF_MEM_grow_clean;
    {$ifend}
    {$if declared(BUF_MEM_grow_clean_introduced)}
    if LibVersion < BUF_MEM_grow_clean_introduced then
    begin
      {$if declared(FC_BUF_MEM_grow_clean)}
      BUF_MEM_grow_clean := FC_BUF_MEM_grow_clean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_grow_clean_removed)}
    if BUF_MEM_grow_clean_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_grow_clean)}
      BUF_MEM_grow_clean := _BUF_MEM_grow_clean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_grow_clean_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_grow_clean');
    {$ifend}
  end;
  
  BUF_reverse := LoadLibFunction(ADllHandle, BUF_reverse_procname);
  FuncLoadError := not assigned(BUF_reverse);
  if FuncLoadError then
  begin
    {$if not defined(BUF_reverse_allownil)}
    BUF_reverse := ERR_BUF_reverse;
    {$ifend}
    {$if declared(BUF_reverse_introduced)}
    if LibVersion < BUF_reverse_introduced then
    begin
      {$if declared(FC_BUF_reverse)}
      BUF_reverse := FC_BUF_reverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_reverse_removed)}
    if BUF_reverse_removed <= LibVersion then
    begin
      {$if declared(_BUF_reverse)}
      BUF_reverse := _BUF_reverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_reverse_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_reverse');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  BUF_MEM_new := nil;
  BUF_MEM_new_ex := nil;
  BUF_MEM_free := nil;
  BUF_MEM_grow := nil;
  BUF_MEM_grow_clean := nil;
  BUF_reverse := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.