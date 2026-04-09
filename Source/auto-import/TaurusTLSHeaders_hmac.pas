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

unit TaurusTLSHeaders_hmac;

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
  HMAC_MAX_MD_CBLOCK = 200;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  HMAC_size: function(e: PHMAC_CTX): TIdC_SIZET; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_size}

  HMAC_CTX_new: function: PHMAC_CTX; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_CTX_new}

  HMAC_CTX_reset: function(ctx: PHMAC_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_CTX_reset}

  HMAC_CTX_free: procedure(ctx: PHMAC_CTX); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_CTX_free}

  HMAC_Init_ex: function(ctx: PHMAC_CTX; key: Pointer; len: TIdC_INT; md: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_Init_ex}

  HMAC_Update: function(ctx: PHMAC_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_Update}

  HMAC_Final: function(ctx: PHMAC_CTX; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_Final}

  HMAC_CTX_copy: function(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_CTX_copy}

  HMAC_CTX_set_flags: procedure(ctx: PHMAC_CTX; flags: TIdC_ULONG); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_CTX_set_flags}

  HMAC_CTX_get_md: function(ctx: PHMAC_CTX): PEVP_MD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM HMAC_CTX_get_md}

  HMAC: function(evp_md: PEVP_MD; key: Pointer; key_len: TIdC_INT; data: PIdAnsiChar; data_len: TIdC_SIZET; md: PIdAnsiChar; md_len: PIdC_UINT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM HMAC}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function HMAC_size(e: PHMAC_CTX): TIdC_SIZET; cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC_CTX_new: PHMAC_CTX; cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC_CTX_reset(ctx: PHMAC_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure HMAC_CTX_free(ctx: PHMAC_CTX); cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC_Init_ex(ctx: PHMAC_CTX; key: Pointer; len: TIdC_INT; md: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC_Update(ctx: PHMAC_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC_Final(ctx: PHMAC_CTX; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TIdC_ULONG); cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC_CTX_get_md(ctx: PHMAC_CTX): PEVP_MD; cdecl; deprecated 'In OpenSSL 3_0_0';
function HMAC(evp_md: PEVP_MD; key: Pointer; key_len: TIdC_INT; data: PIdAnsiChar; data_len: TIdC_SIZET; md: PIdAnsiChar; md_len: PIdC_UINT): PIdAnsiChar; cdecl;
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

function HMAC_size(e: PHMAC_CTX): TIdC_SIZET; cdecl external CLibCrypto name 'HMAC_size';
function HMAC_CTX_new: PHMAC_CTX; cdecl external CLibCrypto name 'HMAC_CTX_new';
function HMAC_CTX_reset(ctx: PHMAC_CTX): TIdC_INT; cdecl external CLibCrypto name 'HMAC_CTX_reset';
procedure HMAC_CTX_free(ctx: PHMAC_CTX); cdecl external CLibCrypto name 'HMAC_CTX_free';
function HMAC_Init_ex(ctx: PHMAC_CTX; key: Pointer; len: TIdC_INT; md: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'HMAC_Init_ex';
function HMAC_Update(ctx: PHMAC_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'HMAC_Update';
function HMAC_Final(ctx: PHMAC_CTX; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'HMAC_Final';
function HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TIdC_INT; cdecl external CLibCrypto name 'HMAC_CTX_copy';
procedure HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TIdC_ULONG); cdecl external CLibCrypto name 'HMAC_CTX_set_flags';
function HMAC_CTX_get_md(ctx: PHMAC_CTX): PEVP_MD; cdecl external CLibCrypto name 'HMAC_CTX_get_md';
function HMAC(evp_md: PEVP_MD; key: Pointer; key_len: TIdC_INT; data: PIdAnsiChar; data_len: TIdC_SIZET; md: PIdAnsiChar; md_len: PIdC_UINT): PIdAnsiChar; cdecl external CLibCrypto name 'HMAC';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  HMAC_size_procname = 'HMAC_size';
  HMAC_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_CTX_new_procname = 'HMAC_CTX_new';
  HMAC_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_CTX_reset_procname = 'HMAC_CTX_reset';
  HMAC_CTX_reset_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_reset_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_CTX_free_procname = 'HMAC_CTX_free';
  HMAC_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_Init_ex_procname = 'HMAC_Init_ex';
  HMAC_Init_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_Init_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_Update_procname = 'HMAC_Update';
  HMAC_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_Final_procname = 'HMAC_Final';
  HMAC_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_CTX_copy_procname = 'HMAC_CTX_copy';
  HMAC_CTX_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_copy_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_CTX_set_flags_procname = 'HMAC_CTX_set_flags';
  HMAC_CTX_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_set_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_CTX_get_md_procname = 'HMAC_CTX_get_md';
  HMAC_CTX_get_md_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_get_md_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  HMAC_procname = 'HMAC';
  HMAC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_HMAC_size(e: PHMAC_CTX): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_size_procname);
end;

function ERR_HMAC_CTX_new: PHMAC_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_new_procname);
end;

function ERR_HMAC_CTX_reset(ctx: PHMAC_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_reset_procname);
end;

procedure ERR_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_free_procname);
end;

function ERR_HMAC_Init_ex(ctx: PHMAC_CTX; key: Pointer; len: TIdC_INT; md: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_Init_ex_procname);
end;

function ERR_HMAC_Update(ctx: PHMAC_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_Update_procname);
end;

function ERR_HMAC_Final(ctx: PHMAC_CTX; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_Final_procname);
end;

function ERR_HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_copy_procname);
end;

procedure ERR_HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TIdC_ULONG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_set_flags_procname);
end;

function ERR_HMAC_CTX_get_md(ctx: PHMAC_CTX): PEVP_MD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_get_md_procname);
end;

function ERR_HMAC(evp_md: PEVP_MD; key: Pointer; key_len: TIdC_INT; data: PIdAnsiChar; data_len: TIdC_SIZET; md: PIdAnsiChar; md_len: PIdC_UINT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  HMAC_size := LoadLibFunction(ADllHandle, HMAC_size_procname);
  FuncLoadError := not assigned(HMAC_size);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_size_allownil)}
    HMAC_size := ERR_HMAC_size;
    {$ifend}
    {$if declared(HMAC_size_introduced)}
    if LibVersion < HMAC_size_introduced then
    begin
      {$if declared(FC_HMAC_size)}
      HMAC_size := FC_HMAC_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_size_removed)}
    if HMAC_size_removed <= LibVersion then
    begin
      {$if declared(_HMAC_size)}
      HMAC_size := _HMAC_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_size_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_size');
    {$ifend}
  end;
  
  HMAC_CTX_new := LoadLibFunction(ADllHandle, HMAC_CTX_new_procname);
  FuncLoadError := not assigned(HMAC_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_new_allownil)}
    HMAC_CTX_new := ERR_HMAC_CTX_new;
    {$ifend}
    {$if declared(HMAC_CTX_new_introduced)}
    if LibVersion < HMAC_CTX_new_introduced then
    begin
      {$if declared(FC_HMAC_CTX_new)}
      HMAC_CTX_new := FC_HMAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_new_removed)}
    if HMAC_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_new)}
      HMAC_CTX_new := _HMAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_new');
    {$ifend}
  end;
  
  HMAC_CTX_reset := LoadLibFunction(ADllHandle, HMAC_CTX_reset_procname);
  FuncLoadError := not assigned(HMAC_CTX_reset);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_reset_allownil)}
    HMAC_CTX_reset := ERR_HMAC_CTX_reset;
    {$ifend}
    {$if declared(HMAC_CTX_reset_introduced)}
    if LibVersion < HMAC_CTX_reset_introduced then
    begin
      {$if declared(FC_HMAC_CTX_reset)}
      HMAC_CTX_reset := FC_HMAC_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_reset_removed)}
    if HMAC_CTX_reset_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_reset)}
      HMAC_CTX_reset := _HMAC_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_reset_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_reset');
    {$ifend}
  end;
  
  HMAC_CTX_free := LoadLibFunction(ADllHandle, HMAC_CTX_free_procname);
  FuncLoadError := not assigned(HMAC_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_free_allownil)}
    HMAC_CTX_free := ERR_HMAC_CTX_free;
    {$ifend}
    {$if declared(HMAC_CTX_free_introduced)}
    if LibVersion < HMAC_CTX_free_introduced then
    begin
      {$if declared(FC_HMAC_CTX_free)}
      HMAC_CTX_free := FC_HMAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_free_removed)}
    if HMAC_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_free)}
      HMAC_CTX_free := _HMAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_free');
    {$ifend}
  end;
  
  
  HMAC_Init_ex := LoadLibFunction(ADllHandle, HMAC_Init_ex_procname);
  FuncLoadError := not assigned(HMAC_Init_ex);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_Init_ex_allownil)}
    HMAC_Init_ex := ERR_HMAC_Init_ex;
    {$ifend}
    {$if declared(HMAC_Init_ex_introduced)}
    if LibVersion < HMAC_Init_ex_introduced then
    begin
      {$if declared(FC_HMAC_Init_ex)}
      HMAC_Init_ex := FC_HMAC_Init_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_Init_ex_removed)}
    if HMAC_Init_ex_removed <= LibVersion then
    begin
      {$if declared(_HMAC_Init_ex)}
      HMAC_Init_ex := _HMAC_Init_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_Init_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_Init_ex');
    {$ifend}
  end;
  
  HMAC_Update := LoadLibFunction(ADllHandle, HMAC_Update_procname);
  FuncLoadError := not assigned(HMAC_Update);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_Update_allownil)}
    HMAC_Update := ERR_HMAC_Update;
    {$ifend}
    {$if declared(HMAC_Update_introduced)}
    if LibVersion < HMAC_Update_introduced then
    begin
      {$if declared(FC_HMAC_Update)}
      HMAC_Update := FC_HMAC_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_Update_removed)}
    if HMAC_Update_removed <= LibVersion then
    begin
      {$if declared(_HMAC_Update)}
      HMAC_Update := _HMAC_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_Update');
    {$ifend}
  end;
  
  HMAC_Final := LoadLibFunction(ADllHandle, HMAC_Final_procname);
  FuncLoadError := not assigned(HMAC_Final);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_Final_allownil)}
    HMAC_Final := ERR_HMAC_Final;
    {$ifend}
    {$if declared(HMAC_Final_introduced)}
    if LibVersion < HMAC_Final_introduced then
    begin
      {$if declared(FC_HMAC_Final)}
      HMAC_Final := FC_HMAC_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_Final_removed)}
    if HMAC_Final_removed <= LibVersion then
    begin
      {$if declared(_HMAC_Final)}
      HMAC_Final := _HMAC_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_Final');
    {$ifend}
  end;
  
  HMAC_CTX_copy := LoadLibFunction(ADllHandle, HMAC_CTX_copy_procname);
  FuncLoadError := not assigned(HMAC_CTX_copy);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_copy_allownil)}
    HMAC_CTX_copy := ERR_HMAC_CTX_copy;
    {$ifend}
    {$if declared(HMAC_CTX_copy_introduced)}
    if LibVersion < HMAC_CTX_copy_introduced then
    begin
      {$if declared(FC_HMAC_CTX_copy)}
      HMAC_CTX_copy := FC_HMAC_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_copy_removed)}
    if HMAC_CTX_copy_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_copy)}
      HMAC_CTX_copy := _HMAC_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_copy');
    {$ifend}
  end;
  
  HMAC_CTX_set_flags := LoadLibFunction(ADllHandle, HMAC_CTX_set_flags_procname);
  FuncLoadError := not assigned(HMAC_CTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_set_flags_allownil)}
    HMAC_CTX_set_flags := ERR_HMAC_CTX_set_flags;
    {$ifend}
    {$if declared(HMAC_CTX_set_flags_introduced)}
    if LibVersion < HMAC_CTX_set_flags_introduced then
    begin
      {$if declared(FC_HMAC_CTX_set_flags)}
      HMAC_CTX_set_flags := FC_HMAC_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_set_flags_removed)}
    if HMAC_CTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_set_flags)}
      HMAC_CTX_set_flags := _HMAC_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_set_flags');
    {$ifend}
  end;
  
  HMAC_CTX_get_md := LoadLibFunction(ADllHandle, HMAC_CTX_get_md_procname);
  FuncLoadError := not assigned(HMAC_CTX_get_md);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_get_md_allownil)}
    HMAC_CTX_get_md := ERR_HMAC_CTX_get_md;
    {$ifend}
    {$if declared(HMAC_CTX_get_md_introduced)}
    if LibVersion < HMAC_CTX_get_md_introduced then
    begin
      {$if declared(FC_HMAC_CTX_get_md)}
      HMAC_CTX_get_md := FC_HMAC_CTX_get_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_get_md_removed)}
    if HMAC_CTX_get_md_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_get_md)}
      HMAC_CTX_get_md := _HMAC_CTX_get_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_get_md_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_get_md');
    {$ifend}
  end;
  
  HMAC := LoadLibFunction(ADllHandle, HMAC_procname);
  FuncLoadError := not assigned(HMAC);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_allownil)}
    HMAC := ERR_HMAC;
    {$ifend}
    {$if declared(HMAC_introduced)}
    if LibVersion < HMAC_introduced then
    begin
      {$if declared(FC_HMAC)}
      HMAC := FC_HMAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_removed)}
    if HMAC_removed <= LibVersion then
    begin
      {$if declared(_HMAC)}
      HMAC := _HMAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  HMAC_size := nil;
  HMAC_CTX_new := nil;
  HMAC_CTX_reset := nil;
  HMAC_CTX_free := nil;
  HMAC_Init_ex := nil;
  HMAC_Update := nil;
  HMAC_Final := nil;
  HMAC_CTX_copy := nil;
  HMAC_CTX_set_flags := nil;
  HMAC_CTX_get_md := nil;
  HMAC := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.