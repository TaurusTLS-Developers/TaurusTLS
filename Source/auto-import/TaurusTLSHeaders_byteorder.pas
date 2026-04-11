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

unit TaurusTLSHeaders_byteorder;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;




{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_store_u16_le: function(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_store_u16_be: function(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_store_u32_le: function(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_store_u32_be: function(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_store_u64_le: function(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_store_u64_be: function(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_load_u16_le: function(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_load_u16_be: function(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_load_u32_le: function(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_load_u32_be: function(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_load_u64_le: function(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // OPENSSL_load_u64_be: function(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_store_u16_le(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_store_u16_be(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_store_u32_le(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_store_u32_be(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_store_u64_le(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_store_u64_be(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_load_u16_le(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_load_u16_be(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_load_u32_le(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_load_u32_be(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_load_u64_le(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl;
  { TODO 1 -cID Routine needs attention (Inline or Definition in header) }
  // function OPENSSL_load_u64_be(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl;
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

function OPENSSL_store_u16_le(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_store_u16_le';
function OPENSSL_store_u16_be(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_store_u16_be';
function OPENSSL_store_u32_le(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_store_u32_le';
function OPENSSL_store_u32_be(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_store_u32_be';
function OPENSSL_store_u64_le(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_store_u64_le';
function OPENSSL_store_u64_be(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_store_u64_be';
function OPENSSL_load_u16_le(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_load_u16_le';
function OPENSSL_load_u16_be(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_load_u16_be';
function OPENSSL_load_u32_le(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_load_u32_le';
function OPENSSL_load_u32_be(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_load_u32_be';
function OPENSSL_load_u64_le(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_load_u64_le';
function OPENSSL_load_u64_be(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_load_u64_be';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OPENSSL_store_u16_le_procname = 'OPENSSL_store_u16_le';
  OPENSSL_store_u16_le_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_store_u16_be_procname = 'OPENSSL_store_u16_be';
  OPENSSL_store_u16_be_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_store_u32_le_procname = 'OPENSSL_store_u32_le';
  OPENSSL_store_u32_le_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_store_u32_be_procname = 'OPENSSL_store_u32_be';
  OPENSSL_store_u32_be_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_store_u64_le_procname = 'OPENSSL_store_u64_le';
  OPENSSL_store_u64_le_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_store_u64_be_procname = 'OPENSSL_store_u64_be';
  OPENSSL_store_u64_be_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_load_u16_le_procname = 'OPENSSL_load_u16_le';
  OPENSSL_load_u16_le_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_load_u16_be_procname = 'OPENSSL_load_u16_be';
  OPENSSL_load_u16_be_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_load_u32_le_procname = 'OPENSSL_load_u32_le';
  OPENSSL_load_u32_le_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_load_u32_be_procname = 'OPENSSL_load_u32_be';
  OPENSSL_load_u32_be_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_load_u64_le_procname = 'OPENSSL_load_u64_le';
  OPENSSL_load_u64_le_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_load_u64_be_procname = 'OPENSSL_load_u64_be';
  OPENSSL_load_u64_be_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OPENSSL_store_u16_le(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_store_u16_le_procname);
end;

function ERR_OPENSSL_store_u16_be(_out: PIdAnsiChar; val: TIdC_UINT16): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_store_u16_be_procname);
end;

function ERR_OPENSSL_store_u32_le(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_store_u32_le_procname);
end;

function ERR_OPENSSL_store_u32_be(_out: PIdAnsiChar; val: TIdC_UINT32): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_store_u32_be_procname);
end;

function ERR_OPENSSL_store_u64_le(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_store_u64_le_procname);
end;

function ERR_OPENSSL_store_u64_be(_out: PIdAnsiChar; val: TIdC_UINT64): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_store_u64_be_procname);
end;

function ERR_OPENSSL_load_u16_le(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_load_u16_le_procname);
end;

function ERR_OPENSSL_load_u16_be(val: PIdC_UINT16; _in: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_load_u16_be_procname);
end;

function ERR_OPENSSL_load_u32_le(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_load_u32_le_procname);
end;

function ERR_OPENSSL_load_u32_be(val: PIdC_UINT32; _in: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_load_u32_be_procname);
end;

function ERR_OPENSSL_load_u64_le(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_load_u64_le_procname);
end;

function ERR_OPENSSL_load_u64_be(val: PIdC_UINT64; _in: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_load_u64_be_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OPENSSL_store_u16_le := LoadLibFunction(ADllHandle, OPENSSL_store_u16_le_procname);
  FuncLoadError := not assigned(OPENSSL_store_u16_le);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_store_u16_le_allownil)}
    OPENSSL_store_u16_le := ERR_OPENSSL_store_u16_le;
    {$ifend}
    {$if declared(OPENSSL_store_u16_le_introduced)}
    if LibVersion < OPENSSL_store_u16_le_introduced then
    begin
      {$if declared(FC_OPENSSL_store_u16_le)}
      OPENSSL_store_u16_le := FC_OPENSSL_store_u16_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_store_u16_le_removed)}
    if OPENSSL_store_u16_le_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_store_u16_le)}
      OPENSSL_store_u16_le := _OPENSSL_store_u16_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_store_u16_le_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_store_u16_le');
    {$ifend}
  end;
  
  OPENSSL_store_u16_be := LoadLibFunction(ADllHandle, OPENSSL_store_u16_be_procname);
  FuncLoadError := not assigned(OPENSSL_store_u16_be);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_store_u16_be_allownil)}
    OPENSSL_store_u16_be := ERR_OPENSSL_store_u16_be;
    {$ifend}
    {$if declared(OPENSSL_store_u16_be_introduced)}
    if LibVersion < OPENSSL_store_u16_be_introduced then
    begin
      {$if declared(FC_OPENSSL_store_u16_be)}
      OPENSSL_store_u16_be := FC_OPENSSL_store_u16_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_store_u16_be_removed)}
    if OPENSSL_store_u16_be_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_store_u16_be)}
      OPENSSL_store_u16_be := _OPENSSL_store_u16_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_store_u16_be_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_store_u16_be');
    {$ifend}
  end;
  
  OPENSSL_store_u32_le := LoadLibFunction(ADllHandle, OPENSSL_store_u32_le_procname);
  FuncLoadError := not assigned(OPENSSL_store_u32_le);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_store_u32_le_allownil)}
    OPENSSL_store_u32_le := ERR_OPENSSL_store_u32_le;
    {$ifend}
    {$if declared(OPENSSL_store_u32_le_introduced)}
    if LibVersion < OPENSSL_store_u32_le_introduced then
    begin
      {$if declared(FC_OPENSSL_store_u32_le)}
      OPENSSL_store_u32_le := FC_OPENSSL_store_u32_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_store_u32_le_removed)}
    if OPENSSL_store_u32_le_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_store_u32_le)}
      OPENSSL_store_u32_le := _OPENSSL_store_u32_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_store_u32_le_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_store_u32_le');
    {$ifend}
  end;
  
  OPENSSL_store_u32_be := LoadLibFunction(ADllHandle, OPENSSL_store_u32_be_procname);
  FuncLoadError := not assigned(OPENSSL_store_u32_be);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_store_u32_be_allownil)}
    OPENSSL_store_u32_be := ERR_OPENSSL_store_u32_be;
    {$ifend}
    {$if declared(OPENSSL_store_u32_be_introduced)}
    if LibVersion < OPENSSL_store_u32_be_introduced then
    begin
      {$if declared(FC_OPENSSL_store_u32_be)}
      OPENSSL_store_u32_be := FC_OPENSSL_store_u32_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_store_u32_be_removed)}
    if OPENSSL_store_u32_be_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_store_u32_be)}
      OPENSSL_store_u32_be := _OPENSSL_store_u32_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_store_u32_be_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_store_u32_be');
    {$ifend}
  end;
  
  OPENSSL_store_u64_le := LoadLibFunction(ADllHandle, OPENSSL_store_u64_le_procname);
  FuncLoadError := not assigned(OPENSSL_store_u64_le);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_store_u64_le_allownil)}
    OPENSSL_store_u64_le := ERR_OPENSSL_store_u64_le;
    {$ifend}
    {$if declared(OPENSSL_store_u64_le_introduced)}
    if LibVersion < OPENSSL_store_u64_le_introduced then
    begin
      {$if declared(FC_OPENSSL_store_u64_le)}
      OPENSSL_store_u64_le := FC_OPENSSL_store_u64_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_store_u64_le_removed)}
    if OPENSSL_store_u64_le_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_store_u64_le)}
      OPENSSL_store_u64_le := _OPENSSL_store_u64_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_store_u64_le_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_store_u64_le');
    {$ifend}
  end;
  
  OPENSSL_store_u64_be := LoadLibFunction(ADllHandle, OPENSSL_store_u64_be_procname);
  FuncLoadError := not assigned(OPENSSL_store_u64_be);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_store_u64_be_allownil)}
    OPENSSL_store_u64_be := ERR_OPENSSL_store_u64_be;
    {$ifend}
    {$if declared(OPENSSL_store_u64_be_introduced)}
    if LibVersion < OPENSSL_store_u64_be_introduced then
    begin
      {$if declared(FC_OPENSSL_store_u64_be)}
      OPENSSL_store_u64_be := FC_OPENSSL_store_u64_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_store_u64_be_removed)}
    if OPENSSL_store_u64_be_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_store_u64_be)}
      OPENSSL_store_u64_be := _OPENSSL_store_u64_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_store_u64_be_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_store_u64_be');
    {$ifend}
  end;
  
  OPENSSL_load_u16_le := LoadLibFunction(ADllHandle, OPENSSL_load_u16_le_procname);
  FuncLoadError := not assigned(OPENSSL_load_u16_le);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_u16_le_allownil)}
    OPENSSL_load_u16_le := ERR_OPENSSL_load_u16_le;
    {$ifend}
    {$if declared(OPENSSL_load_u16_le_introduced)}
    if LibVersion < OPENSSL_load_u16_le_introduced then
    begin
      {$if declared(FC_OPENSSL_load_u16_le)}
      OPENSSL_load_u16_le := FC_OPENSSL_load_u16_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_u16_le_removed)}
    if OPENSSL_load_u16_le_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_u16_le)}
      OPENSSL_load_u16_le := _OPENSSL_load_u16_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_u16_le_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_u16_le');
    {$ifend}
  end;
  
  OPENSSL_load_u16_be := LoadLibFunction(ADllHandle, OPENSSL_load_u16_be_procname);
  FuncLoadError := not assigned(OPENSSL_load_u16_be);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_u16_be_allownil)}
    OPENSSL_load_u16_be := ERR_OPENSSL_load_u16_be;
    {$ifend}
    {$if declared(OPENSSL_load_u16_be_introduced)}
    if LibVersion < OPENSSL_load_u16_be_introduced then
    begin
      {$if declared(FC_OPENSSL_load_u16_be)}
      OPENSSL_load_u16_be := FC_OPENSSL_load_u16_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_u16_be_removed)}
    if OPENSSL_load_u16_be_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_u16_be)}
      OPENSSL_load_u16_be := _OPENSSL_load_u16_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_u16_be_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_u16_be');
    {$ifend}
  end;
  
  OPENSSL_load_u32_le := LoadLibFunction(ADllHandle, OPENSSL_load_u32_le_procname);
  FuncLoadError := not assigned(OPENSSL_load_u32_le);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_u32_le_allownil)}
    OPENSSL_load_u32_le := ERR_OPENSSL_load_u32_le;
    {$ifend}
    {$if declared(OPENSSL_load_u32_le_introduced)}
    if LibVersion < OPENSSL_load_u32_le_introduced then
    begin
      {$if declared(FC_OPENSSL_load_u32_le)}
      OPENSSL_load_u32_le := FC_OPENSSL_load_u32_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_u32_le_removed)}
    if OPENSSL_load_u32_le_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_u32_le)}
      OPENSSL_load_u32_le := _OPENSSL_load_u32_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_u32_le_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_u32_le');
    {$ifend}
  end;
  
  OPENSSL_load_u32_be := LoadLibFunction(ADllHandle, OPENSSL_load_u32_be_procname);
  FuncLoadError := not assigned(OPENSSL_load_u32_be);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_u32_be_allownil)}
    OPENSSL_load_u32_be := ERR_OPENSSL_load_u32_be;
    {$ifend}
    {$if declared(OPENSSL_load_u32_be_introduced)}
    if LibVersion < OPENSSL_load_u32_be_introduced then
    begin
      {$if declared(FC_OPENSSL_load_u32_be)}
      OPENSSL_load_u32_be := FC_OPENSSL_load_u32_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_u32_be_removed)}
    if OPENSSL_load_u32_be_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_u32_be)}
      OPENSSL_load_u32_be := _OPENSSL_load_u32_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_u32_be_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_u32_be');
    {$ifend}
  end;
  
  OPENSSL_load_u64_le := LoadLibFunction(ADllHandle, OPENSSL_load_u64_le_procname);
  FuncLoadError := not assigned(OPENSSL_load_u64_le);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_u64_le_allownil)}
    OPENSSL_load_u64_le := ERR_OPENSSL_load_u64_le;
    {$ifend}
    {$if declared(OPENSSL_load_u64_le_introduced)}
    if LibVersion < OPENSSL_load_u64_le_introduced then
    begin
      {$if declared(FC_OPENSSL_load_u64_le)}
      OPENSSL_load_u64_le := FC_OPENSSL_load_u64_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_u64_le_removed)}
    if OPENSSL_load_u64_le_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_u64_le)}
      OPENSSL_load_u64_le := _OPENSSL_load_u64_le;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_u64_le_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_u64_le');
    {$ifend}
  end;
  
  OPENSSL_load_u64_be := LoadLibFunction(ADllHandle, OPENSSL_load_u64_be_procname);
  FuncLoadError := not assigned(OPENSSL_load_u64_be);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_load_u64_be_allownil)}
    OPENSSL_load_u64_be := ERR_OPENSSL_load_u64_be;
    {$ifend}
    {$if declared(OPENSSL_load_u64_be_introduced)}
    if LibVersion < OPENSSL_load_u64_be_introduced then
    begin
      {$if declared(FC_OPENSSL_load_u64_be)}
      OPENSSL_load_u64_be := FC_OPENSSL_load_u64_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_load_u64_be_removed)}
    if OPENSSL_load_u64_be_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_load_u64_be)}
      OPENSSL_load_u64_be := _OPENSSL_load_u64_be;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_load_u64_be_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_load_u64_be');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OPENSSL_store_u16_le := nil;
  OPENSSL_store_u16_be := nil;
  OPENSSL_store_u32_le := nil;
  OPENSSL_store_u32_be := nil;
  OPENSSL_store_u64_le := nil;
  OPENSSL_store_u64_be := nil;
  OPENSSL_load_u16_le := nil;
  OPENSSL_load_u16_be := nil;
  OPENSSL_load_u32_le := nil;
  OPENSSL_load_u32_be := nil;
  OPENSSL_load_u64_le := nil;
  OPENSSL_load_u64_be := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.