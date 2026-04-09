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

unit TaurusTLSHeaders_ripemd;

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
  PRIPEMD160state_st = ^TRIPEMD160state_st;
  TRIPEMD160state_st = record end;
  {$EXTERNALSYM PRIPEMD160state_st}

  PRIPEMD160_CTX = ^TRIPEMD160_CTX;
  TRIPEMD160_CTX = TRIPEMD160state_st;
  {$EXTERNALSYM PRIPEMD160_CTX}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  RIPEMD160_DIGEST_LENGTH = 20;
  RIPEMD160_LONG = unsignedint;
  RIPEMD160_CBLOCK = 64;
  RIPEMD160_LBLOCK = (RIPEMD160_CBLOCK/4);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  RIPEMD160_Init: function(c: PRIPEMD160_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RIPEMD160_Init}

  RIPEMD160_Update: function(c: PRIPEMD160_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RIPEMD160_Update}

  RIPEMD160_Final: function(md: PIdAnsiChar; c: PRIPEMD160_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RIPEMD160_Final}

  RIPEMD160: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RIPEMD160}

  RIPEMD160_Transform: procedure(c: PRIPEMD160_CTX; b: PIdAnsiChar); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RIPEMD160_Transform}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function RIPEMD160_Init(c: PRIPEMD160_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RIPEMD160_Update(c: PRIPEMD160_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RIPEMD160_Final(md: PIdAnsiChar; c: PRIPEMD160_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RIPEMD160(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure RIPEMD160_Transform(c: PRIPEMD160_CTX; b: PIdAnsiChar); cdecl; deprecated 'In OpenSSL 3_0_0';
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

function RIPEMD160_Init(c: PRIPEMD160_CTX): TIdC_INT; cdecl external CLibCrypto name 'RIPEMD160_Init';
function RIPEMD160_Update(c: PRIPEMD160_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'RIPEMD160_Update';
function RIPEMD160_Final(md: PIdAnsiChar; c: PRIPEMD160_CTX): TIdC_INT; cdecl external CLibCrypto name 'RIPEMD160_Final';
function RIPEMD160(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'RIPEMD160';
procedure RIPEMD160_Transform(c: PRIPEMD160_CTX; b: PIdAnsiChar); cdecl external CLibCrypto name 'RIPEMD160_Transform';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  RIPEMD160_Init_procname = 'RIPEMD160_Init';
  RIPEMD160_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RIPEMD160_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RIPEMD160_Update_procname = 'RIPEMD160_Update';
  RIPEMD160_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RIPEMD160_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RIPEMD160_Final_procname = 'RIPEMD160_Final';
  RIPEMD160_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RIPEMD160_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RIPEMD160_procname = 'RIPEMD160';
  RIPEMD160_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RIPEMD160_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RIPEMD160_Transform_procname = 'RIPEMD160_Transform';
  RIPEMD160_Transform_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RIPEMD160_Transform_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_RIPEMD160_Init(c: PRIPEMD160_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RIPEMD160_Init_procname);
end;

function ERR_RIPEMD160_Update(c: PRIPEMD160_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RIPEMD160_Update_procname);
end;

function ERR_RIPEMD160_Final(md: PIdAnsiChar; c: PRIPEMD160_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RIPEMD160_Final_procname);
end;

function ERR_RIPEMD160(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RIPEMD160_procname);
end;

procedure ERR_RIPEMD160_Transform(c: PRIPEMD160_CTX; b: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RIPEMD160_Transform_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  RIPEMD160_Init := LoadLibFunction(ADllHandle, RIPEMD160_Init_procname);
  FuncLoadError := not assigned(RIPEMD160_Init);
  if FuncLoadError then
  begin
    {$if not defined(RIPEMD160_Init_allownil)}
    RIPEMD160_Init := ERR_RIPEMD160_Init;
    {$ifend}
    {$if declared(RIPEMD160_Init_introduced)}
    if LibVersion < RIPEMD160_Init_introduced then
    begin
      {$if declared(FC_RIPEMD160_Init)}
      RIPEMD160_Init := FC_RIPEMD160_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RIPEMD160_Init_removed)}
    if RIPEMD160_Init_removed <= LibVersion then
    begin
      {$if declared(_RIPEMD160_Init)}
      RIPEMD160_Init := _RIPEMD160_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RIPEMD160_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('RIPEMD160_Init');
    {$ifend}
  end;
  
  RIPEMD160_Update := LoadLibFunction(ADllHandle, RIPEMD160_Update_procname);
  FuncLoadError := not assigned(RIPEMD160_Update);
  if FuncLoadError then
  begin
    {$if not defined(RIPEMD160_Update_allownil)}
    RIPEMD160_Update := ERR_RIPEMD160_Update;
    {$ifend}
    {$if declared(RIPEMD160_Update_introduced)}
    if LibVersion < RIPEMD160_Update_introduced then
    begin
      {$if declared(FC_RIPEMD160_Update)}
      RIPEMD160_Update := FC_RIPEMD160_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RIPEMD160_Update_removed)}
    if RIPEMD160_Update_removed <= LibVersion then
    begin
      {$if declared(_RIPEMD160_Update)}
      RIPEMD160_Update := _RIPEMD160_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RIPEMD160_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('RIPEMD160_Update');
    {$ifend}
  end;
  
  RIPEMD160_Final := LoadLibFunction(ADllHandle, RIPEMD160_Final_procname);
  FuncLoadError := not assigned(RIPEMD160_Final);
  if FuncLoadError then
  begin
    {$if not defined(RIPEMD160_Final_allownil)}
    RIPEMD160_Final := ERR_RIPEMD160_Final;
    {$ifend}
    {$if declared(RIPEMD160_Final_introduced)}
    if LibVersion < RIPEMD160_Final_introduced then
    begin
      {$if declared(FC_RIPEMD160_Final)}
      RIPEMD160_Final := FC_RIPEMD160_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RIPEMD160_Final_removed)}
    if RIPEMD160_Final_removed <= LibVersion then
    begin
      {$if declared(_RIPEMD160_Final)}
      RIPEMD160_Final := _RIPEMD160_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RIPEMD160_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('RIPEMD160_Final');
    {$ifend}
  end;
  
  RIPEMD160 := LoadLibFunction(ADllHandle, RIPEMD160_procname);
  FuncLoadError := not assigned(RIPEMD160);
  if FuncLoadError then
  begin
    {$if not defined(RIPEMD160_allownil)}
    RIPEMD160 := ERR_RIPEMD160;
    {$ifend}
    {$if declared(RIPEMD160_introduced)}
    if LibVersion < RIPEMD160_introduced then
    begin
      {$if declared(FC_RIPEMD160)}
      RIPEMD160 := FC_RIPEMD160;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RIPEMD160_removed)}
    if RIPEMD160_removed <= LibVersion then
    begin
      {$if declared(_RIPEMD160)}
      RIPEMD160 := _RIPEMD160;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RIPEMD160_allownil)}
    if FuncLoadError then
      AFailed.Add('RIPEMD160');
    {$ifend}
  end;
  
  RIPEMD160_Transform := LoadLibFunction(ADllHandle, RIPEMD160_Transform_procname);
  FuncLoadError := not assigned(RIPEMD160_Transform);
  if FuncLoadError then
  begin
    {$if not defined(RIPEMD160_Transform_allownil)}
    RIPEMD160_Transform := ERR_RIPEMD160_Transform;
    {$ifend}
    {$if declared(RIPEMD160_Transform_introduced)}
    if LibVersion < RIPEMD160_Transform_introduced then
    begin
      {$if declared(FC_RIPEMD160_Transform)}
      RIPEMD160_Transform := FC_RIPEMD160_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RIPEMD160_Transform_removed)}
    if RIPEMD160_Transform_removed <= LibVersion then
    begin
      {$if declared(_RIPEMD160_Transform)}
      RIPEMD160_Transform := _RIPEMD160_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RIPEMD160_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('RIPEMD160_Transform');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  RIPEMD160_Init := nil;
  RIPEMD160_Update := nil;
  RIPEMD160_Final := nil;
  RIPEMD160 := nil;
  RIPEMD160_Transform := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.