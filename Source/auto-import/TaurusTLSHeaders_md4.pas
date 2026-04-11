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

unit TaurusTLSHeaders_md4;

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



// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  PMD4state_st = ^TMD4state_st;
  TMD4state_st =   record
    A: TIdC_UINT;
    B: TIdC_UINT;
    C: TIdC_UINT;
    D: TIdC_UINT;
    Nl: TIdC_UINT;
    Nh: TIdC_UINT;
    data: PIdC_UINT;
    num: TIdC_UINT;
  end;
  {$EXTERNALSYM PMD4state_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  MD4_DIGEST_LENGTH = 16;
  MD4_LONG = unsignedint;
  MD4_CBLOCK = 64;
  MD4_LBLOCK = (MD4_CBLOCK/4);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  MD4_Init: function(c: PMD4_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD4_Init}

  MD4_Update: function(c: PMD4_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD4_Update}

  MD4_Final: function(md: PIdAnsiChar; c: PMD4_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD4_Final}

  MD4: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD4}

  MD4_Transform: procedure(c: PMD4_CTX; b: PIdAnsiChar); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD4_Transform}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function MD4_Init(c: PMD4_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MD4_Update(c: PMD4_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MD4_Final(md: PIdAnsiChar; c: PMD4_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MD4(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure MD4_Transform(c: PMD4_CTX; b: PIdAnsiChar); cdecl; deprecated 'In OpenSSL 3_0_0';
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

function MD4_Init(c: PMD4_CTX): TIdC_INT; cdecl external CLibCrypto name 'MD4_Init';
function MD4_Update(c: PMD4_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'MD4_Update';
function MD4_Final(md: PIdAnsiChar; c: PMD4_CTX): TIdC_INT; cdecl external CLibCrypto name 'MD4_Final';
function MD4(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'MD4';
procedure MD4_Transform(c: PMD4_CTX; b: PIdAnsiChar); cdecl external CLibCrypto name 'MD4_Transform';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  MD4_Init_procname = 'MD4_Init';
  MD4_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD4_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD4_Update_procname = 'MD4_Update';
  MD4_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD4_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD4_Final_procname = 'MD4_Final';
  MD4_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD4_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD4_procname = 'MD4';
  MD4_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD4_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD4_Transform_procname = 'MD4_Transform';
  MD4_Transform_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD4_Transform_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_MD4_Init(c: PMD4_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD4_Init_procname);
end;

function ERR_MD4_Update(c: PMD4_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD4_Update_procname);
end;

function ERR_MD4_Final(md: PIdAnsiChar; c: PMD4_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD4_Final_procname);
end;

function ERR_MD4(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD4_procname);
end;

procedure ERR_MD4_Transform(c: PMD4_CTX; b: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD4_Transform_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  MD4_Init := LoadLibFunction(ADllHandle, MD4_Init_procname);
  FuncLoadError := not assigned(MD4_Init);
  if FuncLoadError then
  begin
    {$if not defined(MD4_Init_allownil)}
    MD4_Init := ERR_MD4_Init;
    {$ifend}
    {$if declared(MD4_Init_introduced)}
    if LibVersion < MD4_Init_introduced then
    begin
      {$if declared(FC_MD4_Init)}
      MD4_Init := FC_MD4_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD4_Init_removed)}
    if MD4_Init_removed <= LibVersion then
    begin
      {$if declared(_MD4_Init)}
      MD4_Init := _MD4_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD4_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('MD4_Init');
    {$ifend}
  end;
  
  MD4_Update := LoadLibFunction(ADllHandle, MD4_Update_procname);
  FuncLoadError := not assigned(MD4_Update);
  if FuncLoadError then
  begin
    {$if not defined(MD4_Update_allownil)}
    MD4_Update := ERR_MD4_Update;
    {$ifend}
    {$if declared(MD4_Update_introduced)}
    if LibVersion < MD4_Update_introduced then
    begin
      {$if declared(FC_MD4_Update)}
      MD4_Update := FC_MD4_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD4_Update_removed)}
    if MD4_Update_removed <= LibVersion then
    begin
      {$if declared(_MD4_Update)}
      MD4_Update := _MD4_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD4_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('MD4_Update');
    {$ifend}
  end;
  
  MD4_Final := LoadLibFunction(ADllHandle, MD4_Final_procname);
  FuncLoadError := not assigned(MD4_Final);
  if FuncLoadError then
  begin
    {$if not defined(MD4_Final_allownil)}
    MD4_Final := ERR_MD4_Final;
    {$ifend}
    {$if declared(MD4_Final_introduced)}
    if LibVersion < MD4_Final_introduced then
    begin
      {$if declared(FC_MD4_Final)}
      MD4_Final := FC_MD4_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD4_Final_removed)}
    if MD4_Final_removed <= LibVersion then
    begin
      {$if declared(_MD4_Final)}
      MD4_Final := _MD4_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD4_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('MD4_Final');
    {$ifend}
  end;
  
  MD4 := LoadLibFunction(ADllHandle, MD4_procname);
  FuncLoadError := not assigned(MD4);
  if FuncLoadError then
  begin
    {$if not defined(MD4_allownil)}
    MD4 := ERR_MD4;
    {$ifend}
    {$if declared(MD4_introduced)}
    if LibVersion < MD4_introduced then
    begin
      {$if declared(FC_MD4)}
      MD4 := FC_MD4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD4_removed)}
    if MD4_removed <= LibVersion then
    begin
      {$if declared(_MD4)}
      MD4 := _MD4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD4_allownil)}
    if FuncLoadError then
      AFailed.Add('MD4');
    {$ifend}
  end;
  
  MD4_Transform := LoadLibFunction(ADllHandle, MD4_Transform_procname);
  FuncLoadError := not assigned(MD4_Transform);
  if FuncLoadError then
  begin
    {$if not defined(MD4_Transform_allownil)}
    MD4_Transform := ERR_MD4_Transform;
    {$ifend}
    {$if declared(MD4_Transform_introduced)}
    if LibVersion < MD4_Transform_introduced then
    begin
      {$if declared(FC_MD4_Transform)}
      MD4_Transform := FC_MD4_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD4_Transform_removed)}
    if MD4_Transform_removed <= LibVersion then
    begin
      {$if declared(_MD4_Transform)}
      MD4_Transform := _MD4_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD4_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('MD4_Transform');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  MD4_Init := nil;
  MD4_Update := nil;
  MD4_Final := nil;
  MD4 := nil;
  MD4_Transform := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.