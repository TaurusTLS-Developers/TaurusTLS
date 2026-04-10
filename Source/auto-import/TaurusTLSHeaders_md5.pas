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

unit TaurusTLSHeaders_md5;

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
  PMD5state_st = ^TMD5state_st;
  TMD5state_st =   record
    A: TIdC_UINT;
    B: TIdC_UINT;
    C: TIdC_UINT;
    D: TIdC_UINT;
    Nl: TIdC_UINT;
    Nh: TIdC_UINT;
    data: PIdC_UINT;
    num: TIdC_UINT;
  end;
  {$EXTERNALSYM PMD5state_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  MD5_DIGEST_LENGTH = 16;
  MD5_LONG = unsignedint;
  MD5_CBLOCK = 64;
  MD5_LBLOCK = (MD5_CBLOCK/4);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  MD5_Init: function(c: PMD5_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD5_Init}

  MD5_Update: function(c: PMD5_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD5_Update}

  MD5_Final: function(md: PIdAnsiChar; c: PMD5_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD5_Final}

  MD5: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD5}

  MD5_Transform: function(c: PMD5_CTX; b: PIdAnsiChar): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MD5_Transform}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function MD5_Init(c: PMD5_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MD5_Update(c: PMD5_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MD5_Final(md: PIdAnsiChar; c: PMD5_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MD5(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function MD5_Transform(c: PMD5_CTX; b: PIdAnsiChar): void; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function MD5_Init(c: PMD5_CTX): TIdC_INT; cdecl external CLibCrypto name 'MD5_Init';
function MD5_Update(c: PMD5_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'MD5_Update';
function MD5_Final(md: PIdAnsiChar; c: PMD5_CTX): TIdC_INT; cdecl external CLibCrypto name 'MD5_Final';
function MD5(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'MD5';
function MD5_Transform(c: PMD5_CTX; b: PIdAnsiChar): void; cdecl external CLibCrypto name 'MD5_Transform';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  MD5_Init_procname = 'MD5_Init';
  MD5_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD5_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD5_Update_procname = 'MD5_Update';
  MD5_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD5_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD5_Final_procname = 'MD5_Final';
  MD5_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD5_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD5_procname = 'MD5';
  MD5_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD5_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MD5_Transform_procname = 'MD5_Transform';
  MD5_Transform_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MD5_Transform_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_MD5_Init(c: PMD5_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD5_Init_procname);
end;

function ERR_MD5_Update(c: PMD5_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD5_Update_procname);
end;

function ERR_MD5_Final(md: PIdAnsiChar; c: PMD5_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD5_Final_procname);
end;

function ERR_MD5(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD5_procname);
end;

function ERR_MD5_Transform(c: PMD5_CTX; b: PIdAnsiChar): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MD5_Transform_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  MD5_Init := LoadLibFunction(ADllHandle, MD5_Init_procname);
  FuncLoadError := not assigned(MD5_Init);
  if FuncLoadError then
  begin
    {$if not defined(MD5_Init_allownil)}
    MD5_Init := ERR_MD5_Init;
    {$ifend}
    {$if declared(MD5_Init_introduced)}
    if LibVersion < MD5_Init_introduced then
    begin
      {$if declared(FC_MD5_Init)}
      MD5_Init := FC_MD5_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD5_Init_removed)}
    if MD5_Init_removed <= LibVersion then
    begin
      {$if declared(_MD5_Init)}
      MD5_Init := _MD5_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD5_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('MD5_Init');
    {$ifend}
  end;
  
  MD5_Update := LoadLibFunction(ADllHandle, MD5_Update_procname);
  FuncLoadError := not assigned(MD5_Update);
  if FuncLoadError then
  begin
    {$if not defined(MD5_Update_allownil)}
    MD5_Update := ERR_MD5_Update;
    {$ifend}
    {$if declared(MD5_Update_introduced)}
    if LibVersion < MD5_Update_introduced then
    begin
      {$if declared(FC_MD5_Update)}
      MD5_Update := FC_MD5_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD5_Update_removed)}
    if MD5_Update_removed <= LibVersion then
    begin
      {$if declared(_MD5_Update)}
      MD5_Update := _MD5_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD5_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('MD5_Update');
    {$ifend}
  end;
  
  MD5_Final := LoadLibFunction(ADllHandle, MD5_Final_procname);
  FuncLoadError := not assigned(MD5_Final);
  if FuncLoadError then
  begin
    {$if not defined(MD5_Final_allownil)}
    MD5_Final := ERR_MD5_Final;
    {$ifend}
    {$if declared(MD5_Final_introduced)}
    if LibVersion < MD5_Final_introduced then
    begin
      {$if declared(FC_MD5_Final)}
      MD5_Final := FC_MD5_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD5_Final_removed)}
    if MD5_Final_removed <= LibVersion then
    begin
      {$if declared(_MD5_Final)}
      MD5_Final := _MD5_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD5_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('MD5_Final');
    {$ifend}
  end;
  
  MD5 := LoadLibFunction(ADllHandle, MD5_procname);
  FuncLoadError := not assigned(MD5);
  if FuncLoadError then
  begin
    {$if not defined(MD5_allownil)}
    MD5 := ERR_MD5;
    {$ifend}
    {$if declared(MD5_introduced)}
    if LibVersion < MD5_introduced then
    begin
      {$if declared(FC_MD5)}
      MD5 := FC_MD5;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD5_removed)}
    if MD5_removed <= LibVersion then
    begin
      {$if declared(_MD5)}
      MD5 := _MD5;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD5_allownil)}
    if FuncLoadError then
      AFailed.Add('MD5');
    {$ifend}
  end;
  
  MD5_Transform := LoadLibFunction(ADllHandle, MD5_Transform_procname);
  FuncLoadError := not assigned(MD5_Transform);
  if FuncLoadError then
  begin
    {$if not defined(MD5_Transform_allownil)}
    MD5_Transform := ERR_MD5_Transform;
    {$ifend}
    {$if declared(MD5_Transform_introduced)}
    if LibVersion < MD5_Transform_introduced then
    begin
      {$if declared(FC_MD5_Transform)}
      MD5_Transform := FC_MD5_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MD5_Transform_removed)}
    if MD5_Transform_removed <= LibVersion then
    begin
      {$if declared(_MD5_Transform)}
      MD5_Transform := _MD5_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MD5_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('MD5_Transform');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  MD5_Init := nil;
  MD5_Update := nil;
  MD5_Final := nil;
  MD5 := nil;
  MD5_Transform := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.