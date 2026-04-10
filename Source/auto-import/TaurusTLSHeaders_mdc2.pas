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

unit TaurusTLSHeaders_mdc2;

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
  Pmdc2_ctx_st = ^Tmdc2_ctx_st;
  Tmdc2_ctx_st =   record
    num: TIdC_UINT;
    data: PIdAnsiChar;
    h: TDES_cblock;
    hh: TDES_cblock;
    pad_type: TIdC_UINT;
  end;
  {$EXTERNALSYM Pmdc2_ctx_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  MDC2_DIGEST_LENGTH = 16;
  MDC2_BLOCK = 8;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  MDC2_Init: function(c: PMDC2_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MDC2_Init}

  MDC2_Update: function(c: PMDC2_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MDC2_Update}

  MDC2_Final: function(md: PIdAnsiChar; c: PMDC2_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MDC2_Final}

  MDC2: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM MDC2}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function MDC2_Init(c: PMDC2_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MDC2_Update(c: PMDC2_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MDC2_Final(md: PIdAnsiChar; c: PMDC2_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function MDC2(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function MDC2_Init(c: PMDC2_CTX): TIdC_INT; cdecl external CLibCrypto name 'MDC2_Init';
function MDC2_Update(c: PMDC2_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'MDC2_Update';
function MDC2_Final(md: PIdAnsiChar; c: PMDC2_CTX): TIdC_INT; cdecl external CLibCrypto name 'MDC2_Final';
function MDC2(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'MDC2';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  MDC2_Init_procname = 'MDC2_Init';
  MDC2_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MDC2_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MDC2_Update_procname = 'MDC2_Update';
  MDC2_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MDC2_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MDC2_Final_procname = 'MDC2_Final';
  MDC2_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MDC2_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  MDC2_procname = 'MDC2';
  MDC2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  MDC2_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_MDC2_Init(c: PMDC2_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MDC2_Init_procname);
end;

function ERR_MDC2_Update(c: PMDC2_CTX; data: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MDC2_Update_procname);
end;

function ERR_MDC2_Final(md: PIdAnsiChar; c: PMDC2_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MDC2_Final_procname);
end;

function ERR_MDC2(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(MDC2_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  MDC2_Init := LoadLibFunction(ADllHandle, MDC2_Init_procname);
  FuncLoadError := not assigned(MDC2_Init);
  if FuncLoadError then
  begin
    {$if not defined(MDC2_Init_allownil)}
    MDC2_Init := ERR_MDC2_Init;
    {$ifend}
    {$if declared(MDC2_Init_introduced)}
    if LibVersion < MDC2_Init_introduced then
    begin
      {$if declared(FC_MDC2_Init)}
      MDC2_Init := FC_MDC2_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MDC2_Init_removed)}
    if MDC2_Init_removed <= LibVersion then
    begin
      {$if declared(_MDC2_Init)}
      MDC2_Init := _MDC2_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MDC2_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('MDC2_Init');
    {$ifend}
  end;
  
  MDC2_Update := LoadLibFunction(ADllHandle, MDC2_Update_procname);
  FuncLoadError := not assigned(MDC2_Update);
  if FuncLoadError then
  begin
    {$if not defined(MDC2_Update_allownil)}
    MDC2_Update := ERR_MDC2_Update;
    {$ifend}
    {$if declared(MDC2_Update_introduced)}
    if LibVersion < MDC2_Update_introduced then
    begin
      {$if declared(FC_MDC2_Update)}
      MDC2_Update := FC_MDC2_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MDC2_Update_removed)}
    if MDC2_Update_removed <= LibVersion then
    begin
      {$if declared(_MDC2_Update)}
      MDC2_Update := _MDC2_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MDC2_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('MDC2_Update');
    {$ifend}
  end;
  
  MDC2_Final := LoadLibFunction(ADllHandle, MDC2_Final_procname);
  FuncLoadError := not assigned(MDC2_Final);
  if FuncLoadError then
  begin
    {$if not defined(MDC2_Final_allownil)}
    MDC2_Final := ERR_MDC2_Final;
    {$ifend}
    {$if declared(MDC2_Final_introduced)}
    if LibVersion < MDC2_Final_introduced then
    begin
      {$if declared(FC_MDC2_Final)}
      MDC2_Final := FC_MDC2_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MDC2_Final_removed)}
    if MDC2_Final_removed <= LibVersion then
    begin
      {$if declared(_MDC2_Final)}
      MDC2_Final := _MDC2_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MDC2_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('MDC2_Final');
    {$ifend}
  end;
  
  MDC2 := LoadLibFunction(ADllHandle, MDC2_procname);
  FuncLoadError := not assigned(MDC2);
  if FuncLoadError then
  begin
    {$if not defined(MDC2_allownil)}
    MDC2 := ERR_MDC2;
    {$ifend}
    {$if declared(MDC2_introduced)}
    if LibVersion < MDC2_introduced then
    begin
      {$if declared(FC_MDC2)}
      MDC2 := FC_MDC2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(MDC2_removed)}
    if MDC2_removed <= LibVersion then
    begin
      {$if declared(_MDC2)}
      MDC2 := _MDC2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(MDC2_allownil)}
    if FuncLoadError then
      AFailed.Add('MDC2');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  MDC2_Init := nil;
  MDC2_Update := nil;
  MDC2_Final := nil;
  MDC2 := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.