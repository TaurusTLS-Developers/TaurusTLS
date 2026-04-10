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

unit TaurusTLSHeaders_rc4;

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
  Prc4_key_st = ^Trc4_key_st;
  Trc4_key_st =   record
    x: TIdC_UINT;
    y: TIdC_UINT;
    data: PIdC_UINT;
  end;
  {$EXTERNALSYM Prc4_key_st}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  RC4_options: function: PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC4_options}

  RC4_set_key: function(key: PRC4_KEY; len: TIdC_INT; data: PIdAnsiChar): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC4_set_key}

  RC4: function(key: PRC4_KEY; len: TIdC_SIZET; indata: PIdAnsiChar; outdata: PIdAnsiChar): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC4}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function RC4_options: PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function RC4_set_key(key: PRC4_KEY; len: TIdC_INT; data: PIdAnsiChar): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RC4(key: PRC4_KEY; len: TIdC_SIZET; indata: PIdAnsiChar; outdata: PIdAnsiChar): void; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function RC4_options: PIdAnsiChar; cdecl external CLibCrypto name 'RC4_options';
function RC4_set_key(key: PRC4_KEY; len: TIdC_INT; data: PIdAnsiChar): void; cdecl external CLibCrypto name 'RC4_set_key';
function RC4(key: PRC4_KEY; len: TIdC_SIZET; indata: PIdAnsiChar; outdata: PIdAnsiChar): void; cdecl external CLibCrypto name 'RC4';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  RC4_options_procname = 'RC4_options';
  RC4_options_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC4_options_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC4_set_key_procname = 'RC4_set_key';
  RC4_set_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC4_set_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC4_procname = 'RC4';
  RC4_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC4_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_RC4_options: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC4_options_procname);
end;

function ERR_RC4_set_key(key: PRC4_KEY; len: TIdC_INT; data: PIdAnsiChar): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC4_set_key_procname);
end;

function ERR_RC4(key: PRC4_KEY; len: TIdC_SIZET; indata: PIdAnsiChar; outdata: PIdAnsiChar): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC4_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  RC4_options := LoadLibFunction(ADllHandle, RC4_options_procname);
  FuncLoadError := not assigned(RC4_options);
  if FuncLoadError then
  begin
    {$if not defined(RC4_options_allownil)}
    RC4_options := ERR_RC4_options;
    {$ifend}
    {$if declared(RC4_options_introduced)}
    if LibVersion < RC4_options_introduced then
    begin
      {$if declared(FC_RC4_options)}
      RC4_options := FC_RC4_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC4_options_removed)}
    if RC4_options_removed <= LibVersion then
    begin
      {$if declared(_RC4_options)}
      RC4_options := _RC4_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC4_options_allownil)}
    if FuncLoadError then
      AFailed.Add('RC4_options');
    {$ifend}
  end;
  
  RC4_set_key := LoadLibFunction(ADllHandle, RC4_set_key_procname);
  FuncLoadError := not assigned(RC4_set_key);
  if FuncLoadError then
  begin
    {$if not defined(RC4_set_key_allownil)}
    RC4_set_key := ERR_RC4_set_key;
    {$ifend}
    {$if declared(RC4_set_key_introduced)}
    if LibVersion < RC4_set_key_introduced then
    begin
      {$if declared(FC_RC4_set_key)}
      RC4_set_key := FC_RC4_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC4_set_key_removed)}
    if RC4_set_key_removed <= LibVersion then
    begin
      {$if declared(_RC4_set_key)}
      RC4_set_key := _RC4_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC4_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('RC4_set_key');
    {$ifend}
  end;
  
  RC4 := LoadLibFunction(ADllHandle, RC4_procname);
  FuncLoadError := not assigned(RC4);
  if FuncLoadError then
  begin
    {$if not defined(RC4_allownil)}
    RC4 := ERR_RC4;
    {$ifend}
    {$if declared(RC4_introduced)}
    if LibVersion < RC4_introduced then
    begin
      {$if declared(FC_RC4)}
      RC4 := FC_RC4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC4_removed)}
    if RC4_removed <= LibVersion then
    begin
      {$if declared(_RC4)}
      RC4 := _RC4;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC4_allownil)}
    if FuncLoadError then
      AFailed.Add('RC4');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  RC4_options := nil;
  RC4_set_key := nil;
  RC4 := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.