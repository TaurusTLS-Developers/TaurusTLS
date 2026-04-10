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

unit TaurusTLSHeaders_whrlpool;

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
  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // struct {
  //     union {
  //         unsigned char c[WHIRLPOOL_DIGEST_LENGTH];
  //         /* double q is here to ensure 64-bit alignment */
  //         double q[WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
  //     } H;
  //     unsigned char data[WHIRLPOOL_BBLOCK / 8];
  //     unsigned int bitoff;
  //     size_t bitlen[WHIRLPOOL_COUNTER / sizeof(size_t)];
  // }


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  WHIRLPOOL_DIGEST_LENGTH = (512/8);
  WHIRLPOOL_BBLOCK = 512;
  WHIRLPOOL_COUNTER = (256/8);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  WHIRLPOOL_Init: function(c: PWHIRLPOOL_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM WHIRLPOOL_Init}

  WHIRLPOOL_Update: function(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM WHIRLPOOL_Update}

  WHIRLPOOL_BitUpdate: function(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TIdC_SIZET): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM WHIRLPOOL_BitUpdate}

  WHIRLPOOL_Final: function(md: PIdAnsiChar; c: PWHIRLPOOL_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM WHIRLPOOL_Final}

  WHIRLPOOL: function(inp: Pointer; bytes: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM WHIRLPOOL}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TIdC_SIZET): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function WHIRLPOOL_Final(md: PIdAnsiChar; c: PWHIRLPOOL_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function WHIRLPOOL(inp: Pointer; bytes: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TIdC_INT; cdecl external CLibCrypto name 'WHIRLPOOL_Init';
function WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'WHIRLPOOL_Update';
function WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TIdC_SIZET): void; cdecl external CLibCrypto name 'WHIRLPOOL_BitUpdate';
function WHIRLPOOL_Final(md: PIdAnsiChar; c: PWHIRLPOOL_CTX): TIdC_INT; cdecl external CLibCrypto name 'WHIRLPOOL_Final';
function WHIRLPOOL(inp: Pointer; bytes: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'WHIRLPOOL';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  WHIRLPOOL_Init_procname = 'WHIRLPOOL_Init';
  WHIRLPOOL_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  WHIRLPOOL_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  WHIRLPOOL_Update_procname = 'WHIRLPOOL_Update';
  WHIRLPOOL_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  WHIRLPOOL_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  WHIRLPOOL_BitUpdate_procname = 'WHIRLPOOL_BitUpdate';
  WHIRLPOOL_BitUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  WHIRLPOOL_BitUpdate_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  WHIRLPOOL_Final_procname = 'WHIRLPOOL_Final';
  WHIRLPOOL_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  WHIRLPOOL_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  WHIRLPOOL_procname = 'WHIRLPOOL';
  WHIRLPOOL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  WHIRLPOOL_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_Init_procname);
end;

function ERR_WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_Update_procname);
end;

function ERR_WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TIdC_SIZET): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_BitUpdate_procname);
end;

function ERR_WHIRLPOOL_Final(md: PIdAnsiChar; c: PWHIRLPOOL_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_Final_procname);
end;

function ERR_WHIRLPOOL(inp: Pointer; bytes: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  WHIRLPOOL_Init := LoadLibFunction(ADllHandle, WHIRLPOOL_Init_procname);
  FuncLoadError := not assigned(WHIRLPOOL_Init);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_Init_allownil)}
    WHIRLPOOL_Init := ERR_WHIRLPOOL_Init;
    {$ifend}
    {$if declared(WHIRLPOOL_Init_introduced)}
    if LibVersion < WHIRLPOOL_Init_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_Init)}
      WHIRLPOOL_Init := FC_WHIRLPOOL_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_Init_removed)}
    if WHIRLPOOL_Init_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_Init)}
      WHIRLPOOL_Init := _WHIRLPOOL_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_Init');
    {$ifend}
  end;
  
  WHIRLPOOL_Update := LoadLibFunction(ADllHandle, WHIRLPOOL_Update_procname);
  FuncLoadError := not assigned(WHIRLPOOL_Update);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_Update_allownil)}
    WHIRLPOOL_Update := ERR_WHIRLPOOL_Update;
    {$ifend}
    {$if declared(WHIRLPOOL_Update_introduced)}
    if LibVersion < WHIRLPOOL_Update_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_Update)}
      WHIRLPOOL_Update := FC_WHIRLPOOL_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_Update_removed)}
    if WHIRLPOOL_Update_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_Update)}
      WHIRLPOOL_Update := _WHIRLPOOL_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_Update');
    {$ifend}
  end;
  
  WHIRLPOOL_BitUpdate := LoadLibFunction(ADllHandle, WHIRLPOOL_BitUpdate_procname);
  FuncLoadError := not assigned(WHIRLPOOL_BitUpdate);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_BitUpdate_allownil)}
    WHIRLPOOL_BitUpdate := ERR_WHIRLPOOL_BitUpdate;
    {$ifend}
    {$if declared(WHIRLPOOL_BitUpdate_introduced)}
    if LibVersion < WHIRLPOOL_BitUpdate_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_BitUpdate)}
      WHIRLPOOL_BitUpdate := FC_WHIRLPOOL_BitUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_BitUpdate_removed)}
    if WHIRLPOOL_BitUpdate_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_BitUpdate)}
      WHIRLPOOL_BitUpdate := _WHIRLPOOL_BitUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_BitUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_BitUpdate');
    {$ifend}
  end;
  
  WHIRLPOOL_Final := LoadLibFunction(ADllHandle, WHIRLPOOL_Final_procname);
  FuncLoadError := not assigned(WHIRLPOOL_Final);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_Final_allownil)}
    WHIRLPOOL_Final := ERR_WHIRLPOOL_Final;
    {$ifend}
    {$if declared(WHIRLPOOL_Final_introduced)}
    if LibVersion < WHIRLPOOL_Final_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_Final)}
      WHIRLPOOL_Final := FC_WHIRLPOOL_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_Final_removed)}
    if WHIRLPOOL_Final_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_Final)}
      WHIRLPOOL_Final := _WHIRLPOOL_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_Final');
    {$ifend}
  end;
  
  WHIRLPOOL := LoadLibFunction(ADllHandle, WHIRLPOOL_procname);
  FuncLoadError := not assigned(WHIRLPOOL);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_allownil)}
    WHIRLPOOL := ERR_WHIRLPOOL;
    {$ifend}
    {$if declared(WHIRLPOOL_introduced)}
    if LibVersion < WHIRLPOOL_introduced then
    begin
      {$if declared(FC_WHIRLPOOL)}
      WHIRLPOOL := FC_WHIRLPOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_removed)}
    if WHIRLPOOL_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL)}
      WHIRLPOOL := _WHIRLPOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  WHIRLPOOL_Init := nil;
  WHIRLPOOL_Update := nil;
  WHIRLPOOL_BitUpdate := nil;
  WHIRLPOOL_Final := nil;
  WHIRLPOOL := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.