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

unit TaurusTLSHeaders_seed;

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
  Pseed_key_st = ^Tseed_key_st;
  Tseed_key_st =   record
    data: PIdC_UINT;
  end;
  {$EXTERNALSYM Pseed_key_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  SEED_BLOCK_SIZE = 16;
  SEED_KEY_LENGTH = 16;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  SEED_set_key: procedure(rawkey: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SEED_set_key}

  SEED_encrypt: procedure(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SEED_encrypt}

  SEED_decrypt: procedure(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SEED_decrypt}

  SEED_ecb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SEED_ecb_encrypt}

  SEED_cbc_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SEED_cbc_encrypt}

  SEED_cfb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SEED_cfb128_encrypt}

  SEED_ofb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SEED_ofb128_encrypt}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

procedure SEED_set_key(rawkey: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SEED_encrypt(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SEED_decrypt(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SEED_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SEED_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SEED_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SEED_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
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

procedure SEED_set_key(rawkey: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl external CLibCrypto name 'SEED_set_key';
procedure SEED_encrypt(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl external CLibCrypto name 'SEED_encrypt';
procedure SEED_decrypt(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl external CLibCrypto name 'SEED_decrypt';
procedure SEED_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE; enc: TIdC_INT); cdecl external CLibCrypto name 'SEED_ecb_encrypt';
procedure SEED_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'SEED_cbc_encrypt';
procedure SEED_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'SEED_cfb128_encrypt';
procedure SEED_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT); cdecl external CLibCrypto name 'SEED_ofb128_encrypt';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  SEED_set_key_procname = 'SEED_set_key';
  SEED_set_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SEED_set_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SEED_encrypt_procname = 'SEED_encrypt';
  SEED_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SEED_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SEED_decrypt_procname = 'SEED_decrypt';
  SEED_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SEED_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SEED_ecb_encrypt_procname = 'SEED_ecb_encrypt';
  SEED_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SEED_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SEED_cbc_encrypt_procname = 'SEED_cbc_encrypt';
  SEED_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SEED_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SEED_cfb128_encrypt_procname = 'SEED_cfb128_encrypt';
  SEED_cfb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SEED_cfb128_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SEED_ofb128_encrypt_procname = 'SEED_ofb128_encrypt';
  SEED_ofb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SEED_ofb128_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

procedure ERR_SEED_set_key(rawkey: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SEED_set_key_procname);
end;

procedure ERR_SEED_encrypt(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SEED_encrypt_procname);
end;

procedure ERR_SEED_decrypt(s: PIdAnsiChar; d: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SEED_decrypt_procname);
end;

procedure ERR_SEED_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PSEED_KEY_SCHEDULE; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SEED_ecb_encrypt_procname);
end;

procedure ERR_SEED_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SEED_cbc_encrypt_procname);
end;

procedure ERR_SEED_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SEED_cfb128_encrypt_procname);
end;

procedure ERR_SEED_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; len: TIdC_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: PIdAnsiChar; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SEED_ofb128_encrypt_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  SEED_set_key := LoadLibFunction(ADllHandle, SEED_set_key_procname);
  FuncLoadError := not assigned(SEED_set_key);
  if FuncLoadError then
  begin
    {$if not defined(SEED_set_key_allownil)}
    SEED_set_key := ERR_SEED_set_key;
    {$ifend}
    {$if declared(SEED_set_key_introduced)}
    if LibVersion < SEED_set_key_introduced then
    begin
      {$if declared(FC_SEED_set_key)}
      SEED_set_key := FC_SEED_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SEED_set_key_removed)}
    if SEED_set_key_removed <= LibVersion then
    begin
      {$if declared(_SEED_set_key)}
      SEED_set_key := _SEED_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SEED_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('SEED_set_key');
    {$ifend}
  end;
  
  SEED_encrypt := LoadLibFunction(ADllHandle, SEED_encrypt_procname);
  FuncLoadError := not assigned(SEED_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(SEED_encrypt_allownil)}
    SEED_encrypt := ERR_SEED_encrypt;
    {$ifend}
    {$if declared(SEED_encrypt_introduced)}
    if LibVersion < SEED_encrypt_introduced then
    begin
      {$if declared(FC_SEED_encrypt)}
      SEED_encrypt := FC_SEED_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SEED_encrypt_removed)}
    if SEED_encrypt_removed <= LibVersion then
    begin
      {$if declared(_SEED_encrypt)}
      SEED_encrypt := _SEED_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SEED_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('SEED_encrypt');
    {$ifend}
  end;
  
  SEED_decrypt := LoadLibFunction(ADllHandle, SEED_decrypt_procname);
  FuncLoadError := not assigned(SEED_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(SEED_decrypt_allownil)}
    SEED_decrypt := ERR_SEED_decrypt;
    {$ifend}
    {$if declared(SEED_decrypt_introduced)}
    if LibVersion < SEED_decrypt_introduced then
    begin
      {$if declared(FC_SEED_decrypt)}
      SEED_decrypt := FC_SEED_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SEED_decrypt_removed)}
    if SEED_decrypt_removed <= LibVersion then
    begin
      {$if declared(_SEED_decrypt)}
      SEED_decrypt := _SEED_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SEED_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('SEED_decrypt');
    {$ifend}
  end;
  
  SEED_ecb_encrypt := LoadLibFunction(ADllHandle, SEED_ecb_encrypt_procname);
  FuncLoadError := not assigned(SEED_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(SEED_ecb_encrypt_allownil)}
    SEED_ecb_encrypt := ERR_SEED_ecb_encrypt;
    {$ifend}
    {$if declared(SEED_ecb_encrypt_introduced)}
    if LibVersion < SEED_ecb_encrypt_introduced then
    begin
      {$if declared(FC_SEED_ecb_encrypt)}
      SEED_ecb_encrypt := FC_SEED_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SEED_ecb_encrypt_removed)}
    if SEED_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_SEED_ecb_encrypt)}
      SEED_ecb_encrypt := _SEED_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SEED_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('SEED_ecb_encrypt');
    {$ifend}
  end;
  
  SEED_cbc_encrypt := LoadLibFunction(ADllHandle, SEED_cbc_encrypt_procname);
  FuncLoadError := not assigned(SEED_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(SEED_cbc_encrypt_allownil)}
    SEED_cbc_encrypt := ERR_SEED_cbc_encrypt;
    {$ifend}
    {$if declared(SEED_cbc_encrypt_introduced)}
    if LibVersion < SEED_cbc_encrypt_introduced then
    begin
      {$if declared(FC_SEED_cbc_encrypt)}
      SEED_cbc_encrypt := FC_SEED_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SEED_cbc_encrypt_removed)}
    if SEED_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_SEED_cbc_encrypt)}
      SEED_cbc_encrypt := _SEED_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SEED_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('SEED_cbc_encrypt');
    {$ifend}
  end;
  
  SEED_cfb128_encrypt := LoadLibFunction(ADllHandle, SEED_cfb128_encrypt_procname);
  FuncLoadError := not assigned(SEED_cfb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(SEED_cfb128_encrypt_allownil)}
    SEED_cfb128_encrypt := ERR_SEED_cfb128_encrypt;
    {$ifend}
    {$if declared(SEED_cfb128_encrypt_introduced)}
    if LibVersion < SEED_cfb128_encrypt_introduced then
    begin
      {$if declared(FC_SEED_cfb128_encrypt)}
      SEED_cfb128_encrypt := FC_SEED_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SEED_cfb128_encrypt_removed)}
    if SEED_cfb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_SEED_cfb128_encrypt)}
      SEED_cfb128_encrypt := _SEED_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SEED_cfb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('SEED_cfb128_encrypt');
    {$ifend}
  end;
  
  SEED_ofb128_encrypt := LoadLibFunction(ADllHandle, SEED_ofb128_encrypt_procname);
  FuncLoadError := not assigned(SEED_ofb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(SEED_ofb128_encrypt_allownil)}
    SEED_ofb128_encrypt := ERR_SEED_ofb128_encrypt;
    {$ifend}
    {$if declared(SEED_ofb128_encrypt_introduced)}
    if LibVersion < SEED_ofb128_encrypt_introduced then
    begin
      {$if declared(FC_SEED_ofb128_encrypt)}
      SEED_ofb128_encrypt := FC_SEED_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SEED_ofb128_encrypt_removed)}
    if SEED_ofb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_SEED_ofb128_encrypt)}
      SEED_ofb128_encrypt := _SEED_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SEED_ofb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('SEED_ofb128_encrypt');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  SEED_set_key := nil;
  SEED_encrypt := nil;
  SEED_decrypt := nil;
  SEED_ecb_encrypt := nil;
  SEED_cbc_encrypt := nil;
  SEED_cfb128_encrypt := nil;
  SEED_ofb128_encrypt := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.