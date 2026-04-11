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

unit TaurusTLSHeaders_cast;

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
  Pcast_key_st = ^Tcast_key_st;
  Tcast_key_st =   record
    data: PIdC_UINT;
    short_key: TIdC_INT;
  end;
  {$EXTERNALSYM Pcast_key_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  CAST_BLOCK = 8;
  CAST_KEY_LENGTH = 16;
  CAST_ENCRYPT = 1;
  CAST_DECRYPT = 0;
  CAST_LONG = unsignedint;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  CAST_set_key: procedure(key: PCAST_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM CAST_set_key}

  CAST_ecb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAST_KEY; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM CAST_ecb_encrypt}

  CAST_encrypt: procedure(data: PIdC_UINT; key: PCAST_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM CAST_encrypt}

  CAST_decrypt: procedure(data: PIdC_UINT; key: PCAST_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM CAST_decrypt}

  CAST_cbc_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PCAST_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM CAST_cbc_encrypt}

  CAST_cfb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM CAST_cfb64_encrypt}

  CAST_ofb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM CAST_ofb64_encrypt}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

procedure CAST_set_key(key: PCAST_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure CAST_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAST_KEY; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure CAST_encrypt(data: PIdC_UINT; key: PCAST_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure CAST_decrypt(data: PIdC_UINT; key: PCAST_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure CAST_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PCAST_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure CAST_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure CAST_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
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

procedure CAST_set_key(key: PCAST_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl external CLibCrypto name 'CAST_set_key';
procedure CAST_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAST_KEY; enc: TIdC_INT); cdecl external CLibCrypto name 'CAST_ecb_encrypt';
procedure CAST_encrypt(data: PIdC_UINT; key: PCAST_KEY); cdecl external CLibCrypto name 'CAST_encrypt';
procedure CAST_decrypt(data: PIdC_UINT; key: PCAST_KEY); cdecl external CLibCrypto name 'CAST_decrypt';
procedure CAST_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PCAST_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'CAST_cbc_encrypt';
procedure CAST_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'CAST_cfb64_encrypt';
procedure CAST_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl external CLibCrypto name 'CAST_ofb64_encrypt';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  CAST_set_key_procname = 'CAST_set_key';
  CAST_set_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CAST_set_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CAST_ecb_encrypt_procname = 'CAST_ecb_encrypt';
  CAST_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CAST_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CAST_encrypt_procname = 'CAST_encrypt';
  CAST_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CAST_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CAST_decrypt_procname = 'CAST_decrypt';
  CAST_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CAST_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CAST_cbc_encrypt_procname = 'CAST_cbc_encrypt';
  CAST_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CAST_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CAST_cfb64_encrypt_procname = 'CAST_cfb64_encrypt';
  CAST_cfb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CAST_cfb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CAST_ofb64_encrypt_procname = 'CAST_ofb64_encrypt';
  CAST_ofb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  CAST_ofb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

procedure ERR_CAST_set_key(key: PCAST_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_set_key_procname);
end;

procedure ERR_CAST_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAST_KEY; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_ecb_encrypt_procname);
end;

procedure ERR_CAST_encrypt(data: PIdC_UINT; key: PCAST_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_encrypt_procname);
end;

procedure ERR_CAST_decrypt(data: PIdC_UINT; key: PCAST_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_decrypt_procname);
end;

procedure ERR_CAST_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PCAST_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_cbc_encrypt_procname);
end;

procedure ERR_CAST_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_cfb64_encrypt_procname);
end;

procedure ERR_CAST_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PCAST_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_ofb64_encrypt_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  CAST_set_key := LoadLibFunction(ADllHandle, CAST_set_key_procname);
  FuncLoadError := not assigned(CAST_set_key);
  if FuncLoadError then
  begin
    {$if not defined(CAST_set_key_allownil)}
    CAST_set_key := ERR_CAST_set_key;
    {$ifend}
    {$if declared(CAST_set_key_introduced)}
    if LibVersion < CAST_set_key_introduced then
    begin
      {$if declared(FC_CAST_set_key)}
      CAST_set_key := FC_CAST_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CAST_set_key_removed)}
    if CAST_set_key_removed <= LibVersion then
    begin
      {$if declared(_CAST_set_key)}
      CAST_set_key := _CAST_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CAST_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CAST_set_key');
    {$ifend}
  end;
  
  CAST_ecb_encrypt := LoadLibFunction(ADllHandle, CAST_ecb_encrypt_procname);
  FuncLoadError := not assigned(CAST_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CAST_ecb_encrypt_allownil)}
    CAST_ecb_encrypt := ERR_CAST_ecb_encrypt;
    {$ifend}
    {$if declared(CAST_ecb_encrypt_introduced)}
    if LibVersion < CAST_ecb_encrypt_introduced then
    begin
      {$if declared(FC_CAST_ecb_encrypt)}
      CAST_ecb_encrypt := FC_CAST_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CAST_ecb_encrypt_removed)}
    if CAST_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CAST_ecb_encrypt)}
      CAST_ecb_encrypt := _CAST_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CAST_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CAST_ecb_encrypt');
    {$ifend}
  end;
  
  CAST_encrypt := LoadLibFunction(ADllHandle, CAST_encrypt_procname);
  FuncLoadError := not assigned(CAST_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CAST_encrypt_allownil)}
    CAST_encrypt := ERR_CAST_encrypt;
    {$ifend}
    {$if declared(CAST_encrypt_introduced)}
    if LibVersion < CAST_encrypt_introduced then
    begin
      {$if declared(FC_CAST_encrypt)}
      CAST_encrypt := FC_CAST_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CAST_encrypt_removed)}
    if CAST_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CAST_encrypt)}
      CAST_encrypt := _CAST_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CAST_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CAST_encrypt');
    {$ifend}
  end;
  
  CAST_decrypt := LoadLibFunction(ADllHandle, CAST_decrypt_procname);
  FuncLoadError := not assigned(CAST_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CAST_decrypt_allownil)}
    CAST_decrypt := ERR_CAST_decrypt;
    {$ifend}
    {$if declared(CAST_decrypt_introduced)}
    if LibVersion < CAST_decrypt_introduced then
    begin
      {$if declared(FC_CAST_decrypt)}
      CAST_decrypt := FC_CAST_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CAST_decrypt_removed)}
    if CAST_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CAST_decrypt)}
      CAST_decrypt := _CAST_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CAST_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CAST_decrypt');
    {$ifend}
  end;
  
  CAST_cbc_encrypt := LoadLibFunction(ADllHandle, CAST_cbc_encrypt_procname);
  FuncLoadError := not assigned(CAST_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CAST_cbc_encrypt_allownil)}
    CAST_cbc_encrypt := ERR_CAST_cbc_encrypt;
    {$ifend}
    {$if declared(CAST_cbc_encrypt_introduced)}
    if LibVersion < CAST_cbc_encrypt_introduced then
    begin
      {$if declared(FC_CAST_cbc_encrypt)}
      CAST_cbc_encrypt := FC_CAST_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CAST_cbc_encrypt_removed)}
    if CAST_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CAST_cbc_encrypt)}
      CAST_cbc_encrypt := _CAST_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CAST_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CAST_cbc_encrypt');
    {$ifend}
  end;
  
  CAST_cfb64_encrypt := LoadLibFunction(ADllHandle, CAST_cfb64_encrypt_procname);
  FuncLoadError := not assigned(CAST_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CAST_cfb64_encrypt_allownil)}
    CAST_cfb64_encrypt := ERR_CAST_cfb64_encrypt;
    {$ifend}
    {$if declared(CAST_cfb64_encrypt_introduced)}
    if LibVersion < CAST_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_CAST_cfb64_encrypt)}
      CAST_cfb64_encrypt := FC_CAST_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CAST_cfb64_encrypt_removed)}
    if CAST_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CAST_cfb64_encrypt)}
      CAST_cfb64_encrypt := _CAST_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CAST_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CAST_cfb64_encrypt');
    {$ifend}
  end;
  
  CAST_ofb64_encrypt := LoadLibFunction(ADllHandle, CAST_ofb64_encrypt_procname);
  FuncLoadError := not assigned(CAST_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CAST_ofb64_encrypt_allownil)}
    CAST_ofb64_encrypt := ERR_CAST_ofb64_encrypt;
    {$ifend}
    {$if declared(CAST_ofb64_encrypt_introduced)}
    if LibVersion < CAST_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_CAST_ofb64_encrypt)}
      CAST_ofb64_encrypt := FC_CAST_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CAST_ofb64_encrypt_removed)}
    if CAST_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CAST_ofb64_encrypt)}
      CAST_ofb64_encrypt := _CAST_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CAST_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CAST_ofb64_encrypt');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  CAST_set_key := nil;
  CAST_ecb_encrypt := nil;
  CAST_encrypt := nil;
  CAST_decrypt := nil;
  CAST_cbc_encrypt := nil;
  CAST_cfb64_encrypt := nil;
  CAST_ofb64_encrypt := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.