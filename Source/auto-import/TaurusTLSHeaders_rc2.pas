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

unit TaurusTLSHeaders_rc2;

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
  Prc2_key_st = ^Trc2_key_st;
  Trc2_key_st =   record
    data: PRC2_INT;
  end;
  {$EXTERNALSYM Prc2_key_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  RC2_BLOCK = 8;
  RC2_KEY_LENGTH = 16;
  RC2_ENCRYPT = 1;
  RC2_DECRYPT = 0;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  RC2_set_key: procedure(key: PRC2_KEY; len: TIdC_INT; data: PIdAnsiChar; bits: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC2_set_key}

  RC2_ecb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PRC2_KEY; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC2_ecb_encrypt}

  RC2_encrypt: procedure(data: PIdC_ULONG; key: PRC2_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC2_encrypt}

  RC2_decrypt: procedure(data: PIdC_ULONG; key: PRC2_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC2_decrypt}

  RC2_cbc_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PRC2_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC2_cbc_encrypt}

  RC2_cfb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC2_cfb64_encrypt}

  RC2_ofb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RC2_ofb64_encrypt}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

procedure RC2_set_key(key: PRC2_KEY; len: TIdC_INT; data: PIdAnsiChar; bits: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure RC2_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PRC2_KEY; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure RC2_encrypt(data: PIdC_ULONG; key: PRC2_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure RC2_decrypt(data: PIdC_ULONG; key: PRC2_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure RC2_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PRC2_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure RC2_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure RC2_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
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

procedure RC2_set_key(key: PRC2_KEY; len: TIdC_INT; data: PIdAnsiChar; bits: TIdC_INT); cdecl external CLibCrypto name 'RC2_set_key';
procedure RC2_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PRC2_KEY; enc: TIdC_INT); cdecl external CLibCrypto name 'RC2_ecb_encrypt';
procedure RC2_encrypt(data: PIdC_ULONG; key: PRC2_KEY); cdecl external CLibCrypto name 'RC2_encrypt';
procedure RC2_decrypt(data: PIdC_ULONG; key: PRC2_KEY); cdecl external CLibCrypto name 'RC2_decrypt';
procedure RC2_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PRC2_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'RC2_cbc_encrypt';
procedure RC2_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'RC2_cfb64_encrypt';
procedure RC2_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl external CLibCrypto name 'RC2_ofb64_encrypt';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  RC2_set_key_procname = 'RC2_set_key';
  RC2_set_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC2_set_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC2_ecb_encrypt_procname = 'RC2_ecb_encrypt';
  RC2_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC2_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC2_encrypt_procname = 'RC2_encrypt';
  RC2_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC2_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC2_decrypt_procname = 'RC2_decrypt';
  RC2_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC2_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC2_cbc_encrypt_procname = 'RC2_cbc_encrypt';
  RC2_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC2_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC2_cfb64_encrypt_procname = 'RC2_cfb64_encrypt';
  RC2_cfb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC2_cfb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RC2_ofb64_encrypt_procname = 'RC2_ofb64_encrypt';
  RC2_ofb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RC2_ofb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

procedure ERR_RC2_set_key(key: PRC2_KEY; len: TIdC_INT; data: PIdAnsiChar; bits: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC2_set_key_procname);
end;

procedure ERR_RC2_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PRC2_KEY; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC2_ecb_encrypt_procname);
end;

procedure ERR_RC2_encrypt(data: PIdC_ULONG; key: PRC2_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC2_encrypt_procname);
end;

procedure ERR_RC2_decrypt(data: PIdC_ULONG; key: PRC2_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC2_decrypt_procname);
end;

procedure ERR_RC2_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PRC2_KEY; iv: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC2_cbc_encrypt_procname);
end;

procedure ERR_RC2_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC2_cfb64_encrypt_procname);
end;

procedure ERR_RC2_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PRC2_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RC2_ofb64_encrypt_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  RC2_set_key := LoadLibFunction(ADllHandle, RC2_set_key_procname);
  FuncLoadError := not assigned(RC2_set_key);
  if FuncLoadError then
  begin
    {$if not defined(RC2_set_key_allownil)}
    RC2_set_key := ERR_RC2_set_key;
    {$ifend}
    {$if declared(RC2_set_key_introduced)}
    if LibVersion < RC2_set_key_introduced then
    begin
      {$if declared(FC_RC2_set_key)}
      RC2_set_key := FC_RC2_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC2_set_key_removed)}
    if RC2_set_key_removed <= LibVersion then
    begin
      {$if declared(_RC2_set_key)}
      RC2_set_key := _RC2_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC2_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('RC2_set_key');
    {$ifend}
  end;
  
  RC2_ecb_encrypt := LoadLibFunction(ADllHandle, RC2_ecb_encrypt_procname);
  FuncLoadError := not assigned(RC2_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(RC2_ecb_encrypt_allownil)}
    RC2_ecb_encrypt := ERR_RC2_ecb_encrypt;
    {$ifend}
    {$if declared(RC2_ecb_encrypt_introduced)}
    if LibVersion < RC2_ecb_encrypt_introduced then
    begin
      {$if declared(FC_RC2_ecb_encrypt)}
      RC2_ecb_encrypt := FC_RC2_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC2_ecb_encrypt_removed)}
    if RC2_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_RC2_ecb_encrypt)}
      RC2_ecb_encrypt := _RC2_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC2_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RC2_ecb_encrypt');
    {$ifend}
  end;
  
  RC2_encrypt := LoadLibFunction(ADllHandle, RC2_encrypt_procname);
  FuncLoadError := not assigned(RC2_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(RC2_encrypt_allownil)}
    RC2_encrypt := ERR_RC2_encrypt;
    {$ifend}
    {$if declared(RC2_encrypt_introduced)}
    if LibVersion < RC2_encrypt_introduced then
    begin
      {$if declared(FC_RC2_encrypt)}
      RC2_encrypt := FC_RC2_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC2_encrypt_removed)}
    if RC2_encrypt_removed <= LibVersion then
    begin
      {$if declared(_RC2_encrypt)}
      RC2_encrypt := _RC2_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC2_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RC2_encrypt');
    {$ifend}
  end;
  
  RC2_decrypt := LoadLibFunction(ADllHandle, RC2_decrypt_procname);
  FuncLoadError := not assigned(RC2_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(RC2_decrypt_allownil)}
    RC2_decrypt := ERR_RC2_decrypt;
    {$ifend}
    {$if declared(RC2_decrypt_introduced)}
    if LibVersion < RC2_decrypt_introduced then
    begin
      {$if declared(FC_RC2_decrypt)}
      RC2_decrypt := FC_RC2_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC2_decrypt_removed)}
    if RC2_decrypt_removed <= LibVersion then
    begin
      {$if declared(_RC2_decrypt)}
      RC2_decrypt := _RC2_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC2_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RC2_decrypt');
    {$ifend}
  end;
  
  RC2_cbc_encrypt := LoadLibFunction(ADllHandle, RC2_cbc_encrypt_procname);
  FuncLoadError := not assigned(RC2_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(RC2_cbc_encrypt_allownil)}
    RC2_cbc_encrypt := ERR_RC2_cbc_encrypt;
    {$ifend}
    {$if declared(RC2_cbc_encrypt_introduced)}
    if LibVersion < RC2_cbc_encrypt_introduced then
    begin
      {$if declared(FC_RC2_cbc_encrypt)}
      RC2_cbc_encrypt := FC_RC2_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC2_cbc_encrypt_removed)}
    if RC2_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_RC2_cbc_encrypt)}
      RC2_cbc_encrypt := _RC2_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC2_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RC2_cbc_encrypt');
    {$ifend}
  end;
  
  RC2_cfb64_encrypt := LoadLibFunction(ADllHandle, RC2_cfb64_encrypt_procname);
  FuncLoadError := not assigned(RC2_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(RC2_cfb64_encrypt_allownil)}
    RC2_cfb64_encrypt := ERR_RC2_cfb64_encrypt;
    {$ifend}
    {$if declared(RC2_cfb64_encrypt_introduced)}
    if LibVersion < RC2_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_RC2_cfb64_encrypt)}
      RC2_cfb64_encrypt := FC_RC2_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC2_cfb64_encrypt_removed)}
    if RC2_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_RC2_cfb64_encrypt)}
      RC2_cfb64_encrypt := _RC2_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC2_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RC2_cfb64_encrypt');
    {$ifend}
  end;
  
  RC2_ofb64_encrypt := LoadLibFunction(ADllHandle, RC2_ofb64_encrypt_procname);
  FuncLoadError := not assigned(RC2_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(RC2_ofb64_encrypt_allownil)}
    RC2_ofb64_encrypt := ERR_RC2_ofb64_encrypt;
    {$ifend}
    {$if declared(RC2_ofb64_encrypt_introduced)}
    if LibVersion < RC2_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_RC2_ofb64_encrypt)}
      RC2_ofb64_encrypt := FC_RC2_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RC2_ofb64_encrypt_removed)}
    if RC2_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_RC2_ofb64_encrypt)}
      RC2_ofb64_encrypt := _RC2_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RC2_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RC2_ofb64_encrypt');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  RC2_set_key := nil;
  RC2_ecb_encrypt := nil;
  RC2_encrypt := nil;
  RC2_decrypt := nil;
  RC2_cbc_encrypt := nil;
  RC2_cfb64_encrypt := nil;
  RC2_ofb64_encrypt := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.