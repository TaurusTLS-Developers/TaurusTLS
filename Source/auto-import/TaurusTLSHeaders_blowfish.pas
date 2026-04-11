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

unit TaurusTLSHeaders_blowfish;

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
  Pbf_key_st = ^Tbf_key_st;
  Tbf_key_st =   record
    P: PIdC_UINT;
    S: PIdC_UINT;
  end;
  {$EXTERNALSYM Pbf_key_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  BF_BLOCK = 8;
  BF_ENCRYPT = 1;
  BF_DECRYPT = 0;
  BF_LONG = unsignedint;
  BF_ROUNDS = 16;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  BF_set_key: procedure(key: PBF_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_set_key}

  BF_encrypt: procedure(data: PIdC_UINT; key: PBF_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_encrypt}

  BF_decrypt: procedure(data: PIdC_UINT; key: PBF_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_decrypt}

  BF_ecb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PBF_KEY; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_ecb_encrypt}

  BF_cbc_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_cbc_encrypt}

  BF_cfb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_cfb64_encrypt}

  BF_ofb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_ofb64_encrypt}

  BF_options: function: PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM BF_options}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

procedure BF_set_key(key: PBF_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure BF_encrypt(data: PIdC_UINT; key: PBF_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure BF_decrypt(data: PIdC_UINT; key: PBF_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure BF_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PBF_KEY; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure BF_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure BF_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure BF_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function BF_options: PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
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

procedure BF_set_key(key: PBF_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl external CLibCrypto name 'BF_set_key';
procedure BF_encrypt(data: PIdC_UINT; key: PBF_KEY); cdecl external CLibCrypto name 'BF_encrypt';
procedure BF_decrypt(data: PIdC_UINT; key: PBF_KEY); cdecl external CLibCrypto name 'BF_decrypt';
procedure BF_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PBF_KEY; enc: TIdC_INT); cdecl external CLibCrypto name 'BF_ecb_encrypt';
procedure BF_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'BF_cbc_encrypt';
procedure BF_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'BF_cfb64_encrypt';
procedure BF_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl external CLibCrypto name 'BF_ofb64_encrypt';
function BF_options: PIdAnsiChar; cdecl external CLibCrypto name 'BF_options';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  BF_set_key_procname = 'BF_set_key';
  BF_set_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_set_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BF_encrypt_procname = 'BF_encrypt';
  BF_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BF_decrypt_procname = 'BF_decrypt';
  BF_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BF_ecb_encrypt_procname = 'BF_ecb_encrypt';
  BF_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BF_cbc_encrypt_procname = 'BF_cbc_encrypt';
  BF_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BF_cfb64_encrypt_procname = 'BF_cfb64_encrypt';
  BF_cfb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_cfb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BF_ofb64_encrypt_procname = 'BF_ofb64_encrypt';
  BF_ofb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_ofb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  BF_options_procname = 'BF_options';
  BF_options_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  BF_options_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

procedure ERR_BF_set_key(key: PBF_KEY; len: TIdC_INT; data: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_set_key_procname);
end;

procedure ERR_BF_encrypt(data: PIdC_UINT; key: PBF_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_encrypt_procname);
end;

procedure ERR_BF_decrypt(data: PIdC_UINT; key: PBF_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_decrypt_procname);
end;

procedure ERR_BF_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PBF_KEY; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_ecb_encrypt_procname);
end;

procedure ERR_BF_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_cbc_encrypt_procname);
end;

procedure ERR_BF_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_cfb64_encrypt_procname);
end;

procedure ERR_BF_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; schedule: PBF_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_ofb64_encrypt_procname);
end;

function ERR_BF_options: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BF_options_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  BF_set_key := LoadLibFunction(ADllHandle, BF_set_key_procname);
  FuncLoadError := not assigned(BF_set_key);
  if FuncLoadError then
  begin
    {$if not defined(BF_set_key_allownil)}
    BF_set_key := ERR_BF_set_key;
    {$ifend}
    {$if declared(BF_set_key_introduced)}
    if LibVersion < BF_set_key_introduced then
    begin
      {$if declared(FC_BF_set_key)}
      BF_set_key := FC_BF_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_set_key_removed)}
    if BF_set_key_removed <= LibVersion then
    begin
      {$if declared(_BF_set_key)}
      BF_set_key := _BF_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_set_key');
    {$ifend}
  end;
  
  BF_encrypt := LoadLibFunction(ADllHandle, BF_encrypt_procname);
  FuncLoadError := not assigned(BF_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_encrypt_allownil)}
    BF_encrypt := ERR_BF_encrypt;
    {$ifend}
    {$if declared(BF_encrypt_introduced)}
    if LibVersion < BF_encrypt_introduced then
    begin
      {$if declared(FC_BF_encrypt)}
      BF_encrypt := FC_BF_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_encrypt_removed)}
    if BF_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_encrypt)}
      BF_encrypt := _BF_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_encrypt');
    {$ifend}
  end;
  
  BF_decrypt := LoadLibFunction(ADllHandle, BF_decrypt_procname);
  FuncLoadError := not assigned(BF_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_decrypt_allownil)}
    BF_decrypt := ERR_BF_decrypt;
    {$ifend}
    {$if declared(BF_decrypt_introduced)}
    if LibVersion < BF_decrypt_introduced then
    begin
      {$if declared(FC_BF_decrypt)}
      BF_decrypt := FC_BF_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_decrypt_removed)}
    if BF_decrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_decrypt)}
      BF_decrypt := _BF_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_decrypt');
    {$ifend}
  end;
  
  BF_ecb_encrypt := LoadLibFunction(ADllHandle, BF_ecb_encrypt_procname);
  FuncLoadError := not assigned(BF_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_ecb_encrypt_allownil)}
    BF_ecb_encrypt := ERR_BF_ecb_encrypt;
    {$ifend}
    {$if declared(BF_ecb_encrypt_introduced)}
    if LibVersion < BF_ecb_encrypt_introduced then
    begin
      {$if declared(FC_BF_ecb_encrypt)}
      BF_ecb_encrypt := FC_BF_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_ecb_encrypt_removed)}
    if BF_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_ecb_encrypt)}
      BF_ecb_encrypt := _BF_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_ecb_encrypt');
    {$ifend}
  end;
  
  BF_cbc_encrypt := LoadLibFunction(ADllHandle, BF_cbc_encrypt_procname);
  FuncLoadError := not assigned(BF_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_cbc_encrypt_allownil)}
    BF_cbc_encrypt := ERR_BF_cbc_encrypt;
    {$ifend}
    {$if declared(BF_cbc_encrypt_introduced)}
    if LibVersion < BF_cbc_encrypt_introduced then
    begin
      {$if declared(FC_BF_cbc_encrypt)}
      BF_cbc_encrypt := FC_BF_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_cbc_encrypt_removed)}
    if BF_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_cbc_encrypt)}
      BF_cbc_encrypt := _BF_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_cbc_encrypt');
    {$ifend}
  end;
  
  BF_cfb64_encrypt := LoadLibFunction(ADllHandle, BF_cfb64_encrypt_procname);
  FuncLoadError := not assigned(BF_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_cfb64_encrypt_allownil)}
    BF_cfb64_encrypt := ERR_BF_cfb64_encrypt;
    {$ifend}
    {$if declared(BF_cfb64_encrypt_introduced)}
    if LibVersion < BF_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_BF_cfb64_encrypt)}
      BF_cfb64_encrypt := FC_BF_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_cfb64_encrypt_removed)}
    if BF_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_cfb64_encrypt)}
      BF_cfb64_encrypt := _BF_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_cfb64_encrypt');
    {$ifend}
  end;
  
  BF_ofb64_encrypt := LoadLibFunction(ADllHandle, BF_ofb64_encrypt_procname);
  FuncLoadError := not assigned(BF_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(BF_ofb64_encrypt_allownil)}
    BF_ofb64_encrypt := ERR_BF_ofb64_encrypt;
    {$ifend}
    {$if declared(BF_ofb64_encrypt_introduced)}
    if LibVersion < BF_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_BF_ofb64_encrypt)}
      BF_ofb64_encrypt := FC_BF_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_ofb64_encrypt_removed)}
    if BF_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_BF_ofb64_encrypt)}
      BF_ofb64_encrypt := _BF_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_ofb64_encrypt');
    {$ifend}
  end;
  
  BF_options := LoadLibFunction(ADllHandle, BF_options_procname);
  FuncLoadError := not assigned(BF_options);
  if FuncLoadError then
  begin
    {$if not defined(BF_options_allownil)}
    BF_options := ERR_BF_options;
    {$ifend}
    {$if declared(BF_options_introduced)}
    if LibVersion < BF_options_introduced then
    begin
      {$if declared(FC_BF_options)}
      BF_options := FC_BF_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BF_options_removed)}
    if BF_options_removed <= LibVersion then
    begin
      {$if declared(_BF_options)}
      BF_options := _BF_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BF_options_allownil)}
    if FuncLoadError then
      AFailed.Add('BF_options');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  BF_set_key := nil;
  BF_encrypt := nil;
  BF_decrypt := nil;
  BF_ecb_encrypt := nil;
  BF_cbc_encrypt := nil;
  BF_cfb64_encrypt := nil;
  BF_ofb64_encrypt := nil;
  BF_options := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.