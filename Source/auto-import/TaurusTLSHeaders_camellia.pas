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

unit TaurusTLSHeaders_camellia;

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
  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // struct camellia_key_st {
  //     union {
  //         double d; /* ensures 64-bit align */
  //         KEY_TABLE_TYPE rd_key;
  //     } u;
  //     int grand_rounds;
  // }


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  CAMELLIA_BLOCK_SIZE = 16;
  CAMELLIA_ENCRYPT = 1;
  CAMELLIA_DECRYPT = 0;
  CAMELLIA_TABLE_BYTE_LEN = 272;
  CAMELLIA_TABLE_WORD_LEN = (CAMELLIA_TABLE_BYTE_LEN/4);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  Camellia_set_key: function(userKey: PIdAnsiChar; bits: TIdC_INT; key: PCAMELLIA_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_set_key}

  Camellia_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_encrypt}

  Camellia_decrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_decrypt}

  Camellia_ecb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_ecb_encrypt}

  Camellia_cbc_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_cbc_encrypt}

  Camellia_cfb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_cfb128_encrypt}

  Camellia_cfb1_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_cfb1_encrypt}

  Camellia_cfb8_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_cfb8_encrypt}

  Camellia_ofb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_ofb128_encrypt}

  Camellia_ctr128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM Camellia_ctr128_encrypt}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function Camellia_set_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PCAMELLIA_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_cfb1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_cfb8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure Camellia_ctr128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT); cdecl; deprecated 'In OpenSSL 3_0_0';
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

function Camellia_set_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PCAMELLIA_KEY): TIdC_INT; cdecl external CLibCrypto name 'Camellia_set_key';
procedure Camellia_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl external CLibCrypto name 'Camellia_encrypt';
procedure Camellia_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl external CLibCrypto name 'Camellia_decrypt';
procedure Camellia_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY; enc: TIdC_INT); cdecl external CLibCrypto name 'Camellia_ecb_encrypt';
procedure Camellia_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'Camellia_cbc_encrypt';
procedure Camellia_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'Camellia_cfb128_encrypt';
procedure Camellia_cfb1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'Camellia_cfb1_encrypt';
procedure Camellia_cfb8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'Camellia_cfb8_encrypt';
procedure Camellia_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl external CLibCrypto name 'Camellia_ofb128_encrypt';
procedure Camellia_ctr128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT); cdecl external CLibCrypto name 'Camellia_ctr128_encrypt';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  Camellia_set_key_procname = 'Camellia_set_key';
  Camellia_set_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_set_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_encrypt_procname = 'Camellia_encrypt';
  Camellia_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_decrypt_procname = 'Camellia_decrypt';
  Camellia_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_ecb_encrypt_procname = 'Camellia_ecb_encrypt';
  Camellia_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_cbc_encrypt_procname = 'Camellia_cbc_encrypt';
  Camellia_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_cfb128_encrypt_procname = 'Camellia_cfb128_encrypt';
  Camellia_cfb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_cfb128_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_cfb1_encrypt_procname = 'Camellia_cfb1_encrypt';
  Camellia_cfb1_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_cfb1_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_cfb8_encrypt_procname = 'Camellia_cfb8_encrypt';
  Camellia_cfb8_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_cfb8_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_ofb128_encrypt_procname = 'Camellia_ofb128_encrypt';
  Camellia_ofb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_ofb128_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  Camellia_ctr128_encrypt_procname = 'Camellia_ctr128_encrypt';
  Camellia_ctr128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  Camellia_ctr128_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_Camellia_set_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PCAMELLIA_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_set_key_procname);
end;

procedure ERR_Camellia_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_encrypt_procname);
end;

procedure ERR_Camellia_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_decrypt_procname);
end;

procedure ERR_Camellia_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PCAMELLIA_KEY; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_ecb_encrypt_procname);
end;

procedure ERR_Camellia_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_cbc_encrypt_procname);
end;

procedure ERR_Camellia_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_cfb128_encrypt_procname);
end;

procedure ERR_Camellia_cfb1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_cfb1_encrypt_procname);
end;

procedure ERR_Camellia_cfb8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_cfb8_encrypt_procname);
end;

procedure ERR_Camellia_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_ofb128_encrypt_procname);
end;

procedure ERR_Camellia_ctr128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PCAMELLIA_KEY; ivec: PIdAnsiChar; ecount_buf: PIdAnsiChar; num: PIdC_UINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(Camellia_ctr128_encrypt_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  Camellia_set_key := LoadLibFunction(ADllHandle, Camellia_set_key_procname);
  FuncLoadError := not assigned(Camellia_set_key);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_set_key_allownil)}
    Camellia_set_key := ERR_Camellia_set_key;
    {$ifend}
    {$if declared(Camellia_set_key_introduced)}
    if LibVersion < Camellia_set_key_introduced then
    begin
      {$if declared(FC_Camellia_set_key)}
      Camellia_set_key := FC_Camellia_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_set_key_removed)}
    if Camellia_set_key_removed <= LibVersion then
    begin
      {$if declared(_Camellia_set_key)}
      Camellia_set_key := _Camellia_set_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_set_key_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_set_key');
    {$ifend}
  end;
  
  Camellia_encrypt := LoadLibFunction(ADllHandle, Camellia_encrypt_procname);
  FuncLoadError := not assigned(Camellia_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_encrypt_allownil)}
    Camellia_encrypt := ERR_Camellia_encrypt;
    {$ifend}
    {$if declared(Camellia_encrypt_introduced)}
    if LibVersion < Camellia_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_encrypt)}
      Camellia_encrypt := FC_Camellia_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_encrypt_removed)}
    if Camellia_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_encrypt)}
      Camellia_encrypt := _Camellia_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_encrypt');
    {$ifend}
  end;
  
  Camellia_decrypt := LoadLibFunction(ADllHandle, Camellia_decrypt_procname);
  FuncLoadError := not assigned(Camellia_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_decrypt_allownil)}
    Camellia_decrypt := ERR_Camellia_decrypt;
    {$ifend}
    {$if declared(Camellia_decrypt_introduced)}
    if LibVersion < Camellia_decrypt_introduced then
    begin
      {$if declared(FC_Camellia_decrypt)}
      Camellia_decrypt := FC_Camellia_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_decrypt_removed)}
    if Camellia_decrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_decrypt)}
      Camellia_decrypt := _Camellia_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_decrypt');
    {$ifend}
  end;
  
  Camellia_ecb_encrypt := LoadLibFunction(ADllHandle, Camellia_ecb_encrypt_procname);
  FuncLoadError := not assigned(Camellia_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_ecb_encrypt_allownil)}
    Camellia_ecb_encrypt := ERR_Camellia_ecb_encrypt;
    {$ifend}
    {$if declared(Camellia_ecb_encrypt_introduced)}
    if LibVersion < Camellia_ecb_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_ecb_encrypt)}
      Camellia_ecb_encrypt := FC_Camellia_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_ecb_encrypt_removed)}
    if Camellia_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_ecb_encrypt)}
      Camellia_ecb_encrypt := _Camellia_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_ecb_encrypt');
    {$ifend}
  end;
  
  Camellia_cbc_encrypt := LoadLibFunction(ADllHandle, Camellia_cbc_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cbc_encrypt_allownil)}
    Camellia_cbc_encrypt := ERR_Camellia_cbc_encrypt;
    {$ifend}
    {$if declared(Camellia_cbc_encrypt_introduced)}
    if LibVersion < Camellia_cbc_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cbc_encrypt)}
      Camellia_cbc_encrypt := FC_Camellia_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cbc_encrypt_removed)}
    if Camellia_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cbc_encrypt)}
      Camellia_cbc_encrypt := _Camellia_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cbc_encrypt');
    {$ifend}
  end;
  
  Camellia_cfb128_encrypt := LoadLibFunction(ADllHandle, Camellia_cfb128_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cfb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cfb128_encrypt_allownil)}
    Camellia_cfb128_encrypt := ERR_Camellia_cfb128_encrypt;
    {$ifend}
    {$if declared(Camellia_cfb128_encrypt_introduced)}
    if LibVersion < Camellia_cfb128_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cfb128_encrypt)}
      Camellia_cfb128_encrypt := FC_Camellia_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cfb128_encrypt_removed)}
    if Camellia_cfb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cfb128_encrypt)}
      Camellia_cfb128_encrypt := _Camellia_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cfb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cfb128_encrypt');
    {$ifend}
  end;
  
  Camellia_cfb1_encrypt := LoadLibFunction(ADllHandle, Camellia_cfb1_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cfb1_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cfb1_encrypt_allownil)}
    Camellia_cfb1_encrypt := ERR_Camellia_cfb1_encrypt;
    {$ifend}
    {$if declared(Camellia_cfb1_encrypt_introduced)}
    if LibVersion < Camellia_cfb1_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cfb1_encrypt)}
      Camellia_cfb1_encrypt := FC_Camellia_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cfb1_encrypt_removed)}
    if Camellia_cfb1_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cfb1_encrypt)}
      Camellia_cfb1_encrypt := _Camellia_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cfb1_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cfb1_encrypt');
    {$ifend}
  end;
  
  Camellia_cfb8_encrypt := LoadLibFunction(ADllHandle, Camellia_cfb8_encrypt_procname);
  FuncLoadError := not assigned(Camellia_cfb8_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_cfb8_encrypt_allownil)}
    Camellia_cfb8_encrypt := ERR_Camellia_cfb8_encrypt;
    {$ifend}
    {$if declared(Camellia_cfb8_encrypt_introduced)}
    if LibVersion < Camellia_cfb8_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_cfb8_encrypt)}
      Camellia_cfb8_encrypt := FC_Camellia_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_cfb8_encrypt_removed)}
    if Camellia_cfb8_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_cfb8_encrypt)}
      Camellia_cfb8_encrypt := _Camellia_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_cfb8_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_cfb8_encrypt');
    {$ifend}
  end;
  
  Camellia_ofb128_encrypt := LoadLibFunction(ADllHandle, Camellia_ofb128_encrypt_procname);
  FuncLoadError := not assigned(Camellia_ofb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_ofb128_encrypt_allownil)}
    Camellia_ofb128_encrypt := ERR_Camellia_ofb128_encrypt;
    {$ifend}
    {$if declared(Camellia_ofb128_encrypt_introduced)}
    if LibVersion < Camellia_ofb128_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_ofb128_encrypt)}
      Camellia_ofb128_encrypt := FC_Camellia_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_ofb128_encrypt_removed)}
    if Camellia_ofb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_ofb128_encrypt)}
      Camellia_ofb128_encrypt := _Camellia_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_ofb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_ofb128_encrypt');
    {$ifend}
  end;
  
  Camellia_ctr128_encrypt := LoadLibFunction(ADllHandle, Camellia_ctr128_encrypt_procname);
  FuncLoadError := not assigned(Camellia_ctr128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(Camellia_ctr128_encrypt_allownil)}
    Camellia_ctr128_encrypt := ERR_Camellia_ctr128_encrypt;
    {$ifend}
    {$if declared(Camellia_ctr128_encrypt_introduced)}
    if LibVersion < Camellia_ctr128_encrypt_introduced then
    begin
      {$if declared(FC_Camellia_ctr128_encrypt)}
      Camellia_ctr128_encrypt := FC_Camellia_ctr128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(Camellia_ctr128_encrypt_removed)}
    if Camellia_ctr128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_Camellia_ctr128_encrypt)}
      Camellia_ctr128_encrypt := _Camellia_ctr128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(Camellia_ctr128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('Camellia_ctr128_encrypt');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  Camellia_set_key := nil;
  Camellia_encrypt := nil;
  Camellia_decrypt := nil;
  Camellia_ecb_encrypt := nil;
  Camellia_cbc_encrypt := nil;
  Camellia_cfb128_encrypt := nil;
  Camellia_cfb1_encrypt := nil;
  Camellia_cfb8_encrypt := nil;
  Camellia_ofb128_encrypt := nil;
  Camellia_ctr128_encrypt := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.