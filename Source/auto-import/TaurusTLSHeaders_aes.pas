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

unit TaurusTLSHeaders_aes;

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
  Paes_key_st = ^Taes_key_st;
  Taes_key_st =   record
    rd_key: PIdC_UINT;
    rounds: TIdC_INT;
  end;
  {$EXTERNALSYM Paes_key_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  AES_BLOCK_SIZE = 16;
  AES_ENCRYPT = 1;
  AES_DECRYPT = 0;
  AES_MAXNR = 14;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  AES_options: function: PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_options}

  AES_set_encrypt_key: function(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_set_encrypt_key}

  AES_set_decrypt_key: function(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_set_decrypt_key}

  AES_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_encrypt}

  AES_decrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_decrypt}

  AES_ecb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_ecb_encrypt}

  AES_cbc_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_cbc_encrypt}

  AES_cfb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_cfb128_encrypt}

  AES_cfb1_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_cfb1_encrypt}

  AES_cfb8_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_cfb8_encrypt}

  AES_ofb128_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_ofb128_encrypt}

  AES_ige_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_ige_encrypt}

  AES_bi_ige_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_bi_ige_encrypt}

  AES_wrap_key: function(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_wrap_key}

  AES_unwrap_key: function(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM AES_unwrap_key}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function AES_options: PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function AES_set_encrypt_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function AES_set_decrypt_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_cfb1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_cfb8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_ige_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure AES_bi_ige_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function AES_wrap_key(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function AES_unwrap_key(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function AES_options: PIdAnsiChar; cdecl external CLibCrypto name 'AES_options';
function AES_set_encrypt_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl external CLibCrypto name 'AES_set_encrypt_key';
function AES_set_decrypt_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl external CLibCrypto name 'AES_set_decrypt_key';
procedure AES_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl external CLibCrypto name 'AES_encrypt';
procedure AES_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl external CLibCrypto name 'AES_decrypt';
procedure AES_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY; enc: TIdC_INT); cdecl external CLibCrypto name 'AES_ecb_encrypt';
procedure AES_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'AES_cbc_encrypt';
procedure AES_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'AES_cfb128_encrypt';
procedure AES_cfb1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'AES_cfb1_encrypt';
procedure AES_cfb8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'AES_cfb8_encrypt';
procedure AES_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl external CLibCrypto name 'AES_ofb128_encrypt';
procedure AES_ige_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'AES_ige_encrypt';
procedure AES_bi_ige_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'AES_bi_ige_encrypt';
function AES_wrap_key(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'AES_wrap_key';
function AES_unwrap_key(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'AES_unwrap_key';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  AES_options_procname = 'AES_options';
  AES_options_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_options_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_set_encrypt_key_procname = 'AES_set_encrypt_key';
  AES_set_encrypt_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_set_encrypt_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_set_decrypt_key_procname = 'AES_set_decrypt_key';
  AES_set_decrypt_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_set_decrypt_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_encrypt_procname = 'AES_encrypt';
  AES_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_decrypt_procname = 'AES_decrypt';
  AES_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_ecb_encrypt_procname = 'AES_ecb_encrypt';
  AES_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_cbc_encrypt_procname = 'AES_cbc_encrypt';
  AES_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_cfb128_encrypt_procname = 'AES_cfb128_encrypt';
  AES_cfb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_cfb128_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_cfb1_encrypt_procname = 'AES_cfb1_encrypt';
  AES_cfb1_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_cfb1_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_cfb8_encrypt_procname = 'AES_cfb8_encrypt';
  AES_cfb8_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_cfb8_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_ofb128_encrypt_procname = 'AES_ofb128_encrypt';
  AES_ofb128_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_ofb128_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_ige_encrypt_procname = 'AES_ige_encrypt';
  AES_ige_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_ige_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_bi_ige_encrypt_procname = 'AES_bi_ige_encrypt';
  AES_bi_ige_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_bi_ige_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_wrap_key_procname = 'AES_wrap_key';
  AES_wrap_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_wrap_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  AES_unwrap_key_procname = 'AES_unwrap_key';
  AES_unwrap_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  AES_unwrap_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_AES_options: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_options_procname);
end;

function ERR_AES_set_encrypt_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_set_encrypt_key_procname);
end;

function ERR_AES_set_decrypt_key(userKey: PIdAnsiChar; bits: TIdC_INT; key: PAES_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_set_decrypt_key_procname);
end;

procedure ERR_AES_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_encrypt_procname);
end;

procedure ERR_AES_decrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_decrypt_procname);
end;

procedure ERR_AES_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; key: PAES_KEY; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_ecb_encrypt_procname);
end;

procedure ERR_AES_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_cbc_encrypt_procname);
end;

procedure ERR_AES_cfb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_cfb128_encrypt_procname);
end;

procedure ERR_AES_cfb1_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_cfb1_encrypt_procname);
end;

procedure ERR_AES_cfb8_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_cfb8_encrypt_procname);
end;

procedure ERR_AES_ofb128_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_ofb128_encrypt_procname);
end;

procedure ERR_AES_ige_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_ige_encrypt_procname);
end;

procedure ERR_AES_bi_ige_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_bi_ige_encrypt_procname);
end;

function ERR_AES_wrap_key(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_wrap_key_procname);
end;

function ERR_AES_unwrap_key(key: PAES_KEY; iv: PIdAnsiChar; _out: PIdAnsiChar; _in: PIdAnsiChar; inlen: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AES_unwrap_key_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  AES_options := LoadLibFunction(ADllHandle, AES_options_procname);
  FuncLoadError := not assigned(AES_options);
  if FuncLoadError then
  begin
    {$if not defined(AES_options_allownil)}
    AES_options := ERR_AES_options;
    {$ifend}
    {$if declared(AES_options_introduced)}
    if LibVersion < AES_options_introduced then
    begin
      {$if declared(FC_AES_options)}
      AES_options := FC_AES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_options_removed)}
    if AES_options_removed <= LibVersion then
    begin
      {$if declared(_AES_options)}
      AES_options := _AES_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_options_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_options');
    {$ifend}
  end;
  
  AES_set_encrypt_key := LoadLibFunction(ADllHandle, AES_set_encrypt_key_procname);
  FuncLoadError := not assigned(AES_set_encrypt_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_set_encrypt_key_allownil)}
    AES_set_encrypt_key := ERR_AES_set_encrypt_key;
    {$ifend}
    {$if declared(AES_set_encrypt_key_introduced)}
    if LibVersion < AES_set_encrypt_key_introduced then
    begin
      {$if declared(FC_AES_set_encrypt_key)}
      AES_set_encrypt_key := FC_AES_set_encrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_set_encrypt_key_removed)}
    if AES_set_encrypt_key_removed <= LibVersion then
    begin
      {$if declared(_AES_set_encrypt_key)}
      AES_set_encrypt_key := _AES_set_encrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_set_encrypt_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_set_encrypt_key');
    {$ifend}
  end;
  
  AES_set_decrypt_key := LoadLibFunction(ADllHandle, AES_set_decrypt_key_procname);
  FuncLoadError := not assigned(AES_set_decrypt_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_set_decrypt_key_allownil)}
    AES_set_decrypt_key := ERR_AES_set_decrypt_key;
    {$ifend}
    {$if declared(AES_set_decrypt_key_introduced)}
    if LibVersion < AES_set_decrypt_key_introduced then
    begin
      {$if declared(FC_AES_set_decrypt_key)}
      AES_set_decrypt_key := FC_AES_set_decrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_set_decrypt_key_removed)}
    if AES_set_decrypt_key_removed <= LibVersion then
    begin
      {$if declared(_AES_set_decrypt_key)}
      AES_set_decrypt_key := _AES_set_decrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_set_decrypt_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_set_decrypt_key');
    {$ifend}
  end;
  
  AES_encrypt := LoadLibFunction(ADllHandle, AES_encrypt_procname);
  FuncLoadError := not assigned(AES_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_encrypt_allownil)}
    AES_encrypt := ERR_AES_encrypt;
    {$ifend}
    {$if declared(AES_encrypt_introduced)}
    if LibVersion < AES_encrypt_introduced then
    begin
      {$if declared(FC_AES_encrypt)}
      AES_encrypt := FC_AES_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_encrypt_removed)}
    if AES_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_encrypt)}
      AES_encrypt := _AES_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_encrypt');
    {$ifend}
  end;
  
  AES_decrypt := LoadLibFunction(ADllHandle, AES_decrypt_procname);
  FuncLoadError := not assigned(AES_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_decrypt_allownil)}
    AES_decrypt := ERR_AES_decrypt;
    {$ifend}
    {$if declared(AES_decrypt_introduced)}
    if LibVersion < AES_decrypt_introduced then
    begin
      {$if declared(FC_AES_decrypt)}
      AES_decrypt := FC_AES_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_decrypt_removed)}
    if AES_decrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_decrypt)}
      AES_decrypt := _AES_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_decrypt');
    {$ifend}
  end;
  
  AES_ecb_encrypt := LoadLibFunction(ADllHandle, AES_ecb_encrypt_procname);
  FuncLoadError := not assigned(AES_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_ecb_encrypt_allownil)}
    AES_ecb_encrypt := ERR_AES_ecb_encrypt;
    {$ifend}
    {$if declared(AES_ecb_encrypt_introduced)}
    if LibVersion < AES_ecb_encrypt_introduced then
    begin
      {$if declared(FC_AES_ecb_encrypt)}
      AES_ecb_encrypt := FC_AES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_ecb_encrypt_removed)}
    if AES_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_ecb_encrypt)}
      AES_ecb_encrypt := _AES_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_ecb_encrypt');
    {$ifend}
  end;
  
  AES_cbc_encrypt := LoadLibFunction(ADllHandle, AES_cbc_encrypt_procname);
  FuncLoadError := not assigned(AES_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cbc_encrypt_allownil)}
    AES_cbc_encrypt := ERR_AES_cbc_encrypt;
    {$ifend}
    {$if declared(AES_cbc_encrypt_introduced)}
    if LibVersion < AES_cbc_encrypt_introduced then
    begin
      {$if declared(FC_AES_cbc_encrypt)}
      AES_cbc_encrypt := FC_AES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cbc_encrypt_removed)}
    if AES_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cbc_encrypt)}
      AES_cbc_encrypt := _AES_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cbc_encrypt');
    {$ifend}
  end;
  
  AES_cfb128_encrypt := LoadLibFunction(ADllHandle, AES_cfb128_encrypt_procname);
  FuncLoadError := not assigned(AES_cfb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cfb128_encrypt_allownil)}
    AES_cfb128_encrypt := ERR_AES_cfb128_encrypt;
    {$ifend}
    {$if declared(AES_cfb128_encrypt_introduced)}
    if LibVersion < AES_cfb128_encrypt_introduced then
    begin
      {$if declared(FC_AES_cfb128_encrypt)}
      AES_cfb128_encrypt := FC_AES_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cfb128_encrypt_removed)}
    if AES_cfb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cfb128_encrypt)}
      AES_cfb128_encrypt := _AES_cfb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cfb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cfb128_encrypt');
    {$ifend}
  end;
  
  AES_cfb1_encrypt := LoadLibFunction(ADllHandle, AES_cfb1_encrypt_procname);
  FuncLoadError := not assigned(AES_cfb1_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cfb1_encrypt_allownil)}
    AES_cfb1_encrypt := ERR_AES_cfb1_encrypt;
    {$ifend}
    {$if declared(AES_cfb1_encrypt_introduced)}
    if LibVersion < AES_cfb1_encrypt_introduced then
    begin
      {$if declared(FC_AES_cfb1_encrypt)}
      AES_cfb1_encrypt := FC_AES_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cfb1_encrypt_removed)}
    if AES_cfb1_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cfb1_encrypt)}
      AES_cfb1_encrypt := _AES_cfb1_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cfb1_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cfb1_encrypt');
    {$ifend}
  end;
  
  AES_cfb8_encrypt := LoadLibFunction(ADllHandle, AES_cfb8_encrypt_procname);
  FuncLoadError := not assigned(AES_cfb8_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_cfb8_encrypt_allownil)}
    AES_cfb8_encrypt := ERR_AES_cfb8_encrypt;
    {$ifend}
    {$if declared(AES_cfb8_encrypt_introduced)}
    if LibVersion < AES_cfb8_encrypt_introduced then
    begin
      {$if declared(FC_AES_cfb8_encrypt)}
      AES_cfb8_encrypt := FC_AES_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_cfb8_encrypt_removed)}
    if AES_cfb8_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_cfb8_encrypt)}
      AES_cfb8_encrypt := _AES_cfb8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_cfb8_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_cfb8_encrypt');
    {$ifend}
  end;
  
  AES_ofb128_encrypt := LoadLibFunction(ADllHandle, AES_ofb128_encrypt_procname);
  FuncLoadError := not assigned(AES_ofb128_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_ofb128_encrypt_allownil)}
    AES_ofb128_encrypt := ERR_AES_ofb128_encrypt;
    {$ifend}
    {$if declared(AES_ofb128_encrypt_introduced)}
    if LibVersion < AES_ofb128_encrypt_introduced then
    begin
      {$if declared(FC_AES_ofb128_encrypt)}
      AES_ofb128_encrypt := FC_AES_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_ofb128_encrypt_removed)}
    if AES_ofb128_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_ofb128_encrypt)}
      AES_ofb128_encrypt := _AES_ofb128_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_ofb128_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_ofb128_encrypt');
    {$ifend}
  end;
  
  AES_ige_encrypt := LoadLibFunction(ADllHandle, AES_ige_encrypt_procname);
  FuncLoadError := not assigned(AES_ige_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_ige_encrypt_allownil)}
    AES_ige_encrypt := ERR_AES_ige_encrypt;
    {$ifend}
    {$if declared(AES_ige_encrypt_introduced)}
    if LibVersion < AES_ige_encrypt_introduced then
    begin
      {$if declared(FC_AES_ige_encrypt)}
      AES_ige_encrypt := FC_AES_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_ige_encrypt_removed)}
    if AES_ige_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_ige_encrypt)}
      AES_ige_encrypt := _AES_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_ige_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_ige_encrypt');
    {$ifend}
  end;
  
  AES_bi_ige_encrypt := LoadLibFunction(ADllHandle, AES_bi_ige_encrypt_procname);
  FuncLoadError := not assigned(AES_bi_ige_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(AES_bi_ige_encrypt_allownil)}
    AES_bi_ige_encrypt := ERR_AES_bi_ige_encrypt;
    {$ifend}
    {$if declared(AES_bi_ige_encrypt_introduced)}
    if LibVersion < AES_bi_ige_encrypt_introduced then
    begin
      {$if declared(FC_AES_bi_ige_encrypt)}
      AES_bi_ige_encrypt := FC_AES_bi_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_bi_ige_encrypt_removed)}
    if AES_bi_ige_encrypt_removed <= LibVersion then
    begin
      {$if declared(_AES_bi_ige_encrypt)}
      AES_bi_ige_encrypt := _AES_bi_ige_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_bi_ige_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_bi_ige_encrypt');
    {$ifend}
  end;
  
  AES_wrap_key := LoadLibFunction(ADllHandle, AES_wrap_key_procname);
  FuncLoadError := not assigned(AES_wrap_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_wrap_key_allownil)}
    AES_wrap_key := ERR_AES_wrap_key;
    {$ifend}
    {$if declared(AES_wrap_key_introduced)}
    if LibVersion < AES_wrap_key_introduced then
    begin
      {$if declared(FC_AES_wrap_key)}
      AES_wrap_key := FC_AES_wrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_wrap_key_removed)}
    if AES_wrap_key_removed <= LibVersion then
    begin
      {$if declared(_AES_wrap_key)}
      AES_wrap_key := _AES_wrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_wrap_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_wrap_key');
    {$ifend}
  end;
  
  AES_unwrap_key := LoadLibFunction(ADllHandle, AES_unwrap_key_procname);
  FuncLoadError := not assigned(AES_unwrap_key);
  if FuncLoadError then
  begin
    {$if not defined(AES_unwrap_key_allownil)}
    AES_unwrap_key := ERR_AES_unwrap_key;
    {$ifend}
    {$if declared(AES_unwrap_key_introduced)}
    if LibVersion < AES_unwrap_key_introduced then
    begin
      {$if declared(FC_AES_unwrap_key)}
      AES_unwrap_key := FC_AES_unwrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AES_unwrap_key_removed)}
    if AES_unwrap_key_removed <= LibVersion then
    begin
      {$if declared(_AES_unwrap_key)}
      AES_unwrap_key := _AES_unwrap_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AES_unwrap_key_allownil)}
    if FuncLoadError then
      AFailed.Add('AES_unwrap_key');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  AES_options := nil;
  AES_set_encrypt_key := nil;
  AES_set_decrypt_key := nil;
  AES_encrypt := nil;
  AES_decrypt := nil;
  AES_ecb_encrypt := nil;
  AES_cbc_encrypt := nil;
  AES_cfb128_encrypt := nil;
  AES_cfb1_encrypt := nil;
  AES_cfb8_encrypt := nil;
  AES_ofb128_encrypt := nil;
  AES_ige_encrypt := nil;
  AES_bi_ige_encrypt := nil;
  AES_wrap_key := nil;
  AES_unwrap_key := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.