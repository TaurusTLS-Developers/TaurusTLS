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

unit TaurusTLSHeaders_idea;

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
  Pidea_key_st = ^Tidea_key_st;
  Tidea_key_st =   record
    data: PPIDEA_INT;
  end;
  {$EXTERNALSYM Pidea_key_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  IDEA_BLOCK = 8;
  IDEA_KEY_LENGTH = 16;
  IDEA_ENCRYPT = 1;
  IDEA_DECRYPT = 0;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  IDEA_options: function: PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_options}

  IDEA_ecb_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_ecb_encrypt}

  IDEA_set_encrypt_key: procedure(key: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_set_encrypt_key}

  IDEA_set_decrypt_key: procedure(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_set_decrypt_key}

  IDEA_cbc_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_cbc_encrypt}

  IDEA_cfb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_cfb64_encrypt}

  IDEA_ofb64_encrypt: procedure(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_ofb64_encrypt}

  IDEA_encrypt: procedure(_in: PIdC_ULONG; ks: PIDEA_KEY_SCHEDULE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM IDEA_encrypt}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function IDEA_options: PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure IDEA_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure IDEA_set_encrypt_key(key: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure IDEA_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure IDEA_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure IDEA_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure IDEA_encrypt(_in: PIdC_ULONG; ks: PIDEA_KEY_SCHEDULE); cdecl; deprecated 'In OpenSSL 3_0_0';
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function idea_options: PIdAnsiChar; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure idea_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure idea_set_encrypt_key(key: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure idea_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure idea_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; enc: TIdC_INT); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure idea_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure idea_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT); cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // procedure idea_encrypt(_in: PIdC_ULONG; ks: PIDEA_KEY_SCHEDULE); cdecl;


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

function IDEA_options: PIdAnsiChar; cdecl external CLibCrypto name 'IDEA_options';
procedure IDEA_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl external CLibCrypto name 'IDEA_ecb_encrypt';
procedure IDEA_set_encrypt_key(key: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl external CLibCrypto name 'IDEA_set_encrypt_key';
procedure IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl external CLibCrypto name 'IDEA_set_decrypt_key';
procedure IDEA_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; enc: TIdC_INT); cdecl external CLibCrypto name 'IDEA_cbc_encrypt';
procedure IDEA_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl external CLibCrypto name 'IDEA_cfb64_encrypt';
procedure IDEA_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT); cdecl external CLibCrypto name 'IDEA_ofb64_encrypt';
procedure IDEA_encrypt(_in: PIdC_ULONG; ks: PIDEA_KEY_SCHEDULE); cdecl external CLibCrypto name 'IDEA_encrypt';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  IDEA_options_procname = 'IDEA_options';
  IDEA_options_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_options_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  IDEA_ecb_encrypt_procname = 'IDEA_ecb_encrypt';
  IDEA_ecb_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_ecb_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  IDEA_set_encrypt_key_procname = 'IDEA_set_encrypt_key';
  IDEA_set_encrypt_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_set_encrypt_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  IDEA_set_decrypt_key_procname = 'IDEA_set_decrypt_key';
  IDEA_set_decrypt_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_set_decrypt_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  IDEA_cbc_encrypt_procname = 'IDEA_cbc_encrypt';
  IDEA_cbc_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_cbc_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  IDEA_cfb64_encrypt_procname = 'IDEA_cfb64_encrypt';
  IDEA_cfb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_cfb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  IDEA_ofb64_encrypt_procname = 'IDEA_ofb64_encrypt';
  IDEA_ofb64_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_ofb64_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  IDEA_encrypt_procname = 'IDEA_encrypt';
  IDEA_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  IDEA_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function idea_options: PIdAnsiChar; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_options IDEA_options
  }
end;

procedure idea_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_ecb_encrypt IDEA_ecb_encrypt
  }
end;

procedure idea_set_encrypt_key(key: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_set_encrypt_key IDEA_set_encrypt_key
  }
end;

procedure idea_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_set_decrypt_key IDEA_set_decrypt_key
  }
end;

procedure idea_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_cbc_encrypt IDEA_cbc_encrypt
  }
end;

procedure idea_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_cfb64_encrypt IDEA_cfb64_encrypt
  }
end;

procedure idea_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_ofb64_encrypt IDEA_ofb64_encrypt
  }
end;

procedure idea_encrypt(_in: PIdC_ULONG; ks: PIDEA_KEY_SCHEDULE); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    idea_encrypt IDEA_encrypt
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_IDEA_options: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_options_procname);
end;

procedure ERR_IDEA_ecb_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_ecb_encrypt_procname);
end;

procedure ERR_IDEA_set_encrypt_key(key: PIdAnsiChar; ks: PIDEA_KEY_SCHEDULE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_set_encrypt_key_procname);
end;

procedure ERR_IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_set_decrypt_key_procname);
end;

procedure ERR_IDEA_cbc_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_cbc_encrypt_procname);
end;

procedure ERR_IDEA_cfb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT; enc: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_cfb64_encrypt_procname);
end;

procedure ERR_IDEA_ofb64_encrypt(_in: PIdAnsiChar; _out: PIdAnsiChar; length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PIdAnsiChar; num: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_ofb64_encrypt_procname);
end;

procedure ERR_IDEA_encrypt(_in: PIdC_ULONG; ks: PIDEA_KEY_SCHEDULE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_encrypt_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  IDEA_options := LoadLibFunction(ADllHandle, IDEA_options_procname);
  FuncLoadError := not assigned(IDEA_options);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_options_allownil)}
    IDEA_options := ERR_IDEA_options;
    {$ifend}
    {$if declared(IDEA_options_introduced)}
    if LibVersion < IDEA_options_introduced then
    begin
      {$if declared(FC_IDEA_options)}
      IDEA_options := FC_IDEA_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_options_removed)}
    if IDEA_options_removed <= LibVersion then
    begin
      {$if declared(_IDEA_options)}
      IDEA_options := _IDEA_options;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_options_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_options');
    {$ifend}
  end;
  
  IDEA_ecb_encrypt := LoadLibFunction(ADllHandle, IDEA_ecb_encrypt_procname);
  FuncLoadError := not assigned(IDEA_ecb_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_ecb_encrypt_allownil)}
    IDEA_ecb_encrypt := ERR_IDEA_ecb_encrypt;
    {$ifend}
    {$if declared(IDEA_ecb_encrypt_introduced)}
    if LibVersion < IDEA_ecb_encrypt_introduced then
    begin
      {$if declared(FC_IDEA_ecb_encrypt)}
      IDEA_ecb_encrypt := FC_IDEA_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_ecb_encrypt_removed)}
    if IDEA_ecb_encrypt_removed <= LibVersion then
    begin
      {$if declared(_IDEA_ecb_encrypt)}
      IDEA_ecb_encrypt := _IDEA_ecb_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_ecb_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_ecb_encrypt');
    {$ifend}
  end;
  
  IDEA_set_encrypt_key := LoadLibFunction(ADllHandle, IDEA_set_encrypt_key_procname);
  FuncLoadError := not assigned(IDEA_set_encrypt_key);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_set_encrypt_key_allownil)}
    IDEA_set_encrypt_key := ERR_IDEA_set_encrypt_key;
    {$ifend}
    {$if declared(IDEA_set_encrypt_key_introduced)}
    if LibVersion < IDEA_set_encrypt_key_introduced then
    begin
      {$if declared(FC_IDEA_set_encrypt_key)}
      IDEA_set_encrypt_key := FC_IDEA_set_encrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_set_encrypt_key_removed)}
    if IDEA_set_encrypt_key_removed <= LibVersion then
    begin
      {$if declared(_IDEA_set_encrypt_key)}
      IDEA_set_encrypt_key := _IDEA_set_encrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_set_encrypt_key_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_set_encrypt_key');
    {$ifend}
  end;
  
  IDEA_set_decrypt_key := LoadLibFunction(ADllHandle, IDEA_set_decrypt_key_procname);
  FuncLoadError := not assigned(IDEA_set_decrypt_key);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_set_decrypt_key_allownil)}
    IDEA_set_decrypt_key := ERR_IDEA_set_decrypt_key;
    {$ifend}
    {$if declared(IDEA_set_decrypt_key_introduced)}
    if LibVersion < IDEA_set_decrypt_key_introduced then
    begin
      {$if declared(FC_IDEA_set_decrypt_key)}
      IDEA_set_decrypt_key := FC_IDEA_set_decrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_set_decrypt_key_removed)}
    if IDEA_set_decrypt_key_removed <= LibVersion then
    begin
      {$if declared(_IDEA_set_decrypt_key)}
      IDEA_set_decrypt_key := _IDEA_set_decrypt_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_set_decrypt_key_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_set_decrypt_key');
    {$ifend}
  end;
  
  IDEA_cbc_encrypt := LoadLibFunction(ADllHandle, IDEA_cbc_encrypt_procname);
  FuncLoadError := not assigned(IDEA_cbc_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_cbc_encrypt_allownil)}
    IDEA_cbc_encrypt := ERR_IDEA_cbc_encrypt;
    {$ifend}
    {$if declared(IDEA_cbc_encrypt_introduced)}
    if LibVersion < IDEA_cbc_encrypt_introduced then
    begin
      {$if declared(FC_IDEA_cbc_encrypt)}
      IDEA_cbc_encrypt := FC_IDEA_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_cbc_encrypt_removed)}
    if IDEA_cbc_encrypt_removed <= LibVersion then
    begin
      {$if declared(_IDEA_cbc_encrypt)}
      IDEA_cbc_encrypt := _IDEA_cbc_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_cbc_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_cbc_encrypt');
    {$ifend}
  end;
  
  IDEA_cfb64_encrypt := LoadLibFunction(ADllHandle, IDEA_cfb64_encrypt_procname);
  FuncLoadError := not assigned(IDEA_cfb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_cfb64_encrypt_allownil)}
    IDEA_cfb64_encrypt := ERR_IDEA_cfb64_encrypt;
    {$ifend}
    {$if declared(IDEA_cfb64_encrypt_introduced)}
    if LibVersion < IDEA_cfb64_encrypt_introduced then
    begin
      {$if declared(FC_IDEA_cfb64_encrypt)}
      IDEA_cfb64_encrypt := FC_IDEA_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_cfb64_encrypt_removed)}
    if IDEA_cfb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_IDEA_cfb64_encrypt)}
      IDEA_cfb64_encrypt := _IDEA_cfb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_cfb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_cfb64_encrypt');
    {$ifend}
  end;
  
  IDEA_ofb64_encrypt := LoadLibFunction(ADllHandle, IDEA_ofb64_encrypt_procname);
  FuncLoadError := not assigned(IDEA_ofb64_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_ofb64_encrypt_allownil)}
    IDEA_ofb64_encrypt := ERR_IDEA_ofb64_encrypt;
    {$ifend}
    {$if declared(IDEA_ofb64_encrypt_introduced)}
    if LibVersion < IDEA_ofb64_encrypt_introduced then
    begin
      {$if declared(FC_IDEA_ofb64_encrypt)}
      IDEA_ofb64_encrypt := FC_IDEA_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_ofb64_encrypt_removed)}
    if IDEA_ofb64_encrypt_removed <= LibVersion then
    begin
      {$if declared(_IDEA_ofb64_encrypt)}
      IDEA_ofb64_encrypt := _IDEA_ofb64_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_ofb64_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_ofb64_encrypt');
    {$ifend}
  end;
  
  IDEA_encrypt := LoadLibFunction(ADllHandle, IDEA_encrypt_procname);
  FuncLoadError := not assigned(IDEA_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(IDEA_encrypt_allownil)}
    IDEA_encrypt := ERR_IDEA_encrypt;
    {$ifend}
    {$if declared(IDEA_encrypt_introduced)}
    if LibVersion < IDEA_encrypt_introduced then
    begin
      {$if declared(FC_IDEA_encrypt)}
      IDEA_encrypt := FC_IDEA_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(IDEA_encrypt_removed)}
    if IDEA_encrypt_removed <= LibVersion then
    begin
      {$if declared(_IDEA_encrypt)}
      IDEA_encrypt := _IDEA_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(IDEA_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('IDEA_encrypt');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  IDEA_options := nil;
  IDEA_ecb_encrypt := nil;
  IDEA_set_encrypt_key := nil;
  IDEA_set_decrypt_key := nil;
  IDEA_cbc_encrypt := nil;
  IDEA_cfb64_encrypt := nil;
  IDEA_ofb64_encrypt := nil;
  IDEA_encrypt := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.