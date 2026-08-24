/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_idea.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_idea.h2pas
     and this file regenerated. TaurusTLSHeaders_idea.h2pas is distributed with the full Indy
     Distribution.
   *)
   
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

// Headers for OpenSSL 1.1.1
// idea.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  // Added '_CONST' to avoid name clashes
  {$EXTERNALSYM IDEA_ENCRYPT_CONST}
  IDEA_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  {$EXTERNALSYM IDEA_DECRYPT_CONST}
  IDEA_DECRYPT_CONST = 0;

  {$EXTERNALSYM IDEA_BLOCK}
  IDEA_BLOCK      = 8;
  {$EXTERNALSYM IDEA_KEY_LENGTH}
  IDEA_KEY_LENGTH = 16;

type
  {$EXTERNALSYM IDEA_INT}
  IDEA_INT = type TIdC_INT;

  {$EXTERNALSYM idea_key_st}
  idea_key_st = record
    data: array[0..8, 0..5] of IDEA_INT;
  end;
  {$EXTERNALSYM IDEA_KEY_SCHEDULE}
  IDEA_KEY_SCHEDULE = idea_key_st;
  {$EXTERNALSYM PIDEA_KEY_SCHEDULE}
  PIDEA_KEY_SCHEDULE = ^IDEA_KEY_SCHEDULE;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM IDEA_options}
  IDEA_options: function : PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM IDEA_ecb_encrypt}
  IDEA_ecb_encrypt: procedure (const in_: PByte; var out_; ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
  {$EXTERNALSYM IDEA_set_encrypt_key}
  IDEA_set_encrypt_key: procedure (const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
  {$EXTERNALSYM IDEA_set_decrypt_key}
  IDEA_set_decrypt_key: procedure (ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl = nil;
  {$EXTERNALSYM IDEA_cbc_encrypt}
  IDEA_cbc_encrypt: procedure (const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM IDEA_cfb64_encrypt}
  IDEA_cfb64_encrypt: procedure (const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: PIdC_INT; enc: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM IDEA_ofb64_encrypt}
  IDEA_ofb64_encrypt: procedure (const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: PIdC_INT); cdecl = nil;
  {$EXTERNALSYM IDEA_encrypt}
  IDEA_encrypt: procedure (in_: PIdC_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl = nil;

{$ELSE}
  {$EXTERNALSYM IDEA_options}
  function IDEA_options: PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM IDEA_ecb_encrypt}
  procedure IDEA_ecb_encrypt(const in_: PByte; var out_; ks: PIDEA_KEY_SCHEDULE) cdecl; external CLibCrypto;
  {$EXTERNALSYM IDEA_set_encrypt_key}
  procedure IDEA_set_encrypt_key(const key: PByte; ks: PIDEA_KEY_SCHEDULE) cdecl; external CLibCrypto;
  {$EXTERNALSYM IDEA_set_decrypt_key}
  procedure IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE) cdecl; external CLibCrypto;
  {$EXTERNALSYM IDEA_cbc_encrypt}
  procedure IDEA_cbc_encrypt(const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM IDEA_cfb64_encrypt}
  procedure IDEA_cfb64_encrypt(const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: PIdC_INT; enc: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM IDEA_ofb64_encrypt}
  procedure IDEA_ofb64_encrypt(const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: PIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM IDEA_encrypt}
  procedure IDEA_encrypt(in_: PIdC_LONG; ks: PIDEA_KEY_SCHEDULE) cdecl; external CLibCrypto;

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  IDEA_options_procname = 'IDEA_options';
  IDEA_ecb_encrypt_procname = 'IDEA_ecb_encrypt';
  IDEA_set_encrypt_key_procname = 'IDEA_set_encrypt_key';
  IDEA_set_decrypt_key_procname = 'IDEA_set_decrypt_key';
  IDEA_cbc_encrypt_procname = 'IDEA_cbc_encrypt';
  IDEA_cfb64_encrypt_procname = 'IDEA_cfb64_encrypt';
  IDEA_ofb64_encrypt_procname = 'IDEA_ofb64_encrypt';
  IDEA_encrypt_procname = 'IDEA_encrypt';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_IDEA_options: PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_options_procname);
end;


procedure  ERR_IDEA_ecb_encrypt(const in_: PByte; var out_; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_ecb_encrypt_procname);
end;


procedure  ERR_IDEA_set_encrypt_key(const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_set_encrypt_key_procname);
end;


procedure  ERR_IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_set_decrypt_key_procname);
end;


procedure  ERR_IDEA_cbc_encrypt(const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE;
  iv: PByte; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_cbc_encrypt_procname);
end;


procedure  ERR_IDEA_cfb64_encrypt(const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE;
  iv: PByte; num: PIdC_INT; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_cfb64_encrypt_procname);
end;


procedure  ERR_IDEA_ofb64_encrypt(const in_: PByte; var out_; _length: TIdC_LONG; ks: PIDEA_KEY_SCHEDULE;
  iv: PByte; num: PIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_ofb64_encrypt_procname);
end;


procedure  ERR_IDEA_encrypt(in_: PIdC_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(IDEA_encrypt_procname);
end;



  {$I TaurusTLSNoRetValOn.inc}
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

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
  {$I TaurusTLSUnusedParamOn.inc}
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
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
