/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_cast.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_cast.h2pas
     and this file regenerated. TaurusTLSHeaders_cast.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_cast;

interface

// Headers for OpenSSL 1.1.1
// cast.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  {$EXTERNALSYM CAST_ENCRYPT_CONST}
  CAST_ENCRYPT_CONST =  1;
  {$EXTERNALSYM CAST_DECRYPT_CONST}
  CAST_DECRYPT_CONST =  0;
  {$EXTERNALSYM CAST_BLOCK}
  CAST_BLOCK =  8;
  {$EXTERNALSYM CAST_KEY_LENGTH}
  CAST_KEY_LENGTH = 16;

type
  {$EXTERNALSYM CAST_LONG}
  CAST_LONG = type TIdC_UINT;
  {$EXTERNALSYM PCAST_LONG}
  PCAST_LONG = ^CAST_LONG;

  {$EXTERNALSYM cast_key_st}
  cast_key_st = record
    data: array of CAST_LONG;
    short_key: TIdC_INT;              //* Use reduced rounds for short key */
  end;

  {$EXTERNALSYM CAST_KEY}
  CAST_KEY = cast_key_st;
  {$EXTERNALSYM PCAST_KEY}
  PCAST_KEY = ^CAST_KEY;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM CAST_set_key}
  CAST_set_key: procedure (key: PCast_Key; len: TIdC_INT; const data: PByte); cdecl = nil;
  {$EXTERNALSYM CAST_ecb_encrypt}
  CAST_ecb_encrypt: procedure (const in_: PByte; out_: PByte; const key: PCast_Key; enc: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM CAST_encrypt}
  CAST_encrypt: procedure (data: PCAST_LONG; const key: PCast_Key); cdecl = nil;
  {$EXTERNALSYM CAST_decrypt}
  CAST_decrypt: procedure (data: PCAST_LONG; const key: PCast_Key); cdecl = nil;
  {$EXTERNALSYM CAST_cbc_encrypt}
  CAST_cbc_encrypt: procedure (const in_: PByte; out_: PByte; _length: TIdC_LONG; const ks: PCast_Key; iv: PByte; enc: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM CAST_cfb64_encrypt}
  CAST_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; _length: TIdC_LONG; const schedule: PCast_Key; ivec: PByte; num: PIdC_INT; enc: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM CAST_ofb64_encrypt}
  CAST_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; _length: TIdC_LONG; const schedule: PCast_Key; ivec: PByte; num: PIdC_INT); cdecl = nil;

{$ELSE}
  {$EXTERNALSYM CAST_set_key}
  procedure CAST_set_key(key: PCast_Key; len: TIdC_INT; const data: PByte) cdecl; external CLibCrypto;
  {$EXTERNALSYM CAST_ecb_encrypt}
  procedure CAST_ecb_encrypt(const in_: PByte; out_: PByte; const key: PCast_Key; enc: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM CAST_encrypt}
  procedure CAST_encrypt(data: PCAST_LONG; const key: PCast_Key) cdecl; external CLibCrypto;
  {$EXTERNALSYM CAST_decrypt}
  procedure CAST_decrypt(data: PCAST_LONG; const key: PCast_Key) cdecl; external CLibCrypto;
  {$EXTERNALSYM CAST_cbc_encrypt}
  procedure CAST_cbc_encrypt(const in_: PByte; out_: PByte; _length: TIdC_LONG; const ks: PCast_Key; iv: PByte; enc: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM CAST_cfb64_encrypt}
  procedure CAST_cfb64_encrypt(const in_: PByte; out_: PByte; _length: TIdC_LONG; const schedule: PCast_Key; ivec: PByte; num: PIdC_INT; enc: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM CAST_ofb64_encrypt}
  procedure CAST_ofb64_encrypt(const in_: PByte; out_: PByte; _length: TIdC_LONG; const schedule: PCast_Key; ivec: PByte; num: PIdC_INT) cdecl; external CLibCrypto;

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
  CAST_set_key_procname = 'CAST_set_key';
  CAST_ecb_encrypt_procname = 'CAST_ecb_encrypt';
  CAST_encrypt_procname = 'CAST_encrypt';
  CAST_decrypt_procname = 'CAST_decrypt';
  CAST_cbc_encrypt_procname = 'CAST_cbc_encrypt';
  CAST_cfb64_encrypt_procname = 'CAST_cfb64_encrypt';
  CAST_ofb64_encrypt_procname = 'CAST_ofb64_encrypt';

   {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
procedure  ERR_CAST_set_key(key: PCast_Key; len: TIdC_INT; const data: PByte); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_set_key_procname);
end;


procedure  ERR_CAST_ecb_encrypt(const in_: PByte; out_: PByte; const key: PCast_Key; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_ecb_encrypt_procname);
end;


procedure  ERR_CAST_encrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_encrypt_procname);
end;


procedure  ERR_CAST_decrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_decrypt_procname);
end;


procedure  ERR_CAST_cbc_encrypt(const in_: PByte; out_: PByte; _length: TIdC_LONG; const ks: PCast_Key;
  iv: PByte; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_cbc_encrypt_procname);
end;


procedure  ERR_CAST_cfb64_encrypt(const in_: PByte; out_: PByte; _length: TIdC_LONG; const schedule: PCast_Key;
  ivec: PByte; num: PIdC_INT; enc: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_cfb64_encrypt_procname);
end;


procedure  ERR_CAST_ofb64_encrypt(const in_: PByte; out_: PByte; _length: TIdC_LONG; const schedule: PCast_Key;
  ivec: PByte; num: PIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CAST_ofb64_encrypt_procname);
end;



  {$I TaurusTLSNoRetValOn.inc}
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

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

  {$I TaurusTLSUnusedParamOn.inc}
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
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
