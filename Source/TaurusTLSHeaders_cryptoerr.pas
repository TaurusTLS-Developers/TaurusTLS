/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_cryptoerr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_cryptoerr.h2pas
     and this file regenerated. TaurusTLSHeaders_cryptoerr.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_cryptoerr;

interface

// Headers for OpenSSL 1.1.1
// cryptoerr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * CRYPTO function codes.
   *)
  {$EXTERNALSYM CRYPTO_F_CMAC_CTX_NEW}
  CRYPTO_F_CMAC_CTX_NEW = 120;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_DUP_EX_DATA}
  CRYPTO_F_CRYPTO_DUP_EX_DATA = 110;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_FREE_EX_DATA}
  CRYPTO_F_CRYPTO_FREE_EX_DATA = 111;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX}
  CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_MEMDUP}
  CRYPTO_F_CRYPTO_MEMDUP = 115;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_NEW_EX_DATA}
  CRYPTO_F_CRYPTO_NEW_EX_DATA = 112;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_OCB128_COPY_CTX}
  CRYPTO_F_CRYPTO_OCB128_COPY_CTX = 121;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_OCB128_INIT}
  CRYPTO_F_CRYPTO_OCB128_INIT = 122;
  {$EXTERNALSYM CRYPTO_F_CRYPTO_SET_EX_DATA}
  CRYPTO_F_CRYPTO_SET_EX_DATA = 102;
  {$EXTERNALSYM CRYPTO_F_FIPS_MODE_SET}
  CRYPTO_F_FIPS_MODE_SET = 109;
  {$EXTERNALSYM CRYPTO_F_GET_AND_LOCK}
  CRYPTO_F_GET_AND_LOCK = 113;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_ATEXIT}
  CRYPTO_F_OPENSSL_ATEXIT = 114;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_BUF2HEXSTR}
  CRYPTO_F_OPENSSL_BUF2HEXSTR = 117;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_FOPEN}
  CRYPTO_F_OPENSSL_FOPEN = 119;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_HEXSTR2BUF}
  CRYPTO_F_OPENSSL_HEXSTR2BUF = 118;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_INIT_CRYPTO}
  CRYPTO_F_OPENSSL_INIT_CRYPTO = 116;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_LH_NEW}
  CRYPTO_F_OPENSSL_LH_NEW = 126;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_SK_DEEP_COPY}
  CRYPTO_F_OPENSSL_SK_DEEP_COPY = 127;
  {$EXTERNALSYM CRYPTO_F_OPENSSL_SK_DUP}
  CRYPTO_F_OPENSSL_SK_DUP = 128;
  {$EXTERNALSYM CRYPTO_F_PKEY_HMAC_INIT}
  CRYPTO_F_PKEY_HMAC_INIT = 123;
  {$EXTERNALSYM CRYPTO_F_PKEY_POLY1305_INIT}
  CRYPTO_F_PKEY_POLY1305_INIT = 124;
  {$EXTERNALSYM CRYPTO_F_PKEY_SIPHASH_INIT}
  CRYPTO_F_PKEY_SIPHASH_INIT = 125;
  {$EXTERNALSYM CRYPTO_F_SK_RESERVE}
  CRYPTO_F_SK_RESERVE = 129;

  (*
   * CRYPTO reason codes.
   *)
  {$EXTERNALSYM CRYPTO_R_FIPS_MODE_NOT_SUPPORTED}
  CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101;
  {$EXTERNALSYM CRYPTO_R_ILLEGAL_HEX_DIGIT}
  CRYPTO_R_ILLEGAL_HEX_DIGIT = 102;
  {$EXTERNALSYM CRYPTO_R_ODD_NUMBER_OF_DIGITS}
  CRYPTO_R_ODD_NUMBER_OF_DIGITS = 103;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_CRYPTO_strings}
  ERR_load_CRYPTO_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_CRYPTO_strings}
  function ERR_load_CRYPTO_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_CRYPTO_strings_procname = 'ERR_load_CRYPTO_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_CRYPTO_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_CRYPTO_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_CRYPTO_strings := LoadLibFunction(ADllHandle, ERR_load_CRYPTO_strings_procname);
  FuncLoadError := not assigned(ERR_load_CRYPTO_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_CRYPTO_strings_allownil)}
    ERR_load_CRYPTO_strings := ERR_ERR_load_CRYPTO_strings;
    {$ifend}
    {$if declared(ERR_load_CRYPTO_strings_introduced)}
    if LibVersion < ERR_load_CRYPTO_strings_introduced then
    begin
      {$if declared(FC_ERR_load_CRYPTO_strings)}
      ERR_load_CRYPTO_strings := FC_ERR_load_CRYPTO_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_CRYPTO_strings_removed)}
    if ERR_load_CRYPTO_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_CRYPTO_strings)}
      ERR_load_CRYPTO_strings := _ERR_load_CRYPTO_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_CRYPTO_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_CRYPTO_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_CRYPTO_strings := nil;
end;

initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
  {$ENDIF}
{$ENDIF}
end.
