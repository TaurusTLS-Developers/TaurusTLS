/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_dherr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_dherr.h2pas
     and this file regenerated. TaurusTLSHeaders_dherr.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_dherr;

interface

// Headers for OpenSSL 1.1.1
// dherr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  // DH function codes
  {$EXTERNALSYM DH_F_COMPUTE_KEY}
  DH_F_COMPUTE_KEY               = 102;
  {$EXTERNALSYM DH_F_DHPARAMS_PRINT_FP}
  DH_F_DHPARAMS_PRINT_FP         = 101;
  {$EXTERNALSYM DH_F_DH_BUILTIN_GENPARAMS}
  DH_F_DH_BUILTIN_GENPARAMS      = 106;
  {$EXTERNALSYM DH_F_DH_CHECK_EX}
  DH_F_DH_CHECK_EX               = 121;
  {$EXTERNALSYM DH_F_DH_CHECK_PARAMS_EX}
  DH_F_DH_CHECK_PARAMS_EX        = 122;
  {$EXTERNALSYM DH_F_DH_CHECK_PUB_KEY_EX}
  DH_F_DH_CHECK_PUB_KEY_EX       = 123;
  {$EXTERNALSYM DH_F_DH_CMS_DECRYPT}
  DH_F_DH_CMS_DECRYPT            = 114;
  {$EXTERNALSYM DH_F_DH_CMS_SET_PEERKEY}
  DH_F_DH_CMS_SET_PEERKEY        = 115;
  {$EXTERNALSYM DH_F_DH_CMS_SET_SHARED_INFO}
  DH_F_DH_CMS_SET_SHARED_INFO    = 116;
  {$EXTERNALSYM DH_F_DH_METH_DUP}
  DH_F_DH_METH_DUP               = 117;
  {$EXTERNALSYM DH_F_DH_METH_NEW}
  DH_F_DH_METH_NEW               = 118;
  {$EXTERNALSYM DH_F_DH_METH_SET1_NAME}
  DH_F_DH_METH_SET1_NAME         = 119;
  {$EXTERNALSYM DH_F_DH_NEW_BY_NID}
  DH_F_DH_NEW_BY_NID             = 104;
  {$EXTERNALSYM DH_F_DH_NEW_METHOD}
  DH_F_DH_NEW_METHOD             = 105;
  {$EXTERNALSYM DH_F_DH_PARAM_DECODE}
  DH_F_DH_PARAM_DECODE           = 107;
  {$EXTERNALSYM DH_F_DH_PKEY_PUBLIC_CHECK}
  DH_F_DH_PKEY_PUBLIC_CHECK      = 124;
  {$EXTERNALSYM DH_F_DH_PRIV_DECODE}
  DH_F_DH_PRIV_DECODE            = 110;
  {$EXTERNALSYM DH_F_DH_PRIV_ENCODE}
  DH_F_DH_PRIV_ENCODE            = 111;
  {$EXTERNALSYM DH_F_DH_PUB_DECODE}
  DH_F_DH_PUB_DECODE             = 108;
  {$EXTERNALSYM DH_F_DH_PUB_ENCODE}
  DH_F_DH_PUB_ENCODE             = 109;
  {$EXTERNALSYM DH_F_DO_DH_PRINT}
  DH_F_DO_DH_PRINT               = 100;
  {$EXTERNALSYM DH_F_GENERATE_KEY}
  DH_F_GENERATE_KEY              = 103;
  {$EXTERNALSYM DH_F_PKEY_DH_CTRL_STR}
  DH_F_PKEY_DH_CTRL_STR          = 120;
  {$EXTERNALSYM DH_F_PKEY_DH_DERIVE}
  DH_F_PKEY_DH_DERIVE            = 112;
  {$EXTERNALSYM DH_F_PKEY_DH_INIT}
  DH_F_PKEY_DH_INIT              = 125;
  {$EXTERNALSYM DH_F_PKEY_DH_KEYGEN}
  DH_F_PKEY_DH_KEYGEN            = 113;

  // DH reason codes
  {$EXTERNALSYM DH_R_BAD_GENERATOR}
  DH_R_BAD_GENERATOR             = 101;
  {$EXTERNALSYM DH_R_BN_DECODE_ERROR}
  DH_R_BN_DECODE_ERROR           = 109;
  {$EXTERNALSYM DH_R_BN_ERROR}
  DH_R_BN_ERROR                  = 106;
  {$EXTERNALSYM DH_R_CHECK_INVALID_J_VALUE}
  DH_R_CHECK_INVALID_J_VALUE     = 115;
  {$EXTERNALSYM DH_R_CHECK_INVALID_Q_VALUE}
  DH_R_CHECK_INVALID_Q_VALUE     = 116;
  {$EXTERNALSYM DH_R_CHECK_PUBKEY_INVALID}
  DH_R_CHECK_PUBKEY_INVALID      = 122;
  {$EXTERNALSYM DH_R_CHECK_PUBKEY_TOO_LARGE}
  DH_R_CHECK_PUBKEY_TOO_LARGE    = 123;
  {$EXTERNALSYM DH_R_CHECK_PUBKEY_TOO_SMALL}
  DH_R_CHECK_PUBKEY_TOO_SMALL    = 124;
  {$EXTERNALSYM DH_R_CHECK_P_NOT_PRIME}
  DH_R_CHECK_P_NOT_PRIME         = 117;
  {$EXTERNALSYM DH_R_CHECK_P_NOT_SAFE_PRIME}
  DH_R_CHECK_P_NOT_SAFE_PRIME    = 118;
  {$EXTERNALSYM DH_R_CHECK_Q_NOT_PRIME}
  DH_R_CHECK_Q_NOT_PRIME         = 119;
  {$EXTERNALSYM DH_R_DECODE_ERROR}
  DH_R_DECODE_ERROR              = 104;
  {$EXTERNALSYM DH_R_INVALID_PARAMETER_NAME}
  DH_R_INVALID_PARAMETER_NAME    = 110;
  {$EXTERNALSYM DH_R_INVALID_PARAMETER_NID}
  DH_R_INVALID_PARAMETER_NID     = 114;
  {$EXTERNALSYM DH_R_INVALID_PUBKEY}
  DH_R_INVALID_PUBKEY            = 102;
  {$EXTERNALSYM DH_R_KDF_PARAMETER_ERROR}
  DH_R_KDF_PARAMETER_ERROR       = 112;
  {$EXTERNALSYM DH_R_KEYS_NOT_SET}
  DH_R_KEYS_NOT_SET              = 108;
  {$EXTERNALSYM DH_R_MISSING_PUBKEY}
  DH_R_MISSING_PUBKEY            = 125;
  {$EXTERNALSYM DH_R_MODULUS_TOO_LARGE}
  DH_R_MODULUS_TOO_LARGE         = 103;
  {$EXTERNALSYM DH_R_NOT_SUITABLE_GENERATOR}
  DH_R_NOT_SUITABLE_GENERATOR    = 120;
  {$EXTERNALSYM DH_R_NO_PARAMETERS_SET}
  DH_R_NO_PARAMETERS_SET         = 107;
  {$EXTERNALSYM DH_R_NO_PRIVATE_VALUE}
  DH_R_NO_PRIVATE_VALUE          = 100;
  {$EXTERNALSYM DH_R_PARAMETER_ENCODING_ERROR}
  DH_R_PARAMETER_ENCODING_ERROR  = 105;
  {$EXTERNALSYM DH_R_PEER_KEY_ERROR}
  DH_R_PEER_KEY_ERROR            = 111;
  {$EXTERNALSYM DH_R_SHARED_INFO_ERROR}
  DH_R_SHARED_INFO_ERROR         = 113;
  {$EXTERNALSYM DH_R_UNABLE_TO_CHECK_GENERATOR}
  DH_R_UNABLE_TO_CHECK_GENERATOR = 121;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_DH_strings}
  ERR_load_DH_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_DH_strings}
  function ERR_load_DH_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_DH_strings_procname = 'ERR_load_DH_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_DH_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_DH_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_DH_strings := LoadLibFunction(ADllHandle, ERR_load_DH_strings_procname);
  FuncLoadError := not assigned(ERR_load_DH_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_DH_strings_allownil)}
    ERR_load_DH_strings := ERR_ERR_load_DH_strings;
    {$ifend}
    {$if declared(ERR_load_DH_strings_introduced)}
    if LibVersion < ERR_load_DH_strings_introduced then
    begin
      {$if declared(FC_ERR_load_DH_strings)}
      ERR_load_DH_strings := FC_ERR_load_DH_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_DH_strings_removed)}
    if ERR_load_DH_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_DH_strings)}
      ERR_load_DH_strings := _ERR_load_DH_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_DH_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_DH_strings');
    {$ifend}
  end;


end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_DH_strings := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
