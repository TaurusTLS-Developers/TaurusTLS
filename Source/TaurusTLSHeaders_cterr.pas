/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_cterr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_cterr.h2pas
     and this file regenerated. TaurusTLSHeaders_cterr.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_cterr;

interface

// Headers for OpenSSL 1.1.1
// cterr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  ///*
  // * CT function codes.
  // */
  {$EXTERNALSYM CT_F_CTLOG_NEW}
  CT_F_CTLOG_NEW = 117;
  {$EXTERNALSYM CT_F_CTLOG_NEW_FROM_BASE64}
  CT_F_CTLOG_NEW_FROM_BASE64 = 118;
  {$EXTERNALSYM CT_F_CTLOG_NEW_FROM_CONF}
  CT_F_CTLOG_NEW_FROM_CONF = 119;
  {$EXTERNALSYM CT_F_CTLOG_STORE_LOAD_CTX_NEW}
  CT_F_CTLOG_STORE_LOAD_CTX_NEW = 122;
  {$EXTERNALSYM CT_F_CTLOG_STORE_LOAD_FILE}
  CT_F_CTLOG_STORE_LOAD_FILE = 123;
  {$EXTERNALSYM CT_F_CTLOG_STORE_LOAD_LOG}
  CT_F_CTLOG_STORE_LOAD_LOG = 130;
  {$EXTERNALSYM CT_F_CTLOG_STORE_NEW}
  CT_F_CTLOG_STORE_NEW = 131;
  {$EXTERNALSYM CT_F_CT_BASE64_DECODE}
  CT_F_CT_BASE64_DECODE = 124;
  {$EXTERNALSYM CT_F_CT_POLICY_EVAL_CTX_NEW}
  CT_F_CT_POLICY_EVAL_CTX_NEW = 133;
  {$EXTERNALSYM CT_F_CT_V1_LOG_ID_FROM_PKEY}
  CT_F_CT_V1_LOG_ID_FROM_PKEY = 125;
  {$EXTERNALSYM CT_F_I2O_SCT}
  CT_F_I2O_SCT = 107;
  {$EXTERNALSYM CT_F_I2O_SCT_LIST}
  CT_F_I2O_SCT_LIST = 108;
  {$EXTERNALSYM CT_F_I2O_SCT_SIGNATURE}
  CT_F_I2O_SCT_SIGNATURE = 109;
  {$EXTERNALSYM CT_F_O2I_SCT}
  CT_F_O2I_SCT = 110;
  {$EXTERNALSYM CT_F_O2I_SCT_LIST}
  CT_F_O2I_SCT_LIST = 111;
  {$EXTERNALSYM CT_F_O2I_SCT_SIGNATURE}
  CT_F_O2I_SCT_SIGNATURE = 112;
  {$EXTERNALSYM CT_F_SCT_CTX_NEW}
  CT_F_SCT_CTX_NEW = 126;
  {$EXTERNALSYM CT_F_SCT_CTX_VERIFY}
  CT_F_SCT_CTX_VERIFY = 128;
  {$EXTERNALSYM CT_F_SCT_NEW}
  CT_F_SCT_NEW = 100;
  {$EXTERNALSYM CT_F_SCT_NEW_FROM_BASE64}
  CT_F_SCT_NEW_FROM_BASE64 = 127;
  {$EXTERNALSYM CT_F_SCT_SET0_LOG_ID}
  CT_F_SCT_SET0_LOG_ID = 101;
  {$EXTERNALSYM CT_F_SCT_SET1_EXTENSIONS}
  CT_F_SCT_SET1_EXTENSIONS = 114;
  {$EXTERNALSYM CT_F_SCT_SET1_LOG_ID}
  CT_F_SCT_SET1_LOG_ID = 115;
  {$EXTERNALSYM CT_F_SCT_SET1_SIGNATURE}
  CT_F_SCT_SET1_SIGNATURE = 116;
  {$EXTERNALSYM CT_F_SCT_SET_LOG_ENTRY_TYPE}
  CT_F_SCT_SET_LOG_ENTRY_TYPE = 102;
  {$EXTERNALSYM CT_F_SCT_SET_SIGNATURE_NID}
  CT_F_SCT_SET_SIGNATURE_NID = 103;
  {$EXTERNALSYM CT_F_SCT_SET_VERSION}
  CT_F_SCT_SET_VERSION = 104;


  ///*
  // * CT reason codes.
  // */
  {$EXTERNALSYM CT_R_BASE64_DECODE_ERROR}
  CT_R_BASE64_DECODE_ERROR =  108;
  {$EXTERNALSYM CT_R_INVALID_LOG_ID_LENGTH}
  CT_R_INVALID_LOG_ID_LENGTH =  100;
  {$EXTERNALSYM CT_R_LOG_CONF_INVALID}
  CT_R_LOG_CONF_INVALID =  109;
  {$EXTERNALSYM CT_R_LOG_CONF_INVALID_KEY}
  CT_R_LOG_CONF_INVALID_KEY =  110;
  {$EXTERNALSYM CT_R_LOG_CONF_MISSING_DESCRIPTION}
  CT_R_LOG_CONF_MISSING_DESCRIPTION =  111;
  {$EXTERNALSYM CT_R_LOG_CONF_MISSING_KEY}
  CT_R_LOG_CONF_MISSING_KEY =  112;
  {$EXTERNALSYM CT_R_LOG_KEY_INVALID}
  CT_R_LOG_KEY_INVALID =  113;
  {$EXTERNALSYM CT_R_SCT_FUTURE_TIMESTAMP}
  CT_R_SCT_FUTURE_TIMESTAMP =  116;
  {$EXTERNALSYM CT_R_SCT_INVALID}
  CT_R_SCT_INVALID =   104;
  {$EXTERNALSYM CT_R_SCT_INVALID_SIGNATURE}
  CT_R_SCT_INVALID_SIGNATURE =  107;
  {$EXTERNALSYM CT_R_SCT_LIST_INVALID}
  CT_R_SCT_LIST_INVALID =  105;
  {$EXTERNALSYM CT_R_SCT_LOG_ID_MISMATCH}
  CT_R_SCT_LOG_ID_MISMATCH =  114;
  {$EXTERNALSYM CT_R_SCT_NOT_SET}
  CT_R_SCT_NOT_SET =   106;
  {$EXTERNALSYM CT_R_SCT_UNSUPPORTED_VERSION}
  CT_R_SCT_UNSUPPORTED_VERSION =  115;
  {$EXTERNALSYM CT_R_UNRECOGNIZED_SIGNATURE_NID}
  CT_R_UNRECOGNIZED_SIGNATURE_NID =  101;
  {$EXTERNALSYM CT_R_UNSUPPORTED_ENTRY_TYPE}
  CT_R_UNSUPPORTED_ENTRY_TYPE =  102;
  {$EXTERNALSYM CT_R_UNSUPPORTED_VERSION}
  CT_R_UNSUPPORTED_VERSION =  103;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_CT_strings}
  ERR_load_CT_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_CT_strings}
  function ERR_load_CT_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_CT_strings_procname = 'ERR_load_CT_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_CT_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_CT_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_CT_strings := LoadLibFunction(ADllHandle, ERR_load_CT_strings_procname);
  FuncLoadError := not assigned(ERR_load_CT_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_CT_strings_allownil)}
    ERR_load_CT_strings := ERR_ERR_load_CT_strings;
    {$ifend}
    {$if declared(ERR_load_CT_strings_introduced)}
    if LibVersion < ERR_load_CT_strings_introduced then
    begin
      {$if declared(FC_ERR_load_CT_strings)}
      ERR_load_CT_strings := FC_ERR_load_CT_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_CT_strings_removed)}
    if ERR_load_CT_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_CT_strings)}
      ERR_load_CT_strings := _ERR_load_CT_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_CT_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_CT_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_CT_strings := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
