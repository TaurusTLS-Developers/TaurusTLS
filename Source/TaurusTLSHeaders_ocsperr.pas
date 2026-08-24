/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_ocsperr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_ocsperr.h2pas
     and this file regenerated. TaurusTLSHeaders_ocsperr.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_ocsperr;

interface

// Headers for OpenSSL 1.1.1
// ocsperr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * OCSP function codes.
   *)
  {$EXTERNALSYM OCSP_F_D2I_OCSP_NONCE}
  OCSP_F_D2I_OCSP_NONCE = 102;
  {$EXTERNALSYM OCSP_F_OCSP_BASIC_ADD1_STATUS}
  OCSP_F_OCSP_BASIC_ADD1_STATUS = 103;
  {$EXTERNALSYM OCSP_F_OCSP_BASIC_SIGN}
  OCSP_F_OCSP_BASIC_SIGN = 104;
  {$EXTERNALSYM OCSP_F_OCSP_BASIC_SIGN_CTX}
  OCSP_F_OCSP_BASIC_SIGN_CTX = 119;
  {$EXTERNALSYM OCSP_F_OCSP_BASIC_VERIFY}
  OCSP_F_OCSP_BASIC_VERIFY = 105;
  {$EXTERNALSYM OCSP_F_OCSP_CERT_ID_NEW}
  OCSP_F_OCSP_CERT_ID_NEW = 101;
  {$EXTERNALSYM OCSP_F_OCSP_CHECK_DELEGATED}
  OCSP_F_OCSP_CHECK_DELEGATED = 106;
  {$EXTERNALSYM OCSP_F_OCSP_CHECK_IDS}
  OCSP_F_OCSP_CHECK_IDS = 107;
  {$EXTERNALSYM OCSP_F_OCSP_CHECK_ISSUER}
  OCSP_F_OCSP_CHECK_ISSUER = 108;
  {$EXTERNALSYM OCSP_F_OCSP_CHECK_VALIDITY}
  OCSP_F_OCSP_CHECK_VALIDITY = 115;
  {$EXTERNALSYM OCSP_F_OCSP_MATCH_ISSUERID}
  OCSP_F_OCSP_MATCH_ISSUERID = 109;
  {$EXTERNALSYM OCSP_F_OCSP_PARSE_URL}
  OCSP_F_OCSP_PARSE_URL = 114;
  {$EXTERNALSYM OCSP_F_OCSP_REQUEST_SIGN}
  OCSP_F_OCSP_REQUEST_SIGN = 110;
  {$EXTERNALSYM OCSP_F_OCSP_REQUEST_VERIFY}
  OCSP_F_OCSP_REQUEST_VERIFY = 116;
  {$EXTERNALSYM OCSP_F_OCSP_RESPONSE_GET1_BASIC}
  OCSP_F_OCSP_RESPONSE_GET1_BASIC = 111;
  {$EXTERNALSYM OCSP_F_PARSE_HTTP_LINE1}
  OCSP_F_PARSE_HTTP_LINE1 = 118;

  (*
   * OCSP reason codes.
   *)
  {$EXTERNALSYM OCSP_R_CERTIFICATE_VERIFY_ERROR}
  OCSP_R_CERTIFICATE_VERIFY_ERROR = 101;
  {$EXTERNALSYM OCSP_R_DIGEST_ERR}
  OCSP_R_DIGEST_ERR = 102;
  {$EXTERNALSYM OCSP_R_ERROR_IN_NEXTUPDATE_FIELD}
  OCSP_R_ERROR_IN_NEXTUPDATE_FIELD = 122;
  {$EXTERNALSYM OCSP_R_ERROR_IN_THISUPDATE_FIELD}
  OCSP_R_ERROR_IN_THISUPDATE_FIELD = 123;
  {$EXTERNALSYM OCSP_R_ERROR_PARSING_URL}
  OCSP_R_ERROR_PARSING_URL = 121;
  {$EXTERNALSYM OCSP_R_MISSING_OCSPSIGNING_USAGE}
  OCSP_R_MISSING_OCSPSIGNING_USAGE = 103;
  {$EXTERNALSYM OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE}
  OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE = 124;
  {$EXTERNALSYM OCSP_R_NOT_BASIC_RESPONSE}
  OCSP_R_NOT_BASIC_RESPONSE = 104;
  {$EXTERNALSYM OCSP_R_NO_CERTIFICATES_IN_CHAIN}
  OCSP_R_NO_CERTIFICATES_IN_CHAIN = 105;
  {$EXTERNALSYM OCSP_R_NO_RESPONSE_DATA}
  OCSP_R_NO_RESPONSE_DATA = 108;
  {$EXTERNALSYM OCSP_R_NO_REVOKED_TIME}
  OCSP_R_NO_REVOKED_TIME = 109;
  {$EXTERNALSYM OCSP_R_NO_SIGNER_KEY}
  OCSP_R_NO_SIGNER_KEY = 130;
  {$EXTERNALSYM OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE}
  OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 110;
  {$EXTERNALSYM OCSP_R_REQUEST_NOT_SIGNED}
  OCSP_R_REQUEST_NOT_SIGNED = 128;
  {$EXTERNALSYM OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA}
  OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA = 111;
  {$EXTERNALSYM OCSP_R_ROOT_CA_NOT_TRUSTED}
  OCSP_R_ROOT_CA_NOT_TRUSTED = 112;
  {$EXTERNALSYM OCSP_R_SERVER_RESPONSE_ERROR}
  OCSP_R_SERVER_RESPONSE_ERROR = 114;
  {$EXTERNALSYM OCSP_R_SERVER_RESPONSE_PARSE_ERROR}
  OCSP_R_SERVER_RESPONSE_PARSE_ERROR = 115;
  {$EXTERNALSYM OCSP_R_SIGNATURE_FAILURE}
  OCSP_R_SIGNATURE_FAILURE = 117;
  {$EXTERNALSYM OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND}
  OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND = 118;
  {$EXTERNALSYM OCSP_R_STATUS_EXPIRED}
  OCSP_R_STATUS_EXPIRED = 125;
  {$EXTERNALSYM OCSP_R_STATUS_NOT_YET_VALID}
  OCSP_R_STATUS_NOT_YET_VALID = 126;
  {$EXTERNALSYM OCSP_R_STATUS_TOO_OLD}
  OCSP_R_STATUS_TOO_OLD = 127;
  {$EXTERNALSYM OCSP_R_UNKNOWN_MESSAGE_DIGEST}
  OCSP_R_UNKNOWN_MESSAGE_DIGEST = 119;
  {$EXTERNALSYM OCSP_R_UNKNOWN_NID}
  OCSP_R_UNKNOWN_NID = 120;
  {$EXTERNALSYM OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE}
  OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE = 129;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_OCSP_strings}
  ERR_load_OCSP_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_OCSP_strings}
  function ERR_load_OCSP_strings: TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    , TaurusTLSLoader
  {$ENDIF};
  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  ERR_load_OCSP_strings_procname = 'ERR_load_OCSP_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_OCSP_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_OCSP_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_OCSP_strings := LoadLibFunction(ADllHandle, ERR_load_OCSP_strings_procname);
  FuncLoadError := not assigned(ERR_load_OCSP_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_OCSP_strings_allownil)}
    ERR_load_OCSP_strings := ERR_ERR_load_OCSP_strings;
    {$ifend}
    {$if declared(ERR_load_OCSP_strings_introduced)}
    if LibVersion < ERR_load_OCSP_strings_introduced then
    begin
      {$if declared(FC_ERR_load_OCSP_strings)}
      ERR_load_OCSP_strings := FC_ERR_load_OCSP_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_OCSP_strings_removed)}
    if ERR_load_OCSP_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_OCSP_strings)}
      ERR_load_OCSP_strings := _ERR_load_OCSP_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_OCSP_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_OCSP_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_OCSP_strings := nil;
end;
  {$ENDIF}
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
