/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_pkcs7err.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_pkcs7err.h2pas
     and this file regenerated. TaurusTLSHeaders_pkcs7err.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_pkcs7err;

interface

// Headers for OpenSSL 1.1.1
// pkcs7err.h


uses
  IdCTypes,
  IdGlobal
   {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * PKCS7 function codes.
   *)
  {$EXTERNALSYM PKCS7_F_DO_PKCS7_SIGNED_ATTRIB}
  PKCS7_F_DO_PKCS7_SIGNED_ATTRIB                     = 136;
  {$EXTERNALSYM PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME}
  PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME             = 135;
  {$EXTERNALSYM PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP}
  PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP                  = 118;
  {$EXTERNALSYM PKCS7_F_PKCS7_ADD_CERTIFICATE}
  PKCS7_F_PKCS7_ADD_CERTIFICATE                      = 100;
  {$EXTERNALSYM PKCS7_F_PKCS7_ADD_CRL}
  PKCS7_F_PKCS7_ADD_CRL                              = 101;
  {$EXTERNALSYM PKCS7_F_PKCS7_ADD_RECIPIENT_INFO}
  PKCS7_F_PKCS7_ADD_RECIPIENT_INFO                   = 102;
  {$EXTERNALSYM PKCS7_F_PKCS7_ADD_SIGNATURE}
  PKCS7_F_PKCS7_ADD_SIGNATURE                        = 131;
  {$EXTERNALSYM PKCS7_F_PKCS7_ADD_SIGNER}
  PKCS7_F_PKCS7_ADD_SIGNER                           = 103;
  {$EXTERNALSYM PKCS7_F_PKCS7_BIO_ADD_DIGEST}
  PKCS7_F_PKCS7_BIO_ADD_DIGEST                       = 125;
  {$EXTERNALSYM PKCS7_F_PKCS7_COPY_EXISTING_DIGEST}
  PKCS7_F_PKCS7_COPY_EXISTING_DIGEST                 = 138;
  {$EXTERNALSYM PKCS7_F_PKCS7_CTRL}
  PKCS7_F_PKCS7_CTRL                                 = 104;
  {$EXTERNALSYM PKCS7_F_PKCS7_DATADECODE}
  PKCS7_F_PKCS7_DATADECODE                           = 112;
  {$EXTERNALSYM PKCS7_F_PKCS7_DATAFINAL}
  PKCS7_F_PKCS7_DATAFINAL                            = 128;
  {$EXTERNALSYM PKCS7_F_PKCS7_DATAINIT}
  PKCS7_F_PKCS7_DATAINIT                             = 105;
  {$EXTERNALSYM PKCS7_F_PKCS7_DATAVERIFY}
  PKCS7_F_PKCS7_DATAVERIFY                           = 107;
  {$EXTERNALSYM PKCS7_F_PKCS7_DECRYPT}
  PKCS7_F_PKCS7_DECRYPT                              = 114;
  {$EXTERNALSYM PKCS7_F_PKCS7_DECRYPT_RINFO}
  PKCS7_F_PKCS7_DECRYPT_RINFO                        = 133;
  {$EXTERNALSYM PKCS7_F_PKCS7_ENCODE_RINFO}
  PKCS7_F_PKCS7_ENCODE_RINFO                         = 132;
  {$EXTERNALSYM PKCS7_F_PKCS7_ENCRYPT}
  PKCS7_F_PKCS7_ENCRYPT                              = 115;
  {$EXTERNALSYM PKCS7_F_PKCS7_FINAL}
  PKCS7_F_PKCS7_FINAL                                = 134;
  {$EXTERNALSYM PKCS7_F_PKCS7_FIND_DIGEST}
  PKCS7_F_PKCS7_FIND_DIGEST                          = 127;
  {$EXTERNALSYM PKCS7_F_PKCS7_GET0_SIGNERS}
  PKCS7_F_PKCS7_GET0_SIGNERS                         = 124;
  {$EXTERNALSYM PKCS7_F_PKCS7_RECIP_INFO_SET}
  PKCS7_F_PKCS7_RECIP_INFO_SET                       = 130;
  {$EXTERNALSYM PKCS7_F_PKCS7_SET_CIPHER}
  PKCS7_F_PKCS7_SET_CIPHER                           = 108;
  {$EXTERNALSYM PKCS7_F_PKCS7_SET_CONTENT}
  PKCS7_F_PKCS7_SET_CONTENT                          = 109;
  {$EXTERNALSYM PKCS7_F_PKCS7_SET_DIGEST}
  PKCS7_F_PKCS7_SET_DIGEST                           = 126;
  {$EXTERNALSYM PKCS7_F_PKCS7_SET_TYPE}
  PKCS7_F_PKCS7_SET_TYPE                             = 110;
  {$EXTERNALSYM PKCS7_F_PKCS7_SIGN}
  PKCS7_F_PKCS7_SIGN                                 = 116;
  {$EXTERNALSYM PKCS7_F_PKCS7_SIGNATUREVERIFY}
  PKCS7_F_PKCS7_SIGNATUREVERIFY                      = 113;
  {$EXTERNALSYM PKCS7_F_PKCS7_SIGNER_INFO_SET}
  PKCS7_F_PKCS7_SIGNER_INFO_SET                      = 129;
  {$EXTERNALSYM PKCS7_F_PKCS7_SIGNER_INFO_SIGN}
  PKCS7_F_PKCS7_SIGNER_INFO_SIGN                     = 139;
  {$EXTERNALSYM PKCS7_F_PKCS7_SIGN_ADD_SIGNER}
  PKCS7_F_PKCS7_SIGN_ADD_SIGNER                      = 137;
  {$EXTERNALSYM PKCS7_F_PKCS7_SIMPLE_SMIMECAP}
  PKCS7_F_PKCS7_SIMPLE_SMIMECAP                      = 119;
  {$EXTERNALSYM PKCS7_F_PKCS7_VERIFY}
  PKCS7_F_PKCS7_VERIFY                               = 117;

  (*
   * PKCS7 reason codes.
   *)
  {$EXTERNALSYM PKCS7_R_CERTIFICATE_VERIFY_ERROR}
  PKCS7_R_CERTIFICATE_VERIFY_ERROR                   = 117;
  {$EXTERNALSYM PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER}
  PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER            = 144;
  {$EXTERNALSYM PKCS7_R_CIPHER_NOT_INITIALIZED}
  PKCS7_R_CIPHER_NOT_INITIALIZED                     = 116;
  {$EXTERNALSYM PKCS7_R_CONTENT_AND_DATA_PRESENT}
  PKCS7_R_CONTENT_AND_DATA_PRESENT                   = 118;
  {$EXTERNALSYM PKCS7_R_CTRL_ERROR}
  PKCS7_R_CTRL_ERROR                                 = 152;
  {$EXTERNALSYM PKCS7_R_DECRYPT_ERROR}
  PKCS7_R_DECRYPT_ERROR                              = 119;
  {$EXTERNALSYM PKCS7_R_DIGEST_FAILURE}
  PKCS7_R_DIGEST_FAILURE                             = 101;
  {$EXTERNALSYM PKCS7_R_ENCRYPTION_CTRL_FAILURE}
  PKCS7_R_ENCRYPTION_CTRL_FAILURE                    = 149;
  {$EXTERNALSYM PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE}
  PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 150;
  {$EXTERNALSYM PKCS7_R_ERROR_ADDING_RECIPIENT}
  PKCS7_R_ERROR_ADDING_RECIPIENT                     = 120;
  {$EXTERNALSYM PKCS7_R_ERROR_SETTING_CIPHER}
  PKCS7_R_ERROR_SETTING_CIPHER                       = 121;
  {$EXTERNALSYM PKCS7_R_INVALID_NULL_POINTER}
  PKCS7_R_INVALID_NULL_POINTER                       = 143;
  {$EXTERNALSYM PKCS7_R_INVALID_SIGNED_DATA_TYPE}
  PKCS7_R_INVALID_SIGNED_DATA_TYPE                   = 155;
  {$EXTERNALSYM PKCS7_R_NO_CONTENT}
  PKCS7_R_NO_CONTENT                                 = 122;
  {$EXTERNALSYM PKCS7_R_NO_DEFAULT_DIGEST}
  PKCS7_R_NO_DEFAULT_DIGEST                          = 151;
  {$EXTERNALSYM PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND}
  PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND              = 154;
  {$EXTERNALSYM PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE}
  PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE           = 115;
  {$EXTERNALSYM PKCS7_R_NO_SIGNATURES_ON_DATA}
  PKCS7_R_NO_SIGNATURES_ON_DATA                      = 123;
  {$EXTERNALSYM PKCS7_R_NO_SIGNERS}
  PKCS7_R_NO_SIGNERS                                 = 142;
  {$EXTERNALSYM PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE}
  PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE       = 104;
  {$EXTERNALSYM PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR}
  PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR                  = 124;
  {$EXTERNALSYM PKCS7_R_PKCS7_ADD_SIGNER_ERROR}
  PKCS7_R_PKCS7_ADD_SIGNER_ERROR                     = 153;
  {$EXTERNALSYM PKCS7_R_PKCS7_DATASIGN}
  PKCS7_R_PKCS7_DATASIGN                             = 145;
  {$EXTERNALSYM PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE}
  PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE     = 127;
  {$EXTERNALSYM PKCS7_R_SIGNATURE_FAILURE}
  PKCS7_R_SIGNATURE_FAILURE                          = 105;
  {$EXTERNALSYM PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND}
  PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND               = 128;
  {$EXTERNALSYM PKCS7_R_SIGNING_CTRL_FAILURE}
  PKCS7_R_SIGNING_CTRL_FAILURE                       = 147;
  {$EXTERNALSYM PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE}
  PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE    = 148;
  {$EXTERNALSYM PKCS7_R_SMIME_TEXT_ERROR}
  PKCS7_R_SMIME_TEXT_ERROR                           = 129;
  {$EXTERNALSYM PKCS7_R_UNABLE_TO_FIND_CERTIFICATE}
  PKCS7_R_UNABLE_TO_FIND_CERTIFICATE                 = 106;
  {$EXTERNALSYM PKCS7_R_UNABLE_TO_FIND_MEM_BIO}
  PKCS7_R_UNABLE_TO_FIND_MEM_BIO                     = 107;
  {$EXTERNALSYM PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST}
  PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST              = 108;
  {$EXTERNALSYM PKCS7_R_UNKNOWN_DIGEST_TYPE}
  PKCS7_R_UNKNOWN_DIGEST_TYPE                        = 109;
  {$EXTERNALSYM PKCS7_R_UNKNOWN_OPERATION}
  PKCS7_R_UNKNOWN_OPERATION                          = 110;
  {$EXTERNALSYM PKCS7_R_UNSUPPORTED_CIPHER_TYPE}
  PKCS7_R_UNSUPPORTED_CIPHER_TYPE                    = 111;
  {$EXTERNALSYM PKCS7_R_UNSUPPORTED_CONTENT_TYPE}
  PKCS7_R_UNSUPPORTED_CONTENT_TYPE                   = 112;
  {$EXTERNALSYM PKCS7_R_WRONG_CONTENT_TYPE}
  PKCS7_R_WRONG_CONTENT_TYPE                         = 113;
  {$EXTERNALSYM PKCS7_R_WRONG_PKCS7_TYPE}
  PKCS7_R_WRONG_PKCS7_TYPE                           = 114;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_PKCS7_strings}
  ERR_load_PKCS7_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_PKCS7_strings}
  function ERR_load_PKCS7_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_PKCS7_strings_procname = 'ERR_load_PKCS7_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_PKCS7_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_PKCS7_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_PKCS7_strings := LoadLibFunction(ADllHandle, ERR_load_PKCS7_strings_procname);
  FuncLoadError := not assigned(ERR_load_PKCS7_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_PKCS7_strings_allownil)}
    ERR_load_PKCS7_strings := ERR_ERR_load_PKCS7_strings;
    {$ifend}
    {$if declared(ERR_load_PKCS7_strings_introduced)}
    if LibVersion < ERR_load_PKCS7_strings_introduced then
    begin
      {$if declared(FC_ERR_load_PKCS7_strings)}
      ERR_load_PKCS7_strings := FC_ERR_load_PKCS7_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_PKCS7_strings_removed)}
    if ERR_load_PKCS7_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_PKCS7_strings)}
      ERR_load_PKCS7_strings := _ERR_load_PKCS7_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_PKCS7_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_PKCS7_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_PKCS7_strings := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
