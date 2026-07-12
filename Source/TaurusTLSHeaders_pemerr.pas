/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_pemerr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_pemerr.h2pas
     and this file regenerated. TaurusTLSHeaders_pemerr.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_pemerr;

interface

// Headers for OpenSSL 1.1.1
// pemerr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  // PEM function codes
  {$EXTERNALSYM PEM_F_B2I_DSS}
  PEM_F_B2I_DSS                      = 127;
  {$EXTERNALSYM PEM_F_B2I_PVK_BIO}
  PEM_F_B2I_PVK_BIO                  = 128;
  {$EXTERNALSYM PEM_F_B2I_RSA}
  PEM_F_B2I_RSA                      = 129;
  {$EXTERNALSYM PEM_F_CHECK_BITLEN_DSA}
  PEM_F_CHECK_BITLEN_DSA             = 130;
  {$EXTERNALSYM PEM_F_CHECK_BITLEN_RSA}
  PEM_F_CHECK_BITLEN_RSA             = 131;
  {$EXTERNALSYM PEM_F_D2I_PKCS8PRIVATEKEY_BIO}
  PEM_F_D2I_PKCS8PRIVATEKEY_BIO      = 120;
  {$EXTERNALSYM PEM_F_D2I_PKCS8PRIVATEKEY_FP}
  PEM_F_D2I_PKCS8PRIVATEKEY_FP       = 121;
  {$EXTERNALSYM PEM_F_DO_B2I}
  PEM_F_DO_B2I                       = 132;
  {$EXTERNALSYM PEM_F_DO_B2I_BIO}
  PEM_F_DO_B2I_BIO                   = 133;
  {$EXTERNALSYM PEM_F_DO_BLOB_HEADER}
  PEM_F_DO_BLOB_HEADER               = 134;
  {$EXTERNALSYM PEM_F_DO_I2B}
  PEM_F_DO_I2B                       = 146;
  {$EXTERNALSYM PEM_F_DO_PK8PKEY}
  PEM_F_DO_PK8PKEY                   = 126;
  {$EXTERNALSYM PEM_F_DO_PK8PKEY_FP}
  PEM_F_DO_PK8PKEY_FP                = 125;
  {$EXTERNALSYM PEM_F_DO_PVK_BODY}
  PEM_F_DO_PVK_BODY                  = 135;
  {$EXTERNALSYM PEM_F_DO_PVK_HEADER}
  PEM_F_DO_PVK_HEADER                = 136;
  {$EXTERNALSYM PEM_F_GET_HEADER_AND_DATA}
  PEM_F_GET_HEADER_AND_DATA          = 143;
  {$EXTERNALSYM PEM_F_GET_NAME}
  PEM_F_GET_NAME                     = 144;
  {$EXTERNALSYM PEM_F_I2B_PVK}
  PEM_F_I2B_PVK                      = 137;
  {$EXTERNALSYM PEM_F_I2B_PVK_BIO}
  PEM_F_I2B_PVK_BIO                  = 138;
  {$EXTERNALSYM PEM_F_LOAD_IV}
  PEM_F_LOAD_IV                      = 101;
  {$EXTERNALSYM PEM_F_PEM_ASN1_READ}
  PEM_F_PEM_ASN1_READ                = 102;
  {$EXTERNALSYM PEM_F_PEM_ASN1_READ_BIO}
  PEM_F_PEM_ASN1_READ_BIO            = 103;
  {$EXTERNALSYM PEM_F_PEM_ASN1_WRITE}
  PEM_F_PEM_ASN1_WRITE               = 104;
  {$EXTERNALSYM PEM_F_PEM_ASN1_WRITE_BIO}
  PEM_F_PEM_ASN1_WRITE_BIO           = 105;
  {$EXTERNALSYM PEM_F_PEM_DEF_CALLBACK}
  PEM_F_PEM_DEF_CALLBACK             = 100;
  {$EXTERNALSYM PEM_F_PEM_DO_HEADER}
  PEM_F_PEM_DO_HEADER                = 106;
  {$EXTERNALSYM PEM_F_PEM_GET_EVP_CIPHER_INFO}
  PEM_F_PEM_GET_EVP_CIPHER_INFO      = 107;
  {$EXTERNALSYM PEM_F_PEM_READ}
  PEM_F_PEM_READ                     = 108;
  {$EXTERNALSYM PEM_F_PEM_READ_BIO}
  PEM_F_PEM_READ_BIO                 = 109;
  {$EXTERNALSYM PEM_F_PEM_READ_BIO_DHPARAMS}
  PEM_F_PEM_READ_BIO_DHPARAMS        = 141;
  {$EXTERNALSYM PEM_F_PEM_READ_BIO_EX}
  PEM_F_PEM_READ_BIO_EX              = 145;
  {$EXTERNALSYM PEM_F_PEM_READ_BIO_PARAMETERS}
  PEM_F_PEM_READ_BIO_PARAMETERS      = 140;
  {$EXTERNALSYM PEM_F_PEM_READ_BIO_PRIVATEKEY}
  PEM_F_PEM_READ_BIO_PRIVATEKEY      = 123;
  {$EXTERNALSYM PEM_F_PEM_READ_DHPARAMS}
  PEM_F_PEM_READ_DHPARAMS            = 142;
  {$EXTERNALSYM PEM_F_PEM_READ_PRIVATEKEY}
  PEM_F_PEM_READ_PRIVATEKEY          = 124;
  {$EXTERNALSYM PEM_F_PEM_SIGNFINAL}
  PEM_F_PEM_SIGNFINAL                = 112;
  {$EXTERNALSYM PEM_F_PEM_WRITE}
  PEM_F_PEM_WRITE                    = 113;
  {$EXTERNALSYM PEM_F_PEM_WRITE_BIO}
  PEM_F_PEM_WRITE_BIO                = 114;
  {$EXTERNALSYM PEM_F_PEM_WRITE_PRIVATEKEY}
  PEM_F_PEM_WRITE_PRIVATEKEY         = 139;
  {$EXTERNALSYM PEM_F_PEM_X509_INFO_READ}
  PEM_F_PEM_X509_INFO_READ           = 115;
  {$EXTERNALSYM PEM_F_PEM_X509_INFO_READ_BIO}
  PEM_F_PEM_X509_INFO_READ_BIO       = 116;
  {$EXTERNALSYM PEM_F_PEM_X509_INFO_WRITE_BIO}
  PEM_F_PEM_X509_INFO_WRITE_BIO      = 117;
  // PEM reason codes
  {$EXTERNALSYM PEM_R_BAD_BASE64_DECODE}
  PEM_R_BAD_BASE64_DECODE            = 100;
  {$EXTERNALSYM PEM_R_BAD_DECRYPT}
  PEM_R_BAD_DECRYPT                  = 101;
  {$EXTERNALSYM PEM_R_BAD_END_LINE}
  PEM_R_BAD_END_LINE                 = 102;
  {$EXTERNALSYM PEM_R_BAD_IV_CHARS}
  PEM_R_BAD_IV_CHARS                 = 103;
  {$EXTERNALSYM PEM_R_BAD_MAGIC_NUMBER}
  PEM_R_BAD_MAGIC_NUMBER             = 116;
  {$EXTERNALSYM PEM_R_BAD_PASSWORD_READ}
  PEM_R_BAD_PASSWORD_READ            = 104;
  {$EXTERNALSYM PEM_R_BAD_VERSION_NUMBER}
  PEM_R_BAD_VERSION_NUMBER           = 117;
  {$EXTERNALSYM PEM_R_BIO_WRITE_FAILURE}
  PEM_R_BIO_WRITE_FAILURE            = 118;
  {$EXTERNALSYM PEM_R_CIPHER_IS_NULL}
  PEM_R_CIPHER_IS_NULL               = 127;
  {$EXTERNALSYM PEM_R_ERROR_CONVERTING_PRIVATE_KEY}
  PEM_R_ERROR_CONVERTING_PRIVATE_KEY = 115;
  {$EXTERNALSYM PEM_R_EXPECTING_PRIVATE_KEY_BLOB}
  PEM_R_EXPECTING_PRIVATE_KEY_BLOB   = 119;
  {$EXTERNALSYM PEM_R_EXPECTING_PUBLIC_KEY_BLOB}
  PEM_R_EXPECTING_PUBLIC_KEY_BLOB    = 120;
  {$EXTERNALSYM PEM_R_HEADER_TOO_LONG}
  PEM_R_HEADER_TOO_LONG              = 128;
  {$EXTERNALSYM PEM_R_INCONSISTENT_HEADER}
  PEM_R_INCONSISTENT_HEADER          = 121;
  {$EXTERNALSYM PEM_R_KEYBLOB_HEADER_PARSE_ERROR}
  PEM_R_KEYBLOB_HEADER_PARSE_ERROR   = 122;
  {$EXTERNALSYM PEM_R_KEYBLOB_TOO_SHORT}
  PEM_R_KEYBLOB_TOO_SHORT            = 123;
  {$EXTERNALSYM PEM_R_MISSING_DEK_IV}
  PEM_R_MISSING_DEK_IV               = 129;
  {$EXTERNALSYM PEM_R_NOT_DEK_INFO}
  PEM_R_NOT_DEK_INFO                 = 105;
  {$EXTERNALSYM PEM_R_NOT_ENCRYPTED}
  PEM_R_NOT_ENCRYPTED                = 106;
  {$EXTERNALSYM PEM_R_NOT_PROC_TYPE}
  PEM_R_NOT_PROC_TYPE                = 107;
  {$EXTERNALSYM PEM_R_NO_START_LINE}
  PEM_R_NO_START_LINE                = 108;
  {$EXTERNALSYM PEM_R_PROBLEMS_GETTING_PASSWORD}
  PEM_R_PROBLEMS_GETTING_PASSWORD    = 109;
  {$EXTERNALSYM PEM_R_PVK_DATA_TOO_SHORT}
  PEM_R_PVK_DATA_TOO_SHORT           = 124;
  {$EXTERNALSYM PEM_R_PVK_TOO_SHORT}
  PEM_R_PVK_TOO_SHORT                = 125;
  {$EXTERNALSYM PEM_R_READ_KEY}
  PEM_R_READ_KEY                     = 111;
  {$EXTERNALSYM PEM_R_SHORT_HEADER}
  PEM_R_SHORT_HEADER                 = 112;
  {$EXTERNALSYM PEM_R_UNEXPECTED_DEK_IV}
  PEM_R_UNEXPECTED_DEK_IV            = 130;
  {$EXTERNALSYM PEM_R_UNSUPPORTED_CIPHER}
  PEM_R_UNSUPPORTED_CIPHER           = 113;
  {$EXTERNALSYM PEM_R_UNSUPPORTED_ENCRYPTION}
  PEM_R_UNSUPPORTED_ENCRYPTION       = 114;
  {$EXTERNALSYM PEM_R_UNSUPPORTED_KEY_COMPONENTS}
  PEM_R_UNSUPPORTED_KEY_COMPONENTS   = 126;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_PEM_strings}
  ERR_load_PEM_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_PEM_strings}
  function ERR_load_PEM_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_PEM_strings_procname = 'ERR_load_PEM_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_PEM_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_PEM_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_PEM_strings := LoadLibFunction(ADllHandle, ERR_load_PEM_strings_procname);
  FuncLoadError := not assigned(ERR_load_PEM_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_PEM_strings_allownil)}
    ERR_load_PEM_strings := ERR_ERR_load_PEM_strings;
    {$ifend}
    {$if declared(ERR_load_PEM_strings_introduced)}
    if LibVersion < ERR_load_PEM_strings_introduced then
    begin
      {$if declared(FC_ERR_load_PEM_strings)}
      ERR_load_PEM_strings := FC_ERR_load_PEM_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_PEM_strings_removed)}
    if ERR_load_PEM_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_PEM_strings)}
      ERR_load_PEM_strings := _ERR_load_PEM_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_PEM_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_PEM_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_PEM_strings := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
