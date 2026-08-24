/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_x509err.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_x509err.h2pas
     and this file regenerated. TaurusTLSHeaders_x509err.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_x509err;

interface

// Headers for OpenSSL 1.1.1
// x509err.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * X509 function codes.
   *)
  {$EXTERNALSYM X509_F_ADD_CERT_DIR}
  X509_F_ADD_CERT_DIR                       = 100;
  {$EXTERNALSYM X509_F_BUILD_CHAIN}
  X509_F_BUILD_CHAIN                        = 106;
  {$EXTERNALSYM X509_F_BY_FILE_CTRL}
  X509_F_BY_FILE_CTRL                       = 101;
  {$EXTERNALSYM X509_F_CHECK_NAME_CONSTRAINTS}
  X509_F_CHECK_NAME_CONSTRAINTS             = 149;
  {$EXTERNALSYM X509_F_CHECK_POLICY}
  X509_F_CHECK_POLICY                       = 145;
  {$EXTERNALSYM X509_F_DANE_I2D}
  X509_F_DANE_I2D                           = 107;
  {$EXTERNALSYM X509_F_DIR_CTRL}
  X509_F_DIR_CTRL                           = 102;
  {$EXTERNALSYM X509_F_GET_CERT_BY_SUBJECT}
  X509_F_GET_CERT_BY_SUBJECT                = 103;
  {$EXTERNALSYM X509_F_I2D_X509_AUX}
  X509_F_I2D_X509_AUX                       = 151;
  {$EXTERNALSYM X509_F_LOOKUP_CERTS_SK}
  X509_F_LOOKUP_CERTS_SK                    = 152;
  {$EXTERNALSYM X509_F_NETSCAPE_SPKI_B64_DECODE}
  X509_F_NETSCAPE_SPKI_B64_DECODE           = 129;
  {$EXTERNALSYM X509_F_NETSCAPE_SPKI_B64_ENCODE}
  X509_F_NETSCAPE_SPKI_B64_ENCODE           = 130;
  {$EXTERNALSYM X509_F_NEW_DIR}
  X509_F_NEW_DIR                            = 153;
  {$EXTERNALSYM X509_F_X509AT_ADD1_ATTR}
  X509_F_X509AT_ADD1_ATTR                   = 135;
  {$EXTERNALSYM X509_F_X509V3_ADD_EXT}
  X509_F_X509V3_ADD_EXT                     = 104;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_CREATE_BY_NID}
  X509_F_X509_ATTRIBUTE_CREATE_BY_NID       = 136;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ}
  X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ       = 137;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_CREATE_BY_TXT}
  X509_F_X509_ATTRIBUTE_CREATE_BY_TXT       = 140;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_GET0_DATA}
  X509_F_X509_ATTRIBUTE_GET0_DATA           = 139;
  {$EXTERNALSYM X509_F_X509_ATTRIBUTE_SET1_DATA}
  X509_F_X509_ATTRIBUTE_SET1_DATA           = 138;
  {$EXTERNALSYM X509_F_X509_CHECK_PRIVATE_KEY}
  X509_F_X509_CHECK_PRIVATE_KEY             = 128;
  {$EXTERNALSYM X509_F_X509_CRL_DIFF}
  X509_F_X509_CRL_DIFF                      = 105;
  {$EXTERNALSYM X509_F_X509_CRL_METHOD_NEW}
  X509_F_X509_CRL_METHOD_NEW                = 154;
  {$EXTERNALSYM X509_F_X509_CRL_PRINT_FP}
  X509_F_X509_CRL_PRINT_FP                  = 147;
  {$EXTERNALSYM X509_F_X509_EXTENSION_CREATE_BY_NID}
  X509_F_X509_EXTENSION_CREATE_BY_NID       = 108;
  {$EXTERNALSYM X509_F_X509_EXTENSION_CREATE_BY_OBJ}
  X509_F_X509_EXTENSION_CREATE_BY_OBJ       = 109;
  {$EXTERNALSYM X509_F_X509_GET_PUBKEY_PARAMETERS}
  X509_F_X509_GET_PUBKEY_PARAMETERS         = 110;
  {$EXTERNALSYM X509_F_X509_LOAD_CERT_CRL_FILE}
  X509_F_X509_LOAD_CERT_CRL_FILE            = 132;
  {$EXTERNALSYM X509_F_X509_LOAD_CERT_FILE}
  X509_F_X509_LOAD_CERT_FILE                = 111;
  {$EXTERNALSYM X509_F_X509_LOAD_CRL_FILE}
  X509_F_X509_LOAD_CRL_FILE                 = 112;
  {$EXTERNALSYM X509_F_X509_LOOKUP_METH_NEW}
  X509_F_X509_LOOKUP_METH_NEW               = 160;
  {$EXTERNALSYM X509_F_X509_LOOKUP_NEW}
  X509_F_X509_LOOKUP_NEW                    = 155;
  {$EXTERNALSYM X509_F_X509_NAME_ADD_ENTRY}
  X509_F_X509_NAME_ADD_ENTRY                = 113;
  {$EXTERNALSYM X509_F_X509_NAME_CANON}
  X509_F_X509_NAME_CANON                    = 156;
  {$EXTERNALSYM X509_F_X509_NAME_ENTRY_CREATE_BY_NID}
  X509_F_X509_NAME_ENTRY_CREATE_BY_NID      = 114;
  {$EXTERNALSYM X509_F_X509_NAME_ENTRY_CREATE_BY_TXT}
  X509_F_X509_NAME_ENTRY_CREATE_BY_TXT      = 131;
  {$EXTERNALSYM X509_F_X509_NAME_ENTRY_SET_OBJECT}
  X509_F_X509_NAME_ENTRY_SET_OBJECT         = 115;
  {$EXTERNALSYM X509_F_X509_NAME_ONELINE}
  X509_F_X509_NAME_ONELINE                  = 116;
  {$EXTERNALSYM X509_F_X509_NAME_PRINT}
  X509_F_X509_NAME_PRINT                    = 117;
  {$EXTERNALSYM X509_F_X509_OBJECT_NEW}
  X509_F_X509_OBJECT_NEW                    = 150;
  {$EXTERNALSYM X509_F_X509_PRINT_EX_FP}
  X509_F_X509_PRINT_EX_FP                   = 118;
  {$EXTERNALSYM X509_F_X509_PUBKEY_DECODE}
  X509_F_X509_PUBKEY_DECODE                 = 148;
  {$EXTERNALSYM X509_F_X509_PUBKEY_GET0}
  X509_F_X509_PUBKEY_GET0                   = 119;
  {$EXTERNALSYM X509_F_X509_PUBKEY_SET}
  X509_F_X509_PUBKEY_SET                    = 120;
  {$EXTERNALSYM X509_F_X509_REQ_CHECK_PRIVATE_KEY}
  X509_F_X509_REQ_CHECK_PRIVATE_KEY         = 144;
  {$EXTERNALSYM X509_F_X509_REQ_PRINT_EX}
  X509_F_X509_REQ_PRINT_EX                  = 121;
  {$EXTERNALSYM X509_F_X509_REQ_PRINT_FP}
  X509_F_X509_REQ_PRINT_FP                  = 122;
  {$EXTERNALSYM X509_F_X509_REQ_TO_X509}
  X509_F_X509_REQ_TO_X509                   = 123;
  {$EXTERNALSYM X509_F_X509_STORE_ADD_CERT}
  X509_F_X509_STORE_ADD_CERT                = 124;
  {$EXTERNALSYM X509_F_X509_STORE_ADD_CRL}
  X509_F_X509_STORE_ADD_CRL                 = 125;
  {$EXTERNALSYM X509_F_X509_STORE_ADD_LOOKUP}
  X509_F_X509_STORE_ADD_LOOKUP              = 157;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_GET1_ISSUER}
  X509_F_X509_STORE_CTX_GET1_ISSUER         = 146;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_INIT}
  X509_F_X509_STORE_CTX_INIT                = 143;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_NEW}
  X509_F_X509_STORE_CTX_NEW                 = 142;
  {$EXTERNALSYM X509_F_X509_STORE_CTX_PURPOSE_INHERIT}
  X509_F_X509_STORE_CTX_PURPOSE_INHERIT     = 134;
  {$EXTERNALSYM X509_F_X509_STORE_NEW}
  X509_F_X509_STORE_NEW                     = 158;
  {$EXTERNALSYM X509_F_X509_TO_X509_REQ}
  X509_F_X509_TO_X509_REQ                   = 126;
  {$EXTERNALSYM X509_F_X509_TRUST_ADD}
  X509_F_X509_TRUST_ADD                     = 133;
  {$EXTERNALSYM X509_F_X509_TRUST_SET}
  X509_F_X509_TRUST_SET                     = 141;
  {$EXTERNALSYM X509_F_X509_VERIFY_CERT}
  X509_F_X509_VERIFY_CERT                   = 127;
  {$EXTERNALSYM X509_F_X509_VERIFY_PARAM_NEW}
  X509_F_X509_VERIFY_PARAM_NEW              = 159;

  (*
   * X509 reason codes.
   *)
  {$EXTERNALSYM X509_R_AKID_MISMATCH}
  X509_R_AKID_MISMATCH                      = 110;
  {$EXTERNALSYM X509_R_BAD_SELECTOR}
  X509_R_BAD_SELECTOR                       = 133;
  {$EXTERNALSYM X509_R_BAD_X509_FILETYPE}
  X509_R_BAD_X509_FILETYPE                  = 100;
  {$EXTERNALSYM X509_R_BASE64_DECODE_ERROR}
  X509_R_BASE64_DECODE_ERROR                = 118;
  {$EXTERNALSYM X509_R_CANT_CHECK_DH_KEY}
  X509_R_CANT_CHECK_DH_KEY                  = 114;
  {$EXTERNALSYM X509_R_CERT_ALREADY_IN_HASH_TABLE}
  X509_R_CERT_ALREADY_IN_HASH_TABLE         = 101;
  {$EXTERNALSYM X509_R_CRL_ALREADY_DELTA}
  X509_R_CRL_ALREADY_DELTA                  = 127;
  {$EXTERNALSYM X509_R_CRL_VERIFY_FAILURE}
  X509_R_CRL_VERIFY_FAILURE                 = 131;
  {$EXTERNALSYM X509_R_IDP_MISMATCH}
  X509_R_IDP_MISMATCH                       = 128;
  {$EXTERNALSYM X509_R_INVALID_ATTRIBUTES}
  X509_R_INVALID_ATTRIBUTES                 = 138;
  {$EXTERNALSYM X509_R_INVALID_DIRECTORY}
  X509_R_INVALID_DIRECTORY                  = 113;
  {$EXTERNALSYM X509_R_INVALID_FIELD_NAME}
  X509_R_INVALID_FIELD_NAME                 = 119;
  {$EXTERNALSYM X509_R_INVALID_TRUST}
  X509_R_INVALID_TRUST                      = 123;
  {$EXTERNALSYM X509_R_ISSUER_MISMATCH}
  X509_R_ISSUER_MISMATCH                    = 129;
  {$EXTERNALSYM X509_R_KEY_TYPE_MISMATCH}
  X509_R_KEY_TYPE_MISMATCH                  = 115;
  {$EXTERNALSYM X509_R_KEY_VALUES_MISMATCH}
  X509_R_KEY_VALUES_MISMATCH                = 116;
  {$EXTERNALSYM X509_R_LOADING_CERT_DIR}
  X509_R_LOADING_CERT_DIR                   = 103;
  {$EXTERNALSYM X509_R_LOADING_DEFAULTS}
  X509_R_LOADING_DEFAULTS                   = 104;
  {$EXTERNALSYM X509_R_METHOD_NOT_SUPPORTED}
  X509_R_METHOD_NOT_SUPPORTED               = 124;
  {$EXTERNALSYM X509_R_NAME_TOO_LONG}
  X509_R_NAME_TOO_LONG                      = 134;
  {$EXTERNALSYM X509_R_NEWER_CRL_NOT_NEWER}
  X509_R_NEWER_CRL_NOT_NEWER                = 132;
  {$EXTERNALSYM X509_R_NO_CERTIFICATE_FOUND}
  X509_R_NO_CERTIFICATE_FOUND               = 135;
  {$EXTERNALSYM X509_R_NO_CERTIFICATE_OR_CRL_FOUND}
  X509_R_NO_CERTIFICATE_OR_CRL_FOUND        = 136;
  {$EXTERNALSYM X509_R_NO_CERT_SET_FOR_US_TO_VERIFY}
  X509_R_NO_CERT_SET_FOR_US_TO_VERIFY       = 105;
  {$EXTERNALSYM X509_R_NO_CRL_FOUND}
  X509_R_NO_CRL_FOUND                       = 137;
  {$EXTERNALSYM X509_R_NO_CRL_NUMBER}
  X509_R_NO_CRL_NUMBER                      = 130;
  {$EXTERNALSYM X509_R_PUBLIC_KEY_DECODE_ERROR}
  X509_R_PUBLIC_KEY_DECODE_ERROR            = 125;
  {$EXTERNALSYM X509_R_PUBLIC_KEY_ENCODE_ERROR}
  X509_R_PUBLIC_KEY_ENCODE_ERROR            = 126;
  {$EXTERNALSYM X509_R_SHOULD_RETRY}
  X509_R_SHOULD_RETRY                       = 106;
  {$EXTERNALSYM X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN}
  X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107;
  {$EXTERNALSYM X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY}
  X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY     = 108;
  {$EXTERNALSYM X509_R_UNKNOWN_KEY_TYPE}
  X509_R_UNKNOWN_KEY_TYPE                   = 117;
  {$EXTERNALSYM X509_R_UNKNOWN_NID}
  X509_R_UNKNOWN_NID                        = 109;
  {$EXTERNALSYM X509_R_UNKNOWN_PURPOSE_ID}
  X509_R_UNKNOWN_PURPOSE_ID                 = 121;
  {$EXTERNALSYM X509_R_UNKNOWN_TRUST_ID}
  X509_R_UNKNOWN_TRUST_ID                   = 120;
  {$EXTERNALSYM X509_R_UNSUPPORTED_ALGORITHM}
  X509_R_UNSUPPORTED_ALGORITHM              = 111;
  {$EXTERNALSYM X509_R_WRONG_LOOKUP_TYPE}
  X509_R_WRONG_LOOKUP_TYPE                  = 112;
  {$EXTERNALSYM X509_R_WRONG_TYPE}
  X509_R_WRONG_TYPE                         = 122;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_X509_strings}
  ERR_load_X509_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_X509_strings}
  function ERR_load_X509_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_X509_strings_procname = 'ERR_load_X509_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}
function  ERR_ERR_load_X509_strings: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_X509_strings_procname);
end;

  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_X509_strings := LoadLibFunction(ADllHandle, ERR_load_X509_strings_procname);
  FuncLoadError := not assigned(ERR_load_X509_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_X509_strings_allownil)}
    ERR_load_X509_strings := ERR_ERR_load_X509_strings;
    {$ifend}
    {$if declared(ERR_load_X509_strings_introduced)}
    if LibVersion < ERR_load_X509_strings_introduced then
    begin
      {$if declared(FC_ERR_load_X509_strings)}
      ERR_load_X509_strings := FC_ERR_load_X509_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_X509_strings_removed)}
    if ERR_load_X509_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_X509_strings)}
      ERR_load_X509_strings := _ERR_load_X509_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_X509_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_X509_strings');
    {$ifend}
  end;


end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ERR_load_X509_strings := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
