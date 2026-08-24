/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_srtp.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_srtp.h2pas
     and this file regenerated. TaurusTLSHeaders_srtp.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_srtp;

interface

// Headers for OpenSSL 1.1.1
// srtp.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_ssl;

const
  {$EXTERNALSYM SRTP_AES128_CM_SHA1_80}
  SRTP_AES128_CM_SHA1_80 = $0001;
  {$EXTERNALSYM SRTP_AES128_CM_SHA1_32}
  SRTP_AES128_CM_SHA1_32 = $0002;
  {$EXTERNALSYM SRTP_AES128_F8_SHA1_80}
  SRTP_AES128_F8_SHA1_80 = $0003;
  {$EXTERNALSYM SRTP_AES128_F8_SHA1_32}
  SRTP_AES128_F8_SHA1_32 = $0004;
  {$EXTERNALSYM SRTP_NULL_SHA1_80}
  SRTP_NULL_SHA1_80      = $0005;
  {$EXTERNALSYM SRTP_NULL_SHA1_32}
  SRTP_NULL_SHA1_32      = $0006;

  (* AEAD SRTP protection profiles from RFC 7714 *)
  {$EXTERNALSYM SRTP_AEAD_AES_128_GCM}
  SRTP_AEAD_AES_128_GCM = $0007;
  {$EXTERNALSYM SRTP_AEAD_AES_256_GCM}
  SRTP_AEAD_AES_256_GCM = $0008;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM SSL_CTX_set_tlsext_use_srtp}
  SSL_CTX_set_tlsext_use_srtp: function (ctx: PSSL_CTX; const profiles: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SSL_set_tlsext_use_srtp}
  SSL_set_tlsext_use_srtp: function (ctx: PSSL_CTX; const profiles: PIdAnsiChar): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM SSL_get_srtp_profiles}
  SSL_get_srtp_profiles : function(s: PSSL): PSTACK_OF_SRTP_PROTECTION_PROFILE;  cdecl = nil;
  {$EXTERNALSYM SSL_get_selected_srtp_profile}
  SSL_get_selected_srtp_profile: function (s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM SSL_CTX_set_tlsext_use_srtp}
  function SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM SSL_set_tlsext_use_srtp}
  function SSL_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM SSL_get_srtp_profiles}
  function SSL_get_srtp_profiles(s: PSSL): PSTACK_OF_SRTP_PROTECTION_PROFILE  cdecl; external CLibCrypto;
  {$EXTERNALSYM SSL_get_selected_srtp_profile}
  function SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE cdecl; external CLibCrypto;

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
  SSL_CTX_set_tlsext_use_srtp_procname = 'SSL_CTX_set_tlsext_use_srtp';
  SSL_set_tlsext_use_srtp_procname = 'SSL_set_tlsext_use_srtp';

  SSL_get_srtp_profiles_procname = 'SSL_get_srtp_profiles';
  SSL_get_selected_srtp_profile_procname = 'SSL_get_selected_srtp_profile';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_CTX_set_tlsext_use_srtp_procname);
end;


function  ERR_SSL_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_set_tlsext_use_srtp_procname);
end;

function ERR_SSL_get_srtp_profiles(s: PSSL): PSTACK_OF_SRTP_PROTECTION_PROFILE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException( SSL_get_srtp_profiles_procname);
end;

function  ERR_SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE;   cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_get_selected_srtp_profile_procname);
end;

  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  SSL_CTX_set_tlsext_use_srtp := LoadLibFunction(ADllHandle, SSL_CTX_set_tlsext_use_srtp_procname);
  FuncLoadError := not assigned(SSL_CTX_set_tlsext_use_srtp);
  if FuncLoadError then
  begin
    {$if not defined(SSL_CTX_set_tlsext_use_srtp_allownil)}
    SSL_CTX_set_tlsext_use_srtp := ERR_SSL_CTX_set_tlsext_use_srtp;
    {$ifend}
    {$if declared(SSL_CTX_set_tlsext_use_srtp_introduced)}
    if LibVersion < SSL_CTX_set_tlsext_use_srtp_introduced then
    begin
      {$if declared(FC_SSL_CTX_set_tlsext_use_srtp)}
      SSL_CTX_set_tlsext_use_srtp := FC_SSL_CTX_set_tlsext_use_srtp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_CTX_set_tlsext_use_srtp_removed)}
    if SSL_CTX_set_tlsext_use_srtp_removed <= LibVersion then
    begin
      {$if declared(_SSL_CTX_set_tlsext_use_srtp)}
      SSL_CTX_set_tlsext_use_srtp := _SSL_CTX_set_tlsext_use_srtp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_CTX_set_tlsext_use_srtp_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_CTX_set_tlsext_use_srtp');
    {$ifend}
  end;


  SSL_set_tlsext_use_srtp := LoadLibFunction(ADllHandle, SSL_set_tlsext_use_srtp_procname);
  FuncLoadError := not assigned(SSL_set_tlsext_use_srtp);
  if FuncLoadError then
  begin
    {$if not defined(SSL_set_tlsext_use_srtp_allownil)}
    SSL_set_tlsext_use_srtp := ERR_SSL_set_tlsext_use_srtp;
    {$ifend}
    {$if declared(SSL_set_tlsext_use_srtp_introduced)}
    if LibVersion < SSL_set_tlsext_use_srtp_introduced then
    begin
      {$if declared(FC_SSL_set_tlsext_use_srtp)}
      SSL_set_tlsext_use_srtp := FC_SSL_set_tlsext_use_srtp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_set_tlsext_use_srtp_removed)}
    if SSL_set_tlsext_use_srtp_removed <= LibVersion then
    begin
      {$if declared(_SSL_set_tlsext_use_srtp)}
      SSL_set_tlsext_use_srtp := _SSL_set_tlsext_use_srtp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_set_tlsext_use_srtp_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_set_tlsext_use_srtp');
    {$ifend}
  end;

  SSL_get_srtp_profiles := LoadLibFunction(ADllHandle, SSL_get_srtp_profiles_procname);
  FuncLoadError := not assigned(SSL_get_srtp_profiles);
  if FuncLoadError then
  begin
    {$if not defined(SSL_get_srtp_profiles_allownil)}
    SSL_get_srtp_profiles := ERR_SSL_get_srtp_profiles;
    {$ifend}
    {$if declared(SSL_get_srtp_profiles_introduced)}
    if LibVersion < SSL_get_srtp_profiles_introduced then
    begin
      {$if declared(FC_SSL_get_srtp_profiles)}
      SSL_get_srtp_profiles := FC_SSL_get_srtp_profiles;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_get_srtp_profiles_removed)}
    if SSL_get_srtp_profiles_removed <= LibVersion then
    begin
      {$if declared(_SSL_get_srtp_profiles)}
      SSL_get_srtp_profiles := _SSL_get_srtp_profiles;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_get_srtp_profiles_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_get_srtp_profiles');
    {$ifend}
  end;

  SSL_get_selected_srtp_profile := LoadLibFunction(ADllHandle, SSL_get_selected_srtp_profile_procname);
  FuncLoadError := not assigned(SSL_get_selected_srtp_profile);
  if FuncLoadError then
  begin
    {$if not defined(SSL_get_selected_srtp_profile_allownil)}
    SSL_get_selected_srtp_profile := ERR_SSL_get_selected_srtp_profile;
    {$ifend}
    {$if declared(SSL_get_selected_srtp_profile_introduced)}
    if LibVersion < SSL_get_selected_srtp_profile_introduced then
    begin
      {$if declared(FC_SSL_get_selected_srtp_profile)}
      SSL_get_selected_srtp_profile := FC_SSL_get_selected_srtp_profile;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SSL_get_selected_srtp_profile_removed)}
    if SSL_get_selected_srtp_profile_removed <= LibVersion then
    begin
      {$if declared(_SSL_get_selected_srtp_profile)}
      SSL_get_selected_srtp_profile := _SSL_get_selected_srtp_profile;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SSL_get_selected_srtp_profile_allownil)}
    if FuncLoadError then
      AFailed.Add('SSL_get_selected_srtp_profile');
    {$ifend}
  end;


end;

procedure Unload;
begin
  SSL_CTX_set_tlsext_use_srtp := nil;
  SSL_set_tlsext_use_srtp := nil;
  SSL_get_srtp_profiles := nil;
  SSL_get_selected_srtp_profile := nil;
end;
  {$I TaurusTLSUnusedParamOff.inc}
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
