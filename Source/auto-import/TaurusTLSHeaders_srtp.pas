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

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;




// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  SRTP_AES128_CM_SHA1_80 = $0001;
  SRTP_AES128_CM_SHA1_32 = $0002;
  SRTP_AES128_F8_SHA1_80 = $0003;
  SRTP_AES128_F8_SHA1_32 = $0004;
  SRTP_NULL_SHA1_80 = $0005;
  SRTP_NULL_SHA1_32 = $0006;
  SRTP_AEAD_AES_128_GCM = $0007;
  SRTP_AEAD_AES_256_GCM = $0008;
  SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = $0009;
  SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = $000A;
  SRTP_ARIA_128_CTR_HMAC_SHA1_80 = $000B;
  SRTP_ARIA_128_CTR_HMAC_SHA1_32 = $000C;
  SRTP_ARIA_256_CTR_HMAC_SHA1_80 = $000D;
  SRTP_ARIA_256_CTR_HMAC_SHA1_32 = $000E;
  SRTP_AEAD_ARIA_128_GCM = $000F;
  SRTP_AEAD_ARIA_256_GCM = $0010;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  SSL_CTX_set_tlsext_use_srtp: function(ctx: PSSL_CTX; profiles: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SSL_CTX_set_tlsext_use_srtp}

  SSL_set_tlsext_use_srtp: function(ssl: PSSL; profiles: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SSL_set_tlsext_use_srtp}

  SSL_get_srtp_profiles: function(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl = nil;
  {$EXTERNALSYM SSL_get_srtp_profiles}

  SSL_get_selected_srtp_profile: function(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl = nil;
  {$EXTERNALSYM SSL_get_selected_srtp_profile}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; profiles: PIdAnsiChar): TIdC_INT; cdecl;
function SSL_set_tlsext_use_srtp(ssl: PSSL; profiles: PIdAnsiChar): TIdC_INT; cdecl;
function SSL_get_srtp_profiles(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl;
function SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

implementation

uses
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  classes,
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES IMPORTS
// =============================================================================

function SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; profiles: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'SSL_CTX_set_tlsext_use_srtp';
function SSL_set_tlsext_use_srtp(ssl: PSSL; profiles: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'SSL_set_tlsext_use_srtp';
function SSL_get_srtp_profiles(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl external CLibCrypto name 'SSL_get_srtp_profiles';
function SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl external CLibCrypto name 'SSL_get_selected_srtp_profile';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  SSL_CTX_set_tlsext_use_srtp_procname = 'SSL_CTX_set_tlsext_use_srtp';
  SSL_CTX_set_tlsext_use_srtp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SSL_set_tlsext_use_srtp_procname = 'SSL_set_tlsext_use_srtp';
  SSL_set_tlsext_use_srtp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SSL_get_srtp_profiles_procname = 'SSL_get_srtp_profiles';
  SSL_get_srtp_profiles_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SSL_get_selected_srtp_profile_procname = 'SSL_get_selected_srtp_profile';
  SSL_get_selected_srtp_profile_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; profiles: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_CTX_set_tlsext_use_srtp_procname);
end;

function ERR_SSL_set_tlsext_use_srtp(ssl: PSSL; profiles: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_set_tlsext_use_srtp_procname);
end;

function ERR_SSL_get_srtp_profiles(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_get_srtp_profiles_procname);
end;

function ERR_SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SSL_get_selected_srtp_profile_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
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
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.