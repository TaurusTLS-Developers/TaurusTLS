{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}
/// <summary>
/// Self-registering unit that provides MD2, MD4, MD5, SHA1, SHA224, SHA256,
/// SHA384, SHA512, HMAC-MD5, HMAC-SHA-1, HMAC-SHA-224, HMAC-SHA-384, and
/// HMAC-SHA-512 Support for Indy - Internet Direct. Indy itself will call
/// routines from the implementation section of the unit if you include this
/// unit.
/// </summary>
/// <remarks>
/// <para>
/// MD2, MD4, MD5, and SHA1 are depreciated in favor of more secure
/// algorithms.
/// </para>
/// <para>
/// Some depreciated algorithms may not be provided by the OpenSSL library.
/// </para>
/// </remarks>
unit TaurusTLSIdFIPS;

{$I TaurusTLSLinkDefines.inc}

interface

implementation

uses
  SysUtils,
  IdGlobal,
  IdCTypes,
  IdFIPS,
  TaurusTLSLoader,
  TaurusTLSExceptionHandlers,
  TaurusTLS_ResourceStrings,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_err,
  TaurusTLS_ProviderFIPS,
  TaurusTLSHeaders_core,
  TaurusTLSHeaders_params,
  TaurusTLSHeaders_types;

procedure RequireHashReady;
begin
  if not GetOpenSSLLoader.IsLoaded then
    raise ETaurusTLSLoaderError.Create('OpenSSL must be ready before using Indy hash/HMAC hooks');
end;

// Preserve all configured default properties. When FIPS is selected, additionally
// require its provider for both the outer MAC and the nested digest fetch.
function HashProperties: PIdAnsiChar;
begin
  Result := nil;
  if EVP_default_properties_is_fips_enabled(nil) = 1 then
    Result := 'provider=fips';
end;

// **************** Digest Common Code *********************

function TaurusTLSGetDigestCtx(AInst: PEVP_MD): TIdHashIntCtx;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := EVP_MD_CTX_new;
  if Result = nil then
  begin
    ETaurusTLSEVPMDCTXNew.RaiseException(RSOSSLEVPMDCTXNew);
  end;
  try
    ETaurusTLSDigestInitEx.RaiseIfError(EVP_DigestInit_ex(Result, AInst, nil),
      RSOSSLEVPDigestExError);
  except
    EVP_MD_CTX_free(Result);
    raise;
  end;
end;

// **************** HMAC Common Code ***********************

function TaurusTLSHACMACInit(const AKey: TIdBytes; const ACipher: PIdAnsiChar;
  AExceptionClass: ETaurusTLSAlgorithmNotFoundClass): TIdHMACIntCtx;
var
  LMAC: PEVP_MAC;
  LParams: array[0..2] of OSSL_PARAM;
  LProperties: PIdAnsiChar;
  LEmptyKey: AnsiChar;
  LKey: PIdAnsiChar;
begin
  RequireHashReady;
  LProperties := HashProperties;
  LMAC := EVP_MAC_fetch(nil, 'HMAC', LProperties);
  if LMAC = nil then
    raise AExceptionClass.CreateResMsg;
  try
    Result := EVP_MAC_CTX_new(LMAC);
    if Result = nil then
      ETaurusTLSHMACCTXNew.RaiseException(RSOSSLHMACCTXnew);
  finally
    EVP_MAC_free(LMAC);
  end;
  try
    LParams[0] := OSSL_PARAM_construct_utf8_string('digest', ACipher, 0);
    LParams[1] := OSSL_PARAM_construct_end;
    LParams[2] := OSSL_PARAM_construct_end;
    if LProperties <> nil then
      LParams[1] := OSSL_PARAM_construct_utf8_string('properties', LProperties, 0);
    // A nil key means reuse to EVP_MAC_init; an empty new key needs a pointer.
    LEmptyKey := #0;
    LKey := PIdAnsiChar(AKey);
    {$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
    if Length(AKey) = 0 then
      LKey := @LEmptyKey;
    ETaurusTLSHMACInitEx.RaiseIfError(
      EVP_MAC_init(Result, LKey, Length(AKey), @LParams[0]), RSOSSLHMACInitExError);
    {$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}
  except
    EVP_MAC_CTX_free(Result);
    raise;
  end;
end;

// **************** FIPS Support backend *******************

function TaurusTLSIsHashingIntfAvail: Boolean;
begin
  // Linked native code still requires explicit TaurusTLS runtime initialization.
  Result := GetOpenSSLLoader.IsLoaded;
end;

function TaurusTLSGetFIPSMode: Boolean;
begin
  Result := False;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if not GetOpenSSLLoader.IsLoaded then
    Exit;
  if not FIPSPropertyAPIsAvailable then
    Exit;
  // Availability alone does not mean that configured fetches select FIPS.
  // This is mode reporting, not certification or an operation approval indicator.
  Result := (EVP_default_properties_is_fips_enabled(nil) = 1) and
    IsFIPSProviderLoaded;
{$ENDIF}
end;

function TaurusTLSSetFIPSMode(const AMode: Boolean): Boolean;
begin
  Result := False;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if not GetOpenSSLLoader.IsLoaded then
    Exit;
  if not FIPSPropertyAPIsAvailable then
    Exit;
  // Compatibility no-op only: never activate providers, clear properties or
  // weaken a selected policy. Even an unavailable selected FIPS policy is kept.
  if (EVP_default_properties_is_fips_enabled(nil) = 1) <> AMode then
    Exit;
  Result := not AMode or TaurusTLSGetFIPSMode;
{$ENDIF}
end;

function TaurusIsHashAvail(const AHashName: PIdAnsiChar): Boolean;
var
  LMethod: PEVP_MD;
  LMarked: Boolean;
begin
  Result := False;
  if not GetOpenSSLLoader.IsLoaded then
    Exit;
  LMarked := ERR_set_mark() = 1;
  try
    LMethod := EVP_MD_fetch(nil, AHashName, HashProperties);
    try
      Result := LMethod <> nil;
    finally
      EVP_MD_free(LMethod);
    end;
  finally
    if LMarked then
      ERR_pop_to_mark
    else
      ERR_clear_error;
  end;
end;

function TaurusIsHMACAvail(const AHashName: PIdAnsiChar): Boolean;
var
  LMAC: PEVP_MAC;
  LMarked: Boolean;
begin
  Result := False;
  if not GetOpenSSLLoader.IsLoaded then
    Exit;
  LMarked := ERR_set_mark() = 1;
  try
    LMAC := EVP_MAC_fetch(nil, 'HMAC', HashProperties);
    try
      Result := (LMAC <> nil) and
        ((AHashName = nil) or TaurusIsHashAvail(AHashName));
    finally
      EVP_MAC_free(LMAC);
    end;
  finally
    if LMarked then
      ERR_pop_to_mark
    else
      ERR_clear_error;
  end;
end;

function TaurusTLSIsMD2HashIntfAvail: Boolean;
begin
  Result := TaurusIsHashAvail('MD2')
end;

function  TaurusTLSInternalGetHash(const AHashName : PIdAnsiChar;
  AExceptionClass : ETaurusTLSAlgorithmNotFoundClass): TIdHashIntCtx;
var LMD : PEVP_MD;
begin
  RequireHashReady;
  LMD := EVP_MD_fetch(nil, AHashName, HashProperties);
  if assigned(LMD) then
  begin
    try
      Result := TaurusTLSGetDigestCtx(LMD);
    finally
      EVP_MD_Free(LMD);
    end;
  end
  else
  begin
    raise AExceptionClass.CreateResMsg;
  end;
end;

function TaurusTLSGetMD2HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('MD2',ETaurusTLSMD2NotFound);
end;

function TaurusTLSIsMD4HashIntfAvail: Boolean;
begin
  Result := TaurusIsHashAvail('MD4');
end;

function TaurusTLSGetMD4HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('MD4',ETaurusTLSMD4NotFound);
end;

function TaurusTLSIsMD5HashIntfAvail: Boolean;
begin
  Result := TaurusIsHashAvail('MD5');
end;


function TaurusTLSGetMD5HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('MD5',ETaurusTLSMD5NotFound);
end;

function TaurusTLSIsSHA1HashIntfAvail: Boolean;
begin
  Result := TaurusIsHashAvail('SHA1');
end;

function TaurusTLSGetSHA1HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('SHA1',ETaurusTLSSHA1NotFound);
end;

function TaurusTLSIsSHA224HashIntfAvail: Boolean;
begin
  Result := TaurusIsHashAvail('SHA224');
end;

function TaurusTLSGetSHA224HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('SHA224',ETaurusTLSSHA224NotFound);
end;

function TaurusTLSIsSHA256HashIntfAvail: Boolean;
begin
  Result := TaurusIsHashAvail('SHA256');
end;

function TaurusTLSGetSHA256HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('SHA256',ETaurusTLSSHA256NotFound);
end;

function TaurusTLSIsSHA384HashIntfAvail: Boolean;
begin
   Result := TaurusIsHashAvail('SHA384');
end;

function TaurusTLSGetSHA384HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('SHA384',ETaurusTLSSHA384NotFound);
end;

function TaurusTLSIsSHA512HashIntfAvail: Boolean;
begin
  Result := TaurusIsHashAvail('SHA512');
end;

function TaurusTLSGetSHA512HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSInternalGetHash('SHA512',ETaurusTLSSHA512NotFound);
end;

procedure TaurusTLSUpdateHashInst(ACtx: TIdHashIntCtx; const AIn: TIdBytes);
begin
  RequireHashReady;
  ETaurusTLSDigestUpdate.RaiseIfError(EVP_DigestUpdate(ACtx, PByte(AIn),
    Length(AIn)), RSOSSLEVPDigestUpdateError);
end;

function TaurusTLSFinalHashInst(ACtx: TIdHashIntCtx): TIdBytes;
var
  LLen: TIdC_UInt;
begin
  RequireHashReady;
  try
    SetLength(Result, EVP_MAX_MD_SIZE);
    LLen := 0;
    ETaurusTLSDigestFinalEx.RaiseIfError(
      EVP_DigestFinal_ex(ACtx, PByte(Result), LLen), RSOSSLEVPDigestError);
    SetLength(Result, LLen);
  finally
    EVP_MD_CTX_free(ACtx);
  end;
end;

function TaurusTLSIsHMACAvail: Boolean;
begin
  Result := TaurusIsHMACAvail(nil);
end;

function TaurusTLSIsHMACMD5Avail: Boolean;
begin
  Result := TaurusIsHMACAvail('MD5');
end;

function TaurusTLSGetHMACMD5Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'MD5', ETaurusTLSMD5NotFound);
end;

function TaurusTLSIsHMACSHA1Avail: Boolean;
begin

  Result :=  TaurusIsHMACAvail('SHA1');
end;

function TaurusTLSGetHMACSHA1Inst(const AKey: TIdBytes): TIdHMACIntCtx;

begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA1', ETaurusTLSSHA1NotFound);
end;

function TaurusTLSIsHMACSHA224Avail: Boolean;

begin
  Result :=  TaurusIsHMACAvail('SHA224');
end;

function TaurusTLSGetHMACSHA224Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA224', ETaurusTLSSHA224NotFound);
end;

function TaurusTLSIsHMACSHA256Avail: Boolean;
begin
  Result :=  TaurusIsHMACAvail('SHA256');
end;

function TaurusTLSGetHMACSHA256Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA256', ETaurusTLSSHA256NotFound);
end;


function TaurusTLSIsHMACSHA384Avail: Boolean;
begin
  Result :=  TaurusIsHMACAvail('SHA384');
end;

function TaurusTLSGetHMACSHA384Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA384', ETaurusTLSSHA384NotFound);
end;

function TaurusTLSIsHMACSHA512Avail: Boolean;
begin
  Result :=  TaurusIsHMACAvail('SHA512');
end;

function TaurusTLSGetHMACSHA512Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA512', ETaurusTLSSHA512NotFound);
end;

procedure TaurusTLSUpdateHMACInst(ACtx: TIdHMACIntCtx; const AIn: TIdBytes);
begin
  RequireHashReady;
  ETaurusTLSHMACUpdate.RaiseIfError(EVP_MAC_update(ACtx, PIdAnsiChar(AIn),
    Length(AIn)), RSOSSLHMACUpdateError);
end;

function TaurusTLSFinalHMACInst(ACtx: TIdHMACIntCtx): TIdBytes;
var
  LBufLen, LActualLen: TIdC_SIZET;
begin
  RequireHashReady;
  try
    LBufLen := EVP_MAC_CTX_get_mac_size(ACtx);
    if (LBufLen = 0) or (LBufLen > EVP_MAX_MD_SIZE) then
      ETaurusTLSHMACFinal.RaiseException(RSOSSLHMACFinalError);
    SetLength(Result, LBufLen);
    LActualLen := 0;
    ETaurusTLSHMACFinal.RaiseIfError(
      EVP_MAC_final(ACtx, PIdAnsiChar(Result), LActualLen, LBufLen),
      RSOSSLHMACFinalError);
    SetLength(Result, LActualLen);
  finally
    EVP_MAC_CTX_free(ACtx);
  end;
end;

// ****************************************************

// Install callbacks once. TaurusTLS_ProviderFIPS owns native API validation;
// loader transitions never change the selected Indy backend.
procedure InstallFIPSHooks;
begin
  // A library query must not initialize Indy's separate OpenSSL backend.
  LoadHashLibrary := TaurusTLSIsHashingIntfAvail;
  SetFIPSMode := TaurusTLSSetFIPSMode;
  GetFIPSMode := TaurusTLSGetFIPSMode;
  IsHashingIntfAvail := TaurusTLSIsHashingIntfAvail;
  IsMD2HashIntfAvail := TaurusTLSIsMD2HashIntfAvail;
  GetMD2HashInst := TaurusTLSGetMD2HashInst;
  IsMD4HashIntfAvail := TaurusTLSIsMD4HashIntfAvail;
  GetMD4HashInst := TaurusTLSGetMD4HashInst;
  IsMD5HashIntfAvail := TaurusTLSIsMD5HashIntfAvail;
  GetMD5HashInst := TaurusTLSGetMD5HashInst;
  IsSHA1HashIntfAvail := TaurusTLSIsSHA1HashIntfAvail;
  GetSHA1HashInst := TaurusTLSGetSHA1HashInst;
  IsSHA224HashIntfAvail := TaurusTLSIsSHA224HashIntfAvail;
  GetSHA224HashInst := TaurusTLSGetSHA224HashInst;
  IsSHA256HashIntfAvail := TaurusTLSIsSHA256HashIntfAvail;
  GetSHA256HashInst := TaurusTLSGetSHA256HashInst;
  IsSHA384HashIntfAvail := TaurusTLSIsSHA384HashIntfAvail;
  GetSHA384HashInst := TaurusTLSGetSHA384HashInst;
  IsSHA512HashIntfAvail := TaurusTLSIsSHA512HashIntfAvail;
  GetSHA512HashInst := TaurusTLSGetSHA512HashInst;
  UpdateHashInst := TaurusTLSUpdateHashInst;
  FinalHashInst := TaurusTLSFinalHashInst;
  IsHMACAvail := TaurusTLSIsHMACAvail;
  IsHMACMD5Avail := TaurusTLSIsHMACMD5Avail;
  GetHMACMD5HashInst := TaurusTLSGetHMACMD5Inst;
  IsHMACSHA1Avail := TaurusTLSIsHMACSHA1Avail;
  GetHMACSHA1HashInst := TaurusTLSGetHMACSHA1Inst;
  IsHMACSHA224Avail := TaurusTLSIsHMACSHA224Avail;
  GetHMACSHA224HashInst := TaurusTLSGetHMACSHA224Inst;
  IsHMACSHA256Avail := TaurusTLSIsHMACSHA256Avail;
  GetHMACSHA256HashInst := TaurusTLSGetHMACSHA256Inst;
  IsHMACSHA384Avail := TaurusTLSIsHMACSHA384Avail;
  GetHMACSHA384HashInst := TaurusTLSGetHMACSHA384Inst;
  IsHMACSHA512Avail := TaurusTLSIsHMACSHA512Avail;
  GetHMACSHA512HashInst := TaurusTLSGetHMACSHA512Inst;
  UpdateHMACInst := TaurusTLSUpdateHMACInst;
  FinalHMACInst := TaurusTLSFinalHMACInst;

end;

initialization
  InstallFIPSHooks;
end.
