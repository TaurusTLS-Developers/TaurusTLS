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
unit TaurusTLSFIPS;

{$I TaurusTLSLinkDefines.inc}

interface

uses
  Classes;

/// <summary>
/// Points Indy's IdFIPS hash and HMAC hooks at the TaurusTLS implementations.
/// </summary>
/// <remarks>
/// This is called from this unit's initialization section and from TaurusTLS.LoadOpenSSLLibrary.
/// Other units assign the same hooks from their initialization sections (for example
/// IdSSLOpenSSLHeaders) and the unit initialization order is not guaranteed, notably in
/// statically linked C++Builder applications, so the hooks are reinstalled when the
/// OpenSSL library is loaded.
/// </remarks>
procedure InstallFIPSHooks;

type
  /// <summary>
  /// A procedure that assigns additional IdFIPS hooks.
  /// </summary>
  TFIPSHooksInstaller = procedure;

/// <summary>
/// Adds a procedure that InstallFIPSHooks calls after installing the hash and HMAC hooks.
/// </summary>
/// <remarks>
/// Optional units that assign other IdFIPS hooks (for example TaurusTLS_NTLM) register here
/// from their initialization sections so their hooks are reinstalled along with the hash and
/// HMAC hooks.  The procedure is also called immediately if the TaurusTLS hooks are currently
/// installed.
/// </remarks>
procedure RegisterFIPSHooksInstaller(const AInstaller: TFIPSHooksInstaller);

implementation

uses
  IdGlobal,
  IdCTypes,
  IdFIPS,
  TaurusTLSExceptionHandlers,
  TaurusTLS_ResourceStrings,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_hmac,
  TaurusTLSHeaders_types;

{$I TaurusTLSUnusedParamOff.inc}

function FIPS_mode_set(onoff: TIdC_INT): TIdC_INT; //FI:O804 - Method parameter is declared but not used
  {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := 0;
{$IFDEF OPENSSL_FIPS}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if Assigned(TaurusTLSHeaders_crypto.FIPS_mode_set) then
{$ENDIF}
  begin
    Result := TaurusTLSHeaders_crypto.FIPS_mode_set(onoff);
  end;
{$ENDIF}
end;
{$I TaurusTLSUnusedParamOn.inc}

function FIPS_mode(): TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := 0;
{$IFDEF OPENSSL_FIPS}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if Assigned(TaurusTLSHeaders_crypto.FIPS_mode) then
{$ENDIF}
  begin
    Result := TaurusTLSHeaders_crypto.FIPS_mode;
  end;
{$ENDIF}
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
  ETaurusTLSDigestInitEx.RaiseIfError(EVP_DigestInit_ex(Result, AInst, nil),
    RSOSSLEVPDigestExError);
end;

// **************** HMAC Common Code ***********************

function TaurusTLSHMACInit(const AKey: TIdBytes; AInst: PEVP_MD): TIdHMACIntCtx;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
  Result := HMAC_CTX_new;
  if Result = nil then
  begin
    ETaurusTLSHMACCTXNew.RaiseException(RSOSSLHMACCTXnew);
  end;
  ETaurusTLSHMACInitEx.RaiseIfError(HMAC_Init_ex(Result, PByte(AKey),
    Length(AKey), AInst, nil), RSOSSLHMACInitExError);
end;

// **************** FIPS Support backend *******************

function TaurusTLSIsHashingIntfAvail: Boolean;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_DigestInit_ex) and Assigned(EVP_DigestUpdate) and
    Assigned(EVP_DigestFinal_ex);
{$ELSE}
  Result := true;
{$ENDIF}
end;

function TaurusTLSGetFIPSMode: Boolean;
begin
  Result := FIPS_mode <> 0;
end;

function TaurusTLSSetFIPSMode(const AMode: Boolean): Boolean;
begin
  // leave this empty as we may not be using something that supports FIPS
  if AMode then
  begin
    Result := FIPS_mode_set(1) = 1;
  end
  else
  begin
    Result := FIPS_mode_set(0) = 1;
  end;
end;

function TaurusTLSIsMD2HashIntfAvail: Boolean;
begin
{$IFDEF OPENSSL_NO_MD2}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_md2);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetMD2HashInst: TIdHashIntCtx;
begin
{$IFDEF OPENSSL_NO_MD2}
  Result := nil;
{$ELSE}
  Result := TaurusTLSGetDigestCtx(EVP_md2);
{$ENDIF}
end;

function TaurusTLSIsMD4HashIntfAvail: Boolean;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_md4);
{$ELSE}
  Result := true;
{$ENDIF}
end;

function TaurusTLSGetMD4HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSGetDigestCtx(EVP_md4);
end;

function TaurusTLSIsMD5HashIntfAvail: Boolean;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_md5);
{$ELSE}
  Result := true;
{$ENDIF}
end;

function TaurusTLSGetMD5HashInst: TIdHashIntCtx;
begin
  Result := TaurusTLSGetDigestCtx(EVP_md5);
end;

function TaurusTLSIsSHA1HashIntfAvail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha1);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetSHA1HashInst: TIdHashIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA}
  Result := nil;
{$ELSE}
  Result := TaurusTLSGetDigestCtx(EVP_sha1);
{$ENDIF}
end;

function TaurusTLSIsSHA224HashIntfAvail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha224);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetSHA224HashInst: TIdHashIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
{$ELSE}
  Result := TaurusTLSGetDigestCtx(EVP_sha224);
{$ENDIF}
end;

function TaurusTLSIsSHA256HashIntfAvail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha256);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetSHA256HashInst: TIdHashIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
{$ELSE}
  Result := TaurusTLSGetDigestCtx(EVP_sha256);
{$ENDIF}
end;

function TaurusTLSIsSHA384HashIntfAvail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha384);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetSHA384HashInst: TIdHashIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
{$ELSE}
  Result := TaurusTLSGetDigestCtx(EVP_sha384);
{$ENDIF}
end;

function TaurusTLSIsSHA512HashIntfAvail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha512);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetSHA512HashInst: TIdHashIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
{$ELSE}
  Result := TaurusTLSGetDigestCtx(EVP_sha512);
{$ENDIF}
end;

procedure TaurusTLSUpdateHashInst(ACtx: TIdHashIntCtx; const AIn: TIdBytes);
begin
  ETaurusTLSDigestUpdate.RaiseIfError(EVP_DigestUpdate(ACtx, PByte(AIn),
    Length(AIn)), RSOSSLEVPDigestUpdateError);
end;

function TaurusTLSFinalHashInst(ACtx: TIdHashIntCtx): TIdBytes;
var
  LLen: TIdC_UInt; //PALOFF - Local identifiers that are set more than once without referencing in-between
begin
{$IFDEF fpc}
  Result := nil;
{$ENDIF}
  SetLength(Result, EVP_MAX_MD_SIZE);
  LLen := 0; // unneeded but we get FPC warnings if we don't
  if ETaurusTLSDigestFinalEx.CheckResult(EVP_DigestFinal_ex(ACtx,
    PByte(@Result[0]), LLen), RSOSSLEVPDigestError) then
  begin
    SetLength(Result, LLen);
    EVP_MD_CTX_free(PEVP_MD_CTX(ACtx));
  end;
end;

function TaurusTLSIsHMACAvail: Boolean;
begin
{$IFDEF OPENSSL_NO_HMAC}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(HMAC_CTX_new) and Assigned(HMAC_Init_ex) and
    Assigned(HMAC_Update) and Assigned(HMAC_Final) and Assigned(HMAC_CTX_free);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSIsHMACMD5Avail: Boolean;
begin
{$IFDEF OPENSSL_NO_MD5}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_md5);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetHMACMD5Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
{$IFDEF OPENSSL_NO_MD5}
  Result := nil;
{$ELSE}
  Result := TaurusTLSHMACInit(AKey, EVP_md5);
{$ENDIF}
end;

function TaurusTLSIsHMACSHA1Avail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha1);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetHMACSHA1Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA}
  Result := nil;
{$ELSE}
  Result := TaurusTLSHMACInit(AKey, EVP_sha1);
{$ENDIF}
end;

function TaurusTLSIsHMACSHA224Avail: Boolean;

begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha224);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetHMACSHA224Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
{$ELSE}
  Result := TaurusTLSHMACInit(AKey, EVP_sha224);
{$ENDIF}
end;

function TaurusTLSIsHMACSHA256Avail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha256);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetHMACSHA256Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA256}
  Result := nil;
{$ELSE}
  Result := TaurusTLSHMACInit(AKey, EVP_sha256);
{$ENDIF}
end;

function TaurusTLSIsHMACSHA384Avail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha384);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetHMACSHA384Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
{$ELSE}
  Result := TaurusTLSHMACInit(AKey, EVP_sha384);
{$ENDIF}
end;

function TaurusTLSIsHMACSHA512Avail: Boolean;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := False;
{$ELSE}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := Assigned(EVP_sha512);
{$ELSE}
  Result := true;
{$ENDIF}
{$ENDIF}
end;

function TaurusTLSGetHMACSHA512Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
{$IFDEF OPENSSL_NO_SHA512}
  Result := nil;
{$ELSE}
  Result := TaurusTLSHMACInit(AKey, EVP_sha512);
{$ENDIF}
end;

procedure TaurusTLSUpdateHMACInst(ACtx: TIdHMACIntCtx; const AIn: TIdBytes);
begin
  ETaurusTLSHMACUpdate.RaiseIfError(HMAC_Update(ACtx, PByte(AIn), Length(AIn)),
    RSOSSLHMACUpdateError);
end;

function TaurusTLSFinalHMACInst(ACtx: TIdHMACIntCtx): TIdBytes;
var
  LLen: TIdC_UInt;
begin
  LLen := EVP_MAX_MD_SIZE;
  Result := nil;
  SetLength(Result, LLen);
  if ETaurusTLSHMACFinal.CheckResult(HMAC_Final(ACtx, PByte(@Result[0]), @LLen),
    RSOSSLHMACFinalError) then
  begin
    SetLength(Result, LLen);
    HMAC_CTX_free(ACtx);
  end;
end;

// ****************************************************

var
  GFIPSHooksInstallers: array of TFIPSHooksInstaller;

procedure CallFIPSHooksInstallers;
var
  I: Integer;
begin
  for I := 0 to High(GFIPSHooksInstallers) do
    GFIPSHooksInstallers[I]();
end;

function FIPSHooksInstalled: Boolean;
begin
  Result := @IsHashingIntfAvail = @TaurusTLSIsHashingIntfAvail;
end;

procedure InstallFIPSHooks;
begin
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

  CallFIPSHooksInstallers;
end;

procedure RegisterFIPSHooksInstaller(const AInstaller: TFIPSHooksInstaller);
begin
  SetLength(GFIPSHooksInstallers, Length(GFIPSHooksInstallers) + 1);
  GFIPSHooksInstallers[High(GFIPSHooksInstallers)] := AInstaller;
  if FIPSHooksInstalled then
    AInstaller;
end;

initialization

InstallFIPSHooks;

end.
