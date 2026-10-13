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

{$IFDEF UNITTEST}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
// Test-only access to implementation state; absent from production builds.
function FIPSPropertyAPIsAvailableForTests: Boolean;
function FIPSUsesPropertyAPIsForTests: Boolean;
procedure RevalidateFIPSPropertyAPIsForTests;
{$ENDIF}
{$ENDIF}

implementation

uses
  IdGlobal,
  IdCTypes,
  IdFIPS,
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLSExceptionHandlers,
  TaurusTLS_ResourceStrings,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_hmac,
  TaurusTLSHeaders_types;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  GFIPSUsesPropertyAPIs: Boolean = False;
  GFIPSPropertyAPIsAvailable: Boolean = False;

type
  TTaurusTLSFIPSAPIState = class
  public
    class procedure OnLoadAction(AAction: TOpenSSLLoadAction);
  end;

class procedure TTaurusTLSFIPSAPIState.OnLoadAction(AAction: TOpenSSLLoadAction);
var
  LLoader: IOpenSSLLoader;
begin
  // Invalidate first, including every unload notification.
  GFIPSUsesPropertyAPIs := False;
  GFIPSPropertyAPIsAvailable := False;
  if AAction <> osaLoad then
    Exit;
  LLoader := GetOpenSSLLoader;
  if LLoader = nil then
    Exit;
  if not Assigned(OpenSSL_version_num) then
    Exit;
  GFIPSUsesPropertyAPIs := OpenSSL_version_num() >= $30000000;
  if not GFIPSUsesPropertyAPIs then
    Exit;
  // Headers have finished binding. Inspect failure diagnostics once here:
  // a missing export may have a non-nil exception-stub address.
  GFIPSPropertyAPIsAvailable :=
    Assigned(EVP_default_properties_enable_fips) and
    Assigned(EVP_default_properties_is_fips_enabled) and
    (LLoader.FailedToLoad.IndexOf('EVP_default_properties_enable_fips') < 0) and
    (LLoader.FailedToLoad.IndexOf('EVP_default_properties_is_fips_enabled') < 0);
end;

function TaurusTLSFIPSPropertyAPIsAvailable: Boolean;
begin
  // Repeated mode checks never scan the binding diagnostics.
  Result := GFIPSPropertyAPIsAvailable;
end;

{$IFDEF UNITTEST}
function FIPSPropertyAPIsAvailableForTests: Boolean;
begin
  Result := TaurusTLSFIPSPropertyAPIsAvailable;
end;

function FIPSUsesPropertyAPIsForTests: Boolean;
begin
  Result := GFIPSUsesPropertyAPIs;
end;

procedure RevalidateFIPSPropertyAPIsForTests;
begin
  TTaurusTLSFIPSAPIState.OnLoadAction(osaLoad);
end;
{$ENDIF}
{$ENDIF}

{$I TaurusTLSUnusedParamOff.inc}

function FIPS_mode_set(onoff: TIdC_INT): TIdC_INT; //FI:O804 - Method parameter is declared but not used
  {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := 0;
  // FIPS is supported only by the dynamic linking model.
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if GFIPSUsesPropertyAPIs and not TaurusTLSFIPSPropertyAPIsAvailable then
    Exit;
  if Assigned(TaurusTLSHeaders_crypto.FIPS_mode_set) then
  begin
    Result := TaurusTLSHeaders_crypto.FIPS_mode_set(onoff);
  end;
{$ENDIF}
end;
{$I TaurusTLSUnusedParamOn.inc}

function FIPS_mode(): TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := 0;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if GFIPSUsesPropertyAPIs and not TaurusTLSFIPSPropertyAPIsAvailable then
    Exit;
  if Assigned(TaurusTLSHeaders_crypto.FIPS_mode) then
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

function  TaurusTLSHACMACInit(AKey : TIdBytes; const ACipher : PIdAnsiChar;
  AExceptionClass : ETaurusTLSAlgorithmNotFoundClass) : TIdHMACIntCtx;
var LMD : PEVP_MD;
begin
  LMD := EVP_MD_fetch(nil, ACipher,nil);
  if Assigned(LMD) then
  begin
    Result := TaurusTLSHMACInit(AKey, LMD);
     EVP_MD_free(LMD);
  end
  else
  begin
    raise AExceptionClass.CreateResMsg;
  end;
end;

// **************** FIPS Support backend *******************

function TaurusTLSIsHashingIntfAvail: Boolean;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := GetOpenSSLLoader.IsLoaded;
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

function TaurusIsHashAvail(const AHashName : PIdAnsiChar) : Boolean; {$IFDEF USE_INLINE} inline; {$ENDIF}
var
  lMeth: PEVP_MD;
begin
  lMeth := nil;
  try
    lMeth := EVP_MD_fetch(nil, AHashName, nil);
    Result := Assigned(lMeth);
  finally
    EVP_MD_free(lMeth);
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
  LMD := EVP_MD_fetch(nil,AHashName,nil);
  if assigned(LMD) then
  begin
    Result := TaurusTLSGetDigestCtx(LMD);
    EVP_MD_Free(LMD);
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
  {$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
  if ETaurusTLSDigestFinalEx.CheckResult(EVP_DigestFinal_ex(ACtx,
    PByte(@Result[0]), LLen), RSOSSLEVPDigestError) then
  begin
    SetLength(Result, LLen);
    EVP_MD_CTX_free(PEVP_MD_CTX(ACtx));
  end;
  {$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}
end;

function TaurusTLSIsHMACAvail: Boolean;
begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := GetOpenSSLLoader.IsLoaded;
{$ELSE}
  Result := true;
{$ENDIF}
end;

function TaurusTLSIsHMACMD5Avail: Boolean;
begin
  Result := TaurusIsHashAvail('MD5');
end;

function TaurusTLSGetHMACMD5Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'MD5', ETaurusTLSMD5NotFound);
end;

function TaurusTLSIsHMACSHA1Avail: Boolean;
begin

  Result :=  TaurusIsHashAvail('SHA1');
end;

function TaurusTLSGetHMACSHA1Inst(const AKey: TIdBytes): TIdHMACIntCtx;

begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA1', ETaurusTLSSHA1NotFound);
end;

function TaurusTLSIsHMACSHA224Avail: Boolean;

begin
  Result :=  TaurusIsHashAvail('SHA224');
end;

function TaurusTLSGetHMACSHA224Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA224', ETaurusTLSSHA224NotFound);
end;

function TaurusTLSIsHMACSHA256Avail: Boolean;
begin
  Result :=  TaurusIsHashAvail('SHA256');
end;

function TaurusTLSGetHMACSHA256Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA256', ETaurusTLSSHA256NotFound);
end;


function TaurusTLSIsHMACSHA384Avail: Boolean;
begin
  Result :=  TaurusIsHashAvail('SHA384');
end;

function TaurusTLSGetHMACSHA384Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA384', ETaurusTLSSHA384NotFound);
end;

function TaurusTLSIsHMACSHA512Avail: Boolean;
begin
  Result :=  TaurusIsHashAvail('SHA512');
end;

function TaurusTLSGetHMACSHA512Inst(const AKey: TIdBytes): TIdHMACIntCtx;
begin
  Result := TaurusTLSHACMACInit(AKey, 'SHA512', ETaurusTLSSHA512NotFound);
end;

procedure TaurusTLSUpdateHMACInst(ACtx: TIdHMACIntCtx; const AIn: TIdBytes);
begin
  ETaurusTLSHMACUpdate.RaiseIfError(EVP_MAC_update(ACtx, PIdAnsiChar(AIn),
    Length(AIn)), RSOSSLHMACUpdateError);
end;

function TaurusTLSFinalHMACInst(ACtx: TIdHMACIntCtx): TIdBytes;
var
  LBufLen, LActualLen: TIdC_SIZET;
begin
  Result := nil;
  // calculating the final buffer length
  if (EVP_MAC_final(ACtx, nil, LBufLen, 0) <= 0) and (LBufLen <= 0) then
    Exit;
  SetLength(Result, LBufLen);
  {$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
  if ETaurusTLSHMACFinal.CheckResult(
    EVP_MAC_final(ACtx, PIdAnsiChar(Result), LActualLen, LBufLen),
    RSOSSLHMACFinalError) then
  {$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}
  begin
    if LActualLen < LBufLen then
      SetLength(Result, LActualLen);
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoaderAction(TTaurusTLSFIPSAPIState.OnLoadAction);
// A dependency may have loaded the library before this unit initialized.
if GetOpenSSLLoader <> nil then
  if GetOpenSSLLoader.IsLoaded then
    TTaurusTLSFIPSAPIState.OnLoadAction(osaLoad);
{$ENDIF}

InstallFIPSHooks;

end.
