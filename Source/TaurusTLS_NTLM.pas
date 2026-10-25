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
/// <summary>Installs OpenSSL-backed LM/NTLMv1 response callbacks for Indy.</summary>
/// <remarks>
/// Applications explicitly load OpenSSL and configure the algorithms they permit.
/// This unit neither installs TaurusTLSFIPS nor links/activates a legacy provider.
/// NT responses require MD4 and DES-ECB; LM responses require DES-ECB.
/// </remarks>
unit TaurusTLS_NTLM;

interface

{$IFDEF UNITTEST}
uses
  IdCTypes,
  IdGlobal,
  IdFIPS;

type
  DES_cblock = array [0 .. 7] of Byte;
  PDES_cblock = ^DES_cblock;

procedure Encrypt_DES(const AKey_56: DES_cblock;
  VOut: Pointer; const AIn: Pointer);
procedure calc_resp(VKeys: PDES_cblock;
  const ANonce: TIdBytes; VResults: Pointer);
function SetupLanManagerPassword(const APassword: string;
  const ANonce: TIdBytes): TIdBytes;
function CreateNTPassword(const APassword: string;
  const ANonce: TIdBytes): TIdBytes;
{$ENDIF UNITTEST}

implementation

{$I TaurusTLSLinkDefines.inc}

uses
{$IFNDEF UNITTEST}
  IdCTypes,
  IdGlobal,
  IdFIPS,
{$ENDIF UNITTEST}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers,
  TaurusTLSLoader,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_types,
  SysUtils;

{$IFNDEF UNITTEST}
type
  DES_cblock = array [0 .. 7] of Byte;
  PDES_cblock = ^DES_cblock;
{$ENDIF UNITTEST}

function LoadTaurusTLS: Boolean;
begin
  Result := GetOpenSSLLoader.IsLoaded;
end;

procedure RequireNTLMReady;
begin
  if not LoadTaurusTLS then
    raise ETaurusTLSLoaderError.Create(RSNTLMNotReady);
end;

procedure CheckChallenge(const ANonce: TIdBytes);
begin
  if Length(ANonce) <> SizeOf(DES_cblock) then
    raise EArgumentException.Create(RSNTLMInvalidChallenge);
end;

function TaurusTLSIsNTLMFuncsAvail: Boolean;
var
  LMD: PEVP_MD;
  LCipher: PEVP_CIPHER;
  LMarked: Boolean;
begin
  Result := False;
  // Do not touch native APIs while unloaded, failed or inside a transition.
  if not LoadTaurusTLS then
    Exit;
  if GetFIPSMode() then
    Exit;
  LMD := nil;
  LCipher := nil;
  LMarked := ERR_set_mark() = 1;
  try
    LMD := EVP_MD_fetch(nil, 'MD4', nil);
    if LMD = nil then
      Exit;
    LCipher := EVP_CIPHER_fetch(nil, 'DES-ECB', nil);
    Result := LCipher <> nil;
  finally
    EVP_CIPHER_free(LCipher);
    EVP_MD_free(LMD);
    // A negative availability probe must not leave errors for a later operation.
    if LMarked then
      ERR_pop_to_mark
    else
      ERR_clear_error;
  end;
end;

// Native EVP calls below require explicit buffer addresses and pointer access.
{$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
procedure Encrypt_DES(const AKey_56: DES_cblock;
  VOut: Pointer; const AIn: Pointer);
var
  LKey: DES_cblock;
  LCipher: PEVP_CIPHER;
  LContext: PEVP_CIPHER_CTX;
  LBlock: array [0 .. 2 * SizeOf(DES_cblock) - 1] of Byte;
  LOutLen, LFinalLen: TIdC_INT;
  I, J: Integer;
  LParity: Byte;
begin
  if GetFIPSMode then
    FIPSAlgorithmNotAllowed('DES');
  RequireNTLMReady;
  if (VOut = nil) or (AIn = nil) then
    raise EArgumentException.Create(RSNTLMInvalidBuffer);

  // Expand seven key bytes into eight DES bytes with odd parity.
  LKey[0] := AKey_56[0] and $FE;
  for I := 1 to 6 do
    LKey[I] := ((AKey_56[I - 1] shl (8 - I)) or
      (AKey_56[I] shr I)) and $FE;
  LKey[7] := (AKey_56[6] shl 1) and $FE;
  for I := 0 to High(LKey) do
  begin
    LParity := 1;
    for J := 1 to 7 do
      LParity := LParity xor ((LKey[I] shr J) and 1);
    LKey[I] := LKey[I] or LParity;
  end;

  LCipher := EVP_CIPHER_fetch(nil, 'DES-ECB', nil);
  if LCipher = nil then
    raise ETaurusTLSDES_ECBNotFound.Create(RSSSLDES_ECBNotFound);
  try
    LContext := EVP_CIPHER_CTX_new;
    if LContext = nil then
      raise ETaurusTLSEVPCipherCTXNewFailed.Create(RSMsg_DES_EVP_CIPHER_CTX_new_failed);
    try
      ETaurusTLSEVPEncryptInitEx2Failed.RaiseIfError(
        EVP_EncryptInit_ex2(LContext, LCipher, @LKey[0], nil, nil),
        RSMsg_DES_EVP_EncryptInit_ex2);
      ETaurusTLSEVPEncryptInitEx2Failed.RaiseIfError(
        EVP_CIPHER_CTX_set_padding(LContext, 0), RSNTLMSetPaddingFailed);
      ETaurusTLSEVPEncryptUpdateFailed.RaiseIfError(
        EVP_EncryptUpdate(LContext, LBlock[0], LOutLen, AIn^,
          SizeOf(DES_cblock)), RSMsg_DES_EVP_EncryptUpdate);
      if (LOutLen < 0) or (LOutLen > SizeOf(DES_cblock)) then
        raise ETaurusTLSEVPEncryptUpdateFailed.Create(RSNTLMUnexpectedOutputLength);
      ETaurusTLSEVPEncryptFinalExFailed.RaiseIfError(
        EVP_EncryptFinal_ex(LContext, LBlock[LOutLen], LFinalLen),
        RSMsg_DES_EVP_EncryptFinalEx);
      if LOutLen + LFinalLen <> SizeOf(DES_cblock) then
        raise ETaurusTLSEVPEncryptFinalExFailed.Create(RSNTLMUnexpectedOutputLength);
      // Publish exactly one block, and only after all native calls succeed.
      Move(LBlock[0], VOut^, SizeOf(DES_cblock));
    finally
      EVP_CIPHER_CTX_free(LContext);
    end;
  finally
    EVP_CIPHER_free(LCipher);
  end;
end;

procedure calc_resp(VKeys: PDES_cblock; const ANonce: TIdBytes;
  VResults: Pointer);
var
  LKey: DES_cblock;
  LKeyPtr, LResultPtr: PByte;
  I: Integer;
begin
  CheckChallenge(ANonce);
  if (VKeys = nil) or (VResults = nil) then
    raise EArgumentException.Create(RSNTLMInvalidBuffer);
  LKeyPtr := PByte(VKeys);
  LResultPtr := PByte(VResults);
  for I := 0 to 2 do
  begin
    FillChar(LKey, SizeOf(LKey), 0);
    Move(LKeyPtr^, LKey[0], 7);
    Encrypt_DES(LKey, LResultPtr, @ANonce[0]);
    Inc(LKeyPtr, 7);
    Inc(LResultPtr, SizeOf(DES_cblock));
  end;
end;

function SetupLanManagerPassword(const APassword: string;
  const ANonce: TIdBytes): TIdBytes;
const
  Magic: DES_cblock = ($4B, $47, $53, $21, $40, $23, $24, $25);
var
  LPassword: TIdBytes;
  LPaddedPassword: array [0 .. 13] of Byte;
  LHash: array [0 .. 20] of Byte;
  LKey: DES_cblock;
  LLen: Integer;
begin
  if GetFIPSMode() then
    FIPSAlgorithmNotAllowed('DES');
  CheckChallenge(ANonce);
  RequireNTLMReady;
  // Retain the existing platform encoding and 14-byte truncation contract.
  LPassword := IndyTextEncoding_OSDefault.GetBytes(UpperCase(APassword));
  FillChar(LPaddedPassword, SizeOf(LPaddedPassword), 0);
  LLen := Integer(IndyMin(Length(LPassword), SizeOf(LPaddedPassword)));
  if LLen > 0 then
    Move(LPassword[0], LPaddedPassword[0], LLen);
  FillChar(LHash, SizeOf(LHash), 0);
  FillChar(LKey, SizeOf(LKey), 0);
  Move(LPaddedPassword[0], LKey[0], 7);
  Encrypt_DES(LKey, @LHash[0], @Magic[0]);
  Move(LPaddedPassword[7], LKey[0], 7);
  Encrypt_DES(LKey, @LHash[8], @Magic[0]);
  SetLength(Result, 24);
  calc_resp(PDES_cblock(@LHash[0]), ANonce, @Result[0]);
end;

function CreateNTPassword(const APassword: string;
  const ANonce: TIdBytes): TIdBytes;
var
  LPassword: TIdBytes;
  LHash: array [0 .. 20] of Byte;
  LDigest: array [0 .. EVP_MAX_MD_SIZE - 1] of Byte;
  LMD: PEVP_MD;
  LContext: PEVP_MD_CTX;
  LHashLen: TIdC_UINT;
begin
  CheckMD4Permitted;
  CheckChallenge(ANonce);
  RequireNTLMReady;
  LPassword := IndyTextEncoding_UTF16LE.GetBytes(APassword);
  LMD := EVP_MD_fetch(nil, 'MD4', nil);
  if LMD = nil then
    raise ETaurusTLSMD4NotFound.CreateResMsg;
  try
    LContext := EVP_MD_CTX_new;
    if LContext = nil then
      raise ETaurusTLSEVPMDCTXNew.Create(RSOSSLEVPMDCTXNew);
    try
      FillChar(LHash, SizeOf(LHash), 0);
      ETaurusTLSDigestInitEx.RaiseIfError(
        EVP_DigestInit_ex(LContext, LMD, nil), RSOSSLEVPDigestExError);
      // PByte(nil) is valid for an empty digest input with zero length.
      ETaurusTLSDigestUpdate.RaiseIfError(
        EVP_DigestUpdate(LContext, PByte(LPassword), Length(LPassword)),
        RSOSSLEVPDigestUpdateError);
      ETaurusTLSDigestFinalEx.RaiseIfError(
        EVP_DigestFinal_ex(LContext, @LDigest[0], LHashLen),
        RSOSSLEVPDigestError);
      if LHashLen <> 16 then
        raise ETaurusTLSDigestFinalEx.Create(RSNTLMUnexpectedOutputLength);
      Move(LDigest[0], LHash[0], 16);
    finally
      EVP_MD_CTX_free(LContext);
    end;
  finally
    EVP_MD_free(LMD);
  end;
  SetLength(Result, 24);
  calc_resp(PDES_cblock(@LHash[0]), ANonce, @Result[0]);
end;

{$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}

// Callback addresses remain unchanged across Load/Unload; their bodies check loader state.
procedure InitNTLMHooks;
begin
  {$IF DECLARED(LoadNTLMLibrary)}
  LoadNTLMLibrary := LoadTaurusTLS;
  {$IFEND}
  {$IF DECLARED(IsNTLMFuncsAvail)}
  IsNTLMFuncsAvail := TaurusTLSIsNTLMFuncsAvail;
  {$IFEND}
  {$IF DECLARED(NTLMGetLmChallengeResponse)}
  NTLMGetLmChallengeResponse := SetupLanManagerPassword;
  {$IFEND}
  {$IF DECLARED(NTLMGetNtChallengeResponse)}
  NTLMGetNtChallengeResponse := CreateNTPassword;
  {$IFEND}
end;

initialization
  InitNTLMHooks;
end.
