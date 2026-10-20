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
/// Self-registrated NT LAN Manager (NTLM) Protocol Implementation for Indy -
/// Internet Direct.  Indy itself will call
/// routines from the implementation section of the unit if you include this
/// unit.
/// </summary>
/// <remarks>
/// The NT LAN Manager (NTLM) Protocol is not considered secure.  It has been
/// depreciated even by Microsoft.
/// </remarks>
unit TaurusTLS_NTLM;

interface

{$IFDEF UNITTEST}
uses
  IdCTypes,
  IdGlobal,
  IdFIPS;

type
   {$IFDEF DCC}{$WARN UNSAFE_TYPE OFF}{$ENDIF}
  DES_LONG = type cardinal;
  DES_cblock = array [0 .. 7] of byte;
  PDES_cblock = ^DES_cblock;
  Pdes_key_schedule = ^des_key_schedule;
  DES_ks = record
    ks: array [0 .. 15] of record
    case longint of
    0: (cblock: DES_cblock);
    1: (deslong: array [0 .. 1] of DES_LONG);
    end;
  end;
  DES_key_schedule = DES_ks;
   {$IFDEF DCC}{$WARN UNSAFE_TYPE DEFAULT}{$ENDIF}


procedure Encrypt_DES(const Akey_56: DES_cblock;
  VOut: Pointer; const AIn: Pointer);

procedure calc_resp(Vkeys: PDES_cblock;
  const ANonce: TIdBytes; Vresults: Pdes_key_schedule);

function SetupLanManagerPassword(const APassword: String;
  const ANonce: TIdBytes): TIdBytes;

function CreateNTPassword(const APassword: String;
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
  IdHashMessageDigest,
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers,
  TaurusTLSLoader,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_types,
  TaurusTLS_LegacyProviders,
  TaurusTLSFIPS,
  SysUtils;

function LoadTaurusTLS: Boolean;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := true;
{$ELSE}
  Result := GetOpenSSLLoader.Load;
{$ENDIF}
end;

function TaurusTLSIsNTLMFuncsAvail: Boolean;
begin
  Result := True;
end;

{$IFNDEF UNITTEST}
type
   {$IFDEF DCC}{$WARN UNSAFE_TYPE OFF}{$ENDIF}
  DES_LONG = type cardinal;
  DES_cblock = array [0 .. 7] of byte;
  PDES_cblock = ^DES_cblock;
  Pdes_key_schedule = ^des_key_schedule;
  DES_ks = record
    ks: array [0 .. 15] of record
    case longint of
    0: (cblock: DES_cblock);
    1: (deslong: array [0 .. 1] of DES_LONG);
    end;
  end;
  DES_key_schedule = DES_ks;
   {$IFDEF DCC}{$WARN UNSAFE_TYPE DEFAULT}{$ENDIF}
{$ENDIF UNITTEST}


procedure Encrypt_DES(const Akey_56: des_cblock; VOut : Pointer; const AIn :  Pointer);
Var
  Lkey: des_cblock;  //PALOFF - Local variables that are set but not later used
  LCipher : PEVP_CIPHER;
  LContext : PEVP_CIPHER_CTX;
  LOutLen,
  LTmpLen  : TIdC_INT;
begin
  Lkey[0] := Akey_56[0];
  { /*
    * turns a 56 bit key into the 64 bit, odd parity key and sets the key.
    * The key schedule ks is also set.
    */ }
  Lkey[1] := ((Akey_56[0] SHL 7) and $FF) or (Akey_56[1] SHR 1);
  Lkey[2] := ((Akey_56[1] SHL 6) and $FF) or (Akey_56[2] SHR 2);
  Lkey[3] := ((Akey_56[2] SHL 5) and $FF) or (Akey_56[3] SHR 3);
  Lkey[4] := ((Akey_56[3] SHL 4) and $FF) or (Akey_56[4] SHR 4);
  Lkey[5] := ((Akey_56[4] SHL 3) and $FF) or (Akey_56[5] SHR 5);
  Lkey[6] := ((Akey_56[5] SHL 2) and $FF) or (Akey_56[6] SHR 6);
  Lkey[7] := (Akey_56[6] SHL 1) and $FF;

  LCipher := EVP_CIPHER_fetch(nil,'DES-ECB',nil);
  if Assigned(LCipher) then
  begin
    try
      LContext := EVP_CIPHER_CTX_new;
      if Assigned(LContext) then
      begin
        try
          {$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
          EVP_CIPHER_CTX_ctrl(LContext, EVP_CTRL_RAND_KEY, 0, @LKey);
          if EVP_EncryptInit_ex2( LContext, LCipher, @LKey[0], nil, nil) = 1 then
          begin
            if EVP_EncryptUpdate(LContext,VOut^,LOutLen,Ain, SizeOf(des_key_schedule)) =1 then
            begin
               if EVP_EncryptFinal_ex(LContext, VOut^, LTmpLen) <> 1 then
               begin
                 raise ETaurusTLSEVPEncryptFinalExFailed.Create(RSMsg_DES_EVP_EncryptFinalEx);
               end;
            end
            else
            begin
              raise ETaurusTLSEVPEncryptUpdateFailed.Create(RSMsg_DES_EVP_EncryptUpdate);
            end;
          end
          else
          begin
            raise ETaurusTLSEVPEncryptInitEx2Failed.Create(RSMsg_DES_EVP_EncryptInit_ex2);
          end;
         {$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}
        finally
          EVP_CIPHER_CTX_free(LContext);
        end;
      end
      else
      begin
        raise ETaurusTLSEVPCipherCTXNewFailed.Create(RSMsg_DES_EVP_CIPHER_CTX_new_failed);
      end;
    finally
      EVP_CIPHER_free(LCipher);
    end;
  end
  else
  begin
    raise ETaurusTLSDES_ECBNotFound.Create(RSSSLDES_ECBNotFound);
  end;
end;


{ /*
  * takes a 21 byte array and treats it as 3 56-bit DES keys. The
  * 8 byte plaintext is encrypted with each key and the resulting 24
  * bytes are stored in the results array.
  */ }
procedure calc_resp(Vkeys: PDES_cblock; const ANonce: TIdBytes;
  Vresults: Pdes_key_schedule);
Var
  Lks: des_key_schedule;  //PALOFF - Local variables that are set but not later used
  Lnonce: des_cblock;  //PALOFF - Local variables that are set but not later used
  LCurPtr : Pdes_key_schedule;
begin
  {$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
  FillChar(LKs,SizeOf(LKs),0);
  Move(ANonce[0], Lnonce, 8);
  Encrypt_DES(Lnonce, Vresults,@Lks);
  Encrypt_DES(VKeys^, Vresults,@lks);
  LCurPtr := VResults;
  Inc(LCurPtr,8);
  Encrypt_DES(VKeys^, LCurPtr,@Lks);
  Inc(LCurPtr,8);
  Encrypt_DES(VKeys^, LCurPtr,@Lks);
  {$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}
end;

Const
  Magic: des_cblock = ($4B, $47, $53, $21, $40, $23, $24, $25);

  // * setup LanManager password */
function SetupLanManagerPassword(const APassword: String;
  const ANonce: TIdBytes): TIdBytes;
var
  lm_hpw: array [0 .. 20] of Byte;
  lm_pw: array [0 .. 13] of Byte;
  idx, len: Integer;
  ks: des_key_schedule;   //PALOFF - Local variables that are set but not later used
  lm_resp: array [0 .. 23] of Byte;
  lPassword: {$IFDEF STRING_IS_UNICODE}TIdBytes{$ELSE}AnsiString{$ENDIF};
begin
{$IFDEF STRING_IS_UNICODE}
  lPassword := IndyTextEncoding_OSDefault.GetBytes(UpperCase(APassword));
{$ELSE}
  lPassword := UpperCase(APassword);
{$ENDIF}
  len := Integer(IndyMin(Length(lPassword), 14));
  if len > 0 then
  begin
    Move(lPassword[{$IFDEF STRING_IS_UNICODE}0{$ELSE}1{$ENDIF}], lm_pw[0], len);
  end;
  if len < 14 then
  begin
    for idx := len to 13 do
    begin
      lm_pw[idx] := $0;
    end;
  end;

  // * create LanManager hashed password */

  {$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
  Encrypt_DES(Magic, PDES_cblock(@lm_hpw[0]), @ks);

  Encrypt_DES(Magic, PDES_cblock(PtrUInt(@lm_hpw[0]) + 8),@ks);

  FillChar(lm_hpw[16], 5, 0);

  FillChar(lm_resp[0], 23, 0);
  calc_resp(PDES_cblock(@lm_hpw[0]), ANonce, Pdes_key_schedule(@lm_resp[0]));
  {$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}

  SetLength(Result, SizeOf(lm_resp));
  Move(lm_resp[0], Result[0], SizeOf(lm_resp));
end;

// * create NT hashed password */
function CreateNTPassword(const APassword: String; const ANonce: TIdBytes)
  : TIdBytes;
var
  Lnt_hpw: array [1 .. 21] of Byte;
  Lnt_resp: array [1 .. 24] of Byte;
  LMD4: TIdHashMessageDigest4;   //PALOFF - Created and freed objects
{$IFNDEF STRING_IS_UNICODE}
  i: Integer;
  LPwUnicode: TIdBytes;
{$ENDIF}
begin
  CheckMD4Permitted;
  LMD4 := TIdHashMessageDigest4.Create;
  try
{$IFDEF STRING_IS_UNICODE}
    Move(LMD4.HashString(APassword, IndyTextEncoding_UTF16LE)[0],
      Lnt_hpw[1], 16);
{$ELSE}
    // RLebeau: TODO - should this use UTF-16 as well?  This logic will
    // not produce a valid Unicode string if non-ASCII characters are present!
    SetLength(LPwUnicode, Length(APassword) * SizeOf(WideChar));
    for i := 0 to Length(APassword) - 1 do
    begin
      LPwUnicode[i * 2] := Byte(APassword[i + 1]);
      LPwUnicode[(i * 2) + 1] := Byte(#0);
    end;
    Move(LMD4.HashBytes(LPwUnicode)[0], Lnt_hpw[1], 16);
{$ENDIF}
  finally
    LMD4.Free;
  end;
  FillChar(Lnt_hpw[17], 5, 0);

  FillChar(Lnt_resp[1], 20, 0);
  {$IFDEF DCC}{$WARN UNSAFE_CODE OFF}{$ENDIF}
  calc_resp(PDES_cblock(@Lnt_hpw[1]), ANonce, Pdes_key_schedule(@Lnt_resp[1]));
  {$IFDEF DCC}{$WARN UNSAFE_CODE DEFAULT}{$ENDIF}

  SetLength(Result, SizeOf(Lnt_resp));
  Move(Lnt_resp[1], Result[0], SizeOf(Lnt_resp));
end;

procedure InstallNTLMHooks;
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

RegisterFIPSHooksInstaller(InstallNTLMHooks);

end.
