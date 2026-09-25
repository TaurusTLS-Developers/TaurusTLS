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

implementation
{$I TaurusTLSLinkDefines.inc}
uses
  IdGlobal, IdFIPS, IdHashMessageDigest,
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers,
  TaurusTLSLoader,
  TaurusTLSHeaders_des,
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

function IsNTLMFuncsAvail: Boolean;
begin
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := true;
{$ELSE}
  {$IFDEF OPENSSL_USE_SHARED_LIBRARY}
  Result := True;
  {$ELSE}
  Result := Assigned(DES_set_odd_parity) and Assigned(DES_set_key) and
    Assigned(DES_ecb_encrypt);
  {$ENDIF}
{$ENDIF}
end;

type
  Pdes_key_schedule = ^des_key_schedule;

  { /*
    * turns a 56 bit key into the 64 bit, odd parity key and sets the key.
    * The key schedule ks is also set.
    */ }
procedure setup_des_key(const Akey_56: des_cblock; var Vks: des_key_schedule);
Var
  Lkey: des_cblock;  //PALOFF - Local variables that are set but not later used
begin
  Lkey[0] := Akey_56[0];

  Lkey[1] := ((Akey_56[0] SHL 7) and $FF) or (Akey_56[1] SHR 1);
  Lkey[2] := ((Akey_56[1] SHL 6) and $FF) or (Akey_56[2] SHR 2);
  Lkey[3] := ((Akey_56[2] SHL 5) and $FF) or (Akey_56[3] SHR 3);
  Lkey[4] := ((Akey_56[3] SHL 4) and $FF) or (Akey_56[4] SHR 4);
  Lkey[5] := ((Akey_56[4] SHL 3) and $FF) or (Akey_56[5] SHR 5);
  Lkey[6] := ((Akey_56[5] SHL 2) and $FF) or (Akey_56[6] SHR 6);
  Lkey[7] := (Akey_56[6] SHL 1) and $FF;

  DES_set_odd_parity(@Lkey);
  case DES_set_key(@Lkey, Vks) of
    -1 : raise ETaurusTLSDesSetKeyWrongParity.Create(RSMsg_DES_set_key_wrong_key_parity);
    -2 : raise ETaurusTLSDesSetKeyWeakKey.Create(RSMsg_DES_weak_key);
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
begin
  FillChar(LKs,SizeOf(LKs),0);
  setup_des_key(Vkeys^, Lks);
  Move(ANonce[0], Lnonce, 8);
  DES_ecb_encrypt(@Lnonce, PDES_cblock(@Vresults^), @Lks, DES_ENCRYPT);

  setup_des_key(PDES_cblock(PtrUInt(Vkeys) + 7)^, Lks);
  DES_ecb_encrypt(@Lnonce, PDES_cblock(PtrUInt(Vresults) + 8), @Lks,
    DES_ENCRYPT);

  setup_des_key(PDES_cblock(PtrUInt(Vkeys) + 14)^, Lks);
  DES_ecb_encrypt(@Lnonce, PDES_cblock(PtrUInt(Vresults) + 16), @Lks,
    DES_ENCRYPT);
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

  setup_des_key(PDES_cblock(@lm_pw[0])^, ks);
  DES_ecb_encrypt(@Magic, PDES_cblock(@lm_hpw[0]), @ks, DES_ENCRYPT);

  setup_des_key(PDES_cblock(PtrUInt(@lm_pw[0]) + 7)^, ks);
  DES_ecb_encrypt(@Magic, PDES_cblock(PtrUInt(@lm_hpw[0]) + 8), @ks,
    DES_ENCRYPT);

  FillChar(lm_hpw[16], 5, 0);

  FillChar(lm_resp[0], 23, 0);
  calc_resp(PDES_cblock(@lm_hpw[0]), ANonce, Pdes_key_schedule(@lm_resp[0]));

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
  calc_resp(PDES_cblock(@Lnt_hpw[1]), ANonce, Pdes_key_schedule(@Lnt_resp[1]));

  SetLength(Result, SizeOf(Lnt_resp));
  Move(Lnt_resp[1], Result[0], SizeOf(Lnt_resp));
end;

procedure InstallNTLMHooks;
begin
  IdFIPS.LoadNTLMLibrary := LoadTaurusTLS;
  IdFIPS.IsNTLMFuncsAvail := IsNTLMFuncsAvail;
  IdFIPS.NTLMGetLmChallengeResponse := SetupLanManagerPassword;
  IdFIPS.NTLMGetNtChallengeResponse := CreateNTPassword;
end;

initialization

{$IFDEF GETURIHOST_SUPPORTED}
RegisterFIPSHooksInstaller(InstallNTLMHooks);
{$ENDIF}

end.
