unit TaurusTLS.UT.NTLM;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  IdGlobal,
  TaurusTLS.UT.TestClasses;

type
  [TestFixture]
  [Category('NTLM')]
  TOSSLNTLMFixture = class(TOsslBaseFixture)
  private
    class function HexBytes(const AHex: string): TIdBytes; static;
    class procedure AssertBytesEqual(const AExpected, AActual: TIdBytes); static;
  public
    // Independent NTLMv1 known-answer vector (password Password, challenge below).
    [AutoNameTestCase('Password,0123456789ABCDEF,67C43011F30298A2AD35ECE64F16331C44BDBED927841F94')]
    procedure NTLMResponse(APassword, AChallengeHex, AExpectedHex: string);

    [AutoNameTestCase('Password,0123456789ABCDEF,98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13')]
    procedure LMResponse(APassword, AChallengeHex, AExpectedHex: string);

    // Guards check writes around the 8-byte DES output, not input overreads.
    [AutoNameTestCase('1,1')]
    [AutoNameTestCase('4,4')]
    [AutoNameTestCase('16,16')]
    [AutoNameTestCase('1,16')]
    [AutoNameTestCase('16,1')]
    procedure DESBoundary(ALeftGuard, ARightGuard: Integer);
  end;

implementation

uses
  TaurusTLS_NTLM;

const
  CGuardByte = $A5;
  CDESBlockSize = 8;

class function TOSSLNTLMFixture.HexBytes(const AHex: string): TIdBytes;
var
  LBytes: TBytes;
  I: Integer;
begin
  LBytes := TBytes.FromHexStr(AHex);
  SetLength(Result, Length(LBytes));
  for I := 0 to High(LBytes) do
    Result[I] := LBytes[I];
end;

class procedure TOSSLNTLMFixture.AssertBytesEqual(
  const AExpected, AActual: TIdBytes);
var
  I: Integer;
begin
  Assert.AreEqual<Integer>(Length(AExpected), Length(AActual),
    'Unexpected output length');
  for I := 0 to High(AExpected) do
    Assert.AreEqual<Byte>(AExpected[I], AActual[I],
      Format('Mismatch at byte %d', [I]));
end;

procedure TOSSLNTLMFixture.NTLMResponse(
  APassword, AChallengeHex, AExpectedHex: string);
var
  LChallenge, LActual: TIdBytes;
begin
  CheckAllFailures;
  LChallenge := HexBytes(AChallengeHex);
  Assert.AreEqual<Integer>(8, Length(LChallenge));
  LActual := CreateNTPassword(APassword, LChallenge);
  AssertBytesEqual(HexBytes(AExpectedHex), LActual);
end;

procedure TOSSLNTLMFixture.LMResponse(
  APassword, AChallengeHex, AExpectedHex: string);
var
  LChallenge, LActual: TIdBytes;
begin
  CheckAllFailures;
  LChallenge := HexBytes(AChallengeHex);
  Assert.AreEqual<Integer>(8, Length(LChallenge));
  LActual := SetupLanManagerPassword(APassword, LChallenge);
  AssertBytesEqual(HexBytes(AExpectedHex), LActual);
end;

procedure TOSSLNTLMFixture.DESBoundary(ALeftGuard, ARightGuard: Integer);
var
  LKey: DES_cblock;
  LInput, LInputBefore, LExpected, LBuffer, LActual: TIdBytes;
  I: Integer;
begin
  CheckAllFailures;
  Assert.IsTrue((ALeftGuard > 0) and (ARightGuard > 0));

  // DES 64-bit key 133457799BBCDFF1 stripped of parity bits
  // gives 7-byte NTLM key material 12695BC9B7B7F8.
  // Encrypt_DES is assumed to expand the first seven bytes.
  FillChar(LKey, SizeOf(LKey), 0);
  LActual := HexBytes('12695BC9B7B7F8');
  Move(LActual[0], LKey[0], 7);
  LInput := HexBytes('0123456789ABCDEF');
  LExpected := HexBytes('85E813540F0AB405');
  LInputBefore := Copy(LInput, 0, Length(LInput));

  SetLength(LBuffer, ALeftGuard + CDESBlockSize + ARightGuard);
  FillChar(LBuffer[0], Length(LBuffer), CGuardByte);
  Encrypt_DES(LKey, @LBuffer[ALeftGuard], @LInput[0]);

  for I := 0 to ALeftGuard - 1 do
    Assert.AreEqual<Byte>(CGuardByte, LBuffer[I],
      Format('Left guard changed at %d', [I]));
  for I := ALeftGuard + CDESBlockSize to High(LBuffer) do
    Assert.AreEqual<Byte>(CGuardByte, LBuffer[I],
      Format('Right guard changed at %d', [I]));

  SetLength(LActual, CDESBlockSize);
  Move(LBuffer[ALeftGuard], LActual[0], CDESBlockSize);
  AssertBytesEqual(LExpected, LActual);
  AssertBytesEqual(LInputBefore, LInput); // The plaintext must remain unchanged.
end;

initialization
  TDUnitX.RegisterTestFixture(TOSSLNTLMFixture);

end.
