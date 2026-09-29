unit TaurusTLS.UT.SSLContainers;

interface

uses
  System.Classes, System.SysUtils, DUnitX.TestFramework, DUnitX.Types,
  DUnitX.InternalDataProvider, DUnitX.TestDataProvider,
  IdGlobal, IdCTypes,
  TaurusTLS.UT.TestClasses, TaurusTLSHeaders_types,
  TaurusTLS_Encryptors, TaurusTLS_SSLContainers;

type
  TCustomBytesFixture = class(TOsslBaseFixture)
    FData: TBytes;
    function GetDataLen: NativeUInt;
  protected
    procedure InitData(ASize: TIdC_SizeT); overload;
    procedure InitData(AData: TBytes); overload;
    function CopyData: TBytes;
    class function HexToBytes(const AHexStr: string): TBytes;
    class function Base64ToBytes(const AB64: string): TBytes;
    class function GetBioMemPtr(ABio: ITaurusTLS_Bio; var AMemPtr: pointer): TIdC_INT;
    class procedure TestBytes(AExpected, AData: TBytes); overload;
    class procedure TestData(AExpected: TBytes; AData: pointer; ADataLen: NativeUInt); overload;
    procedure TestBytes(AData: TBytes); overload;
    procedure TestData(AData: pointer; ADataLen: NativeUInt); overload;
    procedure TestBytesIntf(ABytes: ITaurusTLS_Bytes);
    procedure TestBioIntf(ABio: ITaurusTLS_Bio);

    property Data: TBytes read FData;
    property DataLen: NativeUInt read GetDataLen;
  public
    [Teardown]
    procedure TearDown;
  end;

  [TestFixture]
  [Category('Bytes')]
  TBytesFixture = class(TCustomBytesFixture)
  public
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure BytesSame(AHexStr: string); overload;
    [AutoNameTestCase('0')]
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure BytesSame(ASize: NativeUInt); overload;
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure BytesCopy(AHexStr: string); overload;
    [AutoNameTestCase('0')]
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure BytesCopy(ASize: NativeUInt); overload;
    [Test]
    procedure BioNull(ASize: NativeUInt); overload;
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure BioSame(AHexStr: string); overload;
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure BioSame(ASize: NativeUInt); overload;
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure BioCopy(AHexStr: string); overload;
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure BioCopy(ASize: NativeUInt); overload;
    [AutoNameTestCase('383, 1')]
    [AutoNameTestCase('383, 15')]
    procedure BioRepeat(ASize, ACount: NativeUInt);
    [AutoNameTestCase('383, 1')]
    [AutoNameTestCase('383, 15')]
    procedure BioRepeatOneLock(ASize, ACount: NativeUInt);
  end;

  [TestFixture]
  [Category('WipingBytes')]
  TWipingBytesFixture = class(TCustomBytesFixture)
  protected
    class procedure IsEmpty(ABytes: TBytes); overload;
    class procedure IsEmpty(AData: pointer; ASize: NativeUInt); overload;
    class procedure IsBioEmpty(ABio: PBIO; AExpectedLen: NativeUInt); overload;
    procedure TestWipeBytes;
    procedure TestWipeBio;
  public
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure WipeBytes(AHexStr: string); overload;
    [AutoNameTestCase('0')]
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure WipeBytes(ASize: NativeUInt); overload;
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure WipeBio(AHexStr: string); overload;
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure WipeBio(ASize: NativeUInt); overload;
  end;

  [TestFixture]
  [Category('BytesVault')]
  TBytesVaultFixture = class(TCustomBytesFixture)
  protected
    procedure IsEncrypted(const ABytes: TBytes); overload;
    procedure IsEncrypted(AData: pointer; ADataLen: NativeUInt); overload;
    procedure IsUnEncrypted(ABio: ITaurusTLS_Bio); overload;
    class function NewBytes(ABytes: TBytes): ITaurusTLS_Bytes; overload;
    class function NewBytes(AHexStr: string): ITaurusTLS_Bytes; overload;
  public
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure Bytes(AHexStr: string); overload;
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure Bytes(ASize: NativeUInt); overload;
    [AutoNameTestCase('e2')]
    [AutoNameTestCase('026ca6b4d0761ebfcd933a3f7b379e')]
    [AutoNameTestCase('941833f8ffd98ea2861d8c9f718d3f4d'+
      '7ca37f0214e733d1bd1426bfa03fa2c0')]
    procedure Bio(AHexStr: string); overload;
    [AutoNameTestCase('1024')]
    [AutoNameTestCase('177')]
    [AutoNameTestCase('383')]
    procedure Bio(ASize: NativeUInt); overload;
    [AutoNameTestCase('383, 1')]
    [AutoNameTestCase('383, 15')]
    procedure BioRepeat(ASize, ACount: NativeUInt);
    [AutoNameTestCase('383, 1')]
    [AutoNameTestCase('383, 15')]
    procedure BioRepeatOneLock(ASize, ACount: NativeUInt);
  end;

  [TestFixture]
  [Category('PassphraseVault')]
  TPassphraseVaultFixture = class(TCustomBytesFixture)
  protected
    procedure CheckPassphrase(AVault: ITaurusTLS_PassphraseVault;
      const APassStr: UTF8String);
  public
    [TestCase('''Empty String''', '')]
    [TestCase('''Cyrillic''', '1A043804400438043B04380446043004')]
    [TestCase('''The Book (German)''',
      '64006900650020004200FC006300680065007200')]
    procedure UnicodePassphrase(AHexStr: string);
    [TestCase('''Empty String''', '')]
    [TestCase('''Test String''', '5465737420537472696E67')]
    procedure RawBytePassphrase(AHexStr: string);
    [TestCase('''Empty String''', '')]
    [TestCase('''Test String''', '5465737420537472696E67')]
    procedure AnsiPassphrase(AHexStr: string);
    [TestCase('''Empty String''', '')]
    [TestCase('''Test String''', '5465737420537472696E67')]
    [TestCase('Cyrillic', 'D09AD0B8D180D0B8D0BBD0B8D186D0B0')]
    [TestCase('''The Book (German)''', '6469652042C3BC63686572')]
    procedure UTF8Passphrase(AHexStr: string);
  end;


implementation

uses
  System.RTTI, System.NetEncoding, System.TypInfo, TaurusTLSHeaders_bio,
  TaurusTLSHeaders_evp, TaurusTLSHeaders_evperr, TaurusTLS_Random;

{ TCustomBytesFixture }

procedure TCustomBytesFixture.TearDown;
begin
  FData:=nil;
end;

class function TCustomBytesFixture.Base64ToBytes(const AB64: string): TBytes;
begin
  Assert.AreNotEqual(0, Length(AB64),
    'Parameter ''AB64'' must be grater than Zero.');
  Result:=BytesOf(TNetEncoding.Base64.Decode(AB64));
end;

class function TCustomBytesFixture.HexToBytes(const AHexStr: string): TBytes;
var
  lLen: NativeUInt;

begin
  Assert.IsNotEmpty(AHexStr, 'Parameter ''AHexStr'' must not be empty.');
  lLen:=Length(AHexStr);
  Assert.IsFalse(Odd(lLen mod 2), 'HEX String must be divisible by 2.');
  lLen:=lLen div 2;
  SetLength(Result, lLen);
  HexToBin(PChar(AHexStr), 0, Result, 0, lLen);
end;

procedure TCustomBytesFixture.InitData(AData: TBytes);
begin
  FData:=AData;
end;

procedure TCustomBytesFixture.InitData(ASize: TIdC_SizeT);
begin
  FData:=TTaurusTLS_Random.PublicRandom.Random(ASize);
end;

class function TCustomBytesFixture.GetBioMemPtr(ABio: ITaurusTLS_Bio;
  var AMemPtr: pointer): TIdC_INT;
begin
  Assert.IsNotNull(ABio, 'ABio must not be ''nil''.');
  Result:=BIO_get_mem_data(ABio.Bio, AMemPtr);
  Assert.IsTrue(Result >= 0, 'Can not get Data memory pointer form thr ABio.');
end;

function TCustomBytesFixture.GetDataLen: NativeUInt;
begin
  Result:=Length(FData);
end;

function TCustomBytesFixture.CopyData: TBytes;
begin
  Result:=Copy(FData, 0, Length(FData));
end;

class procedure TCustomBytesFixture.TestBytes(AExpected, AData: TBytes);
var
  lExpectedLen, lADataLen: NativeUInt;
begin
  if AExpected = AData then
    Exit; // the same  byte array
  lExpectedLen:=Length(AExpected);
  lADataLen:=Length(AData);
  Assert.AreEqual(lExpectedLen, lADataLen, 'FData and AData lengths are not equal.');
  if lExpectedLen = 0 then
    Exit; // lADataLen = 0 as well.
  Assert.AreEqualMemory(@AExpected[0], @AData[0], lExpectedLen,
    'FData and AData contents are not equal.');
end;

class procedure TCustomBytesFixture.TestData(AExpected: TBytes; AData: pointer;
  ADataLen: NativeUInt);
var
  lExpectedLen: NativeUInt;

begin
  lExpectedLen:=Length(AExpected);
  Assert.AreEqual(lExpectedLen, ADataLen, 'FData and AData lengths are not equal.');
  if lExpectedLen = 0 then
    Exit; // lADataLen = 0 as well.

  if @AExpected[0] = AData then
    Exit; // the same byte array. Address of first element and length are equal.
  Assert.AreEqualMemory(@AExpected[0], AData, lExpectedLen,
    'FData and AData contents are not equal.');
end;

procedure TCustomBytesFixture.TestBytes(AData: TBytes);
begin
  TestBytes(Data, AData);
end;

procedure TCustomBytesFixture.TestData(AData: pointer; ADataLen: NativeUInt);
begin
  TestData(Data, AData, ADataLen);
end;

procedure TCustomBytesFixture.TestBytesIntf(ABytes: ITaurusTLS_Bytes);
begin
  Assert.IsNotNull(ABytes, 'ABytes msut not be ''nil''.');
  TestBytes(ABytes.Bytes);
end;

procedure TCustomBytesFixture.TestBioIntf(ABio: ITaurusTLS_Bio);
var
  lBio: PBIO;
  lBioLen: TIdC_SIZET;
  lMemPtr: Pointer;

begin
  Assert.IsNotNull(ABio, 'ABio msut not be ''nil''.');
  lBIO:=ABio.Bio;
  lBioLen:=BIO_get_mem_data(lBio, lMemPtr);
  Assert.AreEqual<NativeUInt>(DataLen, lBioLen,
    'Unable to extract memory pointer from the lBio');
  TestData(lMemPtr, lBioLen);
end;

{ TPlainBytesFixture }

procedure TBytesFixture.BytesSame(AHexStr: string);
begin
  InitData(HexToBytes(AHexStr));
  TestBytesIntf(TTaurusTLS_Bytes.Create(Data));
end;

procedure TBytesFixture.BytesSame(ASize: NativeUInt);
begin
  InitData(ASize);
  TestBytesIntf(TTaurusTLS_Bytes.Create(Data));
end;

procedure TBytesFixture.BytesCopy(AHexStr: string);
begin
  InitData(HexToBytes(AHexStr));
  TestBytesIntf(TTaurusTLS_Bytes.Create(CopyData));
end;

procedure TBytesFixture.BytesCopy(ASize: NativeUInt);
begin
  InitData(ASize);
  TestBytesIntf(TTaurusTLS_Bytes.Create(CopyData));
end;

procedure TBytesFixture.BioNull(ASize: NativeUInt);
begin
  InitData(0);
  Assert.IsNull((TTaurusTLS_Bytes.Create(Data) as ITaurusTLS_Bytes).NewBio,
    'Excpected ''nil'' Bio.');
end;

procedure TBytesFixture.BioRepeat(ASize, ACount: NativeUInt);
var
  i: NativeUInt;

begin
  InitData(ASize);
  for i:=0 to ACount-1 do
    TestBioIntf((TTaurusTLS_Bytes.Create(Data) as ITaurusTLS_Bytes).NewBio);
end;

procedure TBytesFixture.BioRepeatOneLock(ASize, ACount: NativeUInt);
var
  lBio: ITaurusTLS_Bio;
  i: NativeUInt;

begin
  InitData(ASize);
  lBio:=(TTaurusTLS_Bytes.Create(Data) as ITaurusTLS_Bytes).NewBio;
  TestBioIntf(lBio);
  for i:=0 to ACount-1 do
    TestBioIntf((TTaurusTLS_Bytes.Create(Data) as ITaurusTLS_Bytes).NewBio);
end;

procedure TBytesFixture.BioSame(AHexStr: string);
begin
  InitData(HexToBytes(AHexStr));
  TestBioIntf((TTaurusTLS_Bytes.Create(Data) as ITaurusTLS_Bytes).NewBio);
end;

procedure TBytesFixture.BioSame(ASize: NativeUInt);
begin
  InitData(ASize);
  TestBioIntf((TTaurusTLS_Bytes.Create(Data) as ITaurusTLS_Bytes).NewBio);
end;

procedure TBytesFixture.BioCopy(ASize: NativeUInt);
begin
  InitData(ASize);
  TestBioIntf((TTaurusTLS_Bytes.Create(CopyData) as ITaurusTLS_Bytes).NewBio);
end;

procedure TBytesFixture.BioCopy(AHexStr: string);
begin
  InitData(HexToBytes(AHexStr));
  TestBioIntf((TTaurusTLS_Bytes.Create(CopyData) as ITaurusTLS_Bytes).NewBio);
end;

{ TWipingBytesFixture }

class procedure TWipingBytesFixture.IsEmpty(AData: pointer; ASize: NativeUInt);
var
  lLongPtr: PNativeUInt;
  lBytePtr: PByte;

begin
  if not Assigned(AData) then
    Exit;
  lLongPtr:=AData;
{$POINTERMATH ON}
  while (lLongPtr+1) < (PByte(AData)+ASize) do
    if lLongPtr^ <> 0 then
      Assert.Fail('Data is not wiped out.')
    else
      Inc(lLongPtr);
  lBytePtr:=PByte(lLongPtr);
  while lBytePtr < (PByte(AData)+ASize) do
    if lBytePtr^ <> 0 then
      Assert.Fail('Data is not wiped out.')
    else
      Inc(lBytePtr);
{$POINTERMATH OFF}
end;

class procedure TWipingBytesFixture.IsBioEmpty(ABio: PBIO; AExpectedLen: NativeUInt);
var
  lMemPtr: pointer;
  lLen: TIdC_INT;

begin
  Assert.IsNotNull(ABio, 'ABio msut not be ''nil''.');
  lLen:=BIO_get_mem_data(ABio, lMemPtr);
  Assert.AreEqual<NativeUInt>(AExpectedLen, lLen,
    'ABio length is not equal AExpectedLen.');
  IsEmpty(lMemPtr, AExpectedLen);
end;

class procedure TWipingBytesFixture.IsEmpty(ABytes: TBytes);
var
  lLen: NativeUInt;

begin
  lLen:=Length(ABytes);
  if lLen = 0 then
    Exit;
  IsEmpty(@ABytes[0], lLen);
end;

procedure TWipingBytesFixture.TestWipeBytes;
var
  lBytes: ITaurusTLS_Bytes;
  lData: TBytes;

begin
  lBytes:=TTaurusTLS_WipingBytes.Create(CopyData);
  TestBytesIntf(lBytes);
  lData:=lBytes.Bytes;
  lBytes:=nil;
  IsEmpty(lData);
end;

procedure TWipingBytesFixture.WipeBytes(ASize: NativeUInt);
begin
  InitData(ASize);
  TestWipeBytes;
end;

procedure TWipingBytesFixture.WipeBytes(AHexStr: string);
begin
  InitData(HexToBytes(AHexStr));
  TestWipeBytes;
end;

procedure TWipingBytesFixture.TestWipeBio;
var
  lBytes: ITaurusTLS_Bytes;
  lBio: ITaurusTLS_Bio;
  lBioPtr: pointer;

begin
  lBytes:=TTaurusTLS_WipingBytes.Create(CopyData);
  lBio:=lBytes.NewBio;
  TestBioIntf(lBio);
  GetBioMemPtr(lBio, lBioPtr);
  lBytes:=nil;
  TestBioIntf(lBio);
  lBio:=nil;
  IsEmpty(lBioPtr, DataLen);
end;

procedure TWipingBytesFixture.WipeBio(ASize: NativeUInt);
begin
  InitData(ASize);
  TestWipeBio;
end;

procedure TWipingBytesFixture.WipeBio(AHexStr: string);
begin
  InitData(HexToBytes(AHexStr));
  TestWipeBio;
end;

{ TBytesVaultFixture }

procedure TBytesVaultFixture.IsEncrypted(AData: pointer;
  ADataLen: NativeUInt);
var
  lLen: NativeUInt;

begin
  lLen:=DataLen;
  Assert.AreNotEqual<NativeUInt>(0, lLen, 'Data is not initialized.');
  Assert.IsNotNull(AData, 'AData must be not ''nil''.');
  Assert.AreNotEqual<NativeUInt>(0, lLen, 'ADataLen must be greater than Zero.');
  if lLen > ADataLen then
    lLen:=ADataLen;
  // A few bytes of encrypted data can match the plain data by chance.
  if lLen >= SizeOf(Integer) then
    Assert.AreNotEqualMemory(@FData[0], AData, lLen,
      'Plain and Encrypted data looks the same...');
end;

procedure TBytesVaultFixture.IsEncrypted(const ABytes: TBytes);
var
  lLen: NativeUInt;

begin
  lLen:=Length(ABytes);
  Assert.AreNotEqual<NativeUInt>(0, lLen, 'ABytes should not be an empty array.');
  IsEncrypted(@ABytes[0], lLen);
end;

procedure TBytesVaultFixture.IsUnEncrypted(ABio: ITaurusTLS_Bio);
var
  lMemPtr: Pointer;
  lLen: TIdC_INT;

begin
  lLen:=GetBioMemPtr(ABio, lMemPtr);
  TestData(lMemPtr, lLen);
end;

class function TBytesVaultFixture.NewBytes(
  AHexStr: string): ITaurusTLS_Bytes;
begin
  Result:=NewBytes(HexToBytes(AHexStr));
end;

class function TBytesVaultFixture.NewBytes(ABytes: TBytes): ITaurusTLS_Bytes;
begin
  Result:=TTaurusTLS_BytesVault.Create(ABytes,
    TTaurusTLS_SimpleAESEncryptor.Create(aks192, emOFB));
end;

procedure TBytesVaultFixture.Bytes(ASize: NativeUInt);
var
  lBytes: ITaurusTLS_Bytes;

begin
  InitData(ASize);
  lBytes:=NewBytes(CopyData);
  IsEncrypted(lBytes.Bytes);
end;

procedure TBytesVaultFixture.Bytes(AHexStr: string);
var
  lBytes: ITaurusTLS_Bytes;

begin
  InitData(HexToBytes(AHexStr));
  lBytes:=NewBytes(CopyData);
  IsEncrypted(lBytes.Bytes);
end;

procedure TBytesVaultFixture.Bio(ASize: NativeUInt);
var
  lBytes: ITaurusTLS_Bytes;
  lBio: ITaurusTLS_Bio;

begin
  InitData(ASize);
  lBytes:=NewBytes(CopyData);
  lBio:=lBytes.NewBio;
  IsUnencrypted(lBio);
end;

procedure TBytesVaultFixture.BioRepeat(ASize, ACount: NativeUInt);
var
  lBytes: ITaurusTLS_Bytes;
  i: NativeUInt;

begin
  InitData(ASize);
  lBytes:=NewBytes(CopyData);
  for i:=0 to ACount-1 do
    TestBioIntf(lBytes.NewBio);
end;

procedure TBytesVaultFixture.BioRepeatOneLock(ASize, ACount: NativeUInt);
var
  lBytes: ITaurusTLS_Bytes;
  lBio: ITaurusTLS_Bio;
  i: NativeUInt;

begin
  InitData(ASize);
  lBytes:=NewBytes(CopyData);
  lBio:=lBytes.NewBio;
  TestBioIntf(lBio);
  for i:=0 to ACount-1 do
    TestBioIntf(lBytes.NewBio);
end;

procedure TBytesVaultFixture.Bio(AHexStr: string);
var
  lBytes: ITaurusTLS_Bytes;
  lBio: ITaurusTLS_Bio;

begin
  InitData(HexToBytes(AHexStr));
  lBytes:=NewBytes(CopyData);
  lBio:=lBytes.NewBio;
  IsUnencrypted(lBio);
end;

{ TPassphraseVaultFixture }

procedure TPassphraseVaultFixture.CheckPassphrase(
  AVault: ITaurusTLS_PassphraseVault; const APassStr: UTF8String);
var
  lPassStr: PAnsiChar;
  lPassIntf: ITaurusTLS_Passphrase;

begin
  Assert.IsNotNull(AVault, 'AVault is ''nil''.');
  lPassIntf:=AVault.Passphrase;
  Assert.IsNotNull(AVault, 'lPassIntf is ''nil''.');
  lPassStr:=lPassIntf.PassphraseStr;
  Assert.AreEqual<AnsiString>(AnsiString(APassStr), AnsiString(lPassStr),
    'APassStr and lPassStr are not equal.');
end;

procedure TPassphraseVaultFixture.UnicodePassphrase(AHexStr: string);
var
  lPass, lPassCopy: UTF8String;
  lVault: ITaurusTLS_PassphraseVault;

begin
  THexStrTestTool.FromHex(AHexStr, lPass);
  // we need a full copy as original string should be wiped out
  lPassCopy:=Copy(lPass, 1, Length(lPass));
  lVault:=TTaurusTLS_PassphraseVault.Create(lPass,
    TTaurusTLS_SimpleAESFactory.NewEncryptor);

  TWipeTestTool.CheckWiped(AnsiString(lPass));
  CheckPassphrase(lVault, lPassCopy);
end;

procedure TPassphraseVaultFixture.RawBytePassphrase(AHexStr: string);
var
  lPass, lPassCopy: UTF8String;
  lVault: ITaurusTLS_PassphraseVault;

begin
  THexStrTestTool.FromHex(AHexStr, lPass);
  // we need a full copy as original string should be wiped out
  lPassCopy:=Copy(lPass, 1, Length(lPass));
  lVault:=TTaurusTLS_PassphraseVault.Create(lPass,
    TTaurusTLS_SimpleAESFactory.NewEncryptor);

  TWipeTestTool.CheckWiped(AnsiString(lPass));
  CheckPassphrase(lVault, lPassCopy);
end;

procedure TPassphraseVaultFixture.AnsiPassphrase(AHexStr: string);
var
  lPass, lPassCopy: UTF8String;
  lVault: ITaurusTLS_PassphraseVault;

begin
  THexStrTestTool.FromHex(AHexStr, lPass);
  // we need a full copy as original string should be wiped out
  lPassCopy:=Copy(lPass, 1, Length(lPass));
  lVault:=TTaurusTLS_PassphraseVault.Create(lPass,
    TTaurusTLS_SimpleAESFactory.NewEncryptor);

  TWipeTestTool.CheckWiped(AnsiString(lPass));
  CheckPassphrase(lVault, lPassCopy);
end;

procedure TPassphraseVaultFixture.UTF8Passphrase(AHexStr: string);
var
  lPass, lPassCopy: UTF8String;
  lVault: ITaurusTLS_PassphraseVault;

begin
  THexStrTestTool.FromHex(AHexStr, lPass);
  // we need a full copy as original string should be wiped out
  lPassCopy:=Copy(lPass, 1, Length(lPass));
  lVault:=TTaurusTLS_PassphraseVault.Create(lPass,
    TTaurusTLS_SimpleAESFactory.NewEncryptor);

  TWipeTestTool.CheckWiped(AnsiString(lPass));
  CheckPassphrase(lVault, lPassCopy);
end;

initialization
  TDUnitX.RegisterTestFixture(TBytesFixture);
  TDUnitX.RegisterTestFixture(TWipingBytesFixture);
  TDUnitX.RegisterTestFixture(TBytesVaultFixture);
  TDUnitX.RegisterTestFixture(TPassphraseVaultFixture);

end.
