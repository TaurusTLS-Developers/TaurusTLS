unit TaurusTLS.UT.Encryptors;

interface

uses
  System.SysUtils, DUnitX.TestFramework, DUnitX.Types,
  DUnitX.InternalDataProvider, DUnitX.TestDataProvider,
  IdGlobal, IdCTypes,
  TaurusTLS.UT.TestClasses, TaurusTLSHeaders_types,
  TaurusTLS_Encryptors;

type
  TTaurusTLS_EncodeMode = TTaurusTLS_SimleAESEncodeMode;

  [TestFixture]
  [Category('Ciphers')]
  TCipherFixture = class(TOsslBaseFixture)
  private
    FCipher: TTaurusTLS_Cipher;
    FCipherName: string;
  protected
    function GetCipher(ACipherName: string): TTaurusTLS_Cipher;
    procedure DoWithOSSLCipher(AOSSLCipherProc: TProc<PEVP_CIPHER>);
    function CheckRandomFactor(ABytes: TBytes): NativeInt;

    procedure CheckCipherKeyLen(const ACipherName: string; ALen: TIdC_UINT);
    procedure CheckCipherIVLen(const ACipherName: string; ALen: TIdC_UINT);
    procedure CheckCipherBlockSize(const ACipherName: string; ALen: TIdC_UINT);

  public
    property Cipher[ACipherName: string]: TTaurusTLS_Cipher read GetCipher;

    [Teardown]
    procedure Teardown;
    [AutoNameTestCase('DES3')]
    [AutoNameTestCase('ChaCha20')]
    [AutoNameTestCase('AES-128-CBC-CTS')]
    [AutoNameTestCase('ARIA-256-GCM')]
    [AutoNameTestCase('CAMELLIA-256-CFB')]
    procedure GetCipherByNameAnsiPositive(const ACipherName: RawByteString);
    [AutoNameTestCase('DES3')]
    [AutoNameTestCase('ChaCha20')]
    [AutoNameTestCase('AES-128-CBC-CTS')]
    [AutoNameTestCase('ARIA-256-GCM')]
    [AutoNameTestCase('CAMELLIA-256-CFB')]
    procedure GetCipherByNameUnicodePositive(const ACipherName: string);
    [TestCase('aes-wrong-name', 'aes-wrong-name')]
    procedure GetCipherByNameUnicodeNegative(const ACipherName: string);
    [TestCase('aes-wrong-name', 'aes-wrong-name')]
    procedure GetCipherByNameAnsiNegative(const ACipherName: RawByteString);
    [AutoNameTestCase('DES3')]
    [AutoNameTestCase('ChaCha20')]
    [AutoNameTestCase('AES-128-CBC-CTS')]
    [AutoNameTestCase('ARIA-256-GCM')]
    [AutoNameTestCase('CAMELLIA-256-CFB')]
    procedure NewKey(const ACipherName: string);
    [AutoNameTestCase('DES3')]
    [AutoNameTestCase('ChaCha20')]
    [AutoNameTestCase('AES-128-CBC-CTS')]
    [AutoNameTestCase('ARIA-256-GCM')]
    [AutoNameTestCase('CAMELLIA-256-CFB')]
    procedure NewIV(const ACipherName: string);
    [AutoNameTestCase('DES3')]
    [AutoNameTestCase('ChaCha20')]
    [AutoNameTestCase('AES-128-CBC-CTS')]
    [AutoNameTestCase('ARIA-256-GCM')]
    [AutoNameTestCase('CAMELLIA-256-CFB')]
    procedure KeyLen(const ACipherName: string);
    [AutoNameTestCase('DES3')]
    [AutoNameTestCase('ChaCha20')]
    [AutoNameTestCase('AES-128-CBC-CTS')]
    [AutoNameTestCase('ARIA-256-GCM')]
    [AutoNameTestCase('CAMELLIA-256-CFB')]
    procedure IVLen(const ACipherName: string);
    [AutoNameTestCase('DES3')]
    [AutoNameTestCase('ChaCha20')]
    [AutoNameTestCase('AES-128-CBC-CTS')]
    [AutoNameTestCase('ARIA-256-GCM')]
    [AutoNameTestCase('CAMELLIA-256-CFB')]
    procedure BlockSize(const ACipherName: string);
  end;

  [TestFixture]
  [Category('Encryptor')]
  TSimpleAESEncryptorFixture = class(TOsslBaseFixture)
  private var
    FKeySizeNames: array[TTaurusTLS_AESKeySize] of string;
    FEncoderModeNames: array[TTaurusTLS_EncodeMode] of string;

    function CompareBytes(const A, B: TBytes): boolean;
    procedure EncryptDecrypt(AEncryptor: TTaurusTLS_SimpleAESEncryptor;
      ADataSize: NativeUInt); overload;
    function GetKeySizeByName(AKeySizeName: string): TTaurusTLS_AESKeySize;
    function GetEncodingModeByName(AEncoderModeName: string): TTaurusTLS_EncodeMode;
  protected
    property KeySizeByName[AKeySizeName: string]: TTaurusTLS_AESKeySize
      read GetKeySizeByName;
    property EncodingModeByName[AEncoderModeName: string]: TTaurusTLS_EncodeMode
      read GetEncodingModeByName;
  public
    [Setup]
    procedure Setup;
    [Teardown]
    procedure Teardown;

    [AutoNameTestCase('CBC,1')]
    [AutoNameTestCase('CBC,1024')]
    [AutoNameTestCase('CBC,383')]
    [AutoNameTestCase('CFB,1')]
    [AutoNameTestCase('CFB,1024')]
    [AutoNameTestCase('CFB,383')]
    [AutoNameTestCase('CFB,1')]
    [AutoNameTestCase('CFB,1024')]
    [AutoNameTestCase('CFB,383')]
    [AutoNameTestCase('CTR,1')]
    [AutoNameTestCase('CTR,1024')]
    [AutoNameTestCase('CTR,383')]
    procedure TestEncryptor(AEncoderMode: string; ADataSize: NativeUInt);
  end;

  [TestFixture]
  [Category('SimpleAESFactory')]
  TSimpleAESFactoryFixture = class(TOsslBaseFixture)
  public
    [Test]
    procedure KeySizeNameAll;
    [Test]
    procedure EncodeModeNameAll;
    [AutoNameTestCase('128,CBC')]
    [AutoNameTestCase('192,CFB')]
    [AutoNameTestCase('256,OFB')]
    procedure NewEncryptor(AKeySizeName, AEncodeMode: string);
    [IgnoreMemoryLeaks] // The singleton intsantiates first time.
    [AutoNameTestCase('128,OFB')]
    [AutoNameTestCase('192,CBC')]
    [AutoNameTestCase('256,CFB')]
    procedure SetDefaultCipher(AKeySizeName, AEncodeMode: string);
    [AutoNameTestCase('128,OFB')]
    [AutoNameTestCase('192,CBC')]
    [AutoNameTestCase('256,CFB')]
    procedure NewEncyptorDefault(AKeySizeName, AEncodeMode: string);
  end;

implementation

uses
  System.RTTI, System.NetEncoding, System.TypInfo, TaurusTLSHeaders_bio,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_evp, TaurusTLSHeaders_evperr, TaurusTLS_Random;

type
  TSimpleAESEnums = class
  protected const
    // DO NOT LOCALIZE
    cKeySizes: array[TTaurusTLS_AESKeySize] of string = ('128','192','256');
    cIntKeySizes: array[TTaurusTLS_AESKeySize] of cardinal = (128, 192, 256);
    cEncoderModes: array[TTaurusTLS_EncodeMode] of string =
      ('CBC','CFB','OFB','CTR');
  protected
    class function GetKeySizeNameToEnum(AName: string): TTaurusTLS_AESKeySize;
      static;
    class function GetEncodeModeNameToEnum(AName: string): TTaurusTLS_EncodeMode;
      static;
    class function GetEncodeModeToName(AValue: TTaurusTLS_EncodeMode): string;
      static;
    class function GetKeySizeEnumToName(AValue: TTaurusTLS_AESKeySize): string;
      static;
    class function GetKeySizeNameToInt(AValue: TTaurusTLS_AESKeySize): cardinal;
      static;
  public
    class property KeySize[AName: string]: TTaurusTLS_AESKeySize
      read GetKeySizeNameToEnum;
    class property KeySizeName[AValue: TTaurusTLS_AESKeySize]: string
      read GetKeySizeEnumToName;
    class property EncodeMode[AName: string]: TTaurusTLS_EncodeMode
      read GetEncodeModeNameToEnum;
    class property EncodeModeName[AValue: TTaurusTLS_EncodeMode]: string
      read GetEncodeModeToName;
    class property KeySizeInt[AValue: TTaurusTLS_AESKeySize]: cardinal
      read GetKeySizeNameToInt;
  end;

class function TSimpleAESEnums.GetEncodeModeNameToEnum(
  AName: string): TTaurusTLS_EncodeMode;
var
  lMode: TTaurusTLS_EncodeMode;
begin
  for lMode:=Low(TTaurusTLS_EncodeMode) to High(TTaurusTLS_EncodeMode) do
    if AName.CompareTo(cEncoderModes[lMode]) = 0 then
      Exit(lMode);
  Result:=Low(TTaurusTLS_EncodeMode); // never used: Assert.Fail always raises
  Assert.FailFmt('Unable to convert string value ''%s'' to the value '+
    'of ''TTaurusTLS_EncodeMode'' type.', [AName]);
end;

class function TSimpleAESEnums.GetEncodeModeToName(
  AValue: TTaurusTLS_EncodeMode): string;
begin
  Result:=cEncoderModes[AValue];
end;

class function TSimpleAESEnums.GetKeySizeEnumToName(
  AValue: TTaurusTLS_AESKeySize): string;
begin
  Result:=cKeySizes[AValue];
end;

class function TSimpleAESEnums.GetKeySizeNameToEnum(
  AName: string): TTaurusTLS_AESKeySize;
var
  lKeySize: TTaurusTLS_AESKeySize;
begin
  for lKeySize:=Low(TTaurusTLS_AESKeySize) to High(TTaurusTLS_AESKeySize) do
    if AName.CompareTo(cKeySizes[lKeySize]) = 0 then
      Exit(lKeySize);
  Result:=Low(TTaurusTLS_AESKeySize); // never used: Assert.Fail always raises
  Assert.FailFmt('Unable to convert string value ''%s'' to the value '+
    'of ''TTaurusTLS_EncodeMode'' type.', [AName]);
end;

class function TSimpleAESEnums.GetKeySizeNameToInt(
  AValue: TTaurusTLS_AESKeySize): cardinal;
begin
  Result:=cIntKeySizes[AValue];
end;

{ TCipherFixture }

procedure TCipherFixture.Teardown;
begin
  FreeAndNil(FCipher);
end;

function TCipherFixture.GetCipher(ACipherName: string): TTaurusTLS_Cipher;
begin
  if CompareText(FCipherName, ACipherName) <> 0 then
  begin
    FreeAndNil(FCipher);
    FCipherName:=ACipherName;
  end;
  if not Assigned(FCipher) then
    FCipher:=TTaurusTLS_Cipher.Create(FCipherName);
  Assert.IsNotNull(FCipher,
    Format('Unable to create TTaurusTLS_Cipher instance '+
    'with the cipher name ''%s''.', [ACipherName]));
  Result:=FCipher;
end;

function TCipherFixture.CheckRandomFactor(ABytes: TBytes): NativeInt;
var
  i, lChunkStart, lChunkEnd: NativeInt;
  lBits: set of byte;
  lVal, lUniqueCount: byte;

begin
  Result:=Length(ABytes);
  if Result = 0 then
    Exit;

  lChunkStart:=0;
  repeat
    lChunkEnd:=lChunkStart+High(Byte)+1;
    if lChunkEnd >= Result then
      lChunkEnd:=Result-1;
    lBits:=[];
    for i:=lChunkStart to lChunkEnd do
    begin
      lVal:=ABytes[i];
      if not (lVal in lBits) then
      begin
//        lUniqueCount:=
      end;
    end;

    Inc(lChunkStart);
  until lChunkEnd >= Result;


end;

procedure TCipherFixture.DoWithOSSLCipher(AOSSLCipherProc: TProc<PEVP_CIPHER>);
var
  lOSSLCipher: PEVP_CIPHER;
  lCipherName: RawByteString;

begin
  if not Assigned(AOSSLCipherProc) then
    Assert.Fail(ClassName+'.DoWithOSSLCipher: AOSSLCipherProc should not be ''nil''.');
  lOSSLCipher:=nil;
  lCipherName:=AnsiString(FCipherName);
  try
    lOSSLCipher:=EVP_Cipher_fetch(nil, PIdAnsiChar(lCipherName), nil);
    if not Assigned(lOSSLCipher) then
      Assert.Fail(Format('Unable to initialize Cipher the name ''%s''.',
        [FCipherName]));
    AOSSLCipherProc(lOSSLCipher);
  finally
    if Assigned(lOSSLCipher) then
      EVP_CIPHER_free(lOSSLCipher);
  end;
end;

procedure TCipherFixture.CheckCipherBlockSize(const ACipherName: string;
  ALen: TIdC_UINT);
var
  lOSSLCipherBlockSize: TIdC_UINT;

begin
  DoWithOSSLCipher(
    procedure(AOSSLCipher: PEVP_CIPHER)
    begin
      lOSSLCipherBlockSize:=EVP_CIPHER_get_block_size(AOSSLCipher);
      Assert.AreNotEqual<TIdC_UINT>(0, lOSSLCipherBlockSize,
        'Cipher Block Size is not initialized.');
    end
  );

  Assert.AreEqual<TIdC_UINT>(lOSSLCipherBlockSize, ALen,
    'Invalid Cipher Block Length.');
end;

procedure TCipherFixture.CheckCipherKeyLen(const ACipherName: string;
  ALen: TIdC_UINT);
var
  lOSSLCipherLen: TIdC_UINT;

begin
  DoWithOSSLCipher(
    procedure(AOSSLCipher: PEVP_CIPHER)
    begin
      lOSSLCipherLen:=EVP_CIPHER_get_key_length(AOSSLCipher);
      if lOSSLCipherLen = 0 then
        lOSSLCipherLen:=EVP_MAX_KEY_LENGTH;
    end
  );

  Assert.AreEqual<TIdC_UINT>(lOSSLCipherLen, ALen,
    'Invalid Cipher Key Length.');
end;

procedure TCipherFixture.CheckCipherIVLen(const ACipherName: string; ALen: TIdC_UINT);
var
  lOSSLCipherIVLen: TIdC_UINT;

begin
  DoWithOSSLCipher(
    procedure(AOSSLCipher: PEVP_CIPHER)
    begin
      lOSSLCipherIVLen:=EVP_CIPHER_get_iv_length(AOSSLCipher);
      if lOSSLCipherIVLen = 0 then
        lOSSLCipherIVLen:=EVP_MAX_KEY_LENGTH;
    end
  );

  Assert.AreEqual<TIdC_UINT>(lOSSLCipherIVLen, ALen,
    'Invalid Cipher IV Length.');
end;

procedure TCipherFixture.GetCipherByNameAnsiPositive(
  const ACipherName: RawByteString);
var
  lCipher: PEVP_CIPHER;

begin
  lCipher:=TTaurusTLS_Cipher.GetCipherByName(PIdAnsiChar(ACipherName));
  try
    Assert.IsNotNull(lCipher,
      'TTaurusTLS_Cipher.GetCipherByName returns empty Cipher method implementation.')
  finally
    if Assigned(lCipher) then
      EVP_CIPHER_free(lCipher);
  end;
end;

procedure TCipherFixture.GetCipherByNameUnicodePositive(const ACipherName: string);
var
  lCipher: PEVP_CIPHER;

begin
  lCipher:=TTaurusTLS_Cipher.GetCipherByName(ACipherName);
  try
    Assert.IsNotNull(lCipher,
      'TTaurusTLS_Cipher.GetCipherByName returns empty Cipher method implementation.')
  finally
    if Assigned(lCipher) then
      EVP_CIPHER_free(lCipher);
  end;

end;

procedure TCipherFixture.GetCipherByNameAnsiNegative(
  const ACipherName: RawByteString);
var
  lCipher: PEVP_CIPHER;

begin

  lCipher:=TTaurusTLS_Cipher.GetCipherByName(PIdAnsiChar(ACipherName));
  try
    Assert.IsNull(lCipher,
      'TTaurusTLS_Cipher.GetCipherByName should return '+
      'empty Cipher method implementation for this Cipher name.')
  finally
    if Assigned(lCipher) then
      EVP_CIPHER_free(lCipher);
  end;

end;

procedure TCipherFixture.GetCipherByNameUnicodeNegative(const ACipherName: string);
var
  lCipher: PEVP_CIPHER;

begin
{
  lCipher:=TTaurusTLS_Cipher.GetCipherByName(ACipherName);
  try
    Assert.IsNull(lCipher,
      'TTaurusTLS_Cipher.GetCipherByName should return '+
      'empty Cipher method implementation for this Cipher name.')
  finally
    if Assigned(lCipher) then
      EVP_CIPHER_free(lCipher);
  end;
}
end;

procedure TCipherFixture.NewKey(const ACipherName: string);
begin
  CheckCipherKeyLen(ACipherName, Length(Cipher[ACipherName].NewKey));
end;

procedure TCipherFixture.NewIV(const ACipherName: string);
begin
  CheckCipherIVLen(ACipherName, Length(Cipher[ACipherName].NewIV));
end;

procedure TCipherFixture.KeyLen(const ACipherName: string);
begin
  CheckCipherKeyLen(ACipherName, Cipher[ACipherName].KeyLen);
end;

procedure TCipherFixture.IVLen(const ACipherName: string);
begin
  CheckCipherIVLen(ACipherName, Cipher[ACipherName].IVLen);
end;

procedure TCipherFixture.BlockSize(const ACipherName: string);
begin
  CheckCipherBlockSize(ACipherName, Cipher[ACipherName].BlockSize);
end;

{ TAESEncryptDecryptFixture }

procedure TSimpleAESEncryptorFixture.Setup;
var
  lKeySize: TTaurusTLS_AESKeySize;
  lEncoderMode: TTaurusTLS_EncodeMode;

begin
  for lKeySize:=Low(TTaurusTLS_AESKeySize) to High(TTaurusTLS_AESKeySize) do
    FKeySizeNames[lKeySize]:=TTaurusTLS_SimpleAESFactory.KeySizeName[lKeySize];
  for lEncoderMode:=Low(TTaurusTLS_EncodeMode) to High(TTaurusTLS_EncodeMode) do
    FEncoderModeNames[lEncoderMode]:=
      TTaurusTLS_SimpleAESFactory.EncodeModeName[lEncoderMode];
end;

procedure TSimpleAESEncryptorFixture.Teardown;
var
  lKeySize: TTaurusTLS_AESKeySize;
  lEncoderMode: TTaurusTLS_EncodeMode;

begin
  for lKeySize:=Low(TTaurusTLS_AESKeySize) to High(TTaurusTLS_AESKeySize) do
    FKeySizeNames[lKeySize]:='';
  for lEncoderMode:=Low(TTaurusTLS_EncodeMode) to High(TTaurusTLS_EncodeMode) do
    FEncoderModeNames[lEncoderMode]:='';
end;

function TSimpleAESEncryptorFixture.CompareBytes(const A, B: TBytes): boolean;
var
  lLenA, lLenb, lMinLen: NativeUInt;

begin
  lLenA:=Length(A);
  lLenB:=Length(B);
  if lLenA < lLenB then
    lMinLen:=lLenA
  else
    lMinLen:=lLenB;
  Result:=CompareMem(@A[0], @B[0], lMinLen);
end;

procedure TSimpleAESEncryptorFixture.EncryptDecrypt(
  AEncryptor: TTaurusTLS_SimpleAESEncryptor; ADataSize: NativeUInt);
var
  lPlain, lEnc, lDec: TBytes;

begin
  Assert.IsNotNull(AEncryptor, 'AEncryptor must not be ''nil''.');
  Assert.AreNotEqual<TIdC_UINT>(0, ADataSize, 'ADataSize is Zero.');
  lPlain:=TTaurusTLS_Random.PublicRandom.Random(ADataSize);

  AEncryptor.Encrypt(lPlain, lEnc);
  Assert.AreNotEqual<NativeUInt>(0, Length(lEnc), 'Encrypted size is Zero.');

  // A few bytes of encrypted data can match the plain data by chance
  if ADataSize >= SizeOf(Integer) then
    Assert.IsFalse(CompareBytes(lPlain, lEnc),
      'Content of Plan and Encrypted data is partially or fully equal.');

  AEncryptor.Decrypt(lEnc, lDec);
  Assert.AreNotEqual<NativeUInt>(0, Length(lEnc),  'Decrypted size is Zero.');
  Assert.IsTrue(CompareBytes(lPlain, lDec),
    'Content of Plan and Encrypted data is NOT partially or fully equal.');
  Assert.AreEqual(Length(lPlain), Length(lDec),
    'Length of Plain and Decrypted data are not equal.')
end;

function TSimpleAESEncryptorFixture.GetKeySizeByName(
  AKeySizeName: string): TTaurusTLS_AESKeySize;
var
  lKeySize: TTaurusTLS_AESKeySize;
begin
  for lKeySize:=Low(TTaurusTLS_AESKeySize) to High(TTaurusTLS_AESKeySize) do
    if CompareStr(FKeySizeNames[lKeySize], AKeySizeName) = 0 then
      Exit(lKeySize);
  Result:=Low(TTaurusTLS_AESKeySize); // never used: Assert.Fail always raises
  Assert.Fail(Format('Unknown TTaurusTLS_AESKeySize name ''%s''.',
    [AKeySizeName]));
end;

function TSimpleAESEncryptorFixture.GetEncodingModeByName(
  AEncoderModeName: string): TTaurusTLS_EncodeMode;
var
  lMode: TTaurusTLS_EncodeMode;
begin
  for lMode:=Low(TTaurusTLS_EncodeMode) to High(TTaurusTLS_EncodeMode) do
    if CompareStr(FEncoderModeNames[lMode], AEncoderModeName) = 0 then
      Exit(lMode);
  Result:=Low(TTaurusTLS_EncodeMode); // never used: Assert.Fail always raises
  Assert.Fail(Format('Unknown TTaurusTLS_AESKeySize name ''%s''.',
    [AEncoderModeName]));
end;

procedure TSimpleAESEncryptorFixture.TestEncryptor(AEncoderMode: string;
  ADataSize: NativeUInt);
var
  lEncryptor: TTaurusTLS_SimpleAESEncryptor;
  lKeySize: TTaurusTLS_AESKeySize;

begin
  for lKeySize:=Low(TTaurusTLS_AESKeySize) to High(TTaurusTLS_AESKeySize) do
  begin
    lEncryptor:=nil;
    try
      lEncryptor:=TTaurusTLS_SimpleAESEncryptor.Create(lKeySize,
        EncodingModeByName[AEncoderMode]);
      EncryptDecrypt(lEncryptor, ADataSize);
    finally
      lEncryptor.Free;
    end;
  end;
end;

{ TSimpleAESFactoryFixture }

procedure TSimpleAESFactoryFixture.KeySizeNameAll;
var
  i: TTaurusTLS_AESKeySize;

begin
  for i:=Low(TTaurusTLS_AESKeySize) to High(TTaurusTLS_AESKeySize) do
    Assert.AreEqual(TSimpleAESEnums.KeySizeName[i],
      TTaurusTLS_SimpleAESFactory.KeySizeName[i], 'KeySize Name is invalid.');
end;

procedure TSimpleAESFactoryFixture.EncodeModeNameAll;
var
  i: TTaurusTLS_EncodeMode;

begin
  for i:=Low(TTaurusTLS_EncodeMode) to High(TTaurusTLS_EncodeMode) do
    Assert.AreEqual(TSimpleAESEnums.EncodeModeName[i],
      TTaurusTLS_SimpleAESFactory.EncodeModeName[i], 'EncodeMode Name is invalid.');
end;

procedure TSimpleAESFactoryFixture.NewEncryptor;
var
  lKeySize: TTaurusTLS_AESKeySize;
  lEncodeMode: TTaurusTLS_EncodeMode;
  lEncryptor: TTaurusTLS_CustomEncryptor;

begin
  lKeySize:=TSimpleAESEnums.KeySize[AKeySizeName];
  lEncodeMode:=TSimpleAESEnums.EncodeMode[AEncodeMode];
  lEncryptor:=nil;
  try
    lEncryptor:=TTaurusTLS_SimpleAESFactory.NewEncryptor(lKeySize, lEncodeMode);
    Assert.IsNotNull(lEncryptor, 'NewEncryptor failed to create Encryptor instance');
    Assert.InheritsFrom(lEncryptor.ClassType, TTaurusTLS_SimpleAESEncryptor,
      'Encyptor instance inherits from a unexpected class.');
    Assert.AreEqual(TSimpleAESEnums.KeySizeInt[lKeySize], lEncryptor.KeyLen*8,
      'Invalid Encryptor Cipher KeyLen.');
    Assert.AreEqual<TIdC_INT>(TIdC_INT(lEncodeMode), lEncryptor.Mode,
      'Invalid Encryptor Cipher EncodeMode.');
  finally
    lEncryptor.Free;
  end;
end;

procedure TSimpleAESFactoryFixture.SetDefaultCipher(AKeySizeName,
  AEncodeMode: string);
var
  lKeySize: TTaurusTLS_AESKeySize;
  lEncodeMode: TTaurusTLS_EncodeMode;

begin
  lKeySize:=TSimpleAESEnums.KeySize[AKeySizeName];
  lEncodeMode:=TSimpleAESEnums.EncodeMode[AEncodeMode];
  TTaurusTLS_SimpleAESFactory.SetDefaultCipher(lKeySize, lEncodeMode);
  Assert.AreEqual<TTaurusTLS_AESKeySize>(lKeySize,
    TTaurusTLS_SimpleAESFactory.DefaultKeySize, 'DefaultKeySize was not updated.');
  Assert.AreEqual<TTaurusTLS_EncodeMode>(lEncodeMode,
    TTaurusTLS_SimpleAESFactory.DefaultEncodeMode, 'DefaultKeySize was not updated.');
end;

procedure TSimpleAESFactoryFixture.NewEncyptorDefault(AKeySizeName,
  AEncodeMode: string);
var
  lEncryptor: TTaurusTLS_CustomEncryptor;
  lKeySize: TTaurusTLS_AESKeySize;
  lEncodeMode: TTaurusTLS_EncodeMode;

begin
  lEncryptor:=nil;
  try
    SetDefaultCipher(AKeySizeName, AEncodeMode);
    lEncryptor:=TTaurusTLS_SimpleAESFactory.NewEncryptor;
    lKeySize:=TSimpleAESEnums.KeySize[AKeySizeName];
    lEncodeMode:=TSimpleAESEnums.EncodeMode[AEncodeMode];
    Assert.AreEqual(TSimpleAESEnums.KeySizeInt[lKeySize], lEncryptor.KeyLen*8,
      'Invalid Encryptor Cipher KeyLen.');
    Assert.AreEqual<TIdC_INT>(TIdC_INT(lEncodeMode), lEncryptor.Mode,
      'Invalid Encryptor Cipher EncodeMode.');
  finally
    lEncryptor.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TCipherFixture);
  TDUnitX.RegisterTestFixture(TSimpleAESEncryptorFixture);
  TDUnitX.RegisterTestFixture(TSimpleAESFactoryFixture);

end.
