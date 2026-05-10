unit TaurusTLS.UT.Wrappers.Bio;

interface

uses
  System.SysUtils, DUnitX.TestFramework, TaurusTLS.UT.TestClasses,
  IdGlobal, IdCTypes, TaurusTLSHeaders_types, TaurusTLSHeaders_bio, TaurusTLS_BIO;

type
  TCustomBioFixture = class(TOsslBaseFixture)
  public type
    TFlags = TTaurusTLSCustomBIO.TFlags;

  const
    cWriteData: AnsiString = 'This is a sample data string '+
      'with non-printable trailer characters behind the dot.'+
      #$00#$01#$02#$03#$04#$05#$06#$07#$08#$09#$0A#$0B#$0C#$0D#$0E#$0F;

  protected
    function NewBioWrapper: TTaurusTLSCustomBIO; virtual; abstract;
    class function RandomBytes(ASize: TIdC_SIZET): TIdBytes; static;

    class procedure CheckBioCreated(ABioWrap: TTaurusTLSCustomBIO); static;
    class procedure CheckFlags(ABioWrap: TTaurusTLSCustomBIO;
      const AFlags: TFlags); static;
    class procedure CheckBioEmptyRead(ABioWrap: TTaurusTLSCustomBIO); static;
    class procedure CheckBioRead(ABioWrap: TTaurusTLSCustomBIO;
      const AData: TIdBytes); overload; static;
    class procedure CheckBioRead(ABioWrap: TTaurusTLSCustomBIO;
      const AData: AnsiString); overload; static;
    class procedure CheckBioWrite(ABioWrap: TTaurusTLSCustomBIO;
      const AData: TIdBytes); overload; static;
    class procedure CheckBioWrite(ABioWrap: TTaurusTLSCustomBIO;
      const AData: AnsiString); overload; static;
    class procedure CheckSetString(ABioWrap: TTaurusTLSCustomBIO;
      const AData: AnsiString); static;
    class procedure CheckBioGetString(ABioWrap: TTaurusTLSCustomBIO;
      const AData: AnsiString); static;
  end;


  [TestFixture]
  [Category('WRAP.Bio, WRAP.MemBio')]
  TMemBioFixture = class(TCustomBioFixture)
  public const
    cFlags = [bfReadable, bfWritable, bfResetable, bfConsumable];

  protected
    function NewBioWrapper: TTaurusTLSCustomBIO; override;
  public
    [Test]
    procedure Test_BioCreate;
    [Test]
    procedure Test_BioEmptyRead;
    [Test]
    procedure WriteThenRead;
    [Test]
    procedure WriteAndReset;
    [Test]
    procedure GetAsString;
  end;

  [TestFixture]
  [Category('WRAP.Bio, WRAP.BytesBio')]
  TBytesBioFixture = class(TCustomBioFixture)
  public const
    cDefaultRandomBytesSize = 4069;
    cFlags = [bfReadable, bfResetable];

  protected
    function NewBioWrapper: TTaurusTLSCustomBIO; override;
  public
    [Test]
    procedure Test_BioCreate;
    [TestCase('"Short String"', 'Short String')]
    procedure Test_BioRead(AData: AnsiString);
    [TestCase('"Short String"', 'Short String')]
    procedure Test_BioReadResetRead(AData: AnsiString);
    [TestCase('"Short String"', 'Short String')]
    procedure Test_BioWrite(AData: AnsiString);
  end;

implementation

uses
  TaurusTLS_Random;

{ TCustomBioFixture }

class procedure TCustomBioFixture.CheckBioCreated(ABioWrap: TTaurusTLSCustomBIO);
begin
  Assert.IsNotNull(ABioWrap, '"TTaurusTLSMemBio.Create" returns "nil".');
  Assert.IsNotNull(ABioWrap.BIO, '"BIO" property returns NULL.');
end;

class procedure TCustomBioFixture.CheckFlags(ABioWrap: TTaurusTLSCustomBIO;
  const AFlags: TFlags);
begin
  Assert.IsTrue(ABioWrap.Flags = AFlags,
    'Instance created with incorrect flags set.');
end;

class procedure TCustomBioFixture.CheckBioEmptyRead(ABioWrap: TTaurusTLSCustomBIO);
begin
  CheckBioRead(ABioWrap, []);
end;

class procedure TCustomBioFixture.CheckBioRead(ABioWrap: TTaurusTLSCustomBIO;
  const AData: AnsiString);
begin
  CheckBioRead(ABioWrap, TIdBytes(BytesOf(AData)));
end;

class procedure TCustomBioFixture.CheckBioRead(ABioWrap: TTaurusTLSCustomBIO;
  const AData: TIdBytes);
begin
  var lLen:=Length(AData);
  var lHasRead: TIdC_SIZET:=0;
  var lReadBuf: TIdBytes;

  if lLen = 0 then
    Assert.IsTrue(ABioWrap.Eof, 'Property "Eof" should be "True".')
  else
    Assert.IsFalse(ABioWrap.Eof, 'Property "Eof" should be "False".');

  SetLength(lReadBuf, lLen+8);
  Assert.AreEqual<TIdC_SIZET>(lLen, ABioWrap.Pending,
    'Instance reports Incorect Pending size after read.');
  Assert.IsTrue(ABioWrap.TryRead(lReadBuf[0], lLen, lHasRead),
    Format('Instance should able to read %d bytes.', [lLen]));
  Assert.AreEqual<TIdC_SIZET>(lLen, lHasRead,
    'Incorrect number of bytes has been read.');

  for var i:=Low(AData) to High(AData) do
    Assert.AreEqual(AData[i], lReadBuf[i], 'Incorrect data has been read.');

  for var i:=High(AData)+1 to High(lReadBuf) do
    Assert.AreEqual<byte>(0, lReadBuf[i],
      'Read buffer overlow. Buffer outside of read size has been corrupted.');
end;

class procedure TCustomBioFixture.CheckBioWrite(ABioWrap: TTaurusTLSCustomBIO;
  const AData: AnsiString);
begin
  CheckBioWrite(ABioWrap, TIdBytes(BytesOf(AData)));
end;

class procedure TCustomBioFixture.CheckBioWrite(ABioWrap: TTaurusTLSCustomBIO;
  const AData: TIdBytes);
begin
  var lLen:=Length(AData);
  var lHasWritten: TIdC_SIZET:=0;

  var lPData: Pointer;
  var lDummyData: UInt64:=$FFFFFFFFFFFFFFFF;
  if lLen = 0 then lPData:=@lDummyData else lPData:=@AData[0];

  Assert.IsTrue(ABioWrap.TryWrite(lPData^, lLen, lHasWritten),
    Format('Instance should be able to write %d bytes.', [lLen]));
  Assert.AreEqual<TIdC_SIZET>(lLen, lHasWritten,
    'Incorrect number of bytes has been written.');

  if lLen = 0 then
    Assert.IsTrue(ABioWrap.Eof, 'Property "Eof" should be "True".')
  else
    Assert.IsFalse(ABioWrap.Eof, 'Property "Eof" should be "False".');
  Assert.AreEqual<TIdC_SIZET>(lLen, ABioWrap.Pending,
    'Instance reports Incorect Pending size after write.');
end;

class function TCustomBioFixture.RandomBytes(ASize: TIdC_SIZET): TIdBytes;
begin
  var lRandom: TTaurusTLS_Random:=nil;
  try
    lRandom:=TTaurusTLS_Random.NewRandom(
      TTaurusTLS_OSSLPublicRandomBytes.Create(nil));
    Result:=TIdBytes(lRandom.Random(ASize));
  finally
    lRandom.Free;
  end;
end;

class procedure TCustomBioFixture.CheckBioGetString(ABioWrap: TTaurusTLSCustomBIO;
  const AData: AnsiString);
begin
  var lLen: TIdC_SIZET:=Length(AData);

  if lLen = 0 then
    Assert.IsTrue(ABioWrap.Eof, 'Property "Eof" should be "True".')
  else
    Assert.IsFalse(ABioWrap.Eof, 'Property "Eof" should be "False".');

  var lPending:=ABioWrap.Pending;
  // Pending may or may not include trailing #0 character
  Assert.IsTrue((lLen = lPending) or (lLen+1 = lPending),
    'Instance reports Incorect Pending size after write.');
  var lData:=ABioWrap.AsString;
  Assert.AreEqual<AnsiString>(AData, lData, 'AsString returns incorrect value.');
end;

class procedure TCustomBioFixture.CheckSetString(ABioWrap: TTaurusTLSCustomBIO;
  const AData: AnsiString);
begin
  var lLen: TIdC_SIZET:=Length(AData);
  if lLen > 0 then
    Inc(lLen); // include null-termination

  Assert.WillNotRaise(
    procedure begin ABioWrap.AsString:=AData; end,
    nil,
    'Unable assign the string value'
  );
  if lLen = 0 then
    Assert.IsTrue(ABioWrap.Eof, 'Property "Eof" should be "True".')
  else
    Assert.IsFalse(ABioWrap.Eof, 'Property "Eof" should be "False".');
  Assert.AreEqual<TIdC_SIZET>(lLen, ABioWrap.Pending,
    'Instance reports Incorect Pending size after write.');
end;

{ TMemBioFixture }

function TMemBioFixture.NewBioWrapper: TTaurusTLSCustomBIO;
begin
  Result:=TTaurusTLSMemBio.Create;
end;

procedure TMemBioFixture.Test_BioCreate;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioCreated(lBioWrap);
    CheckFlags(lBioWrap, cFlags);
  finally
    lBioWrap.Free;
  end;
end;

procedure TMemBioFixture.Test_BioEmptyRead;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioEmptyRead(lBioWrap);
  finally
    lBioWrap.Free;
  end;
end;

procedure TMemBioFixture.WriteThenRead;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioWrite(lBioWrap, cWriteData);
    CheckBioRead(lBioWrap, cWriteData);
  finally
    lBioWrap.Free;
  end;
end;

procedure TMemBioFixture.WriteAndReset;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioWrite(lBioWrap, cWriteData);
    CheckBioRead(lBioWrap, cWriteData);
    Assert.WillNotRaise(
      procedure begin lBioWrap.Reset; end,
      ETaurusTLSBioResetError,
      'Instance failed to Reset.');
    CheckBioEmptyRead(lBioWrap);
  finally
    lBioWrap.Free;
  end;
end;

procedure TMemBioFixture.GetAsString;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioWrite(lBioWrap, cWriteData);
    CheckBioGetString(lBioWrap, cWriteData);
  finally
    lBioWrap.Free;
  end;
end;

{ TBytesBioFixture }

function TBytesBioFixture.NewBioWrapper: TTaurusTLSCustomBIO;
begin
  Result:=TTaurusTLSBytesBio.Create(RandomBytes(cDefaultRandomBytesSize));
end;

procedure TBytesBioFixture.Test_BioCreate;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioCreated(lBioWrap);
    CheckFlags(lBioWrap, cFlags);
  finally
    lBioWrap.Free;
  end;
end;

procedure TBytesBioFixture.Test_BioRead(AData: AnsiString);
begin
  var lData:=TIdBytes(BytesOf(AData));
  var lBioWrap:=TTaurusTLSBytesBio.Create(lData);
  try
    CheckBioRead(lBioWrap, AData);
  finally
    lBioWrap.Free;
  end;
end;

procedure TBytesBioFixture.Test_BioReadResetRead(AData: AnsiString);
begin
  var lData:=TIdBytes(BytesOf(AData));
  var lBioWrap:=TTaurusTLSBytesBio.Create(lData);
  try
    CheckBioRead(lBioWrap, AData);
    lBioWrap.Reset;
    CheckBioRead(lBioWrap, AData);
  finally
    lBioWrap.Free;
  end;
end;

procedure TBytesBioFixture.Test_BioWrite(AData: AnsiString);
begin
  var lData:=TIdBytes(BytesOf(AData));
  var lBioWrap:=TTaurusTLSBytesBio.Create([0]); // non epmpty array is required
  try
    Assert.WillRaise(
      procedure begin lBioWrap.Write(AData, Length(lData)) end,
      ETaurusTLSBioWriteError,
      'This BIO object should not support Write operation.'
    );
  finally
    lBioWrap.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TMemBioFixture);
  TDUnitX.RegisterTestFixture(TBytesBioFixture);

end.
