unit TaurusTLS.UT.Wrappers.Bio;

interface

uses
  System.SysUtils, System.Classes, DUnitX.TestFramework, TaurusTLS.UT.TestClasses,
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
      const AData: AnsiString; AIncludeNull: boolean); overload; static;
    class procedure CheckBioWrite(ABioWrap: TTaurusTLSCustomBIO;
      const AData: TIdBytes); overload; static;
    class procedure CheckBioWrite(ABioWrap: TTaurusTLSCustomBIO;
      const AData: AnsiString); overload; static;
    class procedure CheckBioGetString(ABioWrap: TTaurusTLSCustomBIO;
      const AData: AnsiString); static;
    class procedure CheckBioMemData(ABioWrap: TTaurusTLSCustomBIO;
      AData: Pointer; ADataLen: TIdC_SIZET);
  end;


  [TestFixture]
  [Category('WRAP.Bio,WRAP.MemBio')]
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
  [Category('WRAP.Bio,WRAP.BytesBio')]
  TBytesBioFixture = class(TCustomBioFixture)
  public const
    cDefaultRandomBytesSize = 4069;
    cFlags = [bfReadable, bfResetable];
  protected
    FData: TIdBytes;
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

  [TestFixture]
  [Category('WRAP.Bio,WRAP.RawByteStringBIO')]
  TRawByteStringBioFixture = class(TCustomBioFixture)
  public const
    cFlags = [bfReadable, bfResetable];

  protected
    FData: RawByteString;
    function NewBioWrapper: TTaurusTLSCustomBIO; override;
  public
    [Test]
    procedure Test_BioCreate;
    [TestCase('"Short String"', 'Short String')]
    procedure Test_AsString(AData: AnsiString);
    [TestCase('"Short String"', 'Short String')]
    procedure Test_BioReadRead(AData: AnsiString);
    [TestCase('"Short String"', 'Short String')]
    procedure Test_BioReadResetRead(AData: AnsiString);
    [TestCase('"Short String"', 'Short String')]
    procedure Test_BioWrite(AData: AnsiString);
  end;

  [TestFixture]
  [Category('WRAP.Bio,WRAP.RecordBIO')]
  TRecordBioFixture = class(TCustomBioFixture)
  public type
    TSampleRecord = record
      ID: Integer;
      Value: Double;
      Enabled: Boolean;
    end;
  protected const
    FData: TSampleRecord = (ID: 123; Value: 123E-12; Enabled: False);

  protected
    function NewBioWrapper: TTaurusTLSCustomBIO; override;
  public
    [Test]
    procedure Test_BioCreate;
    [Test]
    procedure Test_ReadRecord;
  end;

  [TestFixture]
  [Category('WRAP.Bio,WRAP.Helper')]
  TBioHelperFixture = class(TCustomBioFixture)
  protected
    function NewBioWrapper: TTaurusTLSCustomBIO; override;
  public
    [Test]
    procedure Test_LoadFromStream;
    [Test]
    procedure Test_WriteToStream;
    [Test]
    procedure Test_FlagChecks;
  end;

  [TestFixture]
  [Category('WRAP.Bio,WRAP.Errors')]
  TBioErrorFixture = class(TCustomBioFixture)
  protected
    function NewBioWrapper: TTaurusTLSCustomBIO; override;
  public
    [Test]
    procedure Test_InvalidConstructor;
    [Test]
    procedure Test_NullHandle;
    [Test]
    procedure Test_CheckMethods;
  end;

implementation

uses
  TaurusTLS_Random;

{ TCustomBioFixture }

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
  const AData: AnsiString; AIncludeNull: boolean);
begin
  var lBytes:=TIdBytes(BytesOf(AData));
  if AIncludeNull then
    SetLength(lBytes, Length(lBytes)+1);

  CheckBioRead(ABioWrap, lBytes);
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
  var lData:=ABioWrap.ReadAsString;
  Assert.AreEqual<AnsiString>(AData, lData, 'AsString returns incorrect value.');
end;

class procedure TCustomBioFixture.CheckBioMemData(ABioWrap: TTaurusTLSCustomBIO;
  AData: Pointer; ADataLen: TIdC_SIZET);
begin
  var lDataPtr: pointer;
  Assert.AreEqual<TIdC_SIZET>(ADataLen, BIO_get_mem_data(ABioWrap.Bio, lDataPtr),
    'Instance return incorrect Data Size.');
  Assert.AreEqual(Pointer(AData), lDataPtr,
    'Instance returns incorrect pointer to the Data.');
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
    CheckBioRead(lBioWrap, cWriteData, False);
  finally
    lBioWrap.Free;
  end;
end;

procedure TMemBioFixture.WriteAndReset;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioWrite(lBioWrap, cWriteData);
    CheckBioRead(lBioWrap, cWriteData, False);
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
  FData:=RandomBytes(cDefaultRandomBytesSize);
  Result:=TTaurusTLSBytesBio.Create(FData);
end;

procedure TBytesBioFixture.Test_BioCreate;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioCreated(lBioWrap);
    CheckFlags(lBioWrap, cFlags);
    CheckBioMemData(lBioWrap, @FData[0], Length(FData));
  finally
    lBioWrap.Free;
  end;
end;

procedure TBytesBioFixture.Test_BioRead(AData: AnsiString);
begin
  var lData:=TIdBytes(BytesOf(AData));
  var lBioWrap:=TTaurusTLSBytesBio.Create(lData);
  try
    CheckBioRead(lBioWrap, AData, False);
  finally
    lBioWrap.Free;
  end;
end;

procedure TBytesBioFixture.Test_BioReadResetRead(AData: AnsiString);
begin
  var lData:=TIdBytes(BytesOf(AData));
  var lBioWrap:=TTaurusTLSBytesBio.Create(lData);
  try
    CheckBioRead(lBioWrap, AData, False);
    lBioWrap.Reset;
    CheckBioRead(lBioWrap, AData, False);
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

{ TRawByteStringBioFixture }

function TRawByteStringBioFixture.NewBioWrapper: TTaurusTLSCustomBIO;
begin
  FData:=cWriteData;
  Result:=TTaurusTLSRawByteStringBIO.Create(FData, False);
end;

procedure TRawByteStringBioFixture.Test_BioCreate;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioCreated(lBioWrap);
    CheckFlags(lBioWrap, cFlags);
    CheckBioMemData(lBioWrap, PAnsiChar(FData), Length(FData));
  finally
    lBioWrap.Free;
  end;
end;

procedure TRawByteStringBioFixture.Test_AsString(AData: AnsiString);
begin
  var lBioWrap:=TTaurusTLSRawByteStringBIO.Create(AData);
  try
    CheckBioGetString(lBioWrap, AData);
  finally
    lBioWrap.Free;
  end;
end;

procedure TRawByteStringBioFixture.Test_BioReadRead(AData: AnsiString);
begin
  var lBioWrap:=TTaurusTLSRawByteStringBIO.Create(AData);
  try
    CheckBioRead(lBioWrap, AData, True);
    lBioWrap.Reset;
    CheckBioRead(lBioWrap, AData, True);
  finally
    lBioWrap.Free;
  end;
end;

procedure TRawByteStringBioFixture.Test_BioReadResetRead(AData: AnsiString);
begin
  var lBioWrap:=TTaurusTLSRawByteStringBIO.Create(AData);
  try
    CheckBioRead(lBioWrap, AData, True);
    lBioWrap.Reset;
    CheckBioRead(lBioWrap, AData, True);
  finally
    lBioWrap.Free;
  end;
end;

procedure TRawByteStringBioFixture.Test_BioWrite(AData: AnsiString);
begin
  var lBioWrap:=NewBioWrapper;
  try
    Assert.WillRaise(
      procedure begin lBioWrap.Write(AData[1], Length(AData)) end,
      ETaurusTLSBioWriteError,
      'This BIO object should not support "Write" operation.'
    );
  finally
    lBioWrap.Free;
  end;
end;

{ TRecordBioFixture }

function TRecordBioFixture.NewBioWrapper: TTaurusTLSCustomBIO;
begin
  Result:=TTaurusTLSRecordBIO<TSampleRecord>.Create(FData);
end;

procedure TRecordBioFixture.Test_BioCreate;
begin
  var lBioWrap:=NewBioWrapper;
  try
    CheckBioCreated(lBioWrap);
    Assert.AreEqual<TIdC_SIZET>(SizeOf(TSampleRecord), lBioWrap.Pending,
      'Instance reports incorrect "Pending" size for record BIO.');
  finally
    lBioWrap.Free;
  end;
end;

procedure TRecordBioFixture.Test_ReadRecord;
var
  lRecIn, lRecOut: TSampleRecord;
begin
  lRecIn.ID := 12345;
  lRecIn.Value := 3.14159;
  lRecIn.Enabled := True;

  var lBioWrap:=TTaurusTLSRecordBIO<TSampleRecord>.Create(lRecIn);
  try
    Assert.AreEqual<TIdC_SIZET>(SizeOf(TSampleRecord), lBioWrap.Pending,
      'Instance reports incorrect "Pending" size.');
    var lReadCount := lBioWrap.Read(lRecOut, SizeOf(TSampleRecord));
    Assert.AreEqual<TIdC_SIZET>(SizeOf(TSampleRecord), lReadCount,
      'Incorrect number of bytes has been read.');
    Assert.AreEqual(lRecIn.ID, lRecOut.ID,
      'Record "ID" field value is incorrect.');
    Assert.AreEqual(lRecIn.Value, lRecOut.Value,
      'Record "Value" field value is incorrect.');
    Assert.AreEqual(lRecIn.Enabled, lRecOut.Enabled,
      'Record "Enabled" field value is incorrect.');
  finally
    lBioWrap.Free;
  end;
end;

{ TBioHelperFixture }

function TBioHelperFixture.NewBioWrapper: TTaurusTLSCustomBIO;
begin
  Result := TTaurusTLSMemBio.Create;
end;

procedure TBioHelperFixture.Test_LoadFromStream;
begin
  var lMemBio := TTaurusTLSMemBio.Create;
  var lStream := TMemoryStream.Create;
  try
    var lData := TCustomBioFixture.RandomBytes(10000); // larger than cChunkSize (8192)
    if Length(lData) > 0 then
      lStream.Write(lData[0], Length(lData));
    lStream.Position := 0;

    var lLoaded := lMemBio.LoadFromStream(lStream, TIdC_SIZET(Length(lData)));
    Assert.AreEqual(TIdC_SIZET(Length(lData)), lLoaded,
      'Incorrect number of bytes has been loaded from the stream.');
    Assert.AreEqual(TIdC_SIZET(Length(lData)), lMemBio.Pending,
      'Instance reports incorrect "Pending" size after stream load.');

    var lReadData := lMemBio.ReadAsBytes;
    Assert.AreEqual(Length(lData), Length(lReadData),
      'Incorrect data length returned.');
    if Length(lData) > 0 then
      Assert.AreEqualMemory(@lData[0], @lReadData[0], Length(lData),
        'Incorrect data has been read.');
  finally
    lStream.Free;
    lMemBio.Free;
  end;
end;

procedure TBioHelperFixture.Test_WriteToStream;
begin
  var lData := TCustomBioFixture.RandomBytes(5000);
  var lMemBio := TTaurusTLSBytesBio.Create(lData);
  var lStream := TMemoryStream.Create;
  try
    var lWritten := lMemBio.WriteToStream(lStream, TIdC_SIZET(Length(lData)));
    Assert.AreEqual(TIdC_SIZET(Length(lData)), lWritten,
      'Incorrect number of bytes has been written to the stream.');
    Assert.AreEqual(Int64(Length(lData)), lStream.Size,
      'Stream total size is incorrect.');

    lStream.Position := 0;
    var lReadData: TIdBytes;
    SetLength(lReadData, Length(lData));
    if Length(lData) > 0 then
    begin
      lStream.Read(lReadData[0], Length(lData));
      Assert.AreEqualMemory(@lData[0], @lReadData[0], Length(lData),
        'Incorrect data has been read.');
    end;
  finally
    lStream.Free;
    lMemBio.Free;
  end;
end;

procedure TBioHelperFixture.Test_FlagChecks;
begin
  var lBio := TTaurusTLSMemBio.Create; // bfReadable, bfWritable, bfResetable, bfConsumable
  try
    Assert.IsTrue(
      lBio.HasAllFlags([TTaurusTLSCustomBIO.TFlag.bfReadable, TTaurusTLSCustomBIO.TFlag.bfWritable]));
    Assert.IsTrue(
      lBio.HasAnyFlags([TTaurusTLSCustomBIO.TFlag.bfReadable, TTaurusTLSCustomBIO.TFlag.bfConsumable]));

    Assert.WillNotRaise(
      procedure begin lBio.CheckCanRead end,
      nil,
      'Method "CheckCanRead" should not raise an error.'
    );
    Assert.WillNotRaise(
      procedure begin lBio.CheckCanWrite end,
      nil,
      'Method "CheckCanWrite" should not raise an error.'
    );
    Assert.WillNotRaise(
      procedure begin lBio.CheckCanReset end,
      nil,
      'Method "CheckCanReset" should not raise an error.'
    );
  finally
    lBio.Free;
  end;
end;

{ TBioErrorFixture }

function TBioErrorFixture.NewBioWrapper: TTaurusTLSCustomBIO;
begin
  Result := TTaurusTLSMemBio.Create;
end;

procedure TBioErrorFixture.Test_InvalidConstructor;
begin
  Assert.WillRaise(
    procedure begin TTaurusTLSCustomBIO.Create end,
    ETaurusTLSBioCreateError,
    'Call to abstract default constructor should raise an exception.'
  );
end;

procedure TBioErrorFixture.Test_NullHandle;
begin
  Assert.WillRaise(
    procedure begin TTaurusTLSCustomBIO.Create(nil, []) end,
    ETaurusTLSBioCreateError,
    'Initialization with "nil" BIO handle should raise an exception.'
  );
end;

procedure TBioErrorFixture.Test_CheckMethods;
begin
  var lData: TIdBytes:=[1,2,3];
  var lBytesBio := TTaurusTLSBytesBio.Create(lData); // bfReadable, bfResetable
  try
    Assert.WillNotRaise(
      procedure begin lBytesBio.CheckCanRead end,
      nil,
      'Read-only BIO instance should support reading.'
    );
    Assert.WillRaise(
      procedure begin lBytesBio.CheckCanWrite end,
      ETaurusTLSBioWriteError,
      'Read-only BIO instance should not support writing.'
    );
    Assert.WillNotRaise(
      procedure begin lBytesBio.CheckCanReset end,
      nil,
      'Bytes BIO instance should support resetting.'
    );
  finally
    lBytesBio.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TMemBioFixture);
  TDUnitX.RegisterTestFixture(TBytesBioFixture);
  TDUnitX.RegisterTestFixture(TRawByteStringBioFixture);
  TDUnitX.RegisterTestFixture(TRecordBioFixture);
  TDUnitX.RegisterTestFixture(TBioHelperFixture);
  TDUnitX.RegisterTestFixture(TBioErrorFixture);

end.
