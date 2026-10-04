unit TaurusTLS.UT.Random;

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework, TaurusTLS_Random, TaurusTLS.UT.TestClasses,
  IdGlobal, IdCTypes, TaurusTLSHeaders_types;


type
  EOSSLRandom = class(Exception);

  TRandomSrc = (rsPrivate, rsPublic);
  TOSSLRandomBytesClass = class of TTaurusTLS_CustomOSSLRandomBytes;

  [TestFixture]
  TOSSLRandomBytesFixture = class(TOsslBaseFixture)
  public
    class function GetRandomBytes(ASource: TRandomSrc; ACtx: POSSL_LIB_CTX;
      AStrength: TIdC_UINT): TTaurusTLS_CustomOSSLRandomBytes; static;
    class function SrcFromClass(AClass: TOSSLRandomBytesClass): TRandomSrc;
      static;

    [Test]
    procedure VerifyCreation;
  end;

  [TestFixture]
  [Category('Random')]
  TOSSLRandomFixture = class(TOsslBaseFixture)
  private
    function GetOSSLRandom(ASource: TRandomSrc): TTaurusTLS_OSSLRandom;
    procedure CheckOsslResult(AResult: TIdC_INT);
    procedure RandomT<T: record>(Source: TRandomSrc; Items: TIdC_SIZET);
  public
    [Test]
    [IgnoreMemoryLeaks]
    procedure NewRandomNegative;
    [AutoNameTestCase('5')]
    procedure NewRandomPositive(Iterations: NativeUInt);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomMemory(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomBytes(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomBoundary(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomByte(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomInt(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomInt64(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomExtended(Source: TRandomSrc; Items, Size: TIdC_SIZET);
  end;

  [TestFixture]
  [Category('Random')]
  TRandomFixture = class(TOsslBaseFixture)
  private
    function GetRandom(ASource: TRandomSrc): TTaurusTLS_Random;
    procedure RandomT<T: record>(Source: TRandomSrc; Items: TIdC_SIZET);
  public
    [Test]
    [IgnoreMemoryLeaks]
    procedure NewRandomNegative;
    [AutoNameTestCase('5')]
    procedure NewRandomPositive(Iterations: NativeUInt);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomMemory(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomBytes(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomBoundary(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomByte(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomInt(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomInt64(Source: TRandomSrc; Items, Size: TIdC_SIZET);
    [AutoNameTestCase('rsPrivate,5,1024')]
    [AutoNameTestCase('rsPublic,5,1024')]
    procedure RandomExtended(Source: TRandomSrc; Items, Size: TIdC_SIZET);
  end;


  TBytesList = TList<TBytes>;

  TTools = class
    class function CompareMem(const A, B; Size: TIdC_SIZET): boolean; static;
    class procedure CompareMemTrue(const A, B; Size: TIdC_SIZET;
      Msg: string = ''); static;
    class procedure CompareMemFalse(const A, B; Size: TIdC_SIZET;
      Msg: string = ''); static;
    class procedure CompareBytesListTrue(const List: TBytesList); static;
    class procedure CompareBytesListFalse(const List: TBytesList); static;

    class procedure CompareTrue<T: record>(const A, B: T;
      Msg: string = ''); static;
    class procedure CompareFalse<T: record>(const A, B: T;
      Msg: string = ''); static;
    class procedure CompareListNotAllEqual<T: record>(const List: TList<T>); static;
    class procedure CompareListTrue<T: record>(const List: TList<T>); static;
    class procedure CompareListFalse<T: record>(const List: TList<T>); static;
  end;

implementation

uses
  TaurusTLSHeaders_rand, TaurusTLSHeaders_err, TaurusTLSExceptionHandlers;

{ TTools }

class function TTools.CompareMem(const A, B; Size: TIdC_SIZET): boolean;
begin
  Result:=System.SysUtils.CompareMem(@A, @B, Size);
end;

class procedure TTools.CompareMemTrue(const A, B; Size: TIdC_SIZET; Msg: string);
begin
  Assert.IsTrue(CompareMem(A, B, Size), Format(Msg, [@A, @B]));
end;

class procedure TTools.CompareMemFalse(const A, B; Size: TIdC_SIZET;
  Msg: string);
begin
  Assert.IsFalse(CompareMem(A, B, Size), Format(Msg, [@A, @B]));
end;

class procedure TTools.CompareBytesListTrue(const List: TBytesList);
begin
  var lCount:=List.Count;
  for var x := 0 to lCount - 1 do
    for var y := x + 1 to lCount - 1 do
    begin
      var lBytesA:=List.Items[x];
      var lBytesB:=List.Items[y];
      CompareMemTrue(lBytesA[0], lBytesB[0], Length(lBytesA),
        Format('List.Items[%d] is equal to List.Items[%d]', [x, y]));
    end;
end;

class procedure TTools.CompareTrue<T>(const A, B: T; Msg: string = '');
begin
  CompareMemTrue(A, B, SizeOf(T), Msg);
end;

class procedure TTools.CompareFalse<T>(const A, B: T; Msg: string = '');
begin
  CompareMemFalse(A, B, SizeOf(T), Msg);
end;

class procedure TTools.CompareListNotAllEqual<T>(const List: TList<T>);
begin
  var lA := List.Items[0];
  for var x := 1 to List.Count - 1 do
  begin
    var lB := List.Items[x];
    if not CompareMem(lA, lB, SizeOf(T)) then
      Exit;
  end;
  Assert.Fail(Format('All %d List.Items are equal.', [List.Count]));
end;

class procedure TTools.CompareListTrue<T>(const List: TList<T>);
begin
  var lCount:=List.Count;
  for var x := 0 to lCount - 1 do
    for var y := x + 1 to lCount - 1 do
    begin
      var lA:=List.Items[x];
      var lB:=List.Items[y];
      CompareTrue<T>(lA, lB,
        Format('List.Items[%d] is equal to List.Items[%d]', [x, y]));
    end;
end;

class procedure TTools.CompareListFalse<T>(const List: TList<T>);
begin
  var lCount:=List.Count;
  for var x := 0 to lCount - 2 do
    for var y := Succ(x) to lCount - 1 do
    begin
      var lA:=List.Items[x];
      var lB:=List.Items[y];
      CompareFalse<T>(lA, lB,
        Format('List.Items[%d] is equal to List.Items[%d]', [x, y]));
    end;
end;

class procedure TTools.CompareBytesListFalse(const List: TBytesList);
begin
  var lCount:=List.Count;
  for var x := 0 to lCount - 2 do
    for var y := Succ(x) to lCount - 1 do
    begin
      var lBytesA:=List.Items[x];
      var lBytesB:=List.Items[y];
      CompareMemFalse(lBytesA[0], lBytesB[0], Length(lBytesA),
        Format('List.Items[%d] is equal to List.Items[%d]', [x, y]));
    end;
end;

type
  TMockRandomBytesProc = reference to procedure
    (ctx : POSSL_LIB_CTX; var buf; num: TIdC_SIZET; strength: TIdC_UINT);

  TMockRandomBytes = class(TTaurusTLS_CustomOSSLRandomBytes)
  private
    FMockProc: TMockRandomBytesProc;
  protected
    function DoRandom(ctx : POSSL_LIB_CTX; var buf; num: TIdC_SIZET;
      strength: TIdC_UINT): TIdC_INT; override;
    property MockProc: TMockRandomBytesProc read FMockProc write FMockProc;
  end;

{ TMockRandomBytes }

function TMockRandomBytes.DoRandom(ctx: POSSL_LIB_CTX; var buf; num: TIdC_SIZET;
  strength: TIdC_UINT): TIdC_INT;
begin
  Assert.IsNotNull(@FMockProc, 'MockProc property must be assigned.');
  FMockProc(ctx, buf, num, strength);
  Result:=1;
end;

{ TOSSLRandomBytesFixture }

class function TOSSLRandomBytesFixture.GetRandomBytes(ASource: TRandomSrc;
  ACtx: POSSL_LIB_CTX; AStrength: TIdC_UINT): TTaurusTLS_CustomOSSLRandomBytes;
begin
  case ASource of
    rsPrivate:
      Result:=TTaurusTLS_OSSLPrivateRandomBytes.Create(ACtx, AStrength);
    rsPublic:
      Result:=TTaurusTLS_OSSLPublicRandomBytes.Create(ACtx, AStrength);
  else
    raise EOSSLRandom.Create('Unknown TRandomSrc value');
  end;
end;

class function TOSSLRandomBytesFixture.SrcFromClass(
  AClass: TOSSLRandomBytesClass): TRandomSrc;
begin
  if AClass = TTaurusTLS_OSSLPrivateRandomBytes then
    Result:=rsPrivate
  else if AClass = TTaurusTLS_OSSLPublicRandomBytes then
    Result:=rsPublic
  else
    raise EOSSLRandom.CreateFmt('Unknown class ''%s''', [AClass.ClassName]);
end;

procedure TOSSLRandomBytesFixture.VerifyCreation;
var
  lCtx: POSSL_LIB_CTX;
  lData: NativeUInt;
  lStrength: TIdC_UINT;

begin
  //use System.Random to initialize local variables;
  Randomize;
  lCtx:=POSSL_LIB_CTX(System.Random(High(integer)));
  lData:=System.Random(High(integer));
  lStrength:=Abs(System.Random(RAND_DEFAULT_STRENGTH));

  var lRandomBytes: TMockRandomBytes:=nil;
  try
    lRandomBytes:=TMockRandomBytes.Create(lCtx, lStrength);
    lRandomBytes.MockProc:=procedure(ctx : POSSL_LIB_CTX; var buf;
      num: TIdC_SIZET; strength: TIdC_UINT)
      begin
        Assert.AreEqual(lCtx, ctx, '''lCtx'' and ''ctx'' are not equal.');
        Assert.AreEqual(@lData, @buf, '''@lData'' and ''@buf'' are not equal.');
        Assert.AreEqual<TIdC_SIZET>(SizeOf(lData), num, '''SizeOf(lData)'' and ''num'' are not equal.');
        Assert.AreEqual(lStrength, strength, '''lStrength'' and ''strength'' are not equal.');
        FillChar(buf, num, $00);
      end;
    Assert.AreEqual<TIdC_INT>(1, lRandomBytes.Random(lData, SizeOf(lData)));
    Assert.AreEqual<NativeUInt>(0, lData, 'lRandomBytes.Radndom did not update ''lData''.')
  finally
    lRandomBytes.Free;
  end;
end;

{ TOSSLRandomFixture }

procedure TOSSLRandomFixture.NewRandomNegative;
begin
  Assert.WillRaise(
    procedure
    begin
      var lRandom: TTaurusTLS_OSSLRandom:=nil;
      try
        lRandom:=TTaurusTLS_OSSLRandom.NewRandom(nil);
      finally
        lRandom.Free;
      end;
    end,
    EAssertionFailed
  );
end;

procedure TOSSLRandomFixture.NewRandomPositive(Iterations: NativeUInt);
var
  lCtx: POSSL_LIB_CTX;
  lData: NativeUInt;
  lStrength: TIdC_UINT;

begin
  lCtx:=POSSL_LIB_CTX(System.Random(High(integer)));
  lData:=System.Random(High(integer));
  lStrength:=Abs(System.Random(RAND_DEFAULT_STRENGTH));

  for var i:= 0 to Iterations-1 do
  begin
    var lRandom: TTaurusTLS_OSSLRandom:=nil;
    var lRandomBytes: TMockRandomBytes:=nil;
    try
      lRandomBytes:=TMockRandomBytes.Create(lCtx, lStrength);
      lRandomBytes.MockProc:=procedure(ctx : POSSL_LIB_CTX; var buf;
        num: TIdC_SIZET; strength: TIdC_UINT)
        begin
          Assert.AreEqual(lCtx, ctx, '''lCtx'' and ''ctx'' are not equal.');
          Assert.AreEqual(@lData, @buf, '''@lData'' and ''@buf'' are not equal.');
          Assert.AreEqual<TIdC_SIZET>(SizeOf(lData), num, '''SizeOf(lData)'' and ''num'' are not equal.');
          Assert.AreEqual(lStrength, strength, '''lStrength'' and ''strength'' are not equal.');
          FillChar(buf, num, $00);
        end;
      lRandom:=TTaurusTLS_OSSLRandom.NewRandom(lRandomBytes);
      lRandom.Random(lData, SizeOf(lData));
      Assert.AreEqual<NativeUInt>(0, lData, 'lRandomBytes.Radndom did not update ''lData''.')
    finally
      if Assigned(lRandom) then
        lRandom.Free
      else
        lRandomBytes.Free;
    end;
  end;
end;

function TOSSLRandomFixture.GetOSSLRandom(
  ASource: TRandomSrc): TTaurusTLS_OSSLRandom;
begin
  case ASource of
    rsPrivate:
      Result:=TTaurusTLS_OSSLRandom.PrivateRandom;
    rsPublic:
      Result:=TTaurusTLS_OSSLRandom.PublicRandom;
  else
    raise EOSSLRandom.Create('Unknown TRandomSrc value');
  end;
end;

procedure TOSSLRandomFixture.RandomMemory(Source: TRandomSrc; Items, Size: TIdC_SIZET);
begin
  Assert.IsTrue(Items > 0, 'Items value must be greater than 0.');
  Assert.IsTrue(Size >= 2, 'Size value must be greater or equal 2.');
  var lList: TBytesList:=nil;
  try
    lList:=TList<TBytes>.Create;
    for var i:=0 to Items-1 do
    begin
      var lBytes: TBytes;
      SetLength(lBytes, Size);
      CheckOsslResult(GetOSSLRandom(Source).Random(PByte(@lBytes[0])^, Size));
      lList.Add(lBytes);
    end;

    TTools.CompareBytesListFalse(lList);
  finally
    FreeAndNil(lList);
  end;
end;

procedure TOSSLRandomFixture.RandomT<T>(Source: TRandomSrc; Items: TIdC_SIZET);
var
  lList: TList<T>;
  var i, x, y: TIdC_SIZET;
begin
  Assert.IsTrue(Items > 2, 'Items value must be greater than 2.');
  lList:=nil;
  try
    lList:=TList<T>.Create;
    for i:=0 to Items-1 do
    begin
      var lVal: T;
      CheckOsslResult(GetOSSLRandom(Source).Random<T>(lVal));
      lList.Add(lVal);
    end;

    if SizeOf(T) < SizeOf(Integer) then
    begin
      // A small type has too few values for the items to be reliably distinct
      TTools.CompareListNotAllEqual<T>(lList);
      Exit;      
    end;

    for x := 0 to Items-2 do
      for y := Succ(x) to Items-1 do
        Assert.AreNotEqual(lList[x], lList[y],
          Format('Elements %d and %d are equal.', [x, y]));
  finally
    lList.Free;
  end;
end;

procedure TOSSLRandomFixture.RandomBytes(Source: TRandomSrc; Items, Size: TIdC_SIZET);
begin
  Assert.IsTrue(Items > 0, 'Items value must be greater than 0.');
  Assert.IsTrue(Size >= 2, 'Size value must be greater or equal 2.');
  var lList: TBytesList:=nil;
  try
    lList:=TList<TBytes>.Create;
    for var i:=0 to Items-1 do
    begin
      var lBytes: TBytes;
      CheckOsslResult(GetOSSLRandom(Source).Random(lBytes, Size));
      lList.Add(lBytes);
    end;

    TTools.CompareBytesListFalse(lList);
  finally
    FreeAndNil(lList);
  end;
end;

procedure TOSSLRandomFixture.CheckOsslResult(AResult: TIdC_INT);
begin
  var lErrStr := '';
  if AResult <> 1 then
    lErrStr := Format('OpenSSL Error: %x', [ERR_get_error]);
  Assert.AreEqual(1, AResult, lErrStr);
end;

procedure TOSSLRandomFixture.RandomBoundary(Source: TRandomSrc;
  Items, Size: TIdC_SIZET);
const
  cExt = 4;

type
  TNonZeroSet = set of 0..cExt;

var
  lBytes: TBytes;
  lLowLeft, lLowRight, lHighLeft, lHighRight: TNonZeroSet;

  procedure CheckZeros(Idx, Count: TIdC_SIZET; var AResult: TNonZeroSet);
  begin
    for var i:=0 to Count-1 do // check if any zeros are in the last 4 bytes
      if (lBytes[Idx+i] <> 0) then
        Include(AResult, i);
  end;

begin
  Assert.IsTrue(Items > 2, 'Items value must be greater than 2.');
  Assert.IsTrue(Size >= cExt*2,
    Format('Size value must be greater or equal %d.', [cExt*2]));
  Assert.IsTrue(Size <= High(TIdC_SIZET)-cExt,
    Format('Size value must be greater or equal %d.', [High(TIdC_SIZET)-cExt]));
  SetLength(lBytes, Size+cExt*2);
  lLowLeft:=[]; lLowRight:=[];
  lHighLeft:=[]; lHighRight:=[];

  for var i := 0 to Items-1 do
  begin
    CheckOsslResult(GetOSSLRandom(Source).Random(PByte(@lBytes[cExt])^, Size));
    CheckZeros(0, cExt, lLowLeft);
    CheckZeros(cExt, cExt, lLowRight);
    CheckZeros(Size, cExt, lHighLeft);
    CheckZeros(Size+cExt, cExt, lHighRight);

  end;
  Assert.IsTrue(lLowLeft = [], 'Random procedure overfill lower boundary.');
  Assert.IsTrue(lLowRight <> [], 'Random procedure underfill lower boundary.');
  Assert.IsTrue(lHighLeft <> [], 'Random procedure underfill upper boundary.');
  Assert.IsTrue(lHighRight = [], 'Random procedure overfill upper boundary.')
end;

procedure TOSSLRandomFixture.RandomByte(Source: TRandomSrc; Items, Size: TIdC_SIZET);
begin
  RandomT<byte>(Source,Items);
end;

procedure TOSSLRandomFixture.RandomInt(Source: TRandomSrc; Items, Size: TIdC_SIZET);
begin
  RandomT<integer>(Source,Items);
end;

procedure TOSSLRandomFixture.RandomInt64(Source: TRandomSrc; Items, Size: TIdC_SIZET);
begin
  RandomT<Int64>(Source,Items);
end;

procedure TOSSLRandomFixture.RandomExtended(Source: TRandomSrc; Items, Size: TIdC_SIZET);
var
  lList: TList<extended>;
  var i, x, y: TIdC_SIZET;
begin
  Assert.IsTrue(Items > 2, 'Items value must be greater than 2.');
  lList:=nil;
  try
    lList:=TList<extended>.Create;
    for i:=0 to Items-1 do
    begin
      var lVal: extended;
      CheckOsslResult(GetOSSLRandom(Source).Random(lVal));
      lList.Add(lVal);
    end;

    for x := 0 to Items-2 do
      for y := Succ(x) to Items-1 do
        Assert.AreNotEqual(lList[x], lList[y],
          Format('Elements %d and %d are equal.', [x, y]));
  finally
    lList.Free;
  end;
end;

{ TRandomFixture }

function TRandomFixture.GetRandom(
  ASource: TRandomSrc): TTaurusTLS_Random;
begin
  case ASource of
    rsPrivate:
      Result:=TTaurusTLS_Random.PrivateRandom;
    rsPublic:
      Result:=TTaurusTLS_Random.PublicRandom;
  else
    raise EOSSLRandom.Create('Unknown TRandomSrc value');
  end;
end;

procedure TRandomFixture.RandomT<T>(Source: TRandomSrc; Items: TIdC_SIZET);
var
  lList: TList<T>;
  var i, x, y: TIdC_SIZET;
begin
  Assert.IsTrue(Items > 2, 'Items value must be greater than 2.');
  lList:=nil;
  try
    lList:=TList<T>.Create;
    for i:=0 to Items-1 do
    begin
      var lVal:=GetRandom(Source).Random<T>;
      lList.Add(lVal);
    end;

    if SizeOf(T) < SizeOf(Integer) then
    begin
      // A small type has too few values for the items to be reliably distinct
      TTools.CompareListNotAllEqual<T>(lList);
      Exit;
    end;

    for x := 0 to Items-2 do
      for y := Succ(x) to Items-1 do
        Assert.AreNotEqual(lList[x], lList[y],
          Format('Elements %d and %d are equal.', [x, y]));
  finally
    lList.Free;
  end;
end;

procedure TRandomFixture.NewRandomNegative;
begin
  Assert.WillRaise(
    procedure
    begin
      var lRandom: TTaurusTLS_Random:=nil;
      try
        lRandom:=TTaurusTLS_Random.NewRandom(nil);
      finally
        lRandom.Free;
      end;
    end,
    EAssertionFailed
  );
end;

procedure TRandomFixture.NewRandomPositive(Iterations: NativeUInt);
var
  lCtx: POSSL_LIB_CTX;
  lData: NativeUInt;
  lStrength: TIdC_UINT;

begin
  lCtx:=POSSL_LIB_CTX(System.Random(High(integer)));
  lData:=System.Random(High(integer));
  lStrength:=Abs(System.Random(RAND_DEFAULT_STRENGTH));

  for var i:= 0 to Iterations-1 do
  begin
    var lRandom: TTaurusTLS_Random:=nil;
    var lRandomBytes: TMockRandomBytes:=nil;
    try
      lRandomBytes:=TMockRandomBytes.Create(lCtx, lStrength);
      lRandomBytes.MockProc:=procedure(ctx : POSSL_LIB_CTX; var buf;
        num: TIdC_SIZET; strength: TIdC_UINT)
        begin
          Assert.AreEqual(lCtx, ctx, '''lCtx'' and ''ctx'' are not equal.');
          Assert.AreEqual(@lData, @buf, '''@lData'' and ''@buf'' are not equal.');
          Assert.AreEqual<TIdC_SIZET>(SizeOf(lData), num, '''SizeOf(lData)'' and ''num'' are not equal.');
          Assert.AreEqual(lStrength, strength, '''lStrength'' and ''strength'' are not equal.');
          FillChar(buf, num, $00);
        end;
      lRandom:=TTaurusTLS_Random.NewRandom(lRandomBytes);
      lRandom.Random(lData, SizeOf(lData));
      Assert.AreEqual<NativeUInt>(0, lData, 'lRandomBytes.Radndom did not update ''lData''.')
    finally
      if Assigned(lRandom) then
        lRandom.Free
      else
        lRandomBytes.Free;
    end;
  end;
end;

procedure TRandomFixture.RandomMemory(Source: TRandomSrc; Items,
  Size: TIdC_SIZET);
begin
  Assert.IsTrue(Items > 0, 'Items value must be greater than 0.');
  Assert.IsTrue(Size >= 2, 'Size value must be greater or equal 2.');
  var lList: TBytesList:=nil;
  try
    lList:=TList<TBytes>.Create;
    for var i:=0 to Items-1 do
    begin
      var lBytes: TBytes;
      SetLength(lBytes, Size);
      GetRandom(Source).Random(PByte(@lBytes[0])^, Size);
      lList.Add(lBytes);
    end;

    TTools.CompareBytesListFalse(lList);
  finally
    FreeAndNil(lList);
  end;
end;

procedure TRandomFixture.RandomBytes(Source: TRandomSrc; Items,
  Size: TIdC_SIZET);
begin
  Assert.IsTrue(Items > 0, 'Items value must be greater than 0.');
  Assert.IsTrue(Size >= 2, 'Size value must be greater or equal 2.');
  var lList: TBytesList:=nil;
  try
    lList:=TList<TBytes>.Create;
    for var i:=0 to Items-1 do
    begin
      var lBytes: TBytes:=GetRandom(Source).Random(Size);
      lList.Add(lBytes);
    end;

    TTools.CompareBytesListFalse(lList);
  finally
    FreeAndNil(lList);
  end;
end;

procedure TRandomFixture.RandomBoundary(Source: TRandomSrc; Items,
  Size: TIdC_SIZET);
const
  cExt = 4;

type
  TNonZeroSet = set of 0..cExt;

var
  lBytes: TBytes;
  lLowLeft, lLowRight, lHighLeft, lHighRight: TNonZeroSet;

  procedure CheckZeros(Idx, Count: TIdC_SIZET; var AResult: TNonZeroSet);
  begin
    for var i:=0 to Count-1 do // check if any zeros are in the last 4 bytes
      if (lBytes[Idx+i] <> 0) then
        Include(AResult, i);
  end;

begin
  Assert.IsTrue(Items > 2, 'Items value must be greater than 2.');
  Assert.IsTrue(Size >= cExt*2,
    Format('Size value must be greater or equal %d.', [cExt*2]));
  Assert.IsTrue(Size <= High(TIdC_SIZET)-cExt,
    Format('Size value must be greater or equal %d.', [High(TIdC_SIZET)-cExt]));
  SetLength(lBytes, Size+cExt*2);
  lLowLeft:=[]; lLowRight:=[];
  lHighLeft:=[]; lHighRight:=[];

  for var i := 0 to Items-1 do
  begin
    GetRandom(Source).Random(PByte(@lBytes[cExt])^, Size);
    CheckZeros(0, cExt, lLowLeft);
    CheckZeros(cExt, cExt, lLowRight);
    CheckZeros(Size, cExt, lHighLeft);
    CheckZeros(Size+cExt, cExt, lHighRight);

  end;
  Assert.IsTrue(lLowLeft = [], 'Random procedure overfill lower boundary.');
  Assert.IsTrue(lLowRight <> [], 'Random procedure underfill lower boundary.');
  Assert.IsTrue(lHighLeft <> [], 'Random procedure underfill upper boundary.');
  Assert.IsTrue(lHighRight = [], 'Random procedure overfill upper boundary.')
end;

procedure TRandomFixture.RandomByte(Source: TRandomSrc; Items,
  Size: TIdC_SIZET);
begin
  RandomT<byte>(Source,Items);
end;

procedure TRandomFixture.RandomInt(Source: TRandomSrc; Items, Size: TIdC_SIZET);
begin
  RandomT<integer>(Source,Items);
end;

procedure TRandomFixture.RandomInt64(Source: TRandomSrc; Items,
  Size: TIdC_SIZET);
begin
  RandomT<Int64>(Source,Items);
end;

procedure TRandomFixture.RandomExtended(Source: TRandomSrc; Items,
  Size: TIdC_SIZET);
var
  lList: TList<extended>;
  var i, x, y: TIdC_SIZET;
begin
  Assert.IsTrue(Items > 2, 'Items value must be greater than 2.');
  lList:=nil;
  try
    lList:=TList<extended>.Create;
    for i:=0 to Items-1 do
    begin
      var lVal: extended:=GetRandom(Source).Random;
      lList.Add(lVal);
    end;

    for x := 0 to Items-2 do
      for y := Succ(x) to Items-1 do
        Assert.AreNotEqual(lList[x], lList[y],
          Format('Elements %d and %d are equal.', [x, y]));
  finally
    lList.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TOSSLRandomBytesFixture);
  TDUnitX.RegisterTestFixture(TOSSLRandomFixture);
  TDUnitX.RegisterTestFixture(TRandomFixture);

end.
