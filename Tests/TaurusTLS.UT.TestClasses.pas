{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 - 2025 TaurusTLS Developers, All Rights Reserved       * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I TaurusTLSUTCompilerDefines.inc}
/// <summary>
/// Base Test Fixture class for unit-tests
/// </summary>
unit TaurusTLS.UT.TestClasses;
{$i ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  System.Classes, System.SysUtils, System.IOUtils,
  DUnitX.TestFramework, TaurusTLS.UT.Utils;

type
  ///  <summary>
  ///  Base exception class can be used to make Assert Tests Fixtures
  ///  </summary
  EOsslBaseFixture = class(Exception);

  ///  <summary>
  ///  Base Test Fixture class for unit-tests used OpenSSL library.
  ///  This fixture automatically load OpenSSL library if its not loaded yet.
  ///  </summary
  [TestFixture]
  TOsslBaseFixture = class
  public type
    TTestFlag = (tfOssLibLoaded, tfOssLibFailed, tfGlobalFail, tfBoundary=SizeOf(Cardinal)*8-1);
    TTestFlags = set of TTestFlag;
  private class var
    FFlags: TTestFlags;
  private
    class function GetGlobalFail: boolean; static;
    class function GetOssLibFailed: boolean; static;
    class procedure SetOssLibLoaded(const Value: boolean); static;
    class procedure SetFlag(const AFlag: TTestFlag; AEnable: boolean); static;
  protected
    class function GetOssLibLoaded: boolean; static;
    class procedure SetGlobalFail(const Value: boolean); static;
    class procedure SetOssLibFailed(const Value: boolean); static;
  public
    [SetupFixture]
    ///  <summary>
    ///  The <c>SetupFixture</c> method loads the OpenSSL library
    ///  and set internal library refrerence counter to <c>1</c>,
    ///  or increments internal library refrerence counter otherwise.
    ///  </summary>
    procedure SetupFixture;
    [TearDownFixture]
    ///  <summary>
    ///  The <c>TearDownFixture</c> method decrements internal library refrerence counter
    ///  and unloads the OpenSSL library when it reaches Zero.
    ///  </summary>
    procedure TearDownFixture;

    ///  <summary>
    ///  The <c>CheckLoaded</c> method checks if the OpenSSL library
    ///  has loaded and raise <see ref="EOsslBaseFixture" /> if not.
    ///  </summary>
    class procedure CheckLoaded;
    ///  <summary>
    ///  The <c>CheckLoaded</c> method checks if any faulre registered which
    ///  blocks any Test Fixture execution and raise <see ref="EOsslBaseFixture" />
    ///  if any.
    ///  </summary>
    ///  <remark>
    ///  This method can be overritten by inherited class
    ///  </remark>
    class procedure CheckFailed; virtual;
    ///  <summary>
    ///  The <c>CheckLoaded</c> method checks if any faulre registered
    ///  and OpenSSL Library loased, and raise <see ref="EOsslBaseFixture" /> if any.
    ///  </summary>
    ///  <remark>
    ///  This method can be overritten by inherited class
    ///  </remark>
    class procedure CheckAllFailures; virtual;

    ///  <summary>
    ///  Displays if OpenSSL library loaded.
    ///  </summary>
    class property OssLibLoaded: boolean read GetOssLibLoaded;
    ///  <summary>
    ///  Displays if OpenSSL library is inconsitance state.
    ///  </summary>
    class property OssLibFailed: boolean read GetOssLibFailed ;
    ///  <summary>
    ///  Displays if Test Fixtures has failure which blocks
    ///  other Test Fixtures execution.
    ///  </summary>
    class property GlobalFail: boolean read GetGlobalFail;
  end;

resourcestring
  cOsslNotLoaded = 'Openssl library is not loaded. Skipping remaining tests(s)';
  cOsslLoadFailed = 'Openssl library load failed. Skipping remaining tests(s)';
  cOsslGlobalFail = 'Openssl global failure. Skipping remaining tests(s)';

type
  THexStrTestTool = record
    ///  <summary>
    ///  Checks validity of AHexStr before conversion to bytes array.
    ///  </summary>
    class procedure CheckHex(AHexStr: string);
      overload; static;
    ///  <summary>
    ///  Converts HexEncoded Unicode characters into bytes array
    ///  of Ansi characters in ACodePage
    ///  </summary>
    class function FromHex(AHexStr: string; ACodePage: cardinal): TBytes;
      overload; static;
    ///  <summary>
    ///  Converts HexEncoded Unicode characters into AnsiString
    ///  </summary>
    class procedure FromHex(AHexStr: string; ACodePage: cardinal;
      out AStr: AnsiString); overload; static;
    ///  <summary>
    ///  Converts HexEncoded Unicode characters into RawByteString
    ///  </summary>
    class procedure FromHex(AHexStr: string; out AStr: RawByteString);
      overload; static;
    ///  <summary>
    ///  Converts HexEncoded Unicode characters into UTF8String
    ///  </summary>
    class procedure FromHex(AHexStr: string; out AStr: UTF8String);
      overload; static;
    ///  <summary>
    ///  Converts HexEncoded Unicode characters into UnicodeString
    ///  </summary>
    class procedure FromHex(AHexStr: string; out AStr: UnicodeString);
      overload; static;
    ///  <summary>
    ///  Converts HexEncoded bytes into bytes array as is
    ///  </summary>
    class procedure FromHex(AHexStr: string; out ABytes: TBytes);
      overload; static;
  end;

  TWipeTestTool = record
    ///  <summary>
    ///  Checks if the memory region is filled with zeros
    ///  </summary>
    class procedure CheckWiped(AData: pointer; ASize: NativeUInt); overload; static;
    ///  <summary>
    ///  Checks if the bytes array is filled with zeros
    ///  </summary>
    class procedure CheckWiped(AData: TBytes); overload; static;
    ///  <summary>
    ///  Checks if the part of bytes array is filled with zeros
    ///  </summary>
    class procedure CheckWiped(AData: TBytes; AOffset, ASize: NativeUInt); overload; static;
    ///  <summary>
    ///  Checks if the AnsiString is filled with zeros
    ///  </summary>
    class procedure CheckWiped(AData: AnsiString); overload; static;
    ///  <summary>
    /// Checks if the UnicodeString is filled with zeros
    ///  </summary>
    class procedure CheckWiped(AData: UnicodeString); overload; static;
  end;

  TBytesValidator = record
  public type
    TTrailingNulls = 0..2;
  public
    ///  <summary>
    ///  Compares bytes array and UnicodeString for equality
    ///  including trailing string nulls if AWithTrailingNull=True
    ///  </summary>
    class procedure AreEqual(const ABytes: TBytes; const AStr: UnicodeString;
      AWithTrailingNull: boolean); overload; static;
    ///  <summary>
    ///  Compares bytes array and RawByteString for equality
    ///  including trailing string null if AWithTrailingNull=True
    ///  </summary>
    class procedure AreEqual(const ABytes: TBytes; const AStr: RawByteString;
      AWithTrailingNull: boolean); overload; static;
    ///  <summary>
    ///  Compares bytes subarryas for equality
    ///  </summary>
    class procedure AreEqual(const ABytes, ASrcBytes: TBytes;
      AOffset, ASrcOffset, ACount: Int64); overload; static;
    ///  <summary>
    ///  Compares ABytes bytes array with the ASrcBytes bytes subarray
    ///  starting AOffset for equality
    ///  </summary>
    class procedure AreEqual(const ABytes, ASrcBytes: TBytes;
      AOffset: Int64; ATrailingNulls: TTrailingNulls); overload; static;
    ///  <summary>
    ///  Calculates correct Offset and number of bytes to read based on
    ///  ADataSize bytes array size
    ///  </summary>
    class procedure CalcOffsetAndSize(ADataSize: Int64;
      var AOffset, ACount: Int64); overload; static;
    ///  <summary>
    ///  Calculates correct Offset and number of bytes to read based on
    ///  ABytes bytes array size
    ///  </summary>
    class procedure CalcOffsetAndSize(ABytes: TBytes;
      var AOffset, ACount: Int64); overload; static;
    ///  <summary>
    ///  Calculates correct Offset and number of bytes to read based on
    ///  Stream size
    ///  </summary>
    class procedure CalcOffsetAndSize(AStream: TStream;
      var AOffset, ACount: Int64); overload; static;
  end;

implementation

uses
  System.SyncObjs;

{ TOsslTestBase }

class procedure TOsslBaseFixture.CheckAllFailures;
begin
  CheckLoaded;
  CheckFailed;
end;

class procedure TOsslBaseFixture.CheckFailed;
var
  lReason: string;

begin
  lReason:='';
  if GlobalFail then
    lReason:=cOsslGlobalFail
  else if OssLibFailed then
    lReason:=cOsslLoadFailed;
  if not lReason.IsEmpty then
    raise EOsslBaseFixture.Create(lReason);
end;

class procedure TOsslBaseFixture.CheckLoaded;
begin
  if not OssLibLoaded then
    raise EOsslBaseFixture.CreateRes(@cOsslNotLoaded);
end;

class function TOsslBaseFixture.GetGlobalFail: boolean;
begin
  Result:=tfGlobalFail in FFlags;
end;

class function TOsslBaseFixture.GetOssLibFailed: boolean;
begin
  Result:=tfOssLibFailed in FFlags;
end;

class function TOsslBaseFixture.GetOssLibLoaded: boolean;
begin
  Result:=tfOssLibLoaded in FFlags;
end;

class procedure TOsslBaseFixture.SetOssLibLoaded(const Value: boolean);
begin
  SetFlag(tfOssLibLoaded, Value);
end;

class procedure TOsslBaseFixture.SetGlobalFail(const Value: boolean);
begin
  SetFlag(tfGlobalFail, Value);
end;

class procedure TOsslBaseFixture.SetOssLibFailed(const Value: boolean);
begin
  SetFlag(tfOssLibFailed, Value);
  SetGlobalFail(True);
end;

class procedure TOsslBaseFixture.SetFlag(const AFlag: TTestFlag; AEnable: boolean);
var
  lSpinW: TSpinWait;
  lFlags: TTestFlags;
  lNewFlags: TTestFlags;

begin
  lSpinW.Reset;
  repeat
    lFlags:=FFlags;
    lNewFlags:=lFlags;
    if AEnable then
      lNewFlags:=lFlags+[AFlag]
    else
      lNewFlags:=lFlags-[AFlag];
    // Hack for SET Varibale atomic update
    cardinal((@lFlags)^):=TInterlocked.CompareExchange(cardinal((@FFlags)^),
      cardinal((@lNewFlags)^), cardinal((@lFlags)^));
    if ((AFlag in FFlags) xor (not AEnable)) then
      break;
    lSpinW.SpinCycle;
  until False;
end;

procedure TOsslBaseFixture.SetupFixture;
{$IFDEF MSWINDOWS}
  {$IFNDEF MEMLEAK_DETAILS}
var
  lDebugActive: boolean;
  {$ENDIF MEMLEAK_DETAILS}
{$ENDIF}

begin
{$IFDEF MSWINDOWS}
  {$IFDEF MEMLEAK_DETAILS}
  TFastMMDebugLog.DebugModeActive:=True;
  {$ELSE}
  lDebugActive:=TFastMMDebugLog.DebugModeActive; // To enforce linker add the TFastMMDebugLog class
  {$ENDIF MEMLEAK_DETAILS}
{$ENDIF}
  try
    SetOssLibLoaded(TOsslLoader.Load);
    CheckAllFailures;
  except
    SetGlobalFail(True);
    raise
  end;
end;

procedure TOsslBaseFixture.TearDownFixture;
begin
  if OssLibLoaded then
  try
    TOsslLoader.Unload;
  except
    SetGlobalFail(True);
    raise;
  end;
end;

{ THexStrTestTool }

class procedure THexStrTestTool.CheckHex(AHexStr: string);
var
  lLen, i: NativeUInt;

begin
  lLen:=Length(AHexStr);
  Assert.IsTrue(lLen mod (SizeOf(WideChar)) = 0,
    Format('Length(AHexStr) must be divisible by %d.', [SizeOf(WideChar)]));
  for i:=1 to lLen do
    Assert.IsTrue(CharInSet(AHexStr[i], ['0'..'9','a'..'f','A'..'F']),
      'AHexStr[%d] is not valid hexdemical symbol.')
end;

class function THexStrTestTool.FromHex(AHexStr: string; ACodePage: cardinal): TBytes;
var
  lEnc, lUEnc: TEncoding;
  lBytes: TBytes;
  lBytesSize: NativeUInt;

begin
  lBytesSize:=Length(AHexStr);
  if lBytesSize = 0 then
    Exit;

  lBytesSize:=lBytesSize div 2;
  lUEnc:=TEncoding.Unicode;
  CheckHex(AHexStr);

  if ACodePage = $FFFF then
    lEnc:=nil
  else
    lEnc:=TEncoding.GetEncoding(ACodePage);
  try
    if Assigned(lEnc) then
    begin
      SetLength(lBytes, lBytesSize);
      HexToBin(PChar(AHexStr), 0, lBytes, 0, lBytesSize);
      Result:=TEncoding.Convert(lUEnc, lEnc, lBytes)
    end
    else
      Result:=BytesOf(AHexStr);
  finally
    lEnc.Free;
  end;
end;

class procedure THexStrTestTool.FromHex(AHexStr: string; ACodePage: cardinal;
  out AStr: AnsiString);
var
  lBytes: TBytes;
  lLen: NativeUInt;

begin
  lBytes:=FromHex(AHexStr, ACodePage);
  lLen:=Length(lBytes);
  if lLen > 0 then
  begin
    SetLength(AStr, lLen);
    SetCodePage(RawByteString(AStr), ACodePage, False);
    Move(PByte(lBytes)^, PAnsiChar(AStr)^, lLen);
  end
  else
    AStr:='';
end;

class procedure THexStrTestTool.FromHex(AHexStr: string;
  out AStr: RawByteString);
var
  lLen: NativeUInt;

begin
  CheckHex(AHexStr);
  lLen:=Length(AHexStr) div 2;
  if lLen = 0 then
    Exit;
  SetLength(AStr, lLen);
  SetLength(AStr, HexToBin(PChar(AHexStr), PAnsiChar(AStr), lLen));
end;

class procedure THexStrTestTool.FromHex(AHexStr: string;
  out AStr: UTF8String);
begin
  FromHex(AHexStr, CP_UTF8, AnsiString(AStr));
end;

class procedure THexStrTestTool.FromHex(AHexStr: string;
  out AStr: UnicodeString);
var
  lBytes: TBytes;
  lLen: NativeUInt;

begin
  lBytes:=FromHex(AHexStr, 1200 {//UTF16-LE});
  lLen:=Length(lBytes);
  if lLen > 0 then
  begin
    SetLength(AStr, lLen div SizeOf(WideChar));
    Move(PByte(lBytes)^, PChar(AStr)^, lLen);
  end
  else
    AStr:='';
end;

class procedure THexStrTestTool.FromHex(AHexStr: string; out ABytes: TBytes);
begin
  ABytes:=BytesOf(AHexStr);
end;

{ TWipeTestTool }

class procedure TWipeTestTool.CheckWiped(AData: pointer; ASize: NativeUInt);
var
  lLongPtr: PNativeUInt;
  lBytePtr: PByte;

begin
  if (ASize = 0) or (not Assigned(AData)) then
    Exit;
  lLongPtr:=AData;
{$POINTERMATH ON}
  // checks memory region for zeros with 32bit or 64bit steps (based on CPU arch)
  // until quotient of "ASize div SizeOf(NativeUInt)" reached
  while (lLongPtr+1) <= (PByte(AData)+ASize) do
    if lLongPtr^ <> 0 then
      Assert.Fail('Data is not wiped out.')
    else
      Inc(lLongPtr);
  lBytePtr:=PByte(lLongPtr);
  // checks remianing memory region with 8bit steps.
  while lBytePtr < (PByte(AData)+ASize) do
    if lBytePtr^ <> 0 then
      Assert.Fail('Data is not wiped out.')
    else
      Inc(lBytePtr);
{$POINTERMATH OFF}
end;

class procedure TWipeTestTool.CheckWiped(AData: TBytes);
var
  lLen: NativeUInt;

begin
  lLen:=Length(AData);
  if lLen > 0 then
    CheckWiped(AData, Low(AData), High(AData));
end;

class procedure TWipeTestTool.CheckWiped(AData: TBytes; AOffset,
  ASize: NativeUInt);
begin
  if Length(AData) = 0 then
    Exit;
  Assert.IsTrue(Length(AData) >= (AOffset+ASize),
    'Read out of array bounary.');
  CheckWiped(PByte(@AData[AOffset]), ASize*SizeOf(Byte));
end;

class procedure TWipeTestTool.CheckWiped(AData: AnsiString);
begin
  CheckWiped(PAnsiChar(AData), Length(AData)*SizeOf(AnsiChar));
end;

class procedure TWipeTestTool.CheckWiped(AData: UnicodeString);
begin
  CheckWiped(PWideChar(AData), Length(AData)*SizeOf(WideChar));
end;

{ TBytesValidator }

class procedure TBytesValidator.AreEqual(const ABytes: TBytes;
  const AStr: UnicodeString; AWithTrailingNull: boolean);
var
  lBLen, lSLen: NativeUInt;

begin
  lBLen:=Length(ABytes);
  lSLen:=Length(AStr);
  if AWithTrailingNull then
    Inc(lSLen);
  Assert.AreEqual<NativeUInt>(lBLen, lSLen*SizeOf(WideChar),
    'Length in bytes of ABytes and A and AStr are not equal.');
  Assert.AreEqualMemory(PByte(ABytes), PWideChar(AStr), lBLen);
end;

class procedure TBytesValidator.AreEqual(const ABytes: TBytes;
  const AStr: RawByteString; AWithTrailingNull: boolean);
var
  lBLen, lSLen: NativeUInt;

begin
  lBLen:=Length(ABytes);
  lSLen:=Length(AStr);
  if AWithTrailingNull then
    Inc(lSLen);
  Assert.AreEqual<NativeUInt>(lBLen, lSLen*SizeOf(AnsiChar),
    'Length in bytes of ABytes and A and AStr are not equal.');
  Assert.AreEqualMemory(PByte(ABytes), PAnsiChar(AStr), lBLen);
end;

(*
class procedure TBytesValidator.AreEqual(const ABytes, ASrcBytes: TBytes;
  AOffset: Int64; ATrailingNulls: TTrailingNulls; AllowOutOfBounds: boolean);
var
  lALen, lBLen, lSrcLen: NativeUInt;
  i: integer;

begin
  lALen:=Length(ABytes);
  Assert.IsTrue(lALen-ATrailingNulls >= 0,
    Format('Length(ABytes): "%d" should be greater or equal ATrailingNulls: "%d".',
    [lALen, ATrailingNulls]));
  if lALen > ATrailingNulls then
  begin
    lBLen:=lALen-ATrailingNulls;
    lSrcLen:=Length(ASrcBytes);
    if not AllowOutOfBounds then
      Assert.IsTrue(lSrcLen >= AOffset+lBLen,
        Format('Trying to read outside of ASrcBytes boundary. '+
        'Length(ASrcBytes): %d bytes, less than Length(ASrcBytes)+ACount: %d bytes(s)',
        [lSrcLen, AOffset+lBLen]));
    if (lSrcLen-AOffset) > 0 then
    begin
      lSrcLen:=lSrcLen-AOffset;
      if lSrcLen > lBLen then
        lSrcLen:=lBLen;
    end
    else
      lSrcLen:=0;
    Assert.AreEqual(lSrcLen, lBLen,
      'Length(ABytes) is not equal expected read length.');
    if lSrcLen > 0 then
      Assert.AreEqualMemory(PByte(ABytes), PByte(@ASrcBytes[AOffset]), lBLen,
        'ASrcBytes and ABytes are not equal.');
  end;
  for i := ATrailingNulls-1 downto Low(TTrailingNulls) do
    Assert.AreEqual<byte>(0, ABytes[lALen-i-1],
      Format('No trailing null at position', [lALen-i-1]));
end;

class procedure TBytesValidator.AreEqual(const ABytes: TBytes;
  const AStream: TStream; AOffset: Int64; ATrailingNulls: TTrailingNulls);
var
  lALen, lBLen: NativeUInt;
  lBytes: TBytes;
  lStreamPos, lStreamSize: Int64;
  i: integer;

begin
  Assert.IsNotNull(AStream, 'AStream must not be ''nil''.');
  lALen:=Length(ABytes);
  Assert.IsTrue(lALen-ATrailingNulls >= 0,
    Format('Length(ABytes): "%d" should be greater or equal ATrailingNulls: "%d".',
    [lALen, ATrailingNulls]));
  lStreamSize:=AStream.Size;
  SetLength(lBytes, lALen);
  if lALen > ATrailingNulls then
  begin
    lBLen:=lALen-ATrailingNulls;
    Assert.IsTrue(lStreamSize >= AOffset+lBLen,
      Format('Trying to read behind the End of File. File Size: %d bytes '+
      'less than File Size+ACount: %d byte(s)', [lStreamSize, AOffset+lBLen]));
    lStreamPos:=AStream.Position;
    try
      Assert.AreEqual<Int64>(lBLen, AStream.Read(lBytes, lBLen),
        'Data has read less than reguested.');
    finally
      AStream.Position:=lStreamPos;
    end;
  end;
  Assert.AreEqualMemory(PByte(lBytes), PByte(ABytes), lALen,
    'ABytes and content of AStream are not equal.');
end;
*)

class procedure TBytesValidator.AreEqual(const ABytes, ASrcBytes: TBytes;
  AOffset, ASrcOffset, ACount: Int64);
begin
  if ACount <= 0 then
    Exit;
  Assert.IsTrue(Length(ABytes) >= (AOffset+ACount),
    'Attempt to compare out of ABytes boundary');
  Assert.IsTrue(Length(ASrcBytes) >= (ASrcOffset+ACount),
    'Attempt to compare out of ASrcBytes boundary');
  if (Length(ABytes) = 0) and (Length(ASrcBytes) = 0) then
    Exit; // nothing to compare
  Assert.AreEqualMemory(PByte(@ABytes[AOffset]), PByte(@ASrcBytes[ASrcOffset]),
    ACount, 'Content of subarryas are not equal.');
end;

class procedure TBytesValidator.AreEqual(const ABytes, ASrcBytes: TBytes;
  AOffset: Int64; ATrailingNulls: TTrailingNulls);
var
  i: integer;

begin
  AreEqual(ABytes, ASrcBytes, Low(ABytes), AOffset, Length(ABytes)-ATrailingNulls);
  for i := ATrailingNulls-1 downto Low(TTrailingNulls) do
    Assert.AreEqual<byte>(0, ABytes[Length(ABytes)-i-1],
      Format('No trailing null at position', [Length(ABytes)-i-1]));
end;

class procedure TBytesValidator.CalcOffsetAndSize(ADataSize: Int64;
  var AOffset, ACount: Int64);

begin
  if (ADataSize = 0) or (ACount = 0) then
  begin
    AOffset:=0;
    ACount:=ADataSize;
    Exit;
  end;

  if (AOffset+ACount) > ADataSize then
    ACount:=ADataSize-AOffset;
end;

class procedure TBytesValidator.CalcOffsetAndSize(ABytes: TBytes; var AOffset,
  ACount: Int64);
begin
  CalcOffsetAndSize(Length(ABytes), AOffset, ACount);
end;

class procedure TBytesValidator.CalcOffsetAndSize(AStream: TStream; var AOffset,
  ACount: Int64);
var
  lSize: NativeUInt;

begin
  if Assigned(AStream) then
    lSize:=AStream.Size
  else
    lSize:=0;
  CalcOffsetAndSize(lSize, AOffset, ACount);
end;

initialization

end.
