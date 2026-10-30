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
  DUnitX.TestFramework, TaurusTLSLoader, TaurusTLS.UT.Utils;

type
  ///  <summary>
  ///  Base exception class can be used to make Assert Tests Fixtures
  ///  </summary
  EOsslBaseFixture = class(Exception);

  /// <summary>Configures OpenSSL for fixtures that control its lifecycle explicitly.</summary>
  /// <remarks>Tests execute serially and share the process-wide loader.</remarks>
  TOsslBaseFixture = class
  private
    FLoader: IOpenSSLLoader;
    function GetLoader: IOpenSSLLoader;
  protected
    /// <summary>The shared loader; accessing it never initializes OpenSSL.</summary>
    property Loader: IOpenSSLLoader read GetLoader;
    /// <summary>Applies parsed command-line options, falling back to startup environment defaults.</summary>
    /// <remarks>Call while unloaded. This method does not call Load.</remarks>
    procedure SetupFromCmd; virtual;
    /// <summary>Calls Loader.Load directly, preserving its Boolean result and exceptions.</summary>
    function Load: Boolean;
    /// <summary>Unloads OpenSSL and resets failed state, including partial initialization.</summary>
    procedure Unload;
    /// <summary>Checks current loader readiness without retaining a separate failure flag.</summary>
    procedure CheckLoaded;
  end;

  /// <summary>Loads OpenSSL for a fixture and unloads it after its tests.</summary>
  TOsslAutoloadFixture = class(TOsslBaseFixture)
  private
    FAutoCleanupNeeded: Boolean;
  public
    destructor Destroy; override;
    /// <summary>Configures and loads OpenSSL. Descendants call inherited first.</summary>
    [SetupFixture]
    procedure SetupFixture; virtual;
    /// <summary>Unloads even after a failed load. Descendants call inherited last.</summary>
    [TearDownFixture]
    procedure TearDownFixture; virtual;
  end;

resourcestring
  cOsslNotLoaded = 'OpenSSL is not ready. Initialize it before this test.';
  cOsslLoadFailed = 'OpenSSL could not be loaded.';
  cOsslLoaderPathHelp = 'Specify path to OpenSSL library folder';
  cOsslLoaderConfigHelp = 'Specify path to OpenSSL configuration file';

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

  TTestEnumHelperRec<T> = record
    class function ToString(const AValue: T): string; static;
  end;

  TBytesHelper = record helper for TBytes
    class function FromBase64Str(AValue: string): TBytes;
    class function FromHexStr(AValue: string): TBytes;
  end;

implementation

uses
  System.TypInfo, System.NetEncoding, DUnitX.CommandLine.Options;

{ Parsed options are configuration only; they do not own a loader or load count. }
var
  GOpenSSLPath: string;
  GOpenSSLConfigFile: string;

procedure RegisterLoaderOptions;
begin
  GOpenSSLPath := GetEnvironmentVariable('OPENSSL_PATH');
  GOpenSSLConfigFile := GetEnvironmentVariable('OPENSSL_CONF');
  TOptionsRegistry.RegisterOption<string>('opensslpath', 'osp',
    cOsslLoaderPathHelp,
    procedure(Value: string)
    begin
      GOpenSSLPath := Value;
    end);
  TOptionsRegistry.RegisterOption<string>('openssl-config-path', 'oscp',
    cOsslLoaderConfigHelp,
    procedure(Value: string)
    begin
      GOpenSSLConfigFile := Value;
    end);
end;

{ TOsslBaseFixture }

function TOsslBaseFixture.GetLoader: IOpenSSLLoader;
begin
  if FLoader = nil then
    FLoader := GetOpenSSLLoader;
  Result := FLoader;
end;

procedure TOsslBaseFixture.SetupFromCmd;
begin
  Loader.OpenSSLPath := GOpenSSLPath;
  Loader.ConfigFile := GOpenSSLConfigFile;
end;

function TOsslBaseFixture.Load: Boolean;
begin
  Result := Loader.Load;
end;

procedure TOsslBaseFixture.Unload;
begin
  Loader.Unload;
end;

procedure TOsslBaseFixture.CheckLoaded;
begin
  if not Loader.IsLoaded then
    raise EOsslBaseFixture.CreateRes(@cOsslNotLoaded);
end;

{ TOsslAutoloadFixture }

procedure TOsslAutoloadFixture.SetupFixture;
{$IFDEF USE_FASTMM5}
  {$IFNDEF MEMLEAK_DETAILS}
var
  lDebugActive: Boolean;
  {$ENDIF}
{$ENDIF}
begin
  FAutoCleanupNeeded := True;
  try
{$IFDEF USE_FASTMM5}
  {$IFDEF MEMLEAK_DETAILS}
    TFastMMDebugLog.DebugModeActive := True;
  {$ELSE}
    lDebugActive := TFastMMDebugLog.DebugModeActive;
  {$ENDIF}
{$ENDIF}
    SetupFromCmd;
    if not Load then
      raise EOsslBaseFixture.CreateRes(@cOsslLoadFailed);
  except
    // DUnitX skips fixture teardown after setup errors. Preserve the load error.
    try
      Unload;
      FAutoCleanupNeeded := False;
    except
      on E: Exception do
        Log(TLogLevel.Error, 'OpenSSL cleanup after fixture setup failure: ' +
          E.ClassName + ': ' + E.Message);
    end;
    raise;
  end;
end;

procedure TOsslAutoloadFixture.TearDownFixture;
begin
  Unload;
  FAutoCleanupNeeded := False;
end;

destructor TOsslAutoloadFixture.Destroy;
begin
  try
    // Also covers a descendant setup error after inherited SetupFixture succeeded.
    if FAutoCleanupNeeded then
      Unload;
  finally
    inherited Destroy;
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
    CheckWiped(AData, Low(AData), lLen);
end;

class procedure TWipeTestTool.CheckWiped(AData: TBytes; AOffset,
  ASize: NativeUInt);
begin
  if Length(AData) = 0 then
    Exit;
  Assert.IsTrue(NativeUInt(Length(AData)) >= (AOffset+ASize),
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

{ TTestEnumHelperRec<T> }

class function TTestEnumHelperRec<T>.ToString(const AValue: T): string;
var
  lTI: PTypeInfo ;
  lValue: integer;

begin
  lTI:=TypeInfo(T);
  if Assigned(lTI) then
  begin
    if lTI^.Kind = tkEnumeration then
    begin
      case SizeOf(AValue) of
        1: lValue:=PByte(@AValue)^;
        2: lValue:=PWord(@AValue)^;
        4: lValue:=PInteger(@AValue)^;
      else
        raise EConvertError.CreateFmt(
          'Enumeration type ''%s'' has unsupported data size.', [lTI^.Name]);
      end;
      Result:=GetEnumName(lTI, lValue) // this type cast is safe
    end
    else
      raise EConvertError.CreateFmt(
        'Unable to get Value Name for non-enum type ''%s''.', [lTI^.Name]);
  end
  else
    raise EConvertError.Create('Unable to get type information.');
end;

{ TBytesHelper }

class function TBytesHelper.FromBase64Str(AValue: string): TBytes;
begin
  Assert.AreNotEqual(0, Length(AValue),
    'Parameter ''AValue'' must be grater than Zero.');
  Result:=BytesOf(TNetEncoding.Base64.Decode(AValue));
end;

class function TBytesHelper.FromHexStr(AValue: string): TBytes;
var
  lLen: NativeUInt;

begin
  lLen:=Length(AValue);
  if lLen > 0 then
  begin
    Assert.IsFalse(Odd(lLen mod 2), 'HEX String must be divisible by 2.');
    lLen:=lLen div 2;
    SetLength(Result, lLen);
    HexToBin(PChar(AValue), 0, Result, 0, lLen);
  end
  else
    SetLength(Result, 0);
end;

initialization
  RegisterLoaderOptions;

end.
