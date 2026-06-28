{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I TaurusTLSCompilerDefines.inc}

/// <summary>
///   OpenSSL BIO Object wrapper classes.
/// </summary>
unit TaurusTLS_BIO;
{$I TaurusTLSLinkDefines.inc}

interface

uses
  SysUtils,
  Classes,
  IdCTypes,
  IdGlobal,
  IdGlobalProtocols,
  TaurusTLSHeaders_types,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_bio;

type
  /// <summary>Base exception class for all OpenSSL BIO wrapper errors.</summary>
  ETaurusTLSBioError = class(ETaurusTLSError);
  /// <summary>Raised when an OpenSSL BIO handle cannot be created or initialized.</summary>
  ETaurusTLSBioCreateError = class(ETaurusTLSBioError);
  /// <summary>Raised when an error occurs during a BIO_read operation.</summary>
  ETaurusTLSBioReadError = class(ETaurusTLSBioError);
  /// <summary>Raised when an error occurs during a BIO_write operation.</summary>
  ETaurusTLSBioWriteError = class(ETaurusTLSBioError);
  /// <summary>Raised when a BIO does not support Reset operation.</summary>
  ETaurusTLSBioResetError = class(ETaurusTLSBioError);
  /// <summary>Raised when a BIO does not support Seek operation.</summary>
  ETaurusTLSBioSeekError = class(ETaurusTLSBioError);
  /// <summary>Raised when data cannot be successfully loaded from a TStream into a BIO.</summary>
  ETaurusTLSBioLoadStreamError = class(ETaurusTLSBioError);
  /// <summary>Raised when data cannot be successfully written from a BIO into a TStream.</summary>
  ETaurusTLSBioWriteStreamError = class(ETaurusTLSBioError);

  /// <summary>
  ///   Abstract base class for OpenSSL BIO (Basic I/O) wrappers. Manages the
  ///   lifecycle and reference counting of the underlying PBIO handle.
  /// </summary>
  TTaurusTLSCustomBIO = class abstract
  public type
    /// <summary>Capabilities flags for the BIO wrapper.</summary>
    TFlag = (
      /// <summary>
      ///   <c>bfAppManaged</c> indicates that the data allocated by the
      ///   application memory manager and <b>MUST NOT</b> be managed by OpenSSL
      ///   memory management routines.
      /// </summary>
      bfAppManaged,
      /// <summary>
      ///   <c>bfReadable</c> indicates that the application can read data from
      ///   this <c>BIO object.</c>
      /// </summary>
      bfReadable,
      /// <summary>
      ///   <c>bfWritable</c> indicates that the application can read data from
      ///   this <c>BIO object</c>.
      /// </summary>
      bfWritable,
      /// <summary>
      ///   <c>bfResetable</c> indicates that the application can reset read
      ///   position after reading.
      /// </summary>
      bfResetable,
      /// <summary>
      ///   <c>bfConsumable</c> indicates that the data portion read from the
      ///   BIO becomes unavailable.
      /// </summary>
      bfConsumable,
      /// <summary>
      ///   <c>bfNullTerminator</c> indicates that the BIO Data includes <c>null
      ///   </c> termination character,
      /// </summary>
      bfNullTerminator
    );

    /// <summary>Set of capabilities flags.</summary>
    TFlags = set of TFlag;

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF}
  private
    FFlags: TFlags;
    FBIO: PBIO;
    function GetEof: boolean;
    function GetIsAppManagedBIO: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetIsMemoryBIO: Boolean;{$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetPending: TIdC_SIZET;
  public
    /// <summary>
    ///   Initializes the wrapper with an existing BIO handle and specific
    ///   capability flags.
    /// </summary>
    constructor Create(ABIO: PBIO; AFlags: TFlags); overload;
  public
    /// <summary>
    ///   Default constructor. Raises ETaurusTLSBioCreateError as a specific BIO type
    ///   must be chosen.
    /// </summary>
    constructor Create; overload;
    /// <summary>
    ///   Frees the underlying OpenSSL BIO handle and destroys the object.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    ///   Tries to reset the BIO object to the initial state.
    /// </summary>
    /// <exception cref="ETaurusTLSBioResetError">
    ///   If BIO object does not support Resed operation or interanl OpenSSL
    ///   falure happens.
    /// </exception>
    /// <remarks>
    ///   This methods works with any memory BIO object. Non-memroy BIO objects
    ///   can generate exceptions.
    /// </remarks>
    procedure Reset;
    /// <summary>
    ///   Tries to reset the BIO object to the initial state.
    /// </summary>
    /// <returns>
    ///   <c>True</c> on success and <c>False</c> on failure
    /// </returns>
    function TryReset: boolean;
    /// <summary>
    ///   Reads ASize bytes from the BIO into AData. Returns True if Read
    ///   operation successed, False otherwise.
    /// </summary>
    function TryRead(var AData; ASize: TIdC_SIZET;
      out AHasRead: TIdC_SIZET): boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Reads ASize bytes from the BIO into AData. Returns the number of bytes
    ///   actually read.
    /// </summary>
    function Read(var AData; ASize: TIdC_SIZET): TIdC_SIZET;
    /// <summary>
    ///   Writes ASize bytes from the BIO into AData. Returns True if Write
    ///   operation successed, False otherwise. <br />
    /// </summary>
    function TryWrite(const AData; ASize: TIdC_SIZET;
      out AHasWritten: TIdC_SIZET): boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Writes ASize bytes from AData into the BIO. Returns the number of
    ///   bytes actually written.
    /// </summary>
    function Write(const AData; ASize: TIdC_SIZET): TIdC_SIZET;
    /// <summary>
    ///   The raw OpenSSL PBIO handle.
    /// </summary>
    property BIO: PBIO read FBIO;
    /// <summary>
    ///   The capability flags assigned to this BIO instance.
    /// </summary>
    property Flags: TFlags read FFlags;
    /// <summary>
    ///   Returns True if the Reading operation is reached end of the BIO object
    ///   data.
    /// </summary>
    property Eof: boolean read GetEof;
    /// <summary>
    ///   Indicates if the underlying BIO is a memory BIO (BIO_s_mem or
    ///   BIO_s_secmem).
    /// </summary>
    property IsMemoryBIO: Boolean read GetIsMemoryBIO;

    property IsAppManagedBIO: boolean read GetIsAppManagedBIO;
    /// <summary>
    ///   The number of bytes currently pending/available in the BIO.
    /// </summary>
    property Pending: TIdC_SIZET read GetPending;
    /// <summary>
    ///   Provides access to the BIO content as a RawByteString. Reading
    ///   consumes data from memory BIOs.
    /// </summary>
    function ReadAsString: RawByteString;
    /// <summary>
    ///   Provides access to the BIO content as a array of bytes. Reading
    ///   consumes data from memory BIOs.
    /// </summary>
    function ReadAsBytes: TIdBytes;
  end;

  /// <summary>
  ///   Helper class providing stream-based I/O and capability validation for
  ///   BIO wrappers.
  /// </summary>
  TTaurusTLSCustomBIOHelper = class helper for TTaurusTLSCustomBIO
  public const
    /// <summary>Buffer size used for chunked stream operations.</summary>
    cChunkSize = 8192;
  public
    /// <summary>
    ///   Validates that the BIO can be reset to initial state
    /// </summary>
    /// <exception cref="ETaurusTLSBioResetError">
    ///   When the BIO object does not support the <c>Reset</c> operation.
    /// </exception>
    procedure CheckCanReset; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the BIO can read from the BIO object.
    /// </summary>
    /// <exception cref="ETaurusTLSBioReadError">
    ///   When the BIO object does not support Read operation.
    /// </exception>
    procedure CheckCanRead; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the BIO can write to the BIO object.
    /// </summary>
    /// <exception cref="ETaurusTLSBioReadError">
    ///   When the BIO object does not support Write operation.
    /// </exception>
    procedure CheckCanWrite; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the property <see
    ///   cref="TaurusTLS_BIO|TTaurusTLSCustomBIO.Flags">Flags</see> contains
    ///   all values included in the parameter <c>AFlags</c>
    /// </summary>
    /// <param name="AFlags">
    ///   Set of flags to validate
    /// </param>
    /// <returns>
    ///   True if all Flags in the <c>AFlags</c> parameter included in the <see
    ///   cref="TaurusTLS_BIO|TTaurusTLSCustomBIO.Flags">Flags</see> property.
    /// </returns>
    function HasAllFlags(const AFlags: TTaurusTLSCustomBIO.TFlags): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the property <see
    ///   cref="TaurusTLS_BIO|TTaurusTLSCustomBIO.Flags">Flags</see> contains
    ///   one or more values included in the parameter <c>AFlags</c>
    /// </summary>
    /// <param name="AFlags">
    ///   Set of flags to validate
    /// </param>
    /// <returns>
    ///   True if any Flags in the <c>AFlags</c> parameter included in the <see
    ///   cref="TaurusTLS_BIO|TTaurusTLSCustomBIO.Flags">Flags</see> property.
    /// </returns>
    function HasAnyFlags(const AFlags: TTaurusTLSCustomBIO.TFlags): boolean;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Reads data from the provided TStream and writes it into the BIO.
    /// </summary>
    function LoadFromStream(const AStream: TStream; ASize: TIdC_SIZET): TIdC_SIZET;
    /// <summary>
    ///   Reads data from the BIO and writes it into the provided TStream.
    /// </summary>
    function WriteToStream(const AStream: TStream; ASize: TIdC_SIZET;
      AChunkSize: TIdC_SIZET = cChunkSize): TIdC_SIZET;
  end;

  /// <summary>
  ///   Wrapper for an OpenSSL internal memory BIO (BIO_s_mem).
  /// </summary>
  TTaurusTLSMemBio = class(TTaurusTLSCustomBIO)
  public
    /// <summary>Creates a new, empty OpenSSL managed memory BIO.</summary>
    constructor Create; overload;
  end;

  /// <summary>
  ///   Abstract base for BIOs that wrap existing Pascal-managed memory buffers
  ///   without copying.
  /// </summary>
  TTaurusTLSCustomRawMemBio = class abstract(TTaurusTLSCustomBIO)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FMemPtr: Pointer;
    FMemSize: TIdC_SIZET;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    /// <summary>
    ///   Called during destruction to allow descendants to perform additional
    ///   cleanup.
    /// </summary>
    procedure DoFreeMem;
  public
    /// <summary>
    ///   Initializes a non-copying BIO (BIO_new_mem_buf) pointing to the
    ///   specified memory address.
    /// </summary>
    constructor Create(const AData: Pointer; ASize: TIdC_SIZET;
      const AFlags: TTaurusTLSCustomBIO.TFlags = [bfReadable, bfResetable]); overload;
  public
    /// <summary>
    ///   Ensures cleanup of the Delphi wrapper and calls DoFreeMem.
    /// </summary>
    destructor Destroy; override;
  end;

  /// <summary>A read-only BIO wrapper for a TBytes array.</summary>
  TTaurusTLSBytesBio = class(TTaurusTLSCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: TBytes;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    property Data: TBytes read FData;
  public
    /// <summary>
    ///   Creates a BIO that reads directly from the provided TIdBytes.
    /// </summary>
    constructor Create(const AData: TBytes);
  end;

  /// <summary>A read-only BIO wrapper for a TIdBytes array.</summary>
  TTaurusTLSIdBytesBio = class(TTaurusTLSCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: TIdBytes;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    property Data: TIdBytes read FData;
  public
    /// <summary>
    ///   Creates a BIO that reads directly from the provided TIdBytes.
    /// </summary>
    constructor Create(const AData: TIdBytes);
  end;

  /// <summary>A read-only BIO wrapper for a RawByteString.</summary>
  TTaurusTLSRawByteStringBIO = class(TTaurusTLSCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: RawByteString;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    property Data: RawByteString read FData;
  public
    /// <summary>
    ///   Creates a BIO that reads directly from the provided RawByteString.
    /// </summary>
    /// <param name="AData">
    ///   The string to wrap.
    /// </param>
    /// <param name="AIncludeNull">
    ///   If True (default), includes the string's null terminator in the BIO
    ///   buffer.
    /// </param>
    constructor Create(const AData: RawByteString; AIncludeNull: boolean = True);
  end;

  /// <summary>
  ///   A generic read-only BIO wrapper for a Pascal record.
  /// </summary>
  /// <remarks>
  ///   This Generic type is intended to use with Pascal simple types and
  ///   records. Managed types like strings or dynamic arrays are not supported.
  /// </remarks>
  TTaurusTLSRecordBIO<T: record> = class(TTaurusTLSCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: T;
  public
    /// <summary>
    ///   Creates a BIO that reads directly from an internal copy of the
    ///   provided record.
    /// </summary>
    constructor Create(const AData: T);
  end;

implementation
uses
  TaurusTLS_ResourceStrings;

{ TTaurusTLSCustomBIOHelper }

procedure TTaurusTLSCustomBIOHelper.CheckCanRead;
begin
  if not (bfReadable in Flags) then
    ETaurusTLSBioReadError.RaiseWithMessage(RSMsg_Bio_ReadCheck_err);
end;

procedure TTaurusTLSCustomBIOHelper.CheckCanReset;
begin
  if not (bfResetable in Flags) then
    ETaurusTLSBioResetError.RaiseWithMessage(RSMsg_Bio_ResetCheck_err);
end;

procedure TTaurusTLSCustomBIOHelper.CheckCanWrite;
begin
  if not (bfWritable in Flags) then
    ETaurusTLSBioWriteError.RaiseWithMessage(RSMsg_Bio_WriteCheck_err);
end;

function TTaurusTLSCustomBIOHelper.HasAllFlags(
  const AFlags: TTaurusTLSCustomBIO.TFlags): boolean;
begin
  Result:=(Flags * AFlags) = AFlags;
end;

function TTaurusTLSCustomBIOHelper.HasAnyFlags(
  const AFlags: TTaurusTLSCustomBIO.TFlags): boolean;
begin
  Result:=(Flags * AFlags) <> [];
end;

function TTaurusTLSCustomBIOHelper.LoadFromStream(const AStream: TStream;
  ASize: TIdC_SIZET): TIdC_SIZET;
var
  lRemaining: TIdC_INT;
  lChunkToRead: TIdC_INT;
  lActuallyRead: TIdC_INT;
  lBuf: TIdBytes;
begin
  Result := 0;
  {$IFNDEF FPC}
  lRemaining := IndyMin(ASize, TIdC_SIZET(AStream.Size - AStream.Position));
  {$ELSE}
   lRemaining := IndyMin(Int64(ASize), TIdC_SIZET(AStream.Size - AStream.Position));
  {$ENDIF}
  if lRemaining = 0 then Exit;

  CheckCanWrite;
  SetLength(lBuf, cChunkSize);

  while lRemaining > 0 do
  begin
    lChunkToRead := IndyMin(lRemaining, cChunkSize);
    lActuallyRead := AStream.Read(lBuf[0], lChunkToRead);
    if lActuallyRead <= 0 then Break;

    if TIdC_INT(Write(lBuf[0], lActuallyRead)) <> lActuallyRead then
      ETaurusTLSBioLoadStreamError.RaiseWithMessage(RSMsg_Bio_StreamRead_err);

    Dec(lRemaining, lActuallyRead);
    Inc(Result, lActuallyRead);
  end;
end;

function TTaurusTLSCustomBIOHelper.WriteToStream(const AStream: TStream;
  ASize, AChunkSize: TIdC_SIZET): TIdC_SIZET;
var
  lReadSize: TIdC_SIZET;
  lBuf: TIdBytes;
  lToRead: TIdC_SIZET;

begin
  Result := 0;
  if ASize = 0 then Exit;
  CheckCanRead;

  lToRead := IndyMin(int64(ASize), int64(Pending));
  if lToRead = 0 then Exit;

  SetLength(lBuf, AChunkSize);

  while lToRead > 0 do
  begin
    // Reads from the BIO
    lReadSize := Read(lBuf[0], IndyMin(int64(lToRead), int64(AChunkSize)));  //PALOFF "NativeUInt cast to Integer"
    if lReadSize = 0 then Break;

    AStream.WriteBuffer(lBuf[0], Integer(lReadSize)); //PALOFF "NativeUInt cast to Integer"
    Inc(Result, lReadSize);
    Dec(lToRead, lReadSize);
  end;
end;

{ TTaurusTLSCustomBIO }

constructor TTaurusTLSCustomBIO.Create;
begin
  ETaurusTLSBioCreateError.RaiseWithMessage(RSMsg_Bio_WrongConstructor_err);
end;

constructor TTaurusTLSCustomBIO.Create(ABIO: PBIO; AFlags: TFlags);
begin
  if not Assigned(ABIO) then
    ETaurusTLSBioCreateError.RaiseWithMessage(RSMsg_Bio_NullBio_err);
  FBIO:=ABIO;
  FFlags:=AFlags;
end;

destructor TTaurusTLSCustomBIO.Destroy;
begin
  BIO_free(FBIO);
  inherited;
end;

function TTaurusTLSCustomBIO.GetIsAppManagedBIO: boolean;
begin
  Result:=bfAppManaged in Flags;
end;

function TTaurusTLSCustomBIO.GetIsMemoryBIO: Boolean;
begin
  Result:=BIO_method_type(FBIO) = BIO_TYPE_MEM;
end;

function TTaurusTLSCustomBIO.GetPending: TIdC_SIZET;
begin
  Result:=BIO_ctrl_pending(FBIO);
end;

function TTaurusTLSCustomBIO.TryRead(var AData; ASize: TIdC_SIZET;
  out AHasRead: TIdC_SIZET): boolean;
begin
  AHasRead:=0;
  if (ASize = 0) then
    Exit(True);

  if not (bfReadable in FFlags) then
    Exit(False);

  Result:=BIO_read_ex(FBIO, AData, ASize, AHasRead) = 1;
  // OpenSSL return -1 if Data Read size is less the requested and Eof happens.
  // We are not going to thread this as error.
  if (not Result) and Eof then
    Result:=True;
end;

function TTaurusTLSCustomBIO.Read(var AData; ASize: TIdC_SIZET): TIdC_SIZET;
begin
  Result := 0;
  if ASize = 0 then
    Exit;
  CheckCanRead;
  if not TryRead(AData, ASize, Result) then
    ETaurusTLSBioReadError.RaiseWithMessage(RSMsg_Bio_Read_err)
end;

function TTaurusTLSCustomBIO.TryWrite(const AData; ASize: TIdC_SIZET;
  out AHasWritten: TIdC_SIZET): boolean;
begin
  Result:=False;
  AHasWritten:=0;
  if (ASize = 0) or (not (bfWritable in FFlags)) then
    Exit;
  Result:=BIO_write_ex(FBIO, AData, ASize, AHasWritten) = 1;
end;

function TTaurusTLSCustomBIO.Write(const AData; ASize: TIdC_SIZET): TIdC_SIZET;
begin
  Result := 0;
  if ASize = 0 then
    Exit;
  CheckCanWrite;
  if not TryWrite(AData, ASize, Result) then
    ETaurusTLSBioWriteError.RaiseWithMessage(RSMsg_Bio_Write_err)
end;

function TTaurusTLSCustomBIO.ReadAsBytes: TIdBytes;
var
  lSize: TIdC_SIZET;
  lActuallyRead: TIdC_SIZET;

begin
  lActuallyRead:=0;
  lSize:=Pending;
  SetLength(Result, lSize);
  if lSize > 0 then
    lActuallyRead:=Read(Result[0], lSize);

  // Shrink if read size is less than expected.
  if lActuallyRead < lSize then
    SetLength(Result, lActuallyRead);
end;

procedure TTaurusTLSCustomBIO.Reset;
begin
  CheckCanReset;
  if BIO_reset(FBIO) <> 1 then
    ETaurusTLSBioResetError.RaiseWithMessage(RSMsg_Bio_Reset_err)
end;

function TTaurusTLSCustomBIO.TryReset: boolean;
begin
  Result:=(bfResetable in FFlags) and
    (BIO_reset(FBIO) <= 1);
end;

function TTaurusTLSCustomBIO.ReadAsString: RawByteString;
var
  lSize: TIdC_SIZET;
  lActuallyRead: TIdC_SIZET;

begin
  lActuallyRead:=0;
  lSize:=Pending;
  SetLength(Result, lSize);
  if lSize > 0 then
  begin
    lActuallyRead:=Read(Result[1], lSize);
    if bfNullTerminator in FFlags then
      Dec(lActuallyRead);
  end;
  // Shrink if read size is less than expected.
  if lActuallyRead < lSize then
    SetLength(Result, lActuallyRead);
end;

function TTaurusTLSCustomBIO.GetEof: boolean;
begin
  Result:=BIO_eof(FBIO) = 1;
end;

{ TTaurusTLSMemBio }

constructor TTaurusTLSMemBio.Create;
begin
  inherited Create(BIO_new(BIO_s_mem()),
    [bfReadable, bfWritable, bfResetable, bfConsumable]);
end;

{ TTaurusTLSCustomRawMemBio }

constructor TTaurusTLSCustomRawMemBio.Create(const AData: Pointer;
  ASize: TIdC_SIZET; const AFlags: TTaurusTLSCustomBIO.TFlags);
begin
  if not Assigned(AData) and (ASize = 0) then
    ETaurusTLSBioCreateError.RaiseWithMessage(RSMsg_Bio_EmptyMemPtr_err);

  inherited Create(BIO_new_mem_buf(AData^, ASize), Flags+[bfAppManaged]);
  FMemPtr := AData;
  FMemSize := ASize;
end;

destructor TTaurusTLSCustomRawMemBio.Destroy;
begin
  DoFreeMem;
  inherited;
end;

procedure TTaurusTLSCustomRawMemBio.DoFreeMem;
begin
  // Do Nothing by default;     PALOFF - Empty begin/end-blocks
end;

{ TTaurusTLSBytesBio }

constructor TTaurusTLSBytesBio.Create(const AData: TBytes);
begin
  inherited Create(PByte(AData), Length(AData)*SizeOf(Byte)); // PALOFF Possible bad pointer usage
  FData:=AData;
end;

{ TTaurusTLSIdBytesBio }

constructor TTaurusTLSIdBytesBio.Create(const AData: TIdBytes);
begin
  inherited Create(PByte(AData), Length(AData)*SizeOf(Byte)); // PALOFF Possible bad pointer usage
  FData:=AData;
end;

{ TTaurusTLSRawByteStringBIO }

constructor TTaurusTLSRawByteStringBIO.Create(const AData: RawByteString;
  AIncludeNull: boolean = True);
var
  lLen: TIdC_SizeT;
  lFlags: TFlags;

begin
  lFlags:=[bfReadable, bfResetable];
  lLen:=Length(AData);
  if AIncludeNull then // include terminating #0 character
  begin
    if lLen > 0 then
      FData:=AData
    else
      FData:=#0;
    Inc(lLen);
    Include(lFlags, bfNullTerminator);
  end
  else
    FData:=AData;
  // created includes null-terminator if requested
  inherited Create(PAnsiChar(FData), lLen*SizeOf(AnsiChar), lFlags); //PALOFF RawByteString cast to PAnsiChar 
end;

{ TTaurusTLSRecordBIO<T> }

constructor TTaurusTLSRecordBIO<T>.Create(const AData: T);
begin
  FData:=AData;
  inherited Create(@FData, SizeOf(AData));
end;

end.
