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

unit TaurusTLS_BIO;

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
  /// <summary>Raised when a BIO cloning operation (reference count increment) fails.</summary>
  ETaurusTLSBioCloneError = class(ETaurusTLSBioError);
  /// <summary>Raised when an error occurs during a BIO_read operation.</summary>
  ETaurusTLSBioReadError = class(ETaurusTLSBioError);
  /// <summary>Raised when an error occurs during a BIO_write operation.</summary>
  ETaurusTLSBioWriteError = class(ETaurusTLSBioError);
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
      ///   <c>cbReadable</c> indicates that the application can read data from
      ///   this <c>BIO object.</c>
      /// </summary>
      cbReadable,
      /// <summary>
      ///   cbWritable indicates that the application can read data from this
      ///   <c>BIO object</c>.
      /// </summary>
      cbWritable,
      /// <summary>
      ///   <c>cbClonable</c> indicates that the application can clone this
      ///   <c>BIO object</c>.
      /// </summary>
      cbClonable
    );
    /// <summary>Set of capabilities flags.</summary>
    TFlags = set of TFlag;
  public const
    /// <summary>Default flags for a BIO that supports all operations.</summary>
    cFlagsAll = [cbReadable, cbWritable, cbClonable];
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FFlags: TFlags;
    FBIO: PBIO;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    /// <summary>
    ///   Internal method to instantiate a specific descendant during a Clone
    ///   operation.
    /// </summary>
    function DoClone: TTaurusTLSCustomBIO; virtual; abstract;
    /// <summary>
    ///   Attempts to increment the OpenSSL internal reference count of the BIO.
    /// </summary>
    function TryBIOAddRef: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Increments the reference count and returns the BIO handle. Raises
    ///   ETaurusTLSBioCloneError on failure.
    /// </summary>
    function BIOAddRef: PBIO; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Returns the number of bytes available for reading in the BIO.
    /// </summary>
    function GetPending: TIdC_SIZET;
    /// <summary>
    ///   Virtual getter to retrieve the BIO content as a TIdBytes array.
    /// </summary>
    function GetAsBytes: TIdBytes; virtual;
    /// <summary>
    ///   Virtual setter to write a TIdBytes array into the BIO.
    /// </summary>
    procedure SetAsBytes(const AValue: TIdBytes); virtual;
    /// <summary>
    ///   Virtual getter to retrieve the BIO content as a RawByteString.
    /// </summary>
    function GetAsString: RawByteString; virtual;
    /// <summary>
    ///   Virtual setter to write a RawByteString into the BIO.
    /// </summary>
    procedure SetAsString(const AValue: RawByteString); virtual;
    /// <summary>
    ///   Returns True if the underlying OpenSSL BIO is a memory-type BIO.
    /// </summary>
    function GetIsMemoryBIO: Boolean;{$IFDEF USE_INLINE}inline;{$ENDIF}
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
    ///   Creates a new Delphi wrapper instance pointing to the same OpenSSL BIO
    ///   handle (incrementing ref count).
    /// </summary>
    function Clone: TTaurusTLSCustomBIO; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Reads ASize bytes from the BIO into AData. Returns the number of bytes
    ///   actually read.
    /// </summary>
    function Read(var AData; ASize: TIdC_SIZET): TIdC_SIZET;
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
    ///   Indicates if the underlying BIO is a memory BIO (BIO_s_mem or
    ///   BIO_s_secmem).
    /// </summary>
    property IsMemoryBIO: Boolean read GetIsMemoryBIO;
    /// <summary>
    ///   The number of bytes currently pending/available in the BIO.
    /// </summary>
    property Pending: TIdC_SIZET read GetPending;
    /// <summary>
    ///   Provides access to the BIO content as a RawByteString. Reading
    ///   consumes data from memory BIOs.
    /// </summary>
    property AsString: RawByteString read GetAsString write SetAsString;
    /// <summary>
    ///   Provides access to the BIO content as a array of bytes. Reading
    ///   consumes data from memory BIOs.
    /// </summary>
    property AsBytes: TIdBytes read GetAsBytes write SetAsBytes;
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
    ///   Validates that the BIO is readable; raises ETaurusTLSBioReadError if not.
    /// </summary>
    procedure CheckCanRead; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the BIO is writable; raises ETaurusTLSBioWriteError if not.
    /// </summary>
    procedure CheckCanWrite; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the BIO is clonable; raises ETaurusTLSBioCloneError if not.
    /// </summary>
    procedure CheckCanClone; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Reads data from the provided TStream and writes it into the BIO.
    /// </summary>
    function LoadFromStream(const AStream: TStream; ASize: TIdC_SIZET): TIdC_SIZET;
    /// <summary>
    ///   Reads data from the BIO and writes it into the provided TStream.
    /// </summary>
    function WriteToStream(const AStream: TStream; ASize: TIdC_SIZET): TIdC_SIZET;
  end;

  /// <summary>
  ///   Wrapper for an OpenSSL internal memory BIO (BIO_s_mem).
  /// </summary>
  TTaurusTLSMemBio = class(TTaurusTLSCustomBIO)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoClone: TTaurusTLSCustomBIO; override;
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
    constructor Create(AMemPtr: Pointer; ASize: TIdC_SIZET; AIsClonable: boolean = False); overload;
    /// <summary>
    ///   Ensures cleanup of the Delphi wrapper and calls DoFreeMem.
    /// </summary>
    destructor Destroy; override;
  end;

  /// <summary>A read-only BIO wrapper for a TIdBytes array.</summary>
  TTaurusTLSBytesBio = class(TTaurusTLSCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: TIdBytes;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoClone: TTaurusTLSCustomBIO; override;
    function GetAsBytes: TIdBytes; override;
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
    function DoClone: TTaurusTLSCustomBIO; override;
    function GetAsString: RawByteString; override;
  public
    /// <summary>
    ///   Creates a BIO that reads directly from the provided RawByteString.
    /// </summary>
    constructor Create(const AData: RawByteString);
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
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoClone: TTaurusTLSCustomBIO; override;
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

function TTaurusTLSCustomBIO.TryBIOAddRef: boolean;
begin
  Result:=BIO_up_ref(FBIO) = 1;
end;

function TTaurusTLSCustomBIO.GetIsMemoryBIO: Boolean;
begin
  Result:=BIO_method_type(FBIO) = BIO_TYPE_MEM;
end;

function TTaurusTLSCustomBIO.GetPending: TIdC_SIZET;
begin
  Result:=BIO_ctrl_pending(FBIO);
end;

function TTaurusTLSCustomBIO.Read(var AData; ASize: TIdC_SIZET): TIdC_SIZET;
var
  lResult: TIdC_INT;

begin
  if ASize = 0 then
    Exit;
  CheckCanRead;
  lResult:=BIO_read_ex(FBIO, AData, ASize, Result);
  if lResult <> 1 then
    ETaurusTLSBioReadError.RaiseWithMessage(RSMsg_Bio_Read_err)
end;

function TTaurusTLSCustomBIO.Write(const AData; ASize: TIdC_SIZET): TIdC_SIZET;
var
  lResult: TIdC_INT;

begin
  if ASize = 0 then
    Exit;
  CheckCanWrite;
  lResult:=BIO_write_ex(FBIO, AData, ASize, Result);
  if lResult <> 1 then
    ETaurusTLSBioWriteError.RaiseWithMessage(RSMsg_Bio_Write_err)
end;

procedure TTaurusTLSCustomBIO.SetAsBytes(const AValue: TIdBytes);
var
  lSize: TIdC_SIZET;

begin
  lSize:=Length(AValue);
  if lSize > 0 then
    Write(AValue[0], lSize);
end;

function TTaurusTLSCustomBIO.GetAsBytes: TIdBytes;
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

procedure TTaurusTLSCustomBIO.SetAsString(const AValue: RawByteString);
var
  lSize: TIdC_SIZET;

begin
  lSize:=Length(AValue);
  if lSize > 0 then
    Write(AValue[1], lSize);
end;

function TTaurusTLSCustomBIO.GetAsString: RawByteString;
var
  lSize: TIdC_SIZET;
  lActuallyRead: TIdC_SIZET;

begin
  lActuallyRead:=0;
  lSize:=Pending;
  SetLength(Result, lSize);
  if lSize > 0 then
    lActuallyRead:=Read(Result[1], lSize);

  // Shrink if read size is less than expected.
  if lActuallyRead < lSize then
    SetLength(Result, lActuallyRead);
end;

function TTaurusTLSCustomBIO.BIOAddRef: PBIO;
begin
  if not TryBIOAddRef then
    ETaurusTLSBioCloneError.RaiseWithMessage(RSMsg_Bio_AddRef_err);
  Result:=FBIO;
end;

function TTaurusTLSCustomBIO.Clone: TTaurusTLSCustomBIO;
begin
  CheckCanClone;
  Result:=DoClone;
end;

{ TTaurusTLSCustomBIOHelper }

procedure TTaurusTLSCustomBIOHelper.CheckCanClone;
begin
  if not (cbClonable in Flags) then
    ETaurusTLSBioCloneError.RaiseWithMessage(RSMsg_Bio_CloneCheck_err);
end;

procedure TTaurusTLSCustomBIOHelper.CheckCanRead;
begin
  if not (cbReadable in Flags) then
    raise ETaurusTLSBioReadError.Create(RSMsg_Bio_ReadCheck_err);
end;

procedure TTaurusTLSCustomBIOHelper.CheckCanWrite;
begin
  if not (cbWritable in Flags) then
    raise ETaurusTLSBioReadError.Create(RSMsg_Bio_WriteCheck_err);
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
  lRemaining := IndyMin(ASize, TIdC_SIZET(AStream.Size - AStream.Position));
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
  ASize: TIdC_SIZET): TIdC_SIZET;
var
  lReadSize: TIdC_SIZET;
  lBufSize: TIdC_LONGLONG;
  lBuf: TIdBytes;
  lBufPtr: Pointer;
  lToRead: TIdC_SIZET;

begin
  Result := 0;
  if ASize = 0 then Exit;
  CheckCanRead;

  if IsMemoryBIO then
  begin
    // Optimization: Use BIO_get_mem_data to avoid copying if possible
    lBufSize := BIO_get_mem_data(BIO, lBufPtr);
    if lBufSize <= 0 then Exit;
    lToRead := IndyMin(ASize, TIdC_SIZET(lBufSize));
    Result := AStream.Write(lBufPtr^, Integer(lToRead));
  end
  else
  begin
    SetLength(lBuf, cChunkSize);
    lToRead := ASize;
    while lToRead > 0 do
    begin
      // Reads from the BIO
      lReadSize := Read(lBuf[0], IndyMin(lToRead, cChunkSize));
      if lReadSize = 0 then Break;

      AStream.WriteBuffer(lBuf[0], Integer(lReadSize));
      Inc(Result, lReadSize);
      Dec(lToRead, lReadSize);
    end;
  end;
end;

{ TTaurusTLSMemBio }

constructor TTaurusTLSMemBio.Create;
begin
  inherited Create(BIO_new(BIO_s_mem()), cFlagsAll);
end;

function TTaurusTLSMemBio.DoClone: TTaurusTLSCustomBIO;
begin
  Result := TTaurusTLSMemBio(ClassType).Create(BIOAddRef, Flags);
end;

{ TTaurusTLSCustomRawMemBio }

constructor TTaurusTLSCustomRawMemBio.Create(AMemPtr: Pointer; ASize: TIdC_SIZET;
  AIsClonable: boolean = False);
var
  LFlags: TFlags;

begin
  if (not Assigned(AMemPtr)) or (ASize = 0) then
    ETaurusTLSBioCreateError.RaiseWithMessage(RSMsg_Bio_EmptyMemPtr_err);

  LFlags:=[cbReadable];
  if AIsClonable then
    Include(LFlags, cbClonable);

  inherited Create(BIO_new_mem_buf(AMemPtr^, ASize), lFlags);
  FMemPtr := AMemPtr;
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

function TTaurusTLSBytesBio.GetAsBytes: TIdBytes;
begin
  Result:=FData;
end;

constructor TTaurusTLSBytesBio.Create(const AData: TIdBytes);
begin
  inherited Create(Pointer(AData), Length(AData), True);
  FData:=AData;
end;

function TTaurusTLSBytesBio.DoClone: TTaurusTLSCustomBIO;
begin
  Result:=TTaurusTLSBytesBio.Create(FData);
end;

{ TTaurusTLSRawByteStringBIO }

constructor TTaurusTLSRawByteStringBIO.Create(const AData: RawByteString);
begin
  inherited Create(Pointer(AData), Length(AData), True);
  FData:=AData;
end;

function TTaurusTLSRawByteStringBIO.DoClone: TTaurusTLSCustomBIO;
begin
  Result:=TTaurusTLSRawByteStringBIO.Create(FData);
end;

function TTaurusTLSRawByteStringBIO.GetAsString: RawByteString;
begin
  Result:=FData;
end;

{ TTaurusTLSRecordBIO<T> }

constructor TTaurusTLSRecordBIO<T>.Create(const AData: T);
begin
  FData:=AData;
  inherited Create(@FData, SizeOf(AData), True);
end;

function TTaurusTLSRecordBIO<T>.DoClone: TTaurusTLSCustomBIO;
begin
  Result:=TTaurusTLSRecordBIO<T>.Create(FData);
end;

end.
