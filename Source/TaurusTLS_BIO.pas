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
  EBioError = class(ETaurusTLSError);
  /// <summary>Raised when an OpenSSL BIO handle cannot be created or initialized.</summary>
  EBioCreateError = class(EBioError);
  /// <summary>Raised when a BIO cloning operation (reference count increment) fails.</summary>
  EBioCloneError = class(EBioError);
  /// <summary>Raised when an error occurs during a BIO_read operation.</summary>
  EBioReadError = class(EBioError);
  /// <summary>Raised when an error occurs during a BIO_write operation.</summary>
  EBioWriteError = class(EBioError);
  /// <summary>Raised when data cannot be successfully loaded from a TStream into a BIO.</summary>
  EBioLoadStreamError = class(EBioError);
  /// <summary>Raised when data cannot be successfully written from a BIO into a TStream.</summary>
  EBioWriteStreamError = class(EBioError);

  /// <summary>
  ///   Abstract base class for OpenSSL BIO (Basic I/O) wrappers. Manages the
  ///   lifecycle and reference counting of the underlying PBIO handle.
  /// </summary>
  TCustomBIO = class abstract
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
    function DoClone: TCustomBIO; virtual; abstract;
    /// <summary>
    ///   Attempts to increment the OpenSSL internal reference count of the BIO.
    /// </summary>
    function TryBIOAddRef: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Increments the reference count and returns the BIO handle. Raises
    ///   EBioCloneError on failure.
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
    procedure SetAsBytes(Value: TIdBytes); virtual;
    /// <summary>
    ///   Virtual getter to retrieve the BIO content as a RawByteString.
    /// </summary>
    function GetAsString: RawByteString; virtual;
    /// <summary>
    ///   Virtual setter to write a RawByteString into the BIO.
    /// </summary>
    procedure SetAsString(Value: RawByteString); virtual;
    /// <summary>
    ///   Returns True if the underlying OpenSSL BIO is a memory-type BIO.
    /// </summary>
    function GetIsMemoryBIO: Boolean;{$IFDEF USE_INLINE}inline;{$ENDIF}
  protected
    /// <summary>
    ///   Initializes the wrapper with an existing BIO handle and specific
    ///   capability flags.
    /// </summary>
    constructor Create(ABIO: PBIO; AFlags: TFlags); overload;
  public
    /// <summary>
    ///   Default constructor. Raises EBioCreateError as a specific BIO type
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
    function Clone: TCustomBIO; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Reads ASize bytes from the BIO into AData. Returns the number of bytes
    ///   actually read.
    /// </summary>
    function Read(var AData; ASize: TIdC_SIZET): TIdC_SIZET; virtual;
    /// <summary>
    ///   Writes ASize bytes from AData into the BIO. Returns the number of
    ///   bytes actually written.
    /// </summary>
    function Write(const AData; ASize: TIdC_SIZET): TIdC_SIZET; virtual;
    /// <summary>
    ///   The raw OpenSSL PBIO handle.
    /// </summary>
    property BIO: PBIO read FBIO;
    /// <summary>
    ///   The capability flags assigned to this BIO instance.
    /// </summary>
    property Flags: TFLags read FFlags;
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
  TCustomBIOHelper = class helper for TCustomBIO
  public const
    /// <summary>Buffer size used for chunked stream operations.</summary>
    cChunkSize = 4096;
  public
    /// <summary>
    ///   Validates that the BIO is readable; raises EBioReadError if not.
    /// </summary>
    procedure CheckCanRead; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the BIO is writable; raises EBioWriteError if not.
    /// </summary>
    procedure CheckCanWrite; {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    ///   Validates that the BIO is clonable; raises EBioCloneError if not.
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
  TOsslMemBio = class(TCustomBIO)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoClone: TCustomBIO; override;
  public
    /// <summary>Creates a new, empty OpenSSL managed memory BIO.</summary>
    constructor Create; overload;
  end;

  /// <summary>
  ///   Abstract base for BIOs that wrap existing Pascal-managed memory buffers
  ///   without copying.
  /// </summary>
  TCustomRawMemBio = class abstract(TCustomBIO)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FMemPtr: Pointer;
    FMemSize: TIdC_SIZET;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    /// <summary>
    ///   Called during destruction to allow descendants to perform additional
    ///   cleanup.
    /// </summary>
    procedure DoFreeMem; virtual;
    /// <summary>
    ///   Initializes a non-copying BIO (BIO_new_mem_buf) pointing to the
    ///   specified memory address.
    /// </summary>
    constructor Create(AMemPtr: Pointer; ASize: TIdC_SIZET; AIsClonable: boolean = False); overload;
  public
    /// <summary>
    ///   Ensures cleanup of the Delphi wrapper and calls DoFreeMem.
    /// </summary>
    destructor Destroy; override;
  end;

  /// <summary>A read-only BIO wrapper for a TIdBytes array.</summary>
  TBytesBio = class(TCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: TIdBytes;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoClone: TCustomBIO; override;
    function GetAsBytes: TIdBytes; override;
  public
    /// <summary>
    ///   Creates a BIO that reads directly from the provided TIdBytes.
    /// </summary>
    constructor Create(const AData: TIdBytes);
  end;

  /// <summary>A read-only BIO wrapper for a RawByteString.</summary>
  TRawByteStringBIO = class(TCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: RawByteString;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoClone: TCustomBIO; override;
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
  TRecordBIO<T: record> = class(TCustomRawMemBio)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FData: T;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoClone: TCustomBIO; override;
  public
    /// <summary>
    ///   Creates a BIO that reads directly from an internal copy of the
    ///   provided record.
    /// </summary>
    constructor Create(const AData: T);
  end;

implementation

{ TCustomBIO }

constructor TCustomBIO.Create;
begin
  EBioCreateError.RaiseWithMessage('Unable to create BIO wrapper with this constructor.');
end;

constructor TCustomBIO.Create(ABIO: PBIO; AFlags: TFlags);
begin
  if not Assigned(ABIO) then
    EBioCreateError.RaiseWithMessage('Unable to create BIO wrapper with the NULL BIO.');
  FBIO:=ABIO;
  FFlags:=AFlags;
end;

destructor TCustomBIO.Destroy;
begin
  BIO_free(FBIO);
  inherited;
end;

function TCustomBIO.TryBIOAddRef: boolean;
begin
  Result:=BIO_up_ref(FBIO) = 1;
end;

function TCustomBIO.GetIsMemoryBIO: Boolean;
begin
  Result:=BIO_method_type(FBIO) = BIO_TYPE_MEM;
end;

function TCustomBIO.GetPending: TIdC_SIZET;
begin
  Result:=BIO_ctrl_pending(FBIO);
end;

function TCustomBIO.Read(var AData; ASize: TIdC_SIZET): TIdC_SIZET;
var
  lResult: TIdC_INT;

begin
  if ASize = 0 then
    Exit;
  CheckCanRead;
  lResult:=BIO_read_ex(FBIO, AData, ASize, Result);
  if lResult <> 1 then
    EBioReadError.RaiseWithMessage('Error reading from the BIO object.')
end;

function TCustomBIO.Write(const AData; ASize: TIdC_SIZET): TIdC_SIZET;
var
  lResult: TIdC_INT;

begin
  if ASize = 0 then
    Exit;
  CheckCanWrite;
  lResult:=BIO_write_ex(FBIO, AData, ASize, Result);
  if lResult <> 1 then
    EBioWriteError.RaiseWithMessage('Error writting to the BIO object.')
end;

procedure TCustomBIO.SetAsBytes(Value: TIdBytes);
var
  lSize: TIdC_SIZET;

begin
  lSize:=Length(Value);
  if lSize > 0 then
    Write(Value[0], lSize);
end;

function TCustomBIO.GetAsBytes: TIdBytes;
var
  lSize: TIdC_SIZET;

begin
  lSize:=Pending;
  SetLength(Result, lSize);
  if lSize > 0 then
    Read(Result[0], lSize);
end;

procedure TCustomBIO.SetAsString(Value: RawByteString);
var
  lSize: TIdC_SIZET;

begin
  lSize:=Length(Value);
  if lSize > 0 then
    Write(Value[1], lSize);
end;

function TCustomBIO.GetAsString: RawByteString;
var
  lSize: TIdC_SIZET;

begin
  lSize:=Pending;
  SetLength(Result, lSize);
  if lSize > 0 then
    Read(Result[1], lSize);
end;

function TCustomBIO.BIOAddRef: PBIO;
begin
  if not TryBIOAddRef then
    EBioCloneError.RaiseWithMessage('BIO object cloning faulure.');
  Result:=FBIO;
end;

function TCustomBIO.Clone: TCustomBIO;
begin
  CheckCanClone;
  Result:=DoClone;
end;

{ TCustomBIOHelper }

procedure TCustomBIOHelper.CheckCanClone;
begin
  if not (cbClonable in Flags) then
    EBioCloneError.RaiseWithMessage('This BIO object is not configured for cloning.');
end;

procedure TCustomBIOHelper.CheckCanRead;
begin
  if not (cbReadable in Flags) then
    raise EBioReadError.Create('This BIO object is not configured for reading.');
end;

procedure TCustomBIOHelper.CheckCanWrite;
begin
  if not (cbWritable in Flags) then
    raise EBioReadError.Create('This BIO object is not configured for writting.');
end;

function TCustomBIOHelper.LoadFromStream(const AStream: TStream;
  ASize: TIdC_SIZET): TIdC_SIZET;
var
  lRemaining: TIdC_SIZET;
  lChunkToRead: TIdC_SIZET;
  lActuallyRead: TIdC_SIZET;
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
    lActuallyRead := AStream.Read(lBuf[0], Integer(lChunkToRead));
    if lActuallyRead <= 0 then Break;

    if Write(lBuf[0], lActuallyRead) <> lActuallyRead then
      EBioLoadStreamError.RaiseWithMessage('Error writing to BIO from stream.');

    Dec(lRemaining, lActuallyRead);
    Inc(Result, lActuallyRead);
  end;
end;

function TCustomBIOHelper.WriteToStream(const AStream: TStream;
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

{ TOsslMemBio }

constructor TOsslMemBio.Create;
begin
  inherited Create(BIO_new(BIO_s_mem()), cFlagsAll);
end;

function TOsslMemBio.DoClone: TCustomBIO;
begin
  Result := TOsslMemBio(ClassType).Create(BIOAddRef, Flags);
end;

{ TCustomRawMemBio }

constructor TCustomRawMemBio.Create(AMemPtr: Pointer; ASize: TIdC_SIZET;
  AIsClonable: boolean = False);
var
  LFlags: TFlags;

begin
  if (not Assigned(AMemPtr)) or (ASize = 0) then
    EBioCreateError.RaiseWithMessage('Unable to create BIO object with empty memory pointer.');

  LFlags:=[cbReadable];
  if AIsClonable then
    Include(LFlags, cbClonable);

  inherited Create(BIO_new_mem_buf(AMemPtr^, ASize), lFlags);
  FMemPtr := AMemPtr;
  FMemSize := ASize;
end;

destructor TCustomRawMemBio.Destroy;
begin
  DoFreeMem;
  inherited;
end;

procedure TCustomRawMemBio.DoFreeMem;
begin
  // Do Nothing by default;
end;

{ TBytesBio }

function TBytesBio.GetAsBytes: TIdBytes;
begin
  Result:=FData;
end;

constructor TBytesBio.Create(const AData: TIdBytes);
begin
  inherited Create(Pointer(AData), Length(AData), True);
  FData:=AData;
end;

function TBytesBio.DoClone: TCustomBIO;
begin
  Result:=TBytesBio.Create(FData);
end;

{ TRawByteStringBIO }

constructor TRawByteStringBIO.Create(const AData: RawByteString);
begin
  inherited Create(Pointer(AData), Length(AData), True);
  FData:=AData;
end;

function TRawByteStringBIO.DoClone: TCustomBIO;
begin
  Result:=TRawByteStringBIO.Create(FData);
end;

function TRawByteStringBIO.GetAsString: RawByteString;
begin
  Result:=FData;
end;

{ TRecordBIO<T> }

constructor TRecordBIO<T>.Create(const AData: T);
begin
  FData:=AData;
  inherited Create(@FData, SizeOf(AData), True);
end;

function TRecordBIO<T>.DoClone: TCustomBIO;
begin
  Result:=TRecordBIO<T>.Create(FData);
end;

end.
