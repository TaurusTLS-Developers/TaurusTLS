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

unit TaurusTLS_ECHStore;

interface

uses
  Classes,
  SysUtils,
  IdCTypes,
  IdGlobal,
  TaurusTLSHeaders_types,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_ech,
  TaurusTLSHeaders_hpke;

type
  /// <summary>
  ///   Base class for OpenSSL ECH (Encrypted Client Hello) store management.
  /// </summary>
  /// <remarks>
  ///   This class wraps the OpenSSL 4.0 OSSL_ECHSTORE API, providing functionality 
  ///   to manage ECH configurations and keys.
  /// </remarks>
  TTaurusTLS_CustomECHStore = class abstract
  public const
    /// <summary>Maximum allowed length for an ECHConfigList.</summary>
    cECHConfigListMaxLen = (1 shl 16) - 1;
    /// <summary>Minimum allowed length for a single ECHConfig.</summary>
    cECHConfigMinLen = OSSL_ECH_MIN_ECHCONFIG_LEN;
    /// <summary>Maximum allowed length for a single ECHConfig.</summary>
    cECHConfigMaxLen = OSSL_ECH_MAX_ECHCONFIG_LEN;

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FStore: POSSL_ECHSTORE;

  private
    function GetCount: TIdC_Int;
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    function GetKeyCount: TIdC_INT;
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    function GetECHConfig(AIdx: TIdC_INT): string;
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    function GetHasPrivateKey(AIdx: TIdC_INT): boolean;
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    function GetIdxForRetry(AIdx: TIdC_INT): TIdC_INT;
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    function GetPublicName(AIdx: TIdC_INT): string;
    function GetAge(AIdx: TIdC_INT): TIdC_TIMET;
      {$IFDEF USE_INLINE} inline; {$ENDIF}

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    /// <summary>Initializes a new instance from an existing OpenSSL ECH store pointer.</summary>
    /// <param name="AStore">Pointer to the OSSL_ECHSTORE object. Must not be nil.</param>
    constructor Create(AStore: POSSL_ECHSTORE); overload;
    /// <summary>Returns the ECH version supported by this store.</summary>
    function GetECHVersion: TIdC_UINT16; virtual;

    /// <summary>Generates a new ECH configuration and adds it to the store.</summary>
    /// <param name="APublicName">The public name for the ECH configuration.</param>
    /// <param name="ASuite">The HPKE suite to use.</param>
    procedure DoNewConfig(const APublicName: string; const ASuite: OSSL_HPKE_SUITE);
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Reads an ECHConfigList from a BIO and adds it to the store.</summary>
    /// <param name="ABio">The BIO containing the binary ECHConfigList.</param>
    procedure DoSetConfigList(ABio: PBio); overload;
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Sets a private key and reads an ECH configuration from a PEM BIO.</summary>
    /// <param name="ABio">The BIO containing the PEM-encoded configuration.</param>
    /// <param name="APrivKey">The private key to associate with the configuration.</param>
    /// <param name="AIdxForRetry">Index for retry signaling.</param>
    procedure DoSetKeyAndReadBioPem(ABio: PBio; APrivKey: PEVP_PKEY;
      AIdxForRetry: TIdC_INT); {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Reads an ECH configuration from a PEM BIO.</summary>
    /// <param name="ABio">The BIO containing the PEM-encoded configuration.</param>
    /// <param name="AIdxForRetry">Index for retry signaling.</param>
    procedure DoReadBioPem(ABio: PBio; AIdxForRetry: TIdC_INT);
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Writes an ECH configuration from the store to a PEM BIO.</summary>
    /// <param name="ABio">The destination BIO.</param>
    /// <param name="AIdx">The index of the configuration to write.</param>
    procedure DoWriteBioPem(ABio: PBio; AIdx: TIdC_INT);
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Flushes old ECH keys from the store.</summary>
    /// <param name="AAge">The age threshold for flushing keys.</param>
    procedure DoFlushKeys(AAge: TIdC_TIMET);
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Retrieves information about a specific entry in the ECH store.</summary>
    /// <param name="AIdx">The index of the entry.</param>
    /// <param name="AAge">Pointer to receive the age of the entry.</param>
    /// <param name="APublicName">Pointer to receive the public name (caller must free).</param>
    /// <param name="AECHConfig">Pointer to receive the ECH configuration (caller must free).</param>
    /// <param name="AHasPrivateKey">Pointer to receive a flag indicating if a private key is present.</param>
    /// <param name="AIdxForRetry">Pointer to receive the retry index.</param>
    procedure DoGetInfo(AIdx: TIdC_INT; AAge: PIdC_TIMET;
      APublicName, AECHConfig: PPIdAnsiChar;
      AHasPrivateKey, AIdxForRetry: PIdC_INT); {$IFDEF USE_INLINE} inline; {$ENDIF}

    /// <summary>The number of private keys in the store.</summary>
    property KeyCount: TIdC_INT read GetKeyCount;
    /// <summary>Indicates if a private key is present for the configuration at the specified index.</summary>
    property HasPrivateKey[AIdx: TIdC_INT]: boolean read GetHasPrivateKey;
    /// <summary>The retry index for the configuration at the specified index.</summary>
    property IdxForRetry[AIdx: TIdC_INT]: TIdC_INT read GetIdxForRetry;
  public
    /// <summary>Creates a new empty ECH store.</summary>
    constructor Create; overload;
    /// <summary>
    ///   Creates a copy of ECH store associated with an SSL context.
    /// </summary>
    /// <param name="ASSLCtx">
    ///   The SSL context pointer.
    /// </param>
    constructor Create(ASSLCtx: PSSL_CTX); overload;
    /// <summary>
    ///   Creates a copy of ECH store associated with an SSL object.
    /// </summary>
    /// <param name="ASSL">
    ///   The SSL object pointer.
    /// </param>
    constructor Create(ASSL: PSSL); overload;
    /// <summary>Destroys the ECH store and releases associated OpenSSL resources.</summary>
    destructor Destroy; override;

    /// <summary>
    ///   Sets the ECHConfigList from a Base64 string.
    /// </summary>
    /// <param name="AECHConfigList">
    ///   The ECHConfigList data in the Base64 string.
    /// </param>
    procedure SetConfigList(AECHConfigList: string); overload;
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>
    ///   Selects a specific ECH configuration from the store for use.
    /// </summary>
    /// <param name="AIdx">
    ///   The index of the configuration to select.
    /// </param>
    /// <remarks>
    ///   All configurations except selected are purged from the store.
    /// </remarks>
    procedure SelectConfig(AIdx: TIdC_INT);
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Attaches the ECH store to an OpenSSL SSL context object.</summary>
    /// <param name="ASSLCtx">The SSL context pointer to attach the store to.</param>
    /// <remarks>The SSL context takes a reference to the store.</remarks>
    procedure Attach(ASSLCtx: PSSL_CTX); overload; {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Attaches the ECH store to an OpenSSL SSL object.</summary>
    /// <param name="ASSL">The SSL object pointer to attach the store to.</param>
    /// <remarks>The SSL object takes a reference to the store.</remarks>
    procedure Attach(ASSL: PSSL); overload; {$IFDEF USE_INLINE} inline; {$ENDIF}

    /// <summary>Retrieves the public name of the configuration at the specified index.</summary>
    property PublicName[AIdx: TIdC_INT]: string read GetPublicName;
    /// <summary>Retrieves the ECH configuration at the specified index.</summary>
    property ECHConfig[AIdx: TIdC_INT]: string read GetECHConfig;
    /// <summary>Retrieves the age of the configuration at the specified index.</summary>
    property Age[AIdx: TIdC_INT]: TIdC_TIMET read GetAge;
    /// <summary>The total number of configurations in the store.</summary>
    property Count: TIdC_INT read GetCount;
    /// <summary>The underlying OpenSSL ECH store pointer.</summary>
    property Store: POSSL_ECHSTORE read FStore;
  end;

  /// <summary>
  ///   ECH store specialized for client-side operations.
  /// </summary>
  TClientECHStore = class(TTaurusTLS_CustomECHStore)
  end;

  /// <summary>
  ///   ECH store specialized for server-side operations, including key management.
  /// </summary>
  TServerECHStore = class(TTaurusTLS_CustomECHStore)
  private
    function GetAsPem(AIdx: TIdC_INT): string;
    function PemToBio(const APemStr: RawByteString): PBIO; {$IFDEF USE_INLINE} inline; {$ENDIF}
    function ReadPemToStr(const AStream: TStream): RawByteString;
    procedure ReadPem(const APemStr: RawByteString; AIdxForRetry: TIdC_INT); overload;
    procedure SetKeyAndReadPem(APrivKey: PEVP_PKEY; APemStr: RawByteString;
      AIdxForRetry: TIdC_INT); overload;

  public
    /// <summary>Generates a new ECH configuration with associated keys.</summary>
    /// <param name="APublicName">The public name for the ECH configuration.</param>
    /// <param name="ASuite">The HPKE suite to use.</param>
    procedure NewConfig(const APublicName: string; const ASuite: OSSL_HPKE_SUITE);
      {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>
    ///   Removes expired private keys from the store.
    /// </summary>
    /// <param name="AAge">
    ///   Threshold age in seconds for removal.
    /// </param>
    procedure FlushKeys(AAge: TIdC_TIMET);
      {$IFDEF USE_INLINE} inline; {$ENDIF}

    /// <summary>Loads an ECH configuration from a PEM string.</summary>
    /// <param name="APemStr">The PEM-encoded configuration.</param>
    /// <param name="AIdxForRetry">Index for retry signaling.</param>
    procedure ReadPem(const APemStr: string; AIdxForRetry: TIdC_INT); overload;
    /// <summary>Loads an ECH configuration from a stream containing PEM data.</summary>
    /// <param name="AStream">The stream to read from.</param>
    /// <param name="AIdxForRetry">Index for retry signaling.</param>
    procedure ReadPem(const AStream: TStream; AIdxForRetry: TIdC_INT) overload;
    /// <summary>Sets a private key and loads an ECH configuration from a PEM string.</summary>
    /// <param name="APrivKey">The private key to associate.</param>
    /// <param name="APemStr">The PEM-encoded configuration.</param>
    /// <param name="AIdxForRetry">Index for retry signaling.</param>
    procedure SetKeyAndReadPem(APrivKey: PEVP_PKEY; const APemStr: string;
      AIdxForRetry: TIdC_INT); overload; {$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Sets a private key and loads an ECH configuration from a stream.</summary>
    /// <param name="APrivKey">The private key to associate.</param>
    /// <param name="AStream">The stream containing PEM data.</param>
    /// <param name="AIdxForRetry">Index for retry signaling.</param>
    procedure SetKeyAndReadPem(APrivKey: PEVP_PKEY; const AStream: TStream;
      AIdxForRetry: TIdC_INT); overload;{$IFDEF USE_INLINE} inline; {$ENDIF}
    /// <summary>Writes an ECH configuration from the store to a stream in PEM format.</summary>
    /// <param name="AStream">The destination stream.</param>
    /// <param name="AIdx">The index of the configuration to write.</param>
    procedure WritePem(const AStream: TStream; AIdx: TIdC_INT);

    /// <summary>The number of private keys in the store.</summary>
    property KeyCount;
    /// <summary>Indicates if a private key is present for the configuration at the specified index.</summary>
    property HasPrivateKey;
    /// <summary>The retry index for the configuration at the specified index.</summary>
    property IdxForRetry;
    /// <summary>Returns the PEM representation of the configuration at the specified index.</summary>
    property AsPem[AIdx: TIdC_INT]: string read GetAsPem;
  end;

  /// <summary>
  ///   Exception class for ECH store related errors.
  /// </summary>
  ETaurusTLSECHStoreError = class(ETaurusTLSError)
    /// <summary>Checks an OpenSSL return code and raises an exception on failure.</summary>
    /// <param name="ACode">The return code to check (1 indicates success).</param>
    /// <param name="AMessage">The error message to use if checking fails.</param>
    class procedure CheckAndRaise(ACode: TIdC_INT; const AMessage: string);
    /// <summary>Checks an OpenSSL return code and raises a formatted exception on failure.</summary>
    /// <param name="ACode">The return code to check (1 indicates success).</param>
    /// <param name="AMessage">The formatted error message.</param>
    /// <param name="AArgs">Arguments for the formatted message.</param>
    class procedure CheckAndRaiseFmt(ACode: TIdC_INT; const AMessage: string;
      AArgs: array of const);
  end;

implementation

uses
{$IFDEF WINDOWS}
  IdIDN,
{$ENDIF}
  TaurusTLSHeaders_bio,
  TaurusTLS_ResourceStrings;

{ ETaurusTLSECHStoreError }

class procedure ETaurusTLSECHStoreError.CheckAndRaise(ACode: TIdC_INT;
  const AMessage: string);
{$IFDEF USE_NORETURN}noreturn;{$ENDIF}
begin
  if ACode <> 1 then
    RaiseWithMessage(AMessage);
end;

class procedure ETaurusTLSECHStoreError.CheckAndRaiseFmt(ACode: TIdC_INT;
  const AMessage: string; AArgs: array of const);
{$IFDEF USE_NORETURN}noreturn;{$ENDIF}
begin
  if ACode <> 1 then
    RaiseWithMessageFmt(AMessage, AArgs);
end;

{ TTaurusTLS_CustomECHStore }

constructor TTaurusTLS_CustomECHStore.Create(AStore: POSSL_ECHSTORE);
begin
  if not Assigned(AStore) then
    ETaurusTLSECHStoreError.RaiseWithMessage(RSMsg_ECHStore_null_value_err);
  FStore:=AStore;
end;

constructor TTaurusTLS_CustomECHStore.Create;
begin
  Create(OSSL_ECHSTORE_new(nil, nil));
end;

constructor TTaurusTLS_CustomECHStore.Create(ASSL: PSSL);
begin
  Create(SSL_get1_echstore(ASSL));
end;

constructor TTaurusTLS_CustomECHStore.Create(ASSLCtx: PSSL_CTX);
begin
  Create(SSL_CTX_get1_echstore(ASSLCtx));
end;

destructor TTaurusTLS_CustomECHStore.Destroy;
begin
  OSSL_ECHSTORE_free(FStore);
  FStore:=nil;
  inherited;
end;

function TTaurusTLS_CustomECHStore.GetECHConfig(AIdx: TIdC_INT): string;
var
  LECHConfig: PIdAnsiChar;

begin
  LECHConfig:=nil;
  try
    DoGetInfo(AIdx, nil, nil, @LECHConfig, nil, nil);
    Result:=string(LECHConfig);
  finally
    OPENSSL_free(LECHConfig)
  end;
end;

function TTaurusTLS_CustomECHStore.GetECHVersion: TIdC_UINT16;
begin
  Result:=OSSL_ECH_CURRENT_VERSION;
end;

function TTaurusTLS_CustomECHStore.GetHasPrivateKey(AIdx: TIdC_INT): boolean;
var
  lHasPrivateKey: LongBool; // 32-bit integer; 0 = False; (not 0) = True;

begin
  lHasPrivateKey:=False;
  DoGetInfo(AIdx, nil, nil, nil, @lHasPrivateKey, nil);
  Result:=lHasPrivateKey;
end;

function TTaurusTLS_CustomECHStore.GetIdxForRetry(AIdx: TIdC_INT): TIdC_INT;
begin
  DoGetInfo(AIdx, nil, nil, nil, nil, @Result);
end;

function TTaurusTLS_CustomECHStore.GetAge(AIdx: TIdC_INT): TIdC_TIMET;
begin
  DoGetInfo(AIdx, @Result, nil, nil, nil, nil);
end;

function TTaurusTLS_CustomECHStore.GetCount: TIdC_INT;
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_num_entries(FStore, @Result),
    RSMsg_ECHStore_num_err);
end;

function TTaurusTLS_CustomECHStore.GetKeyCount: TIdC_INT;
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_num_keys(FStore, @Result),
    RSMsg_ECHStore_numkey_err);
end;

function TTaurusTLS_CustomECHStore.GetPublicName(AIdx: TIdC_INT): string;
var
  LPublicName: PIdAnsiChar;

begin
  LPublicName:=nil;
  try
    DoGetInfo(AIdx, nil, @LPublicName, nil, nil, nil);
    Result:=string(LPublicName);
  finally
    OPENSSL_free(LPublicName)
  end;
end;

procedure TTaurusTLS_CustomECHStore.DoSetConfigList(ABio: PBio);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_read_echconfiglist(FStore, ABio),
    RSMsg_ECHStore_read_echconfiglist_err
  );
end;

procedure TTaurusTLS_CustomECHStore.DoReadBioPem(ABio: PBio;
  AIdxForRetry: TIdC_INT);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_read_pem(FStore, ABio, AIdxForRetry),
    RSMsg_ECHStore_pem_read_err
  );
end;

procedure TTaurusTLS_CustomECHStore.SelectConfig(AIdx: TIdC_INT);
begin
  ETaurusTLSECHStoreError.CheckAndRaiseFmt(
    OSSL_ECHSTORE_downselect(FStore, AIdx),
    RSMsg_ECHStore_downselect_err, [AIdx]
  );
end;

procedure TTaurusTLS_CustomECHStore.SetConfigList(AECHConfigList: string);
var
  LBio: PBio;
  lInLen: TIdC_INT;
  LECHConfigList: RawByteString;

begin
  lInLen:=Length(AECHConfigList);
  if (lInLen > cECHConfigListMaxLen) then
    ETaurusTLSECHStoreError.RaiseWithMessage(RSMsg_ECHStore_too_long_echconfiglist_err);

  LECHConfigList:=RawByteString(AECHConfigList);
  lBio:=nil;
  try
    lBio:=BIO_new_mem_buf(LECHConfigList[1], lInLen);
    if not Assigned(lBio) then
       ETaurusTLSECHStoreError.RaiseWithMessage(RSMsg_ECHStore_read_echconfiglist_err);

    DoSetConfigList(lBio);
  finally
    BIO_free(lBio);
  end;
end;

procedure TTaurusTLS_CustomECHStore.DoSetKeyAndReadBioPem(ABio: PBio;
  APrivKey: PEVP_PKEY; AIdxForRetry: TIdC_INT);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_set1_key_and_read_pem(FStore, APrivKey, ABio, AIdxForRetry),
    RSMsg_ECHStore_keypem_read_err);
end;

procedure TTaurusTLS_CustomECHStore.DoWriteBioPem(ABio: PBio; AIdx: TIdC_INT);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_write_pem(FStore, AIdx, ABio),
    RSMsg_ECHStore_pem_write_err);
end;

procedure TTaurusTLS_CustomECHStore.DoFlushKeys(AAge: TIdC_TIMET);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_flush_keys(FStore, AAge),
    RSMsg_ECHStore_flushkeys_err);
end;

procedure TTaurusTLS_CustomECHStore.DoGetInfo(AIdx: TIdC_INT; AAge: PIdC_TIMET;
  APublicName, AECHConfig: PPIdAnsiChar; AHasPrivateKey,
  AIdxForRetry: PIdC_INT);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    OSSL_ECHSTORE_get1_info(FStore, AIdx, AAge, APublicName, AECHConfig,
      AHasPrivateKey, AIdxForRetry),
    RSMsg_ECHStore_getinfo_err);
end;

procedure TTaurusTLS_CustomECHStore.DoNewConfig(const APublicName: string;
  const ASuite: OSSL_HPKE_SUITE);
var
  LPublicName: TBytes;

begin
  {$IFNDEF WINDOWS}
  LPublicName:=BytesOf(APublicName+#0);
  {$ELSE}
  if Assigned(IdnToAscii) then
    LPublicName:=BytesOf(IDNToPunnyCode(
      {$IFDEF STRING_IS_UNICODE}
      APublicName
      {$ELSE}
      TIdUnicodeString(APublicName)
      {$ENDIF}
      )+#0)
  else
    LPublicName := BytesOf(APublicName+#0);
  {$ENDIF}
  ETaurusTLSECHStoreError.CheckAndRaise(
     OSSL_ECHSTORE_new_config(Store, GetECHVersion, 0,
      PIdAnsiChar(LPublicName), ASuite),
    RSMsg_ECHStore_new_config_err);
end;

procedure TTaurusTLS_CustomECHStore.Attach(ASSLCtx: PSSL_CTX);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    SSL_CTX_set1_echstore(ASSLCtx, FStore),
    RSMsg_ECHStore_attachsslctx_err
  );
end;

procedure TTaurusTLS_CustomECHStore.Attach(ASSL: PSSL);
begin
  ETaurusTLSECHStoreError.CheckAndRaise(
    SSL_set1_echstore(ASSL, FStore),
    RSMsg_ECHStore_attachssl_err
  );
end;

{ TServerECHStore }

procedure TServerECHStore.FlushKeys(AAge: TIdC_TIMET);
begin
  DoFlushKeys(AAge);
end;

function TServerECHStore.GetAsPem(AIdx: TIdC_INT): string;
var
  LBio: PBio;
  LPemPtr: PIdAnsiChar;
  LPemLen: TIdC_INT;

begin
  LBio:=nil;
  Result:='';

  try
    LBio:=BIO_new(BIO_s_mem());
    DoWriteBioPem(lBIO, AIdx);
    LPemLen:=BIO_get_mem_data(LBio, Pointer(LPemPtr));
    if Assigned(LPemPtr) and (LPemLen > 0) then
      SetString(Result, LPemPtr, LPemLen);
  finally
    BIO_free(LBio);
  end;
end;

procedure TServerECHStore.NewConfig(const APublicName: string;
  const ASuite: OSSL_HPKE_SUITE);
begin
  DoNewConfig(APublicName, ASuite);
end;

function TServerECHStore.PemToBio(const APemStr: RawByteString): PBIO;
var
  LLen: TIdC_INT;

begin
  Result:=nil;
  LLen:=Length(APemStr);
  if (LLen < cECHConfigMinLen) or (LLen > cECHConfigMaxLen) then
    ETaurusTLSECHStoreError.RaiseWithMessage(RSMsg_ECHStore_pemfmt_err);

  Result:=BIO_new_mem_buf(APemStr[1], LLen);
end;

function TServerECHStore.ReadPemToStr(const AStream: TStream): RawByteString;
var
  LLen: Int64;

begin
  if not Assigned(AStream) then
    ETaurusTLSECHStoreError.RaiseWithMessage(RSMsg_ECHStore_stream_err);

  LLen:=AStream.Size - AStream.Position;
  if (LLen < cECHConfigMinLen) or (LLen > cECHConfigMaxLen) then
    ETaurusTLSECHStoreError.RaiseWithMessage(RSMsg_ECHStore_pemfmt_err);

  SetLength(Result, LLen);
  AStream.Read(Result[1], LLen);
end;

procedure TServerECHStore.ReadPem(const AStream: TStream; AIdxForRetry: TIdC_INT);
begin
  ReadPem(ReadPemToStr(AStream), AIdxForRetry);
end;

procedure TServerECHStore.ReadPem(const APemStr: RawByteString;
  AIdxForRetry: TIdC_INT);
var
  LBio: PBio;

begin
  LBio:=PemToBio(APemStr);
  try
    DoReadBioPem(LBio, AIdxForRetry);
  finally
    BIO_free(LBio);
  end;
end;

procedure TServerECHStore.ReadPem(const APemStr: string; AIdxForRetry: TIdC_INT);
begin
  ReadPem(RawByteString(APemStr), AIdxForRetry);
end;

procedure TServerECHStore.SetKeyAndReadPem(APrivKey: PEVP_PKEY;
  APemStr: RawByteString; AIdxForRetry: TIdC_INT);
var
  LBio: PBIO;

begin
  LBio:=PemToBio(APemStr);
  try
    DoSetKeyAndReadBioPem(LBio, APrivKey, AIdxForRetry);
  finally
    BIO_free(LBio);
  end;
end;

procedure TServerECHStore.SetKeyAndReadPem(APrivKey: PEVP_PKEY;
  const APemStr: string; AIdxForRetry: TIdC_INT);
begin
  SetKeyAndReadPem(APrivKey, RawByteString(APemStr), AIdxForRetry);
end;

procedure TServerECHStore.SetKeyAndReadPem(APrivKey: PEVP_PKEY;
  const AStream: TStream; AIdxForRetry: TIdC_INT);
begin
  SetKeyAndReadPem(APrivKey, ReadPemToStr(AStream), AIdxForRetry);
end;

procedure TServerECHStore.WritePem(const AStream: TStream; AIdx: TIdC_INT);
var
  LBio: PBio;
  LPemPtr: PIdAnsiChar;
  LPemLen: TIdC_INT;

begin
  if not Assigned(AStream) then
    ETaurusTLSECHStoreError.RaiseWithMessage(RSMsg_ECHStore_stream_err);

  LBio:=nil;

  try
    LBio:=BIO_new(BIO_s_mem());
    DoWriteBioPem(lBIO, AIdx);
    LPemLen:=BIO_get_mem_data(LBio, Pointer(LPemPtr));
    if Assigned(LPemPtr) and (LPemLen > 0) then
      AStream.Write(LPemPtr^, LPemLen);
  finally
    BIO_free(LBio);
  end;
end;

end.
