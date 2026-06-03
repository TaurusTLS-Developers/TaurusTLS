# Detailed Design Document: Server-Side Multi-Tenancy, SNI Routing, and ECH Decryption

## 1. Class Definitions & Collections

### 1.1. Design-Time Collection Classes (`TaurusTLS_Sockets.pas`)
These classes allow developers to configure multiple virtual servers directly in the Delphi/Lazarus Object Inspector.

~~~pascal
type
  TTaurusTLSVirtualServerCollection = class;

  /// <summary>
  ///   Represents a single virtual server (tenant) with its own credentials and policies.
  /// </summary>
  TTaurusTLSVirtualServerItem = class(TCollectionItem)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FHostName: string;
    FNormalizedHostName: RawByteString; // Cached lower-case Punycode
    FIsWildcard: Boolean;
    FAssetStore: TTaurusTLSOSSLStore;   // Unified asset store (Delphi Stream, HSM, or URL)
    FClientTrustStore: TaurusTLS_X509Store;
    FECHStore: TTaurusTLSECHStore;
    FSSLCtx: PSSL_CTX;                  // Compiled private context
    FLeafCert: PX509;                   // Cached, reference-counted leaf certificate
    FECHPrivateKeyURI: string;          // Tentative/Under Review
    
    procedure BuildConfig;
    procedure FreeConfig;
    function GetIsWildcard: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    function GetDisplayName: string; override;
  public
    destructor Destroy; override;
    
    property SSLCtx: PSSL_CTX read FSSLCtx;
    property LeafCert: PX509 read FLeafCert;
    property IsWildcard: Boolean read GetIsWildcard;
    property NormalizedHostName: RawByteString read FNormalizedHostName;
  published
    property HostName: string read FHostName write FHostName;
    property AssetStore: TTaurusTLSOSSLStore read FAssetStore write FAssetStore;
    property ClientTrustStore: TaurusTLS_X509Store read FClientTrustStore write FClientTrustStore;
    property ECHStore: TTaurusTLSECHStore read FECHStore write FECHStore;
    property ECHPrivateKeyURI: string read FECHPrivateKeyURI write FECHPrivateKeyURI; // Tentative
  end;

  /// <summary>
  ///   Manages the collection of virtual servers and compiles their isolated contexts.
  /// </summary>
  TTaurusTLSVirtualServerCollection = class(TOwnedCollection)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    function GetItem(Index: Integer): TTaurusTLSVirtualServerItem;
    procedure SetItem(Index: Integer; const Value: TTaurusTLSVirtualServerItem);
  public
    constructor Create(AOwner: TPersistent);
    function Add: TTaurusTLSVirtualServerItem;
    function FindServer(const AHostName: string): TTaurusTLSVirtualServerItem;
    procedure BuildAllConfigs;
    procedure FreeAllConfigs;
    property Items[Index: Integer]: TTaurusTLSVirtualServerItem read GetItem write SetItem; default;
  end;
~~~

### 1.2. The High-Level Server Component Hook (`TaurusTLS.pas`)
The server-side IOHandler owns the collection, the high-performance runtime map, and the read-write synchronizer.

~~~pascal
type
  TTaurusTLSVirtualServerMap = TDictionary<RawByteString, TTaurusTLSVirtualServerItem>;

  TTaurusTLSServerIOHandler = class(TIdServerIOHandlerSSLBase)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FVirtualServers: TTaurusTLSVirtualServerCollection;
    FRuntimeServerMap: TTaurusTLSVirtualServerMap;
    FMapLock: TMultiReadExclusiveWriteSynchronizer; // Protects the runtime dictionary
    FStrictSNICheck: Boolean;
    FDefaultConfig: TTaurusTLSCustomSocketConfig;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    
    procedure InitServerCTX;
    property VirtualServers: TTaurusTLSVirtualServerCollection read FVirtualServers;
    property StrictSNICheck: Boolean read FStrictSNICheck write FStrictSNICheck;
    property DefaultConfig: TTaurusTLSCustomSocketConfig read FDefaultConfig;
  end;
~~~

---

## 2. Servername Callback Bridge Implementation

The static servername callback is registered on the master `SSL_CTX`. It intercepts the client's SNI and dynamically swaps the active context to the matching virtual server using thread-safe read locks.

~~~pascal
function TaurusTLS_ServerNameCallback(ssl: PSSL; ad: PInteger; arg: Pointer): Integer; cdecl;
var
  LServerName: PIdAnsiChar;
  LAnsiName: RawByteString;
  LServerIO: TTaurusTLSServerIOHandler;
  LServerItem: TTaurusTLSVirtualServerItem;
  LTargetCtx: PSSL_CTX;
  LIdx: Integer;
begin
  Result := SSL_TLSEXT_ERR_OK; // Default: SNI acknowledged [1.2.8]

  if not Assigned(ssl) then Exit;
  
  LServerName := SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if not Assigned(LServerName) then Exit;

  LServerIO := TTaurusTLSServerIOHandler(arg);
  if not Assigned(LServerIO) then Exit;

  // The wire SNI is already in Punycode. We only need to lowercase it.
  LAnsiName := LowerCase(RawByteString(LServerName));

  // Acquire a shared read lock to enable parallel, congestion-free lookups
  LServerIO.FMapLock.BeginRead;
  try
    // --- PHASE 1: EXACT MATCH (O(1) Hash Lookup) ---
    if LServerIO.FRuntimeServerMap.TryGetValue(LAnsiName, LServerItem) then
    begin
      LTargetCtx := LServerItem.SSLCtx;
      if Assigned(LTargetCtx) then
      begin
        if SSL_get_SSL_CTX(ssl) <> LTargetCtx then
          SSL_set_SSL_CTX(ssl, LTargetCtx);
        Exit;
      end;
    end;

    // --- PHASE 2: WILDCARD/SAN FALLBACK (O(N) Collection Walk) ---
    // If exact match fails, iterate over the complete collection of virtual servers.
    // X509_check_host natively checks the SAN list first (including wildcards),
    // then falls back to checking the Common Name (CN).
    for LIdx := 0 to LServerIO.VirtualServers.Count - 1 do
    begin
      LServerItem := LServerIO.VirtualServers[LIdx];
      
      if (LServerItem.LeafCert <> nil) and 
         (X509_check_host(LServerItem.LeafCert, PIdAnsiChar(LAnsiName), Length(LAnsiName), 0, nil) = 1) then
      begin
        LTargetCtx := LServerItem.SSLCtx;
        if Assigned(LTargetCtx) then
        begin
          if SSL_get_SSL_CTX(ssl) <> LTargetCtx then
            SSL_set_SSL_CTX(ssl, LTargetCtx);
          Exit;
        end;
      end;
    end;

    // --- PHASE 3: UNKNOWN SNI POLICY ---
    if LServerIO.StrictSNICheck then
    begin
      if Assigned(ad) then
        ad^ := SSL_AD_UNRECOGNIZED_NAME;     // Set unrecognized_name alert byte [1.2.8]
      Result := SSL_TLSEXT_ERR_ALERT_FATAL; // Hard-abort handshake immediately [1.2.8]
    end
    else
    begin
      Result := SSL_TLSEXT_ERR_NOACK; // Unacknowledged, fall back to default [1.2.8]
    end;
  finally
    LServerIO.FMapLock.EndRead;
  end;
end;
~~~

---

## 3. Virtual Server Configuration Compilation (BuildConfig)

Each TTaurusTLSVirtualServerItem compiles its own SSL_CTX during startup.

#### How the ECH private key is safely loaded:
1.  The standard server certificate and primary private keys are loaded via the main `FAssetStore: TTaurusTLSOSSLStore` [1.1].
2.  The public ECH config list is loaded into `FECHStore` using `SetConfigList`.
3.  If `FECHPrivateKeyURI` is specified, we instantiate a temporary, lightweight `TTaurusTLSOSSLStore` specifically to load the HPKE private key (since it *is* a standard `EVP_PKEY` format) [1.1].
4.  Because both `TTaurusTLSECHStore` and `TTaurusTLSVirtualServerItem` are declared in the same unit (`TaurusTLS_Sockets.pas`), we can safely invoke `FECHStore`'s unit-protected **`DoSetKeyAndReadBioPem`** method [2] to pair the loaded private key with the ECH configuration cleanly [2].

~~~pascal
procedure TTaurusTLSVirtualServerItem.BuildConfig;
var
  LItem: TTaurusTLSOSSLStore.TStoreItem;
  LMatchingKey: PEVP_PKEY;
  LEchKeyStore: TTaurusTLSOSSLStore;
  LEchKeyItem: TTaurusTLSOSSLStore.TStoreItem;
  LItemIdx, LKeyIdx: Integer;
  LEchKey: PEVP_PKEY;
  LBio: PBIO;
begin
  if Assigned(FSSLCtx) then Exit;

  FSSLCtx := SSL_CTX_new(TLS_server_method());
  if FSSLCtx = nil then
    raise Exception.Create('Failed to allocate SSL_CTX.');

  // 1. Load and Pair Server PKI Identities from FAssetStore (Standard certs and keys)
  if Assigned(FAssetStore) then
  begin
    for LItemIdx := 0 to FAssetStore.FList.Count - 1 do
    begin
      LItem := FAssetStore.FList[LItemIdx];
      if LItem.&Type = sitCert then
      begin
        // Cache the leaf certificate and increment its reference count safely
        if FLeafCert = nil then
        begin
          FLeafCert := LItem.Cert;
          X509_up_ref(FLeafCert); // Isolate leaf cert lifetime
        end;

        LMatchingKey := nil;
        // Search the store for the private key that cryptographically matches this certificate
        for LKeyIdx := 0 to FAssetStore.FList.Count - 1 do
        begin
          if FAssetStore.FList[LKeyIdx].&Type = sitPrivKey then
          begin
            if X509_check_private_key(LItem.Cert, FAssetStore.FList[LKeyIdx].PrivKey) = 1 then
            begin
              LMatchingKey := FAssetStore.FList[LKeyIdx].PrivKey;
              Break;
            end;
          end;
        end;

        // Bind the paired identity atomically
        if Assigned(LMatchingKey) then
        begin
          if SSL_CTX_use_cert_and_key(FSSLCtx, LItem.Cert, LMatchingKey, nil, 0) <> 1 then
            raise Exception.Create('Failed to bind server certificate/key identity.');
        end;
      end;
    end;
  end;

  // 2. Load Client mTLS Trust Anchors
  if Assigned(FClientTrustStore) then
  begin
    X509_STORE_up_ref(FClientTrustStore.Store);
    SSL_CTX_set_cert_store(FSSLCtx, FClientTrustStore.Store);
  end;

  // 3. Configure and Attach Server ECH Decryption Keys
  if (FECHConfigList <> '') and Assigned(FECHStore) then
  begin
    // Step A: Load the public ECHConfigList payload
    FECHStore.SetConfigList(RawByteString(FECHConfigList));

    // Step B: Load the associated ECH private key if configured
    if FECHPrivateKeyURI <> '' then
    begin
      LEchKey := nil;
      // Load the ECH private key using our standard OSSL_STORE (since it is a standard EVP_PKEY)
      LEchKeyStore := TTaurusTLSOSSLStore.Create(RawByteString(FECHPrivateKeyURI), nil, [sitPrivKey]);
      try
        if LEchKeyStore.Count[sitPrivKey] > 0 then
        begin
          for LItemIdx := 0 to LEchKeyStore.FList.Count - 1 do
          begin
            LEchKeyItem := LEchKeyStore.FList[LItemIdx];
            if LEchKeyItem.&Type = sitPrivKey then
            begin
              LEchKey := LEchKeyItem.PrivKey;
              Break;
            end;
          end;
        end;

        if Assigned(LEchKey) then
        begin
          // Create a temporary PEM BIO of the ECH Config to bind the key
          LBio := BIO_new_mem_buf(PAnsiChar(AnsiString(FECHConfigList)), Length(FECHConfigList));
          try
            // Call the unit-protected method to pair the private key with the ECH configuration
            FECHStore.DoSetKeyAndReadBioPem(LBio, LEchKey, 0);
          finally
            BIO_free(LBio);
          end;
        end;
      finally
        LEchKeyStore.Free;
      end;
    end;

    // Step C: Attach the configured ECH store to the virtual server's context
    FECHStore.Attach(FSSLCtx);
  end;
end;
~~~