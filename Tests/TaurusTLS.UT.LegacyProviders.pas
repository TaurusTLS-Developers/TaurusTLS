unit TaurusTLS.UT.LegacyProviders;

/// <summary>
///   Loading and unloading the OpenSSL 3 legacy provider with
///   TaurusTLS_LegacyProviders (#306). The unit is used here without the
///   TaurusTLS components.
/// </summary>
/// <remarks>
///   The tests that need the legacy provider module pass with a message when
///   OpenSSL cannot find it. Put the module next to libcrypto, or set
///   OPENSSL_MODULES to its directory, to run them.
/// </remarks>

interface

uses
  DUnitX.TestFramework, TaurusTLS.UT.TestClasses;

type
  [TestFixture]
  [Category('LegacyProviders')]
  TTaurusTLSLegacyProvidersFixture = class(TOsslBaseFixture)
  private
    FIsOpenSSL3: Boolean;
    FModuleFound: Boolean;
    FMD4WithoutProvider: Boolean;
    FEmptyDir: string;
    function MD4Works: Boolean;
    procedure RequireOpenSSL3;
    procedure RequireModule;
  public
    // DUnitX calls the first method it finds with the attribute, by its
    // address rather than through the VMT, so an override needs the attribute
    // too or it is never called
    [SetupFixture]
    procedure SetupFixture; override;
    [TearDownFixture]
    procedure TearDownFixture; override;
    /// <summary>Each test starts and ends with the provider unloaded.</summary>
    [TearDown]
    procedure TearDown;
    /// <summary>
    ///   Before OpenSSL 3.0 the legacy algorithms are built into libcrypto, so
    ///   loading reports success without loading a provider.
    /// </summary>
    [Test]
    procedure BeforeOpenSSL3_ReportsAvailable;
    /// <summary>A module file that does not exist is not loaded.</summary>
    [Test]
    procedure MissingFile_IsNotLoaded;
    /// <summary>A directory with no module in it is not loaded.</summary>
    [Test]
    procedure DirectoryWithoutModule_IsNotLoaded;
    /// <summary>Unloading when nothing is loaded does nothing.</summary>
    [Test]
    procedure Unload_WhenNotLoaded_DoesNothing;
    /// <summary>Loading the provider makes MD4 available.</summary>
    [Test]
    procedure Load_MakesMD4Available;
    /// <summary>Loading again keeps the provider that is already loaded.</summary>
    [Test]
    procedure Load_Twice_KeepsProvider;
    /// <summary>Unloading the provider takes MD4 away again.</summary>
    [Test]
    procedure Unload_RemovesMD4;
    /// <summary>
    ///   Unloading the OpenSSL libraries through the loader also unloads the
    ///   provider, before the OpenSSL functions are cleared.
    /// </summary>
    [Test]
    procedure LoaderUnload_UnloadsProvider;
    /// <summary>
    ///   Loading the provider loads the OpenSSL libraries first when they are
    ///   not loaded.
    /// </summary>
    [Test]
    procedure Load_LoadsLibraries;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  TaurusTLSLoader,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_evp,
  TaurusTLS_LegacyProviders;

{ TTaurusTLSLegacyProvidersFixture }

function TTaurusTLSLegacyProvidersFixture.MD4Works: Boolean;
var
  LCtx: PEVP_MD_CTX;
begin
  LCtx := EVP_MD_CTX_new;
  Assert.IsNotNull(LCtx, 'EVP_MD_CTX_new');
  try
    Result := EVP_DigestInit_ex(LCtx, EVP_md4, nil) = 1;
  finally
    EVP_MD_CTX_free(LCtx);
  end;
  ERR_clear_error;
end;

procedure TTaurusTLSLegacyProvidersFixture.RequireOpenSSL3;
begin
  if not FIsOpenSSL3 then
    Assert.Pass('Only applies to OpenSSL 3.0 and later');
end;

procedure TTaurusTLSLegacyProvidersFixture.RequireModule;
begin
  RequireOpenSSL3;
  if not FModuleFound then
    Assert.Pass('The legacy provider module was not found');
end;

procedure TTaurusTLSLegacyProvidersFixture.SetupFixture;
begin
  inherited;
  FIsOpenSSL3 := OpenSSL_version_num >= $30000000;
  if FIsOpenSSL3 then
  begin
    // Measured before the provider is loaded, because an OpenSSL
    // configuration file can activate the legacy provider by itself
    FMD4WithoutProvider := MD4Works;
    FModuleFound := LoadLegacyProvider;
    UnloadLegacyProvider;
  end;
  FEmptyDir := TPath.Combine(TPath.GetTempPath, TPath.GetGUIDFileName);
  TDirectory.CreateDirectory(FEmptyDir);
end;

procedure TTaurusTLSLegacyProvidersFixture.TearDownFixture;
begin
  if (FEmptyDir <> '') and TDirectory.Exists(FEmptyDir) then
    TDirectory.Delete(FEmptyDir);
  inherited;
end;

procedure TTaurusTLSLegacyProvidersFixture.TearDown;
begin
  UnloadLegacyProvider;
end;

procedure TTaurusTLSLegacyProvidersFixture.BeforeOpenSSL3_ReportsAvailable;
begin
  if FIsOpenSSL3 then
    Assert.Pass('Only applies before OpenSSL 3.0');
  Assert.IsTrue(LoadLegacyProvider(TPath.Combine(FEmptyDir, 'missing')));
  Assert.IsFalse(IsLegacyProviderLoaded);
end;

procedure TTaurusTLSLegacyProvidersFixture.MissingFile_IsNotLoaded;
begin
  RequireOpenSSL3;
  Assert.IsFalse(LoadLegacyProvider(TPath.Combine(FEmptyDir, 'missing-legacy.dll')));
  Assert.IsFalse(IsLegacyProviderLoaded);
end;

procedure TTaurusTLSLegacyProvidersFixture.DirectoryWithoutModule_IsNotLoaded;
begin
  RequireOpenSSL3;
  Assert.IsFalse(LoadLegacyProvider(FEmptyDir));
  Assert.IsFalse(IsLegacyProviderLoaded);
end;

procedure TTaurusTLSLegacyProvidersFixture.Unload_WhenNotLoaded_DoesNothing;
begin
  Assert.IsFalse(IsLegacyProviderLoaded);
  UnloadLegacyProvider;
  Assert.IsFalse(IsLegacyProviderLoaded);
end;

procedure TTaurusTLSLegacyProvidersFixture.Load_MakesMD4Available;
begin
  RequireModule;
  Assert.IsTrue(LoadLegacyProvider);
  Assert.IsTrue(IsLegacyProviderLoaded);
  Assert.IsTrue(MD4Works);
end;

procedure TTaurusTLSLegacyProvidersFixture.Load_Twice_KeepsProvider;
begin
  RequireModule;
  Assert.IsTrue(LoadLegacyProvider);
  Assert.IsTrue(LoadLegacyProvider(TPath.Combine(FEmptyDir, 'missing-legacy.dll')),
    'The provider that is already loaded is kept');
  Assert.IsTrue(IsLegacyProviderLoaded);
  Assert.IsTrue(MD4Works);
end;

procedure TTaurusTLSLegacyProvidersFixture.Unload_RemovesMD4;
begin
  RequireModule;
  Assert.IsTrue(LoadLegacyProvider);
  UnloadLegacyProvider;
  Assert.IsFalse(IsLegacyProviderLoaded);
  Assert.AreEqual(FMD4WithoutProvider, MD4Works);
end;

procedure TTaurusTLSLegacyProvidersFixture.LoaderUnload_UnloadsProvider;
begin
  RequireModule;
  Assert.IsTrue(LoadLegacyProvider);
  GetOpenSSLLoader.Unload;
  try
    Assert.IsFalse(IsLegacyProviderLoaded);
  finally
    Assert.IsTrue(GetOpenSSLLoader.Load, 'Reload the OpenSSL libraries');
  end;
end;

procedure TTaurusTLSLegacyProvidersFixture.Load_LoadsLibraries;
begin
  RequireModule;
  GetOpenSSLLoader.Unload;
  Assert.IsFalse(GetOpenSSLLoader.IsLoaded);
  Assert.IsTrue(LoadLegacyProvider);
  Assert.IsTrue(GetOpenSSLLoader.IsLoaded);
  Assert.IsTrue(MD4Works);
end;

initialization
  TDUnitX.RegisterTestFixture(TTaurusTLSLegacyProvidersFixture);

end.
