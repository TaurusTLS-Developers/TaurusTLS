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
    FSHA256AfterFirstLoad: Boolean;
    FEmptyDir: string;
    FModuleFile: string;
    FBuiltIn: Boolean;
    function DigestWorks(AMD: Pointer): Boolean;
    function MD4Works: Boolean;
    function IsBuiltIn: Boolean;
    procedure RequireOpenSSL3;
    procedure RequireModule;
    procedure RequireModuleFile;
    procedure RequireNotBuiltIn;
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
    /// <summary>
    ///   When the provider is built into libcrypto (OpenSSL built with
    ///   no-module), it is loaded whatever the module path is.
    /// </summary>
    [Test]
    procedure BuiltIn_IsLoadedWhateverThePath;
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
    /// <summary>
    ///   Loading the provider keeps the default provider available, so
    ///   SHA-256 still works.
    /// </summary>
    /// <remarks>
    ///   OpenSSL keeps the default provider once anything has used it, even
    ///   when a later load disables the fallback providers. So SetupFixture
    ///   checks SHA-256 straight after the first load. That only catches a
    ///   lost default provider when no earlier fixture in the run used
    ///   OpenSSL, as when this fixture is run on its own.
    /// </remarks>
    [Test]
    procedure Load_KeepsDefaultProvider;
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
{$IFDEF MSWINDOWS}
    /// <summary>
    ///   A relative module file name is relative to the current directory.
    ///   OpenSSL resolves relative paths against its modules directory.
    /// </summary>
    [Test]
    procedure RelativeFile_IsRelativeToCurrentDir;
    /// <summary>A relative directory is relative to the current directory.</summary>
    [Test]
    procedure RelativeDirectory_IsRelativeToCurrentDir;
{$ENDIF}
  end;

implementation

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  {$ENDIF}
  System.SysUtils,
  System.IOUtils,
  TaurusTLSLoader,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_provider,
  TaurusTLS_LegacyProviders;

{$IFDEF MSWINDOWS}
/// <summary>The file name of the legacy provider module, if it is loaded.</summary>
function LoadedModuleFile: string;
const
  CNames: array[0..2] of string = ('legacy-x64.dll', 'legacy-arm64.dll', 'legacy.dll');
var
  LName: string;
  LHandle: HMODULE;
  LFileName: array[0..MAX_PATH] of Char;
begin
  for LName in CNames do
  begin
    LHandle := GetModuleHandle(PChar(LName));
    if (LHandle <> 0) and
       (GetModuleFileName(LHandle, LFileName, Length(LFileName)) > 0) then
      Exit(LFileName);
  end;
  Result := '';
end;
{$ENDIF}

{ TTaurusTLSLegacyProvidersFixture }

function TTaurusTLSLegacyProvidersFixture.DigestWorks(AMD: Pointer): Boolean;
var
  LCtx: PEVP_MD_CTX;
begin
  LCtx := EVP_MD_CTX_new;
  Assert.IsNotNull(LCtx, 'EVP_MD_CTX_new');
  try
    Result := EVP_DigestInit_ex(LCtx, AMD, nil) = 1;
  finally
    EVP_MD_CTX_free(LCtx);
  end;
  ERR_clear_error;
end;

// OpenSSL loads a provider by name from the providers built into libcrypto
// before it looks for a module. A separate library context whose module search
// path does not exist can only find a built-in provider.
function TTaurusTLSLegacyProvidersFixture.IsBuiltIn: Boolean;
var
  LCtx: POSSL_LIB_CTX;
  LProvider: POSSL_PROVIDER;
begin
  LCtx := OSSL_LIB_CTX_new;
  Assert.IsNotNull(LCtx, 'OSSL_LIB_CTX_new');
  try
    Assert.AreEqual(1, OSSL_PROVIDER_set_default_search_path(LCtx,
      PAnsiChar(AnsiString(TPath.Combine(FEmptyDir, 'no-modules')))));
    LProvider := OSSL_PROVIDER_try_load(LCtx, 'legacy', 0);
    Result := LProvider <> nil;
    if Result then
      OSSL_PROVIDER_unload(LProvider);
  finally
    OSSL_LIB_CTX_free(LCtx);
  end;
  ERR_clear_error;
end;

function TTaurusTLSLegacyProvidersFixture.MD4Works: Boolean;
begin
  Result := DigestWorks(EVP_md4);
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

procedure TTaurusTLSLegacyProvidersFixture.RequireModuleFile;
begin
  RequireModule;
  if FModuleFile = '' then
    Assert.Pass('The legacy provider module file name is not known');
end;

procedure TTaurusTLSLegacyProvidersFixture.RequireNotBuiltIn;
begin
  RequireOpenSSL3;
  if FBuiltIn then
    Assert.Pass('The legacy provider is built into libcrypto');
end;

procedure TTaurusTLSLegacyProvidersFixture.SetupFixture;
begin
  inherited;
  FEmptyDir := TPath.Combine(TPath.GetTempPath, TPath.GetGUIDFileName);
  TDirectory.CreateDirectory(FEmptyDir);
  // OpenSSL 1.0.2 has no OpenSSL_version_num
  FIsOpenSSL3 := SSLeay >= $30000000;
  if FIsOpenSSL3 then
  begin
    FBuiltIn := IsBuiltIn;
    FModuleFound := LoadLegacyProvider;
    if FModuleFound then
      FSHA256AfterFirstLoad := DigestWorks(EVP_sha256);
{$IFDEF MSWINDOWS}
    FModuleFile := LoadedModuleFile;
{$ENDIF}
    UnloadLegacyProvider;
    // An OpenSSL configuration file can activate the legacy provider by
    // itself, so MD4 can work without this provider
    FMD4WithoutProvider := MD4Works;
  end;
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

procedure TTaurusTLSLegacyProvidersFixture.BuiltIn_IsLoadedWhateverThePath;
begin
  RequireOpenSSL3;
  if not FBuiltIn then
    Assert.Pass('The legacy provider is not built into libcrypto');
  Assert.IsTrue(LoadLegacyProvider(FEmptyDir), 'Directory with no module');
  Assert.IsTrue(MD4Works);
  UnloadLegacyProvider;
  Assert.IsTrue(LoadLegacyProvider(TPath.Combine(FEmptyDir, 'missing-legacy.dll')),
    'Missing module file');
  Assert.IsTrue(MD4Works);
end;

procedure TTaurusTLSLegacyProvidersFixture.MissingFile_IsNotLoaded;
begin
  RequireNotBuiltIn;
  Assert.IsFalse(LoadLegacyProvider(TPath.Combine(FEmptyDir, 'missing-legacy.dll')));
  Assert.IsFalse(IsLegacyProviderLoaded);
end;

procedure TTaurusTLSLegacyProvidersFixture.DirectoryWithoutModule_IsNotLoaded;
begin
  RequireNotBuiltIn;
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

procedure TTaurusTLSLegacyProvidersFixture.Load_KeepsDefaultProvider;
begin
  RequireModule;
  Assert.IsTrue(FSHA256AfterFirstLoad, 'SHA-256 after the first load');
  Assert.IsTrue(LoadLegacyProvider);
  Assert.IsTrue(DigestWorks(EVP_sha256));
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

{$IFDEF MSWINDOWS}
procedure TTaurusTLSLegacyProvidersFixture.RelativeFile_IsRelativeToCurrentDir;
var
  LModuleDir: string;
  LOldDir: string;
begin
  RequireModuleFile;
  // The path has a directory part, which OpenSSL would look for under its
  // modules directory
  LModuleDir := ExtractFileDir(FModuleFile);
  LOldDir := GetCurrentDir;
  Assert.IsTrue(SetCurrentDir(ExtractFileDir(LModuleDir)));
  try
    Assert.IsTrue(LoadLegacyProvider(TPath.Combine(ExtractFileName(LModuleDir),
      ExtractFileName(FModuleFile))));
  finally
    SetCurrentDir(LOldDir);
  end;
  Assert.IsTrue(IsLegacyProviderLoaded);
  Assert.IsTrue(MD4Works);
end;

procedure TTaurusTLSLegacyProvidersFixture.RelativeDirectory_IsRelativeToCurrentDir;
var
  LModuleDir: string;
  LOldDir: string;
begin
  RequireModuleFile;
  LModuleDir := ExtractFileDir(FModuleFile);
  LOldDir := GetCurrentDir;
  Assert.IsTrue(SetCurrentDir(ExtractFileDir(LModuleDir)));
  try
    Assert.IsTrue(LoadLegacyProvider(ExtractFileName(LModuleDir)));
  finally
    SetCurrentDir(LOldDir);
  end;
  Assert.IsTrue(IsLegacyProviderLoaded);
  Assert.IsTrue(MD4Works);
end;
{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TTaurusTLSLegacyProvidersFixture);

end.
