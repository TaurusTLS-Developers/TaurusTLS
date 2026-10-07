{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}
/// <summary>
/// Loads and unloads the OpenSSL 3 legacy provider. This unit does not depend
/// on the TaurusTLS components, so units such as TaurusTLS_NTLM can use it as
/// well as TaurusTLS.
/// </summary>
unit TaurusTLS_LegacyProviders;

{$I TaurusTLSLinkDefines.inc}

interface

/// <summary>
/// True if the OpenSSL 3 legacy provider was loaded by <see
/// cref="LoadLegacyProvider" />.
/// </summary>
function IsLegacyProviderLoaded: Boolean;
/// <summary>
/// Loads the OpenSSL 3 legacy provider so that legacy algorithms such as MD4,
/// DES, RC2, RC4 and Blowfish can be used. The OpenSSL libraries are loaded
/// first if they are not already loaded.
/// </summary>
/// <param name="AModulePath">
/// Optional. Either the file name of the legacy provider module or a
/// directory to search for it. A relative path is relative to the current
/// directory. If empty, the directory set in the <see
/// cref="TaurusTLSLoader|IOpenSSLLoader.OpenSSLPath" /> property and the
/// directory that libcrypto was loaded from are searched, followed by
/// OpenSSL's own search (the <c>OPENSSL_MODULES</c> environment variable or
/// the modules directory compiled into OpenSSL).
/// </param>
/// <returns>
/// True if the legacy algorithms are available. This includes OpenSSL
/// versions before 3.0, where they are built into libcrypto. False if the
/// provider could not be loaded.
/// </returns>
/// <remarks>
/// <para>
/// A directory is searched, along with its "providers" and "ossl-modules"
/// subdirectories, for a module named for the platform first and then for
/// the generic name. On Windows the platform names are "legacy-x64.dll" and
/// "legacy-arm64.dll" and the generic name is "legacy.dll". Renaming the
/// 64-bit module lets 32-bit and 64-bit modules share a directory in the
/// same way that "libcrypto-3.dll" and "libcrypto-3-x64.dll" do.
/// </para>
/// <para>
/// The default provider remains available after the legacy provider is
/// loaded. Legacy algorithms are not FIPS approved.
/// </para>
/// </remarks>
/// <seealso href="https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/">
/// OSSL_PROVIDER-legacy
/// </seealso>
function LoadLegacyProvider(const AModulePath: string = ''): Boolean;
/// <summary>
/// Unloads the OpenSSL 3 legacy provider if it was loaded by <see
/// cref="LoadLegacyProvider" />. It is also unloaded when <see
/// cref="TaurusTLSLoader|IOpenSSLLoader.Unload" /> unloads the OpenSSL
/// libraries, which <see cref="TaurusTLS|UnLoadOpenSSLLibrary" /> does.
/// </summary>
procedure UnloadLegacyProvider;

implementation

uses
{$IFDEF WINDOWS}
  {$IFDEF VCL_XE2_OR_ABOVE}
  WinAPI.Windows,
  {$ELSE}
  Windows,
  {$ENDIF}
{$ENDIF}
  Classes,
  SysUtils,
  IdGlobal,
  TaurusTLSConsts,
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSExceptionHandlers,
  TaurusTLS_ResourceStrings,
{$ENDIF}
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_provider,
  TaurusTLSLoader;

var
  LegacyProvider: POSSL_PROVIDER = nil;
  LegacyProviderUnloaderRegistered: Boolean = False;
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  DefaultProvider: POSSL_PROVIDER = nil;
  {$ENDIF}

const
  CLegacyProviderName = 'legacy';
{$IFDEF WINDOWS}
  CLegacyProviderFile = 'legacy.dll';
  {$IFDEF CPU64}
    {$IFDEF CPUARM64}
  CLegacyProviderPlatformFile = 'legacy-arm64.dll';
    {$ELSE}
  CLegacyProviderPlatformFile = 'legacy-x64.dll';
    {$ENDIF}
  {$ELSE}
  CLegacyProviderPlatformFile = '';
  {$ENDIF}
{$ELSE}
  {$IFDEF OSX_OR_IOS}
  CLegacyProviderFile = 'legacy.dylib';
  {$ELSE}
  CLegacyProviderFile = 'legacy.so';
  {$ENDIF}
  CLegacyProviderPlatformFile = '';
{$ENDIF}

procedure DoUnloadLegacyProvider;
begin
  if LegacyProvider <> nil then
  begin
    OSSL_PROVIDER_unload(LegacyProvider); //PALOFF - Functions called as procedures
    LegacyProvider := nil;
  end;
end;

function IsLegacyProviderLoaded: Boolean;
begin
  Result := LegacyProvider <> nil;
end;

// OpenSSL resolves a relative path against its modules directory rather than
// the current directory, so pass it a path from ExpandFileName or a bare name
function TryLoadLegacyProviderModule(const AModule: string): POSSL_PROVIDER;
begin
  // retain_fallbacks = 1 keeps the default provider available
  Result := OSSL_PROVIDER_try_load(nil, PIdAnsiChar(AnsiString(AModule)), 1);
  if Result = nil then
    ERR_clear_error;
end;

function TryLoadLegacyProviderFromDir(const ADir: string): POSSL_PROVIDER;
const
  CSubDirs: array[0..2] of string = ('', 'providers', 'ossl-modules');
var
  LBaseDir: string;
  LDir: string;
  i: Integer;
begin
  Result := nil;
  if ADir = '' then
    Exit;

  LBaseDir := IncludeTrailingPathDelimiter(ExpandFileName(ADir));
  for i := Low(CSubDirs) to High(CSubDirs) do
  begin
    LDir := LBaseDir;
    if CSubDirs[i] <> '' then
      LDir := LDir + CSubDirs[i] + PathDelim;

    if (CLegacyProviderPlatformFile <> '') and
       FileExists(LDir + CLegacyProviderPlatformFile) then
    begin
      Result := TryLoadLegacyProviderModule(LDir + CLegacyProviderPlatformFile);
      if Result <> nil then
        Exit;
    end;

    if FileExists(LDir + CLegacyProviderFile) then
    begin
      Result := TryLoadLegacyProviderModule(LDir + CLegacyProviderFile);
      if Result <> nil then
        Exit;
    end;
  end;
end;

{$IFDEF WINDOWS}
function LibCryptoDir: string;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  LVersions: TStringList;  //PALOFF - Created and freed objects
  LHandle: HMODULE;
  LFileName: array[0..MAX_PATH] of Char;
  i: Integer;
{$ENDIF}
begin
  Result := '';
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  LVersions := TStringList.Create;
  try
    LVersions.Delimiter := DirListDelimiter;
    LVersions.StrictDelimiter := True;
    LVersions.DelimitedText := GetOpenSSLLoader.SSLLibVersions;
    for i := 0 to LVersions.Count - 1 do
    begin
      LHandle := GetModuleHandle(PChar(CLibCryptoBase + LibSuffix + LVersions[i]));
      if (LHandle <> 0) and
         (GetModuleFileName(LHandle, LFileName, Length(LFileName)) > 0) then
      begin
        Result := ExtractFilePath(LFileName);
        Exit;
      end;
    end;
  finally
    LVersions.Free;
  end;
{$ENDIF}
end;
{$ENDIF}

function LoadLegacyProvider(const AModulePath: string = ''): Boolean;
begin
  SSLIsLoaded.Lock;
  try
    // Only the libraries are loaded so that this unit does not depend on the
    // TaurusTLS unit. TaurusTLS.LoadOpenSSLLibrary does its own setup when it
    // is called.
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    Result := GetOpenSSLLoader.Load;
  if not Result then
    Exit;
{$ELSE}
    Result := True;
{$ENDIF}

    if LegacyProvider <> nil then
      Exit;

    // Before OpenSSL 3.0 the legacy algorithms are built into libcrypto.
    if OpenSSL_version_num < $30000000 then
      Exit;

    // Load the configuration file before the provider, as
    // TaurusTLS.LoadOpenSSLLibrary does, so that any providers it activates
    // are in place first.
    if OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil) < 1 then
    begin
      ERR_clear_error;
      Result := False;
      Exit;
    end;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    if AModulePath <> '' then
    begin
      if DirectoryExists(AModulePath) then
        LegacyProvider := TryLoadLegacyProviderFromDir(AModulePath)
      else
        LegacyProvider := TryLoadLegacyProviderModule(ExpandFileName(AModulePath));
    end
    else
    begin

      LegacyProvider := TryLoadLegacyProviderFromDir(GetOpenSSLLoader.OpenSSLPath);

      if LegacyProvider = nil then
        LegacyProvider := TryLoadLegacyProviderFromDir(LibCryptoDir);
      // OpenSSL searches OPENSSL_MODULES or its compiled in modules directory
      if LegacyProvider = nil then
        LegacyProvider := TryLoadLegacyProviderModule(CLegacyProviderName);
    end;
{$ELSE}
    LegacyProvider := OSSL_PROVIDER_load(nil, 'legacy');
    if LegacyProvider = nil then
       raise ETaurusTLSLegacyProviderNotLoaded.Create(RSMsg_LegacyProviderNotLoaded);
    DefaultProvider := OSSL_PROVIDER_load(nil, 'default');
    if DefaultProvider = nil then
      raise ETaurusTLSDefaultProviderNotLoaded.Create(RSMsg_DefaultProviderNotLoaded);
{$ENDIF}
    Result := LegacyProvider <> nil;

    // IOpenSSLLoader.Unload runs the unloaders in reverse order, so this one
    // runs while the OpenSSL functions are still assigned.
    if Result and not LegacyProviderUnloaderRegistered then
    begin
      Register_SSLUnloader(DoUnloadLegacyProvider);
      LegacyProviderUnloaderRegistered := True;
    end;
  finally
    SSLIsLoaded.Unlock;
  end;
end;

procedure UnloadLegacyProvider;
begin
  SSLIsLoaded.Lock;
  try
    DoUnloadLegacyProvider;
  finally
    SSLIsLoaded.Unlock;
  end;
end;

{$IFDEF  OPENSSL_STATIC_LINK_MODEL}
initialization
  LegacyProvider := nil;
  DefaultProvider := nil;
finalization
  if Assigned(LegacyProvider) then
  begin
    OSSL_PROVIDER_unload(LegacyProvider);
    LegacyProvider := nil;
  end;
  if Assigned(DefaultProvider) then
  begin
    OSSL_PROVIDER_unload(DefaultProvider);
    DefaultProvider := nil;
  end;
{$ENDIF}
end.
