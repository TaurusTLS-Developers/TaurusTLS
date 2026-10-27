/// <summary>Shared provider-test configuration, cleanup and single-scenario selection.</summary>
/// <remarks>Every scenario requires a fresh invocation; no tests start child processes.</remarks>
unit TaurusTLS.UT.Providers.Common;

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  System.SysUtils, DUnitX.TestFramework, TaurusTLS.UT.TestClasses;

type
  /// <summary>Adds temporary configuration ownership to the shared manual fixture.</summary>
  TProviderTestFixture = class(TOsslBaseFixture)
  private
    FOriginalPath, FOriginalConfig, FOriginalVersions: string;
    FStateCaptured: Boolean;
  protected
    FTempDir: string;
    function CreateTempConfigFile(const AContent: string;
      const AFileName: string = ''): string;
  public
    destructor Destroy; override;
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;
  end;

var
  InstalledFIPSConfig: string;

/// <summary>Selects one known case; returns False after listing available scenarios.</summary>
function SelectProviderScenario: Boolean;

implementation

uses
  System.IOUtils, DUnitX.CommandLine.Options, DUnitX.FilterBuilder;

type
  TProviderScenario = record
    Name, TestName: string;
  end;

const
  Scenarios: array[0..31] of TProviderScenario = (
    (Name: 'legacy-active'; TestName: 'Legacy.TTaurusTLSLegacyProvidersLoaderFixture.TestIsLegacyProviderLoaded'),
    (Name: 'legacy-available'; TestName: 'Legacy.TTaurusTLSLegacyProvidersLoaderFixture.TestProvidersAvailability.Legacy'),
    (Name: 'default-available'; TestName: 'Legacy.TTaurusTLSLegacyProvidersLoaderFixture.TestProvidersAvailability.Default'),
    (Name: 'legacy-inactive'; TestName: 'Legacy.TLegacyProviderInactiveFixture.LegacyIsNotActivated'),
    (Name: 'legacy-md4-empty'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.MD4Empty'),
    (Name: 'legacy-md4-abcd'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.MD4ABCD'),
    (Name: 'legacy-ripemd160-empty'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.RIPEMD160Empty'),
    (Name: 'legacy-ripemd160-abcd'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.RIPEMD160ABCD'),
    (Name: 'legacy-whirlpool-empty'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.WhirlpoolEmpty'),
    (Name: 'legacy-whirlpool-abcd'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.WhirlpoolABCD'),
    (Name: 'default-sha1-empty'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.SHA1Empty'),
    (Name: 'default-sha1-abcd'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.SHA1ABCD'),
    (Name: 'default-sha256-empty'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.SHA256Empty'),
    (Name: 'default-sha256-abcd'; TestName: 'Legacy.TTaurusTLSHashes.HashTestHex.SHA256ABCD'),
    (Name: 'fips-available-unselected'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Mode_ReflectsSelection.AvailableNotSelected'),
    (Name: 'fips-selected'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Mode_ReflectsSelection.Selected'),
    (Name: 'fips-digest'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Digest_UsesFIPS'),
    (Name: 'fips-hmac-sha256'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.HMAC_UsesFIPS.SHA256'),
    (Name: 'fips-hmac-sha384'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.HMAC_UsesFIPS.SHA384'),
    (Name: 'fips-hmac-sha512'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.HMAC_UsesFIPS.SHA512'),
    (Name: 'fips-rejects-legacy'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Policy_RejectsLegacyNTLM'),
    (Name: 'fips-self-test'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Provider_SelfTest'),
    (Name: 'fips-reload'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Lifecycle_Reload'),
    (Name: 'fips-inactive-unselected'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Provider_NotActivated.OrdinarySelection'),
    (Name: 'fips-inactive-selected'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Provider_NotActivated.FIPSSelection'),
    (Name: 'fips-wrong-section'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Config_InvalidFIPS.WrongSection'),
    (Name: 'fips-missing-mac'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Config_InvalidFIPS.MissingModuleMAC'),
    (Name: 'fips-invalid-mac'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Config_InvalidFIPS.InvalidModuleMAC'),
    (Name: 'fips-missing-include'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Config_InvalidFIPS.MissingInclude'),
    (Name: 'fips-malformed-include'; TestName: 'FIPS.TConfiguredFIPSProviderFixture.Config_InvalidFIPS.MalformedInclude'),
    (Name: 'fips-missing-module'; TestName: 'FIPS.TProviderMissingFIPSFixture.Config_MissingFIPSModule'),
    (Name: 'legacy-status-reload'; TestName: 'Legacy.TTaurusTLSLegacyProvidersLoaderFixture.StatusAfterUnload')
  );

var
  ScenarioName: string;

function ScenarioSupported(const AName: string): Boolean;
begin
  Result := True;
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Result := not AName.StartsWith('fips-') and (AName <> 'legacy-inactive');
{$ENDIF}
{$IFNDEF STATICLOAD_OPENSSL}
  Result := Result and (AName <> 'legacy-status-reload');
{$ENDIF}
end;

function SelectProviderScenario: Boolean;
var
  Scenario: TProviderScenario;
begin
  if SameText(ScenarioName, 'list') then
  begin
    for Scenario in Scenarios do
      if ScenarioSupported(Scenario.Name) then
        Writeln(Scenario.Name);
    Exit(False);
  end;
  if (TDUnitX.Options.Run.Count <> 0) or (TDUnitX.Options.RunListFile <> '') or
    (TDUnitX.Options.Include <> '') or (TDUnitX.Options.Exclude <> '') then
    raise EArgumentException.Create('Use -scenario:<name> without DUnitX run/category filters');
  for Scenario in Scenarios do
    if SameText(ScenarioName, Scenario.Name) then
    begin
      if not ScenarioSupported(Scenario.Name) then
        raise EArgumentException.Create('Scenario is unsupported in this linking model: ' + ScenarioName);
      TDUnitX.Options.Run.Add('TaurusTLS.UT.Providers.' + Scenario.TestName);
      // CheckCommandLine builds the filter before scenario selection.
      TDUnitX.Filter := TDUnitXFilterBuilder.BuildFilter(TDUnitX.Options);
      Exit(True);
    end;
  raise EArgumentException.Create('Specify one known -scenario:<name>; use -scenario:list to list scenarios');
end;

procedure TProviderTestFixture.Setup;
begin
  Assert.IsFalse(Loader.IsLoaded, 'Provider scenarios require exclusive loader ownership');
  FOriginalPath := Loader.OpenSSLPath;
  FOriginalConfig := Loader.ConfigFile;
  FOriginalVersions := Loader.SSLLibVersions;
  FStateCaptured := True;
  try
    Unload;
    SetupFromCmd;
    FTempDir := TPath.Combine(TPath.GetTempPath, 'TaurusTLS_Providers_' + TGUID.NewGuid.ToString);
    TDirectory.CreateDirectory(FTempDir);
  except
    try
      TearDown;
    except
      on E: Exception do
        Log(TLogLevel.Error, 'Provider setup cleanup: ' + E.Message);
    end;
    raise;
  end;
end;

procedure TProviderTestFixture.TearDown;
begin
  try
    if FStateCaptured then
    try
      Unload;
    finally
      try
        Loader.ConfigFile := FOriginalConfig;
      finally
        try
          Loader.OpenSSLPath := FOriginalPath;
        finally
          Loader.SSLLibVersions := FOriginalVersions;
        end;
      end;
    end;
  finally
    FStateCaptured := False;
    if (FTempDir <> '') and TDirectory.Exists(FTempDir) then
      TDirectory.Delete(FTempDir, True);
    FTempDir := '';
  end;
end;

destructor TProviderTestFixture.Destroy;
begin
  try
    if FStateCaptured or (FTempDir <> '') then
      TearDown;
  finally
    inherited Destroy;
  end;
end;

function TProviderTestFixture.CreateTempConfigFile(const AContent, AFileName: string): string;
var
  FileName: string;
begin
  FileName := AFileName;
  if FileName = '' then
    FileName := TGUID.NewGuid.ToString + '.cnf';
  Result := TPath.Combine(FTempDir, FileName);
  // OpenSSL's configuration parser requires UTF-8 without a BOM.
  TFile.WriteAllBytes(Result, TEncoding.UTF8.GetBytes(AContent));
end;

initialization
  TOptionsRegistry.RegisterOption<string>('scenario', 'sc',
    'Run exactly one provider scenario, or list available scenarios with list',
    procedure(Value: string)
    begin
      if ScenarioName <> '' then
        raise EArgumentException.Create('Specify only one provider scenario per process');
      ScenarioName := Value;
    end);
  TOptionsRegistry.RegisterOption<string>('fips-module-config', 'fmc',
    'Path to installed fipsmodule.cnf for real FIPS provider scenarios',
    procedure(Value: string)
    begin
      if Value = '' then
        raise EArgumentException.Create('-fmc requires an installed fipsmodule.cnf path');
      InstalledFIPSConfig := TPath.GetFullPath(Value);
    end);
end.
