{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 - 2025 TaurusTLS Developers, All Rights Reserved       * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

unit TaurusTLS.UT.Utils.Tests;

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I TaurusTLSUTCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  DUnitX.TestFramework, TaurusTLS.UT.TestClasses;

type
  [TestFixture('', 'Checks manual and automatic OpenSSL fixture lifecycles, command-line defaults, exception propagation and failure cleanup. '
    + 'Requires native-library settings matching the target; uses temporary controlled configuration files.')]
  [Category('Fixtures,Loader.Fixtures')]
  TFixtureLifecycleTests = class(TOsslBaseFixture)
  private
    FOriginalPath, FOriginalVersions, FOriginalConfig: string;
    FCmdPath, FCmdConfig, FDir, FValidConfig: string;
    FCaptured: Boolean;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure Teardown;
    /// <summary>Applying defaults never loads OpenSSL.</summary>
    [Test]
    procedure Manual_ConfigOnly;
    /// <summary>Load preserves the loader's typed exception; Unload resets failure.</summary>
    [Test]
    procedure Manual_Exception;
    /// <summary>Repeated Load does not acquire fixture reference counts.</summary>
    [TestCase('OneLoad', '1')]
    [TestCase('ThreeLoads', '3')]
    procedure Manual_Repeated(const ACount: Integer);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    /// <summary>A missing dynamic library returns False without hiding the result.</summary>
    [Test]
    procedure Manual_False;
{$ENDIF}
    /// <summary>The autoload fixture makes OpenSSL ready and then unloads it.</summary>
    [Test]
    procedure Auto_LoadUnload;
    /// <summary>Failed automatic setup preserves its error and resets failed state.</summary>
    [Test]
    procedure Auto_FailureCleanup;
    /// <summary>Destruction releases loading when normal fixture teardown was skipped.</summary>
    [Test]
    procedure Auto_DestructorCleanup;
  end;

implementation

uses
  System.SysUtils, System.IOUtils, TaurusTLSLoader, TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_crypto;

type
  TAutoloadProbe = class(TOsslAutoloadFixture)
  protected
    procedure SetupFromCmd; override;
  public
    ConfigOverride: string;
  end;

procedure TAutoloadProbe.SetupFromCmd;
begin
  inherited SetupFromCmd;
  Loader.ConfigFile := ConfigOverride;
end;

procedure TFixtureLifecycleTests.Setup;
begin
  Assert.IsFalse(Loader.IsLoaded, 'Fixture contract tests require exclusive loader ownership');
  FOriginalPath := Loader.OpenSSLPath;
  FOriginalVersions := Loader.SSLLibVersions;
  FOriginalConfig := Loader.ConfigFile;
  FCaptured := True;
  try
    Unload;
    SetupFromCmd;
    FCmdPath := Loader.OpenSSLPath;
    FCmdConfig := Loader.ConfigFile;
    FDir := TPath.Combine(TPath.GetTempPath, 'TaurusTLS_Fixtures_' + TGUID.NewGuid.ToString);
    TDirectory.CreateDirectory(FDir);
    FValidConfig := TPath.Combine(FDir, 'valid.cnf');
    TFile.WriteAllText(FValidConfig,
      'openssl_conf = init' + sLineBreak +
      '[init]' + sLineBreak +
      'ssl_conf = ssl_settings' + sLineBreak +
      '[ssl_settings]' + sLineBreak +
      'system_default = tls_defaults' + sLineBreak +
      '[tls_defaults]' + sLineBreak +
      'MinProtocol = TLSv1.2' + sLineBreak);
  except
    try
      Teardown;
    except
      on E: Exception do
        Log(TLogLevel.Error, 'Fixture test setup cleanup: ' + E.Message);
    end;
    raise;
  end;
end;

procedure TFixtureLifecycleTests.Teardown;
begin
  try
    if FCaptured then
    try
      Unload;
    finally
      Loader.ConfigFile := FOriginalConfig;
      Loader.OpenSSLPath := FOriginalPath;
      Loader.SSLLibVersions := FOriginalVersions;
    end;
  finally
    FCaptured := False;
    if (FDir <> '') and TDirectory.Exists(FDir) then
      TDirectory.Delete(FDir, True);
    FDir := '';
  end;
end;

procedure TFixtureLifecycleTests.Manual_ConfigOnly;
begin
  Loader.ConfigFile := TPath.Combine(FDir, 'must_not_be_loaded.cnf');
  SetupFromCmd;
  Assert.AreEqual(FCmdPath, Loader.OpenSSLPath);
  Assert.AreEqual(FCmdConfig, Loader.ConfigFile);
  Assert.IsTrue(Loader.State = lsNotLoaded);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Assert.IsFalse(Assigned(OpenSSL_version_num));
{$ENDIF}
end;

procedure TFixtureLifecycleTests.Manual_Exception;
begin
  Loader.ConfigFile := TPath.Combine(FDir, 'missing.cnf');
  Assert.WillRaise(
    procedure
    begin
      Load;
    end, ETaurusTLSConfigFilePathError);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Loader.ConfigFile := FValidConfig;
  Assert.IsTrue(Load, 'A previous expected failure must not poison subsequent loading');
end;

procedure TFixtureLifecycleTests.Manual_Repeated(const ACount: Integer);
var
  I: Integer;
begin
  Loader.ConfigFile := FValidConfig;
  for I := 1 to ACount do
    Assert.IsTrue(Load);
  CheckLoaded;
  Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded, 'One Unload must suffice after repeated Load calls');
  Unload;
  Assert.IsFalse(Loader.IsLoaded);
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TFixtureLifecycleTests.Manual_False;
begin
  Loader.OpenSSLPath := TPath.Combine(FDir, 'missing_libraries');
  Loader.SSLLibVersions := 'missing_fixture_library_' + TGUID.NewGuid.ToString;
  Assert.IsFalse(Load);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded);
end;
{$ENDIF}

procedure TFixtureLifecycleTests.Auto_LoadUnload;
var
  LProbe: TAutoloadProbe;
begin
  LProbe := TAutoloadProbe.Create;
  try
    LProbe.ConfigOverride := FValidConfig;
    LProbe.SetupFixture;
    Assert.IsTrue(Loader.IsLoaded);
    LProbe.TearDownFixture;
    Assert.IsTrue(Loader.State = lsNotLoaded);
  finally
    LProbe.Free;
  end;
end;

procedure TFixtureLifecycleTests.Auto_FailureCleanup;
var
  LProbe: TAutoloadProbe;
begin
  LProbe := TAutoloadProbe.Create;
  try
    LProbe.ConfigOverride := TPath.Combine(FDir, 'missing_autoload.cnf');
    Assert.WillRaise(
      procedure
      begin
        LProbe.SetupFixture;
      end, ETaurusTLSConfigFilePathError);
    Assert.IsTrue(Loader.State = lsNotLoaded, 'Setup failure must reset loader state');
    LProbe.ConfigOverride := FValidConfig;
    LProbe.SetupFixture;
    Assert.IsTrue(Loader.IsLoaded, 'Expected setup failure must not block recovery');
    LProbe.TearDownFixture;
  finally
    LProbe.Free;
  end;
end;

procedure TFixtureLifecycleTests.Auto_DestructorCleanup;
var
  LProbe: TAutoloadProbe;
begin
  LProbe := TAutoloadProbe.Create;
  try
    LProbe.ConfigOverride := FValidConfig;
    LProbe.SetupFixture;
    Assert.IsTrue(Loader.IsLoaded);
  finally
    LProbe.Free;
  end;
  Assert.IsTrue(Loader.State = lsNotLoaded);
end;

initialization
  TDUnitX.RegisterTestFixture(TFixtureLifecycleTests);

end.
