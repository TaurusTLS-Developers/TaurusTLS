unit TaurusTLS.UT.FIPSProperties;

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  DUnitX.TestFramework, TaurusTLS.UT.TestClasses;

type
  [TestFixture]
  [Category('FIPSProperties')]
  TTaurusTLSFIPSPropertiesFixture = class(TOsslAutoloadFixture)
  public
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
    [Test]
    procedure StaticFIPSIsUnsupported;
{$ELSE}
{$IFDEF UNITTEST}
    [Test]
    procedure LoadedLibraryExposesPropertyAPIs;
    [TestCase('Enable pointer missing', 'True')]
    [TestCase('Query pointer missing', 'False')]
    procedure MissingPointerIsUnavailable(AEnableMissing: Boolean);
    [TestCase('Enable exception stub', 'True')]
    [TestCase('Query exception stub', 'False')]
    procedure ExceptionStubIsUnavailable(AEnableMissing: Boolean);
    [TestCase('OpenSSL 1.1.1', '269488128,False')]
    [TestCase('OpenSSL 3.0', '805306368,True')]
    [TestCase('OpenSSL 4.0', '1073741824,True')]
    procedure VersionSelectsPropertyAPIs(AVersion: Cardinal; AExpected: Boolean);
    [Test]
    procedure MissingVersionIsUnavailable;
    [Test]
    procedure RepeatedReadsDoNotRevalidate;
    [Test]
    procedure UnloadAndReloadRefreshValidation;
    [Test]
    procedure FailedLoadLeavesValidationUnavailable;
{$ENDIF}
{$ENDIF}
  end;

implementation

uses
  System.SysUtils, IdCTypes, IdFIPS, TaurusTLSIdFIPS, TaurusTLS_ProviderFIPS
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSLoader, TaurusTLSHeaders_crypto, TaurusTLSHeaders_evp,
  TaurusTLSHeaders_types, TaurusTLSExceptionHandlers
{$ENDIF}
  ;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure TTaurusTLSFIPSPropertiesFixture.StaticFIPSIsUnsupported;
begin
  Assert.IsFalse(GetFIPSMode);
  Assert.IsFalse(SetFIPSMode(True));
  Assert.IsFalse(SetFIPSMode(False));
end;
{$ELSE}
{$IFDEF UNITTEST}
type
  TEnableFIPS = function(ctx: POSSL_LIB_CTX; enable: TIdC_INT): TIdC_INT; cdecl;
  TQueryFIPS = function(ctx: POSSL_LIB_CTX): TIdC_INT; cdecl;
  TOpenSSLVersion = function: TIdC_ULONG; cdecl;

var
  GTestVersion: TIdC_ULONG;
  GVersionQueryCount: Integer;
  GStubCallCount: Integer;

function TestOpenSSLVersion: TIdC_ULONG; cdecl;
begin
  Inc(GVersionQueryCount);
  Result := GTestVersion;
end;

function EnableExceptionStub(ctx: POSSL_LIB_CTX; enable: TIdC_INT): TIdC_INT; cdecl;
begin
  Inc(GStubCallCount);
  Result := 0;
  ETaurusTLSAPIFunctionNotPresent.RaiseException('Test enable stub');
end;

function QueryExceptionStub(ctx: POSSL_LIB_CTX): TIdC_INT; cdecl;
begin
  Inc(GStubCallCount);
  Result := 0;
  ETaurusTLSAPIFunctionNotPresent.RaiseException('Test query stub');
end;

procedure TTaurusTLSFIPSPropertiesFixture.LoadedLibraryExposesPropertyAPIs;
begin
  Assert.IsTrue(FIPSUsesPropertyAPIsForTests);
  Assert.IsTrue(FIPSPropertyAPIsAvailableForTests);
  Assert.IsTrue(EVP_default_properties_is_fips_enabled(nil) in [0, 1]);
end;

procedure TTaurusTLSFIPSPropertiesFixture.MissingPointerIsUnavailable(
  AEnableMissing: Boolean);
var
  LEnable: TEnableFIPS;
  LQuery: TQueryFIPS;
begin
  LEnable := EVP_default_properties_enable_fips;
  LQuery := EVP_default_properties_is_fips_enabled;
  try
    if AEnableMissing then
      EVP_default_properties_enable_fips := nil
    else
      EVP_default_properties_is_fips_enabled := nil;
    RevalidateFIPSPropertyAPIsForTests;
    Assert.IsTrue(FIPSUsesPropertyAPIsForTests);
    Assert.IsFalse(FIPSPropertyAPIsAvailableForTests);
    Assert.IsFalse(GetFIPSMode);
    Assert.IsFalse(SetFIPSMode(True));
  finally
    EVP_default_properties_enable_fips := LEnable;
    EVP_default_properties_is_fips_enabled := LQuery;
    RevalidateFIPSPropertyAPIsForTests;
  end;
  Assert.IsTrue(FIPSPropertyAPIsAvailableForTests);
end;

procedure TTaurusTLSFIPSPropertiesFixture.ExceptionStubIsUnavailable(
  AEnableMissing: Boolean);
var
  LEnable: TEnableFIPS;
  LQuery: TQueryFIPS;
  LLoader: IOpenSSLLoader;
  LIndex: Integer;
  LName: string;
begin
  LLoader := GetOpenSSLLoader;
  LEnable := EVP_default_properties_enable_fips;
  LQuery := EVP_default_properties_is_fips_enabled;
  if AEnableMissing then
    LName := 'EVP_default_properties_enable_fips'
  else
    LName := 'EVP_default_properties_is_fips_enabled';
  LIndex := LLoader.FailedToLoad.Add(LName);
  try
    GStubCallCount := 0;
    if AEnableMissing then
      EVP_default_properties_enable_fips := EnableExceptionStub
    else
      EVP_default_properties_is_fips_enabled := QueryExceptionStub;
    Assert.IsTrue(Assigned(EVP_default_properties_enable_fips));
    Assert.IsTrue(Assigned(EVP_default_properties_is_fips_enabled));
    RevalidateFIPSPropertyAPIsForTests;
    Assert.IsFalse(FIPSPropertyAPIsAvailableForTests);
    Assert.IsFalse(GetFIPSMode);
    Assert.IsFalse(SetFIPSMode(True));
    Assert.AreEqual(0, GStubCallCount);
  finally
    EVP_default_properties_enable_fips := LEnable;
    EVP_default_properties_is_fips_enabled := LQuery;
    LLoader.FailedToLoad.Delete(LIndex);
    RevalidateFIPSPropertyAPIsForTests;
  end;
  Assert.IsTrue(FIPSPropertyAPIsAvailableForTests);
end;

procedure TTaurusTLSFIPSPropertiesFixture.VersionSelectsPropertyAPIs(
  AVersion: Cardinal; AExpected: Boolean);
var
  LVersion: TOpenSSLVersion;
begin
  LVersion := OpenSSL_version_num;
  try
    GTestVersion := AVersion;
    OpenSSL_version_num := TestOpenSSLVersion;
    RevalidateFIPSPropertyAPIsForTests;
    Assert.AreEqual(AExpected, FIPSUsesPropertyAPIsForTests);
    Assert.AreEqual(AExpected, FIPSPropertyAPIsAvailableForTests);
  finally
    OpenSSL_version_num := LVersion;
    RevalidateFIPSPropertyAPIsForTests;
  end;
end;

procedure TTaurusTLSFIPSPropertiesFixture.MissingVersionIsUnavailable;
var
  LVersion: TOpenSSLVersion;
begin
  LVersion := OpenSSL_version_num;
  try
    OpenSSL_version_num := nil;
    RevalidateFIPSPropertyAPIsForTests;
    Assert.IsFalse(FIPSUsesPropertyAPIsForTests);
    Assert.IsFalse(FIPSPropertyAPIsAvailableForTests);
  finally
    OpenSSL_version_num := LVersion;
    RevalidateFIPSPropertyAPIsForTests;
  end;
end;

procedure TTaurusTLSFIPSPropertiesFixture.RepeatedReadsDoNotRevalidate;
var
  LVersion: TOpenSSLVersion;
  LLoader: IOpenSSLLoader;
  LIndex, I: Integer;
begin
  LLoader := GetOpenSSLLoader;
  LVersion := OpenSSL_version_num;
  try
    GTestVersion := $40000000;
    GVersionQueryCount := 0;
    OpenSSL_version_num := TestOpenSSLVersion;
    RevalidateFIPSPropertyAPIsForTests;
    Assert.AreEqual(1, GVersionQueryCount);
    LIndex := LLoader.FailedToLoad.Add('EVP_default_properties_enable_fips');
    try
      for I := 1 to 100 do
        Assert.IsTrue(FIPSPropertyAPIsAvailableForTests);
      Assert.AreEqual(1, GVersionQueryCount);
      // Initialization, rather than a state read, must observe changed diagnostics.
      RevalidateFIPSPropertyAPIsForTests;
      Assert.IsFalse(FIPSPropertyAPIsAvailableForTests);
      Assert.AreEqual(2, GVersionQueryCount);
    finally
      LLoader.FailedToLoad.Delete(LIndex);
    end;
  finally
    OpenSSL_version_num := LVersion;
    RevalidateFIPSPropertyAPIsForTests;
  end;
end;

procedure TTaurusTLSFIPSPropertiesFixture.UnloadAndReloadRefreshValidation;
var
  LLoader: IOpenSSLLoader;
begin
  LLoader := GetOpenSSLLoader;
  LLoader.Unload;
  try
    Assert.IsFalse(FIPSUsesPropertyAPIsForTests);
    Assert.IsFalse(FIPSPropertyAPIsAvailableForTests);
    Assert.IsFalse(GetFIPSMode);
  finally
    Assert.IsTrue(LLoader.Load);
  end;
  Assert.IsTrue(FIPSUsesPropertyAPIsForTests);
  Assert.IsTrue(FIPSPropertyAPIsAvailableForTests);
end;

procedure TTaurusTLSFIPSPropertiesFixture.FailedLoadLeavesValidationUnavailable;
var
  LLoader: IOpenSSLLoader;
  LPath: string;
begin
  LLoader := GetOpenSSLLoader;
  LPath := LLoader.OpenSSLPath;
  LLoader.Unload;
  try
    LLoader.OpenSSLPath := IncludeTrailingPathDelimiter(LPath) +
      'A04-Missing-' + TGUID.NewGuid.ToString;
    Assert.IsFalse(LLoader.Load);
    Assert.IsFalse(FIPSPropertyAPIsAvailableForTests);
  finally
    LLoader.Unload;
    LLoader.OpenSSLPath := LPath;
    Assert.IsTrue(LLoader.Load);
  end;
  Assert.IsTrue(FIPSPropertyAPIsAvailableForTests);
end;
{$ENDIF}
{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TTaurusTLSFIPSPropertiesFixture);

end.
