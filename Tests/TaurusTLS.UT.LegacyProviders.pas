unit TaurusTLS.UT.LegacyProviders;


interface

uses
  DUnitX.TestFramework, TaurusTLSHeaders_types, TaurusTLS.UT.TestClasses;

type

  /// <summary>
  ///   The <c>TTaurusTLSLegacyProvidersLoaderFixture</c> Fixture verified
  ///   Legacy and Default providers avalability.
  ///   <list type="bullet">
  ///     <item>
  ///       In Dynamic linking mode the provders becomes available after loading
  ///       the OpenSSL library when the
  ///       <font face="Courier New">
  ///         TaurusTLS_LegacyProviders
  ///       </font>
  ///       unit included into <c>uses</c> clause.
  ///     </item>
  ///     <item>
  ///       In Static linking mode the providers must be statically linked into
  ///       the application by including <c>TaurusTLS_LegacyProviders</c> unit
  ///       into <c>uses</c> clause.
  ///     </item>
  ///   </list>
  /// </summary>
  [TestFixture]
  [Category('LegacyProviders')]
  TTaurusTLSLegacyProvidersLoaderFixture = class(TOsslBaseFixture)
  public
    [Test]
    procedure TestIsLegacyProviderLoaded;
    [TestCase('Legacy Providers', 'legacy')]
    [TestCase('Default Providers', 'default')]
    procedure TestProvidersAvailability(AProviderName: string);
  end;

  /// <remarks>
  ///   The <c>TTaurusTLSHashes</c> verifies the <c>Legacy</c> and <c>Default</c> provider hash
  ///   algorithms
  /// </remarks>
  [TestFixture]
  [Category('LegacyProviders')]
  TTaurusTLSHashes = class(TOsslBaseFixture)
  public
    [TestCase('Provider.Legacy (MD4): ''''', 'MD4,,31d6cfe0d16ae931b73c59d7e0c089c0')]
    [TestCase('Provider.Legacy (MD4): ''abcd''', 'MD4,61626364,41decd8f579255c5200f86a4bb3ba740')]

    [TestCase('Provider.Legacy (ripemd160): ''''', 'RIPEMD160,,9c1185a5c5e9fc54612808977ee8f548b2258d31')]
    [TestCase('Provider.Legacy (ripemd160): ''abcd''', 'RIPEMD160,61626364,2e7e536fd487deaa943fda5522d917bdb9011b7a')]

    [TestCase('Provider.Legacy (whirlpool): ''''', 'WHIRLPOOL,,'+
      '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3')]
    [TestCase('Provider.Legacy (whirlpool): ''abcd''', 'WHIRLPOOL,61626364,'+
      'bda164f0b930c43a1bacb5df880b205d15ac847add35145bf25d991ae74f0b72b1ac794f8aacda5fcb3c47038c954742b1857b5856519de4d1e54bfa2fa4eac5')]

    [TestCase('Provider.Default (SHA1): ''''', 'SHA1,,da39a3ee5e6b4b0d3255bfef95601890afd80709')]
    [TestCase('Provider.Default (SHA1): ''abcd''', 'SHA1,61626364,81fe8bfe87576c3ecb22426f8e57847382917acf')]

    [TestCase('Provider.Default (SHA256): ''''', 'SHA256,,'+
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')]
    [TestCase('Provider.Default (SHA256): ''abcd''', 'SHA256,61626364,'+
      '88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589')]
    procedure HashTestHex(const AHashName, AData, AResult: string);
  end;

implementation

uses
  System.SysUtils,
  IdCTypes,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_provider,
  TaurusTLS_LegacyProviders;

{ TTaurusTLSLegacyProvidersLoaderFixture }

procedure TTaurusTLSLegacyProvidersLoaderFixture.TestIsLegacyProviderLoaded;
begin
  Assert.IsTrue(IsLegacyProviderLoaded);
end;

procedure TTaurusTLSLegacyProvidersLoaderFixture.TestProvidersAvailability(
  AProviderName: string);
begin
  Assert.AreEqual(1,
    OSSL_PROVIDER_available(nil, PAnsiChar(UTF8Encode(AProviderName))),
    Format('OpenSSL reports that the provider ''%s'' is not available.',
      [AProviderName])
  );
end;

{ TTaurusTLSHashes }

procedure TTaurusTLSHashes.HashTestHex(const AHashName, AData,
  AResult: string);
begin
  var lHash: PEVP_MD:=nil;
  var lHashSize: TIdC_SIZET:=0;
  var lHashName:=UTF8Encode(AHashName);

  try
    lHash:=EVP_MD_fetch(nil, PAnsiChar(lHashName), nil);
    Assert.IsNotNull(lHash,
      Format('Unable to fetch Hash ''%s''.', [AHashName]));

    lHashSize:=EVP_MD_get_size(lHash);
    Assert.IsTrue(lHashSize > 0,
      Format('Hash hash must be positive integer, '+
      ' but the ''EVP_MD_get_size'' returns ''%d''.', [lHashSize]));

  finally
    EVP_MD_free(lHash);
  end;

  var lHashReturn: TBytes:=nil;
  SetLength(lHashReturn, lHashSize);

  var lData:=TBytes.FromHexStr(AData);
  var lResult:=TBytes.FromHexStr(AResult);

  var lActualSize: TIdC_SIZET:=0;
  Assert.AreEqual(1, EVP_Q_Digest(nil, PAnsiChar(lHashName), nil,
    PByte(lData), Length(lData), PByte(lHashReturn), @lActualSize),
    Format('OpenSSL fials to query Hash for ''%s''.', [AData]));

  Assert.AreEqual(lHashSize, lActualSize, 'Expected and Actual Hash sizes are not equal.');

  TBytesValidator.AreEqual(lResult, lHashReturn, 0, 0, lActualSize);
end;

initialization
  TDUnitX.RegisterTestFixture(TTaurusTLSLegacyProvidersLoaderFixture);
  TDUnitX.RegisterTestFixture(TTaurusTLSHashes);
end.
