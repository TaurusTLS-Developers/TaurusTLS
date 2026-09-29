unit TaurusTLS.UT.InputRanges;

/// <summary>
///   Inputs the library mishandled at the edge of a type's range or encoding:
///   a buffer too large for OpenSSL's int length (#294), a CA directory whose
///   path is not ANSI (#295), certificate names that are not ANSI (#296), and
///   common names that are not hostnames (#297).
/// </summary>

interface

uses
  DUnitX.TestFramework, TaurusTLS.UT.TestClasses;

type
  [TestFixture]
  [Category('InputRanges')]
  TTaurusTLSInputRangesFixture = class(TOsslBaseFixture)
  public
    /// <summary>
    ///   A length past MaxInt gets no BIO. Narrowed to an int it became
    ///   NEGATIVE, which OpenSSL reads as "NUL-terminated". The size is only
    ///   claimed, never allocated: the helper must refuse before reading a byte.
    /// </summary>
    [Test]
    procedure MemBuf_LongerThanMaxInt_GetsNoBio;
    /// <summary>A negative length is refused too.</summary>
    [Test]
    procedure MemBuf_NegativeLength_GetsNoBio;
    /// <summary>An ordinary buffer still gets a BIO holding exactly its bytes.</summary>
    [Test]
    procedure MemBuf_InRange_ReadsBackItsBytes;
    /// <summary>
    ///   A UTF8String entry reads back as the text it holds, not as ANSI
    ///   mojibake. Read through Organization, which has no IDN step, so the
    ///   decoding is tested on its own.
    /// </summary>
    [Test]
    procedure Name_Utf8Entry_ReadsBackUnchanged;
    /// <summary>A BMPString entry reads back whole, not cut at its first zero byte.</summary>
    [Test]
    procedure Name_BmpEntry_ReadsBackUnchanged;
    /// <summary>A name with no common name reads back empty, rather than raising.</summary>
    [Test]
    procedure Name_MissingEntry_IsEmpty;
    /// <summary>A person's name, as a client certificate carries, reads back as stated.</summary>
    [Test]
    procedure Name_PersonCommonName_ReadsBackUnchanged;
{$IFDEF MSWINDOWS}
    /// <summary>A Punycode hostname is still converted to Unicode.</summary>
    [Test]
    procedure Name_PunycodeCommonName_IsConvertedToUnicode;
    /// <summary>
    ///   A CA directory whose path is outside the ANSI code page is really
    ///   read. As AnsiString its path named a directory that does not exist,
    ///   and OpenSSL still reported success with an empty store.
    /// </summary>
    [Test]
    procedure HashedDir_NonAnsiPath_LoadsItsCertificates;
    /// <summary>
    ///   Only the file names OpenSSL's directory lookup reads are loaded from
    ///   such a directory; anything else in it is not part of the store.
    /// </summary>
    [Test]
    procedure HashedDir_NonAnsiPath_IgnoresOtherFiles;
{$ENDIF}
  end;

implementation

uses
  {$IFDEF MSWINDOWS}
  IdIDN,
  {$ENDIF}
  System.SysUtils,
  System.IOUtils,
  IdCTypes,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_x509_vfy,
  TaurusTLS_Files,
  TaurusTLS_X509;

const
  /// <summary>'Mueller Omega' with u-umlaut and capital omega, plus two CJK characters.</summary>
  cNonAnsiName = 'M'#$00FC'ller '#$03A9'mega '#$8A3C#$660E;
  /// <summary>Greek and CJK: no ANSI code page holds both, whatever the machine's is.</summary>
  cNonAnsiDirName = 'TaurusTLS-UT-'#$03A9#$03BC#$03AD#$03B3#$03B1'-'#$8A3C#$660E#$66F8;

  /// <summary>A self-signed certificate for the hashed directory.</summary>
  cCertOne =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIBnTCCAUOgAwIBAgIUahB7vI6+4TI2T34CHNmCcxL/3n8wCgYIKoZIzj0EAwIw'#10 +
    'IzEhMB8GA1UEAwwYaW5wdXQtcmFuZ2VzLW9uZS5leGFtcGxlMCAXDTI2MDkyOTA4'#10 +
    'MzgwMloYDzIxMjYwOTA1MDgzODAyWjAjMSEwHwYDVQQDDBhpbnB1dC1yYW5nZXMt'#10 +
    'b25lLmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQu2vaHGzxEx7a/'#10 +
    '4P8/L+Bz1qMS3W3I1K5a+9WGNSjubuV6rORgZ0Lzx6honqIrPO/JhbXVJRcrcHSj'#10 +
    'oTpnEod9o1MwUTAdBgNVHQ4EFgQUjsZImamw/+BY1QE+8pzmnwcsotgwHwYDVR0j'#10 +
    'BBgwFoAUjsZImamw/+BY1QE+8pzmnwcsotgwDwYDVR0TAQH/BAUwAwEB/zAKBggq'#10 +
    'hkjOPQQDAgNIADBFAiAl7jS2DS7oi7Eu5kkTQltPskcmHklwWnhx8RP9OkHl5gIh'#10 +
    'AJAosjDQ4axqSacmKvwfPpA26DIIjoAfJsBIAzWI1gf9'#10 +
    '-----END CERTIFICATE-----'#10;

  /// <summary>A second, different certificate, for files the store must NOT read.</summary>
  cCertTwo =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIBnTCCAUOgAwIBAgIUcvsctLYH5Kt5cWsh+h/ZBgOwUvAwCgYIKoZIzj0EAwIw'#10 +
    'IzEhMB8GA1UEAwwYaW5wdXQtcmFuZ2VzLXR3by5leGFtcGxlMCAXDTI2MDkyOTA4'#10 +
    'MzgwMloYDzIxMjYwOTA1MDgzODAyWjAjMSEwHwYDVQQDDBhpbnB1dC1yYW5nZXMt'#10 +
    'dHdvLmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ7ZGiJxF1Uo+PH'#10 +
    'd27pNxiYQ4e70gTZ0FbH0lUX+6zi+0BqkWZl8nJ3/OAB4UJFbj9g6MlkCszVlZ8z'#10 +
    'BGEca+8ro1MwUTAdBgNVHQ4EFgQUoBUB2whd2ZTORkYzxyX4pK6e0G4wHwYDVR0j'#10 +
    'BBgwFoAUoBUB2whd2ZTORkYzxyX4pK6e0G4wDwYDVR0TAQH/BAUwAwEB/zAKBggq'#10 +
    'hkjOPQQDAgNIADBFAiAgqa/+VbJIfX8OYTjwJnGKRmSZxR81VcnA77tPbVSt+wIh'#10 +
    'ANTiecyIYOjl15JyR/zDIqLtKhrlNkYpLJ/j3yLM+Mjz'#10 +
    '-----END CERTIFICATE-----'#10;

/// <summary>Number of objects (certificates and CRLs) a store holds.</summary>
function StoreObjectCount(AStore: PX509_STORE): Integer;
var
  LObjects: PSTACK_OF_X509_OBJECT;
begin
  LObjects := X509_STORE_get0_objects(AStore);
  if LObjects = nil then
    Result := 0
  else
    Result := sk_X509_OBJECT_num(LObjects);
end;

/// <summary>The subject-name hash OpenSSL's directory lookup files a PEM certificate under.</summary>
function SubjectHashOf(const APem: string): string;
var
  LBytes: TBytes;
  LBio: PBIO;
  LX509: PX509;
begin
  LBytes := TEncoding.ASCII.GetBytes(APem);
  LBio := BIO_new_mem_buf(LBytes[0], Length(LBytes));
  Assert.IsNotNull(LBio, 'could not wrap the test certificate');
  try
    LX509 := PEM_read_bio_X509(LBio, nil, nil, nil);
    Assert.IsNotNull(LX509, 'the test certificate did not parse');
    try
      Result := LowerCase(IntToHex(X509_subject_name_hash(LX509), 8));
    finally
      X509_free(LX509);
    end;
  finally
    BIO_free(LBio);
  end;
end;

/// <summary>
///   Builds a non-ANSI temporary directory holding cCertOne under its hashed
///   name, plus each of AExtraFiles holding cCertTwo. A store that read any of
///   the extra files would therefore hold two objects rather than one.
/// </summary>
function MakeHashedDir(const AExtraFiles: array of string): string;
var
  LGuid: TGUID;
  I: Integer;
begin
  CreateGUID(LGuid);
  Result := TPath.Combine(TPath.GetTempPath, cNonAnsiDirName + '-' +
    StringReplace(StringReplace(GUIDToString(LGuid), '{', '', []), '}', '', []));
  TDirectory.CreateDirectory(Result);
  TFile.WriteAllBytes(TPath.Combine(Result, SubjectHashOf(cCertOne) + '.0'),
    TEncoding.ASCII.GetBytes(cCertOne));
  for I := Low(AExtraFiles) to High(AExtraFiles) do
    TFile.WriteAllBytes(TPath.Combine(Result, AExtraFiles[I]),
      TEncoding.ASCII.GetBytes(cCertTwo));
end;

/// <summary>
///   Initialises Indy's IDN support, as Indy's Windows socket stack does in any
///   real application. Without it IdnToUnicode is nil, CommonName never tries
///   the conversion, and the CommonName tests could not catch #297.
/// </summary>
procedure EnsureIDN;
begin
  {$IFDEF MSWINDOWS}
  InitIDNLibrary;
  Assert.IsTrue(Assigned(IdnToUnicode), 'the Windows IDN API did not load');
  {$ENDIF}
end;

/// <summary>Builds a name with one UTF-8 common name and returns what CommonName reads back.</summary>
function CommonNameRoundTrip(const ACommonName: string): string;
var
  LName: PX509_NAME;
  LBytes: TBytes;
  LWrapper: TTaurusTLSX509Name;
begin
  EnsureIDN;
  LName := X509_NAME_new;
  Assert.IsNotNull(LName);
  try
    LBytes := TEncoding.UTF8.GetBytes(ACommonName);
    Assert.AreEqual(1, X509_NAME_add_entry_by_txt(LName, 'CN', MBSTRING_UTF8,
      PByte(LBytes), Length(LBytes), -1, 0), 'could not build the name');
    LWrapper := TTaurusTLSX509Name.Create(LName);
    try
      Result := LWrapper.CommonName;
    finally
      LWrapper.Free;
    end;
  finally
    X509_NAME_free(LName);
  end;
end;

{ TTaurusTLSInputRangesFixture }

procedure TTaurusTLSInputRangesFixture.MemBuf_LongerThanMaxInt_GetsNoBio;
var
  LByte: Byte;
begin
  LByte := 0;
  Assert.IsNull(TaurusTLS_BIO_new_mem_buf(LByte, Int64(MaxInt) + 1),
    'a length past MaxInt must not reach BIO_new_mem_buf');
  Assert.IsNull(TaurusTLS_BIO_new_mem_buf(LByte, Int64(High(Cardinal)) + 16),
    'a length past 4 GiB must not wrap round into a small one');
end;

procedure TTaurusTLSInputRangesFixture.MemBuf_NegativeLength_GetsNoBio;
var
  LByte: Byte;
begin
  LByte := 0;
  Assert.IsNull(TaurusTLS_BIO_new_mem_buf(LByte, -1));
end;

procedure TTaurusTLSInputRangesFixture.MemBuf_InRange_ReadsBackItsBytes;
const
  cText: array [0 .. 4] of Byte = (Ord('h'), Ord('e'), Ord('l'), Ord('l'), Ord('o'));
var
  LBio: PBIO;
  LRead: TBytes;
  LCount: Integer;
begin
  SetLength(LRead, 16);
  LBio := TaurusTLS_BIO_new_mem_buf(cText, SizeOf(cText));
  Assert.IsNotNull(LBio);
  try
    LCount := BIO_read(LBio, LRead[0], Length(LRead));
    Assert.AreEqual(5, LCount, 'the BIO must hold exactly the given length');
    Assert.AreEqual('hello', TEncoding.ASCII.GetString(LRead, 0, LCount), False);
  finally
    BIO_free(LBio);
  end;
end;

procedure TTaurusTLSInputRangesFixture.Name_Utf8Entry_ReadsBackUnchanged;
var
  LName: PX509_NAME;
  LBytes: TBytes;
  LWrapper: TTaurusTLSX509Name;
begin
  LName := X509_NAME_new;
  Assert.IsNotNull(LName);
  try
    LBytes := TEncoding.UTF8.GetBytes(cNonAnsiName);
    Assert.AreEqual(1, X509_NAME_add_entry_by_txt(LName, 'O', MBSTRING_UTF8,
      PByte(LBytes), Length(LBytes), -1, 0), 'could not build the name');
    LWrapper := TTaurusTLSX509Name.Create(LName);
    try
      // Case-sensitive on purpose: the subject here is exact text.
      Assert.AreEqual(cNonAnsiName, LWrapper.Organization, False);
    finally
      LWrapper.Free;
    end;
  finally
    X509_NAME_free(LName);
  end;
end;

procedure TTaurusTLSInputRangesFixture.Name_BmpEntry_ReadsBackUnchanged;
const
  cBmpName = #$03A9'mega';
var
  LName: PX509_NAME;
  LBytes: TBytes;
  LWrapper: TTaurusTLSX509Name;
begin
  LName := X509_NAME_new;
  Assert.IsNotNull(LName);
  try
    // MBSTRING_BMP input is UCS-2 big-endian, and is stored as a BMPString.
    LBytes := TEncoding.BigEndianUnicode.GetBytes(cBmpName);
    Assert.AreEqual(1, X509_NAME_add_entry_by_txt(LName, 'O', MBSTRING_BMP,
      PByte(LBytes), Length(LBytes), -1, 0), 'could not build the name');
    LWrapper := TTaurusTLSX509Name.Create(LName);
    try
      Assert.AreEqual(cBmpName, LWrapper.Organization, False);
    finally
      LWrapper.Free;
    end;
  finally
    X509_NAME_free(LName);
  end;
end;

procedure TTaurusTLSInputRangesFixture.Name_MissingEntry_IsEmpty;
var
  LName: PX509_NAME;
  LWrapper: TTaurusTLSX509Name;
begin
  EnsureIDN;
  LName := X509_NAME_new;
  Assert.IsNotNull(LName);
  try
    LWrapper := TTaurusTLSX509Name.Create(LName);
    try
      Assert.AreEqual('', LWrapper.CommonName, False);
    finally
      LWrapper.Free;
    end;
  finally
    X509_NAME_free(LName);
  end;
end;

procedure TTaurusTLSInputRangesFixture.Name_PersonCommonName_ReadsBackUnchanged;
const
  cPerson = 'Hans M'#$00FC'ller';
begin
  Assert.AreEqual(cPerson, CommonNameRoundTrip(cPerson), False);
end;

{$IFDEF MSWINDOWS}
procedure TTaurusTLSInputRangesFixture.Name_PunycodeCommonName_IsConvertedToUnicode;
begin
  // 'xn--mller-kva' is the Punycode form of 'muller' with u-umlaut.
  Assert.AreEqual('m'#$00FC'ller.example', CommonNameRoundTrip('xn--mller-kva.example'), False);
end;

procedure TTaurusTLSInputRangesFixture.HashedDir_NonAnsiPath_LoadsItsCertificates;
var
  LDir: string;
  LStore: PX509_STORE;
begin
  LDir := MakeHashedDir([]);
  try
    Assert.AreNotEqual(LDir, string(AnsiString(LDir)),
      'the test directory must NOT survive the ANSI conversion, or it tests nothing');
    LStore := X509_STORE_new;
    Assert.IsNotNull(LStore);
    try
      Assert.AreEqual(1, TaurusTLS_X509_STORE_load_locations(LStore, '', LDir));
      Assert.AreEqual(1, StoreObjectCount(LStore),
        'the certificate in the non-ANSI directory never reached the store');
    finally
      X509_STORE_free(LStore);
    end;
  finally
    TDirectory.Delete(LDir, True);
  end;
end;

procedure TTaurusTLSInputRangesFixture.HashedDir_NonAnsiPath_IgnoresOtherFiles;
var
  LDir: string;
  LStore: PX509_STORE;
begin
  // 'abcdefgh.0' has the shape of a hashed name but is not hex.
  LDir := MakeHashedDir(['readme.pem', 'ca-bundle.crt', 'abcdefgh.0']);
  try
    LStore := X509_STORE_new;
    Assert.IsNotNull(LStore);
    try
      Assert.AreEqual(1, TaurusTLS_X509_STORE_load_locations(LStore, '', LDir));
      Assert.AreEqual(1, StoreObjectCount(LStore),
        'expected exactly the one hashed certificate: 0 means the directory ' +
        'was not read, 2 that a non-hashed file was');
    finally
      X509_STORE_free(LStore);
    end;
  finally
    TDirectory.Delete(LDir, True);
  end;
end;
{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TTaurusTLSInputRangesFixture);

end.
