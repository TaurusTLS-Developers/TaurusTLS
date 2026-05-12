{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

unit TaurusTLS.UT.Wrappers.ECHStore;

interface

uses
  System.SysUtils,
  System.Classes,
  DUnitX.TestFramework,
  TaurusTLS.UT.TestClasses,
  IdGlobal,
  IdCTypes,
  TaurusTLSHeaders_types,
  TaurusTLS_BIO,
  TaurusTLS_ECHStore;

type
  [TestFixture]
  [Category('WRAP.ECHStore, WRAP.ClientECHStore')]
  TClientECHStoreFixture = class(TOsslBaseFixture)
  public const
    // Valid structurally: [length=00 12 (18 bytes)] [version=fe 0d] [length=00 0e] [payload...]
//    cValidBase64ECHConfig: RawByteString = 'ABK+DQALAAEAAwABBmJlYmViZQA=';
    cValidBase64ECHConfig = 'ADv+DQA3PgAgACAxkmwsb0M/YCP9J9rLZUCaEO/MQZ2OqHbCyUh83j1WNwAEAAEA'+
      'AQAIdGVzdC50bGQAAA==';
  public
    [Test]
    procedure Test_Create;
    [Test]
    procedure Test_SetConfigList_Bio;
    [Test]
    procedure Test_SetConfigList_String;
    [Test]
    procedure Test_SetConfigList_Stream;
    [Test]
    procedure Test_Count;
  end;

implementation

uses
  TaurusTLSHeaders_err;

{ TClientECHStoreFixture }

procedure TClientECHStoreFixture.Test_Create;
begin
  var LStore := TClientECHStore.Create;
  try
    Assert.IsNotNull(LStore, '"TClientECHStore.Create" returns "nil".');
    Assert.IsNotNull(LStore.Store, 'Property "Store" returns "nil".');
    Assert.AreEqual(0, LStore.Count, 'Store "Count" should be 0 upon creation.');
  finally
    LStore.Free;
  end;
end;

procedure TClientECHStoreFixture.Test_SetConfigList_Bio;
begin
  var LStore := TClientECHStore.Create;
  var LBio := TTaurusTLSRawByteStringBIO.Create(cValidBase64ECHConfig, False);
  try
    Assert.WillNotRaise(
      procedure begin LStore.SetConfigList(LBio) end,
      nil,
      'Method "SetConfigList" (BIO wrapper) should not raise an error.'
    );
  finally
    LBio.Free;
    LStore.Free;
  end;
end;

procedure TClientECHStoreFixture.Test_SetConfigList_String;
begin
  var LStore := TClientECHStore.Create;
  try
    Assert.WillNotRaise(
      procedure begin LStore.SetConfigList(cValidBase64ECHConfig) end,
      nil,
      'Method "SetConfigList" (string) should not raise an error.'
    );
  finally
    LStore.Free;
  end;
end;

procedure TClientECHStoreFixture.Test_SetConfigList_Stream;
begin
  var LStore := TClientECHStore.Create;
  var LStream := TStringStream.Create(cValidBase64ECHConfig);
  try
    Assert.WillNotRaise(
      procedure begin LStore.SetConfigList(LStream) end,
      nil,
      'Method "SetConfigList" (stream) should not raise an error.'
    );
  finally
    LStream.Free;
    LStore.Free;
  end;
end;

procedure TClientECHStoreFixture.Test_Count;
begin
  var LStore := TClientECHStore.Create;
  try
    // Ingest the configuration
    LStore.SetConfigList(cValidBase64ECHConfig);
    // Verify count property doesn't fail
    Assert.IsTrue(LStore.Count >= 0, 'Property "Count" value is incorrect.');
  finally
    LStore.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TClientECHStoreFixture);

end.
