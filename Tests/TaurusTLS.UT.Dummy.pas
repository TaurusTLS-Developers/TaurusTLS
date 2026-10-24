{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 - 2025 TaurusTLS Developers, All Rights Reserved       * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

(*
  This init contains the single DUnitX test which does nothing.
  This uinit is included to TaursTLS.UT project temporary
  and can be removed at any time.
*)
unit TaurusTLS.UT.Dummy;

interface

uses
  DUnitX.TestFramework, TaurusTLS.UT.TestClasses;

type
  [TestFixture]
  TFixtureDummy = class(TOsslAutoloadFixture)
  public
    [Test]
    procedure Dummy;
  end;

implementation

{ TFixtureDummy }

procedure TFixtureDummy.Dummy;
begin
  Assert.Pass('This test do nothing.')
end;

initialization
  TDUnitX.RegisterTestFixture(TFixtureDummy);

end.
