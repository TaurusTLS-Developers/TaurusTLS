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
///   Defines and implements common classes and interfaces used in the TaurusTLS
///   library.
/// </summary>
unit TaurusTLS_types;

interface

uses
  IdGlobal,
  IdCTypes,
  TaurusTLSExceptionHandlers;

type
  ETaurusTLSSecurityBits = class(ETaurusTLSError);

  TTaurusTLSSecurityBits = (sbZero, sb80, sb112, sb128, sb192, sb256);
  TTaurusTLSSecurityBitsHelper = record helper for TTaurusTLSSecurityBits
  private
    function GetAsInt: TIdC_INT; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInt(AValue: TIdC_INT); {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    property AsInt: TIdC_INT read GetAsInt write SetAsInt;
  end;

implementation

uses
  TaurusTLS_ResourceStrings;


{ TTaurusTLSSecurityBitsHelper }

function TTaurusTLSSecurityBitsHelper.GetAsInt: TIdC_INT;
begin
  Result:=Ord(Self);
end;

procedure TTaurusTLSSecurityBitsHelper.SetAsInt(AValue: TIdC_INT);
begin
  if not (AValue in [0..5]) then
    raise ETaurusTLSSecurityBits.CreateFmt(RMSG_SecurityBits_Convert_err, [AValue]);
  Self:=TTaurusTLSSecurityBits(AValue);
end;



end.
