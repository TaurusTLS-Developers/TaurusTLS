/// <exclude />
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

/// <summary>Preserves the former legacy-provider unit name and status query.</summary>
/// <remarks>
/// Deprecated; use TaurusTLS_ProviderLegacy in new code. Forwards provider status
/// and includes archive-only builtin registration through the replacement unit.
/// OpenSSL configuration continues to own activation; inclusion does not load
/// OpenSSL or activate the provider.
/// </remarks>
unit TaurusTLS_LegacyProviders deprecated 'Use TaurusTLS_ProviderLegacy';

interface

uses
  TaurusTLS_ProviderLegacy;

// Preserve the old public status query for existing callers.
function IsLegacyProviderLoaded: Boolean;

implementation

function IsLegacyProviderLoaded: Boolean;
begin
  Result := TaurusTLS_ProviderLegacy.IsLegacyProviderLoaded;
end;

end.
