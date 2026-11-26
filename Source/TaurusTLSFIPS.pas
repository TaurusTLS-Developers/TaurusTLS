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

/// <summary>Preserves the former unit name for the Indy hash/HMAC adapter.</summary>
/// <remarks>
/// Deprecated; use TaurusTLSIdFIPS in new code. Including this compatibility
/// unit initializes that adapter without loading OpenSSL or activating FIPS.
/// </remarks>
unit TaurusTLSFIPS deprecated 'Use TaurusTLSIdFIPS';

interface

uses
  TaurusTLSIdFIPS;

implementation

end.
