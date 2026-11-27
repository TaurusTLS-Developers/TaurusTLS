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
/// <summary>Preserves the former unit name for the Indy LM/NTLMv1 adapter.</summary>
/// <remarks>
/// Deprecated; use TaurusTLSIdNTLM in new code. Including this compatibility
/// unit installs the adapter callbacks without loading OpenSSL or activating
/// the legacy provider. Applications retain control of initialization and policy.
/// </remarks>
unit TaurusTLS_NTLM deprecated 'Use TaurusTLSIdNTLM';

interface

uses
  TaurusTLSIdNTLM;

implementation

end.
