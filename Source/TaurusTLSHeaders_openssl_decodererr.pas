/// <exclude />
(* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_asyncerr.h2pas
  It should not be modified directly. All changes should be made to TaurusTLSHeaders_asyncerr.h2pas
  and this file regenerated. TaurusTLSHeaders_asyncerr.h2pas is distributed with the full Indy
  Distribution.
*)

{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2025 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
unit TaurusTLSHeaders_openssl_decodererr;

interface
{*
 * OSSL_DECODER reason codes.
 *}
const
  {$EXTERNALSYM OSSL_DECODER_R_COULD_NOT_DECODE_OBJECT}
  OSSL_DECODER_R_COULD_NOT_DECODE_OBJECT          = 101;
  {$EXTERNALSYM OSSL_DECODER_R_DECODER_NOT_FOUND}
  OSSL_DECODER_R_DECODER_NOT_FOUND                = 102;
  {$EXTERNALSYM OSSL_DECODER_R_MISSING_GET_PARAMS}
  OSSL_DECODER_R_MISSING_GET_PARAMS               = 100;

implementation

end.
