/// <exclude />
{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }


unit TaurusTLSHeaders_dtls;

interface
uses TaurusTLSHeaders_prov_ssl;

const
  {$EXTERNALSYM DTLS_MIN_VERSION}
  DTLS_MIN_VERSION = DTLS1_VERSION;
  {$EXTERNALSYM DTLS_MAX_VERSION}
  DTLS_MAX_VERSION = DTLS1_3_VERSION;

//* Special value for method supporting multiple versions */
  {$EXTERNALSYM DTLS_ANY_VERSION}
  DTLS_ANY_VERSION = $1FFFF;

//* DTLS records and messages lengths and offsets */
  {$EXTERNALSYM DTLS1_COOKIE_LENGTH}
  DTLS1_COOKIE_LENGTH = 255;

  {$EXTERNALSYM DTLS1_RT_HEADER_SEQ_OFFS}
  DTLS1_RT_HEADER_SEQ_OFFS = 5;
  {$EXTERNALSYM DTLS1_RT_HEADER_SEQ_LEN}
  DTLS1_RT_HEADER_SEQ_LEN = 6;
  {$EXTERNALSYM DTLS1_RT_HEADER_LENGTH}
  DTLS1_RT_HEADER_LENGTH = 13;

  {$EXTERNALSYM DTLS1_HM_HEADER_LENGTH}
  DTLS1_HM_HEADER_LENGTH = 12;

  {$EXTERNALSYM DTLS1_HM_BAD_FRAGMENT}
  DTLS1_HM_BAD_FRAGMENT = -2;
  {$EXTERNALSYM DTLS1_HM_FRAGMENT_RETRY}
  DTLS1_HM_FRAGMENT_RETRY = -3;

  {$EXTERNALSYM DTLS1_CCS_HEADER_LENGTH}
  DTLS1_CCS_HEADER_LENGTH = 1;

  {$EXTERNALSYM DTLS1_AL_HEADER_LENGTH}
  DTLS1_AL_HEADER_LENGTH = 2;

  {$EXTERNALSYM DTLS1_TMO_ALERT_COUNT}
  DTLS1_TMO_ALERT_COUNT = 12;

//* DTLS 1.3 Unified header */
  {$EXTERNALSYM DTLS13_UNI_HDR_FIXED_LENGTH}
  DTLS13_UNI_HDR_FIXED_LENGTH = 5;
  {$EXTERNALSYM DTLS13_UNI_HDR_FIX_BITS}
  DTLS13_UNI_HDR_FIX_BITS = $20;
  {$EXTERNALSYM DTLS13_UNI_HDR_CID_BIT}
  DTLS13_UNI_HDR_CID_BIT = $10;
  {$EXTERNALSYM DTLS13_UNI_HDR_SEQ_BIT}
  DTLS13_UNI_HDR_SEQ_BIT = $08;
  {$EXTERNALSYM DTLS13_UNI_HDR_SEQ_OFF}
  DTLS13_UNI_HDR_SEQ_OFF = 1;
  {$EXTERNALSYM DTLS13_UNI_HDR_LEN_BIT}
  DTLS13_UNI_HDR_LEN_BIT = $04;
  {$EXTERNALSYM DTLS13_UNI_HDR_FIX_BITS_MASK}
  DTLS13_UNI_HDR_FIX_BITS_MASK = $e0;
  {$EXTERNALSYM DTLS13_UNI_HDR_EPOCH_BITS_MASK}
  DTLS13_UNI_HDR_EPOCH_BITS_MASK = $03;

  {$EXTERNALSYM DTLS13_CIPHERTEXT_MINSIZE}
  DTLS13_CIPHERTEXT_MINSIZE = 16;

implementation

end.
