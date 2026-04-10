{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
  { error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}
{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}

unit TaurusTLSHeaders_dtls1;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;





// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  DTLS_MIN_VERSION = DTLS1_VERSION;
  DTLS_MAX_VERSION = DTLS1_2_VERSION;
  DTLS1_VERSION_MAJOR = $FE;
  DTLS_ANY_VERSION = $1FFFF;
  DTLS1_COOKIE_LENGTH = 255;
  DTLS1_RT_HEADER_LENGTH = 13;
  DTLS1_HM_HEADER_LENGTH = 12;
  DTLS1_HM_BAD_FRAGMENT = -2;
  DTLS1_HM_FRAGMENT_RETRY = -3;
  DTLS1_CCS_HEADER_LENGTH = 1;
  DTLS1_AL_HEADER_LENGTH = 2;
  DTLS1_TMO_ALERT_COUNT = 12;

implementation

end.