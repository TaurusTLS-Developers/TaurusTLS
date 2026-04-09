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

unit TaurusTLSHeaders_esserr;

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
  ESS_R_EMPTY_ESS_CERT_ID_LIST = 107;
  ESS_R_ESS_CERT_DIGEST_ERROR = 103;
  ESS_R_ESS_CERT_ID_NOT_FOUND = 104;
  ESS_R_ESS_CERT_ID_WRONG_ORDER = 105;
  ESS_R_ESS_DIGEST_ALG_UNKNOWN = 106;
  ESS_R_ESS_SIGNING_CERTIFICATE_ERROR = 102;
  ESS_R_ESS_SIGNING_CERT_ADD_ERROR = 100;
  ESS_R_ESS_SIGNING_CERT_V2_ADD_ERROR = 101;
  ESS_R_MISSING_SIGNING_CERTIFICATE_ATTRIBUTE = 108;

implementation

end.