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

unit TaurusTLSHeaders_crmferr;

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
  CRMF_R_BAD_PBM_ITERATIONCOUNT = 100;
  CRMF_R_CMS_NOT_SUPPORTED = 122;
  CRMF_R_CRMFERROR = 102;
  CRMF_R_ERROR = 103;
  CRMF_R_ERROR_DECODING_CERTIFICATE = 104;
  CRMF_R_ERROR_DECODING_ENCRYPTEDKEY = 123;
  CRMF_R_ERROR_DECRYPTING_CERTIFICATE = 105;
  CRMF_R_ERROR_DECRYPTING_ENCRYPTEDKEY = 124;
  CRMF_R_ERROR_DECRYPTING_ENCRYPTEDVALUE = 125;
  CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY = 106;
  CRMF_R_ERROR_SETTING_PURPOSE = 126;
  CRMF_R_ERROR_VERIFYING_ENCRYPTEDKEY = 127;
  CRMF_R_FAILURE_OBTAINING_RANDOM = 107;
  CRMF_R_ITERATIONCOUNT_BELOW_100 = 108;
  CRMF_R_MALFORMED_IV = 101;
  CRMF_R_NULL_ARGUMENT = 109;
  CRMF_R_POPOSKINPUT_NOT_SUPPORTED = 113;
  CRMF_R_POPO_INCONSISTENT_CENTRAL_KEYGEN = 128;
  CRMF_R_POPO_INCONSISTENT_PUBLIC_KEY = 117;
  CRMF_R_POPO_MISSING = 121;
  CRMF_R_POPO_MISSING_PUBLIC_KEY = 118;
  CRMF_R_POPO_MISSING_SUBJECT = 119;
  CRMF_R_POPO_RAVERIFIED_NOT_ACCEPTED = 120;
  CRMF_R_SETTING_MAC_ALGOR_FAILURE = 110;
  CRMF_R_SETTING_OWF_ALGOR_FAILURE = 111;
  CRMF_R_UNSUPPORTED_ALGORITHM = 112;
  CRMF_R_UNSUPPORTED_CIPHER = 114;
  CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO = 115;
  CRMF_R_UNSUPPORTED_POPO_METHOD = 116;

implementation

end.