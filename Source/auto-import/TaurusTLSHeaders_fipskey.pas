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

unit TaurusTLSHeaders_fipskey;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;




// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  FIPS_KEY_ELEMENTS = $f4,$55,$66,$50,$ac,$31,$d3,$54,$61,$61,$0b,$ac,$4e,$d8,$1b,$1a,$18,$1b,$2d,$8a,$43,$ea,$28,$54,$cb,$ae,$22,$ca,$74,$56,$08,$13;
  FIPS_KEY_STRING = 'f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813';
  FIPS_VENDOR = 'OpenSSL non-compliant FIPS Provider';

implementation

end.