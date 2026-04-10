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

unit TaurusTLSHeaders_comperr;

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
  COMP_R_BROTLI_DECODE_ERROR = 102;
  COMP_R_BROTLI_ENCODE_ERROR = 103;
  COMP_R_BROTLI_NOT_SUPPORTED = 104;
  COMP_R_ZLIB_DEFLATE_ERROR = 99;
  COMP_R_ZLIB_INFLATE_ERROR = 100;
  COMP_R_ZLIB_NOT_SUPPORTED = 101;
  COMP_R_ZSTD_COMPRESS_ERROR = 105;
  COMP_R_ZSTD_DECODE_ERROR = 106;
  COMP_R_ZSTD_DECOMPRESS_ERROR = 107;
  COMP_R_ZSTD_NOT_SUPPORTED = 108;

implementation

end.