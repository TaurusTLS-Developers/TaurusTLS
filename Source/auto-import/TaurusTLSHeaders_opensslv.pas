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

unit TaurusTLSHeaders_opensslv;

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
  OPENSSL_VERSION_MAJOR = 3;
  OPENSSL_VERSION_MINOR = 6;
  OPENSSL_VERSION_PATCH = 3;
  OPENSSL_VERSION_PRE_RELEASE = '-dev';
  OPENSSL_VERSION_BUILD_METADATA = '';
  OPENSSL_SHLIB_VERSION = 3;
  OPENSSL_VERSION_STR = '3.6.3';
  OPENSSL_FULL_VERSION_STR = '3.6.3-dev';
  OPENSSL_RELEASE_DATE = '';
  OPENSSL_VERSION_TEXT = 'OpenSSL 3.6.3-dev ';
  OPENSSL_VERSION_NUMBER = ((OPENSSL_VERSION_MAJOR shl 28) or (OPENSSL_VERSION_MINOR shl 20) or (OPENSSL_VERSION_PATCH shl 4) or $0);

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OPENSSL_VERSION_PREREQ(maj: Pointer; min: Pointer): TIdC_INT; cdecl;


implementation

uses
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  classes,
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers;

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OPENSSL_VERSION_PREREQ(maj: Pointer; min: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_VERSION_PREREQ(maj, min) \
    ((OPENSSL_VERSION_MAJOR << 16) + OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

end.