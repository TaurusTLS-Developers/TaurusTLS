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

unit TaurusTLSHeaders_macros;

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
  NON_EMPTY_TRANSLATION_UNIT = staticvoid*dummy= and dummy;;
  OPENSSL_API_LEVEL = (OPENSSL_CONFIGURED_API);
  OSSL_DEPRECATEDIN_3_6 = OSSL_DEPRECATED(3.6);
  OSSL_DEPRECATEDIN_3_5 = OSSL_DEPRECATED(3.5);
  OSSL_DEPRECATEDIN_3_4 = OSSL_DEPRECATED(3.4);
  OSSL_DEPRECATEDIN_3_1 = OSSL_DEPRECATED(3.1);
  OSSL_DEPRECATEDIN_3_0 = OSSL_DEPRECATED(3.0);
  OSSL_DEPRECATEDIN_1_1_1 = OSSL_DEPRECATED(1.1.1);
  OSSL_DEPRECATEDIN_1_1_0 = OSSL_DEPRECATED(1.1.0);
  OSSL_DEPRECATEDIN_1_0_2 = OSSL_DEPRECATED(1.0.2);
  OSSL_DEPRECATEDIN_1_0_1 = OSSL_DEPRECATED(1.0.1);
  OSSL_DEPRECATEDIN_1_0_0 = OSSL_DEPRECATED(1.0.0);
  OSSL_DEPRECATEDIN_0_9_8 = OSSL_DEPRECATED(0.9.8);
  OPENSSL_FILE = __FILE__;
  OPENSSL_LINE = __LINE__;
  OPENSSL_FUNC = __func__;
  OSSL_CRYPTO_ALLOC = __attribute__((__malloc__));

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function OPENSSL_MSTR_HELPER(x: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OPENSSL_MSTR(x: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}


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

function OPENSSL_MSTR_HELPER(x: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_MSTR_HELPER(x) #x
  }
end;

function OPENSSL_MSTR(x: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OPENSSL_MSTR(x) OPENSSL_MSTR_HELPER(x)
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