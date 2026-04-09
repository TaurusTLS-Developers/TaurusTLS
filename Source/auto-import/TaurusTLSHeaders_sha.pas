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

unit TaurusTLSHeaders_sha;

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
// TYPE DECLARATIONS
// =============================================================================
type
  PSHAstate_st = ^TSHAstate_st;
  TSHAstate_st = record end;
  {$EXTERNALSYM PSHAstate_st}

  PSHA_CTX = ^TSHA_CTX;
  TSHA_CTX = TSHAstate_st;
  {$EXTERNALSYM PSHA_CTX}

  PSHA256state_st = ^TSHA256state_st;
  TSHA256state_st = record end;
  {$EXTERNALSYM PSHA256state_st}

  PSHA256_CTX = ^TSHA256_CTX;
  TSHA256_CTX = TSHA256state_st;
  {$EXTERNALSYM PSHA256_CTX}

  PSHA512state_st = ^TSHA512state_st;
  TSHA512state_st = record end;
  {$EXTERNALSYM PSHA512state_st}

  Punion (unnamed at /home/sasha/dev/openssl/include/openssl/sha.h:113:5) = ^Tunion (unnamed at /home/sasha/dev/openssl/include/openssl/sha.h:113:5);
  {$EXTERNALSYM Punion (unnamed at /home/sasha/dev/openssl/include/openssl/sha.h:113:5)}

  PSHA512_CTX = ^TSHA512_CTX;
  TSHA512_CTX = TSHA512state_st;
  {$EXTERNALSYM PSHA512_CTX}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  SHA_DIGEST_LENGTH = 20;
  SHA_LONG = unsignedint;
  SHA_LBLOCK = 16;
  SHA_CBLOCK = (SHA_LBLOCK*4);
  SHA_LAST_BLOCK = (SHA_CBLOCK-8);
  SHA256_CBLOCK = (SHA_LBLOCK*4);
  SHA256_192_DIGEST_LENGTH = 24;
  SHA224_DIGEST_LENGTH = 28;
  SHA256_DIGEST_LENGTH = 32;
  SHA384_DIGEST_LENGTH = 48;
  SHA512_DIGEST_LENGTH = 64;
  SHA512_CBLOCK = (SHA_LBLOCK*8);
  SHA_LONG64 = unsignedlonglong;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  SHA1_Init: function(c: PSHA_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA1_Init}

  SHA1_Update: function(c: PSHA_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA1_Update}

  SHA1_Final: function(md: PIdAnsiChar; c: PSHA_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA1_Final}

  SHA1_Transform: procedure(c: PSHA_CTX; data: PIdAnsiChar); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA1_Transform}

  SHA1: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM SHA1}

  SHA224_Init: function(c: PSHA256_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA224_Init}

  SHA224_Update: function(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA224_Update}

  SHA224_Final: function(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA224_Final}

  SHA256_Init: function(c: PSHA256_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA256_Init}

  SHA256_Update: function(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA256_Update}

  SHA256_Final: function(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA256_Final}

  SHA256_Transform: procedure(c: PSHA256_CTX; data: PIdAnsiChar); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA256_Transform}

  SHA224: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM SHA224}

  SHA256: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM SHA256}

  SHA384_Init: function(c: PSHA512_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA384_Init}

  SHA384_Update: function(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA384_Update}

  SHA384_Final: function(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA384_Final}

  SHA512_Init: function(c: PSHA512_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA512_Init}

  SHA512_Update: function(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA512_Update}

  SHA512_Final: function(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA512_Final}

  SHA512_Transform: procedure(c: PSHA512_CTX; data: PIdAnsiChar); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM SHA512_Transform}

  SHA384: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM SHA384}

  SHA512: function(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM SHA512}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function SHA1_Init(c: PSHA_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA1_Update(c: PSHA_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA1_Final(md: PIdAnsiChar; c: PSHA_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SHA1_Transform(c: PSHA_CTX; data: PIdAnsiChar); cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA1(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl;
function SHA224_Init(c: PSHA256_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA224_Update(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA224_Final(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA256_Init(c: PSHA256_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA256_Update(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA256_Final(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SHA256_Transform(c: PSHA256_CTX; data: PIdAnsiChar); cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA224(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl;
function SHA256(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl;
function SHA384_Init(c: PSHA512_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA384_Update(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA384_Final(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA512_Init(c: PSHA512_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA512_Update(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA512_Final(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure SHA512_Transform(c: PSHA512_CTX; data: PIdAnsiChar); cdecl; deprecated 'In OpenSSL 3_0_0';
function SHA384(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl;
function SHA512(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

implementation

uses
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  classes,
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES IMPORTS
// =============================================================================

function SHA1_Init(c: PSHA_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA1_Init';
function SHA1_Update(c: PSHA_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SHA1_Update';
function SHA1_Final(md: PIdAnsiChar; c: PSHA_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA1_Final';
procedure SHA1_Transform(c: PSHA_CTX; data: PIdAnsiChar); cdecl external CLibCrypto name 'SHA1_Transform';
function SHA1(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'SHA1';
function SHA224_Init(c: PSHA256_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA224_Init';
function SHA224_Update(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SHA224_Update';
function SHA224_Final(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA224_Final';
function SHA256_Init(c: PSHA256_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA256_Init';
function SHA256_Update(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SHA256_Update';
function SHA256_Final(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA256_Final';
procedure SHA256_Transform(c: PSHA256_CTX; data: PIdAnsiChar); cdecl external CLibCrypto name 'SHA256_Transform';
function SHA224(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'SHA224';
function SHA256(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'SHA256';
function SHA384_Init(c: PSHA512_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA384_Init';
function SHA384_Update(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SHA384_Update';
function SHA384_Final(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA384_Final';
function SHA512_Init(c: PSHA512_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA512_Init';
function SHA512_Update(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SHA512_Update';
function SHA512_Final(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl external CLibCrypto name 'SHA512_Final';
procedure SHA512_Transform(c: PSHA512_CTX; data: PIdAnsiChar); cdecl external CLibCrypto name 'SHA512_Transform';
function SHA384(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'SHA384';
function SHA512(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'SHA512';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  SHA1_Init_procname = 'SHA1_Init';
  SHA1_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA1_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA1_Update_procname = 'SHA1_Update';
  SHA1_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA1_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA1_Final_procname = 'SHA1_Final';
  SHA1_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA1_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA1_Transform_procname = 'SHA1_Transform';
  SHA1_Transform_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA1_Transform_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA1_procname = 'SHA1';
  SHA1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SHA224_Init_procname = 'SHA224_Init';
  SHA224_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA224_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA224_Update_procname = 'SHA224_Update';
  SHA224_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA224_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA224_Final_procname = 'SHA224_Final';
  SHA224_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA224_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA256_Init_procname = 'SHA256_Init';
  SHA256_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA256_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA256_Update_procname = 'SHA256_Update';
  SHA256_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA256_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA256_Final_procname = 'SHA256_Final';
  SHA256_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA256_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA256_Transform_procname = 'SHA256_Transform';
  SHA256_Transform_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA256_Transform_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA224_procname = 'SHA224';
  SHA224_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SHA256_procname = 'SHA256';
  SHA256_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SHA384_Init_procname = 'SHA384_Init';
  SHA384_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA384_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA384_Update_procname = 'SHA384_Update';
  SHA384_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA384_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA384_Final_procname = 'SHA384_Final';
  SHA384_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA384_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA512_Init_procname = 'SHA512_Init';
  SHA512_Init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA512_Init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA512_Update_procname = 'SHA512_Update';
  SHA512_Update_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA512_Update_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA512_Final_procname = 'SHA512_Final';
  SHA512_Final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA512_Final_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA512_Transform_procname = 'SHA512_Transform';
  SHA512_Transform_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  SHA512_Transform_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SHA384_procname = 'SHA384';
  SHA384_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SHA512_procname = 'SHA512';
  SHA512_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_SHA1_Init(c: PSHA_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA1_Init_procname);
end;

function ERR_SHA1_Update(c: PSHA_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA1_Update_procname);
end;

function ERR_SHA1_Final(md: PIdAnsiChar; c: PSHA_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA1_Final_procname);
end;

procedure ERR_SHA1_Transform(c: PSHA_CTX; data: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA1_Transform_procname);
end;

function ERR_SHA1(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA1_procname);
end;

function ERR_SHA224_Init(c: PSHA256_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA224_Init_procname);
end;

function ERR_SHA224_Update(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA224_Update_procname);
end;

function ERR_SHA224_Final(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA224_Final_procname);
end;

function ERR_SHA256_Init(c: PSHA256_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA256_Init_procname);
end;

function ERR_SHA256_Update(c: PSHA256_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA256_Update_procname);
end;

function ERR_SHA256_Final(md: PIdAnsiChar; c: PSHA256_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA256_Final_procname);
end;

procedure ERR_SHA256_Transform(c: PSHA256_CTX; data: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA256_Transform_procname);
end;

function ERR_SHA224(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA224_procname);
end;

function ERR_SHA256(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA256_procname);
end;

function ERR_SHA384_Init(c: PSHA512_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA384_Init_procname);
end;

function ERR_SHA384_Update(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA384_Update_procname);
end;

function ERR_SHA384_Final(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA384_Final_procname);
end;

function ERR_SHA512_Init(c: PSHA512_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA512_Init_procname);
end;

function ERR_SHA512_Update(c: PSHA512_CTX; data: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA512_Update_procname);
end;

function ERR_SHA512_Final(md: PIdAnsiChar; c: PSHA512_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA512_Final_procname);
end;

procedure ERR_SHA512_Transform(c: PSHA512_CTX; data: PIdAnsiChar); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA512_Transform_procname);
end;

function ERR_SHA384(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA384_procname);
end;

function ERR_SHA512(d: PIdAnsiChar; n: TIdC_SIZET; md: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SHA512_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  SHA1_Init := LoadLibFunction(ADllHandle, SHA1_Init_procname);
  FuncLoadError := not assigned(SHA1_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Init_allownil)}
    SHA1_Init := ERR_SHA1_Init;
    {$ifend}
    {$if declared(SHA1_Init_introduced)}
    if LibVersion < SHA1_Init_introduced then
    begin
      {$if declared(FC_SHA1_Init)}
      SHA1_Init := FC_SHA1_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Init_removed)}
    if SHA1_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Init)}
      SHA1_Init := _SHA1_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Init');
    {$ifend}
  end;
  
  SHA1_Update := LoadLibFunction(ADllHandle, SHA1_Update_procname);
  FuncLoadError := not assigned(SHA1_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Update_allownil)}
    SHA1_Update := ERR_SHA1_Update;
    {$ifend}
    {$if declared(SHA1_Update_introduced)}
    if LibVersion < SHA1_Update_introduced then
    begin
      {$if declared(FC_SHA1_Update)}
      SHA1_Update := FC_SHA1_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Update_removed)}
    if SHA1_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Update)}
      SHA1_Update := _SHA1_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Update');
    {$ifend}
  end;
  
  SHA1_Final := LoadLibFunction(ADllHandle, SHA1_Final_procname);
  FuncLoadError := not assigned(SHA1_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Final_allownil)}
    SHA1_Final := ERR_SHA1_Final;
    {$ifend}
    {$if declared(SHA1_Final_introduced)}
    if LibVersion < SHA1_Final_introduced then
    begin
      {$if declared(FC_SHA1_Final)}
      SHA1_Final := FC_SHA1_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Final_removed)}
    if SHA1_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Final)}
      SHA1_Final := _SHA1_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Final');
    {$ifend}
  end;
  
  SHA1_Transform := LoadLibFunction(ADllHandle, SHA1_Transform_procname);
  FuncLoadError := not assigned(SHA1_Transform);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_Transform_allownil)}
    SHA1_Transform := ERR_SHA1_Transform;
    {$ifend}
    {$if declared(SHA1_Transform_introduced)}
    if LibVersion < SHA1_Transform_introduced then
    begin
      {$if declared(FC_SHA1_Transform)}
      SHA1_Transform := FC_SHA1_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_Transform_removed)}
    if SHA1_Transform_removed <= LibVersion then
    begin
      {$if declared(_SHA1_Transform)}
      SHA1_Transform := _SHA1_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1_Transform');
    {$ifend}
  end;
  
  SHA1 := LoadLibFunction(ADllHandle, SHA1_procname);
  FuncLoadError := not assigned(SHA1);
  if FuncLoadError then
  begin
    {$if not defined(SHA1_allownil)}
    SHA1 := ERR_SHA1;
    {$ifend}
    {$if declared(SHA1_introduced)}
    if LibVersion < SHA1_introduced then
    begin
      {$if declared(FC_SHA1)}
      SHA1 := FC_SHA1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA1_removed)}
    if SHA1_removed <= LibVersion then
    begin
      {$if declared(_SHA1)}
      SHA1 := _SHA1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA1_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA1');
    {$ifend}
  end;
  
  SHA224_Init := LoadLibFunction(ADllHandle, SHA224_Init_procname);
  FuncLoadError := not assigned(SHA224_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_Init_allownil)}
    SHA224_Init := ERR_SHA224_Init;
    {$ifend}
    {$if declared(SHA224_Init_introduced)}
    if LibVersion < SHA224_Init_introduced then
    begin
      {$if declared(FC_SHA224_Init)}
      SHA224_Init := FC_SHA224_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_Init_removed)}
    if SHA224_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA224_Init)}
      SHA224_Init := _SHA224_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224_Init');
    {$ifend}
  end;
  
  SHA224_Update := LoadLibFunction(ADllHandle, SHA224_Update_procname);
  FuncLoadError := not assigned(SHA224_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_Update_allownil)}
    SHA224_Update := ERR_SHA224_Update;
    {$ifend}
    {$if declared(SHA224_Update_introduced)}
    if LibVersion < SHA224_Update_introduced then
    begin
      {$if declared(FC_SHA224_Update)}
      SHA224_Update := FC_SHA224_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_Update_removed)}
    if SHA224_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA224_Update)}
      SHA224_Update := _SHA224_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224_Update');
    {$ifend}
  end;
  
  SHA224_Final := LoadLibFunction(ADllHandle, SHA224_Final_procname);
  FuncLoadError := not assigned(SHA224_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_Final_allownil)}
    SHA224_Final := ERR_SHA224_Final;
    {$ifend}
    {$if declared(SHA224_Final_introduced)}
    if LibVersion < SHA224_Final_introduced then
    begin
      {$if declared(FC_SHA224_Final)}
      SHA224_Final := FC_SHA224_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_Final_removed)}
    if SHA224_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA224_Final)}
      SHA224_Final := _SHA224_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224_Final');
    {$ifend}
  end;
  
  SHA256_Init := LoadLibFunction(ADllHandle, SHA256_Init_procname);
  FuncLoadError := not assigned(SHA256_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Init_allownil)}
    SHA256_Init := ERR_SHA256_Init;
    {$ifend}
    {$if declared(SHA256_Init_introduced)}
    if LibVersion < SHA256_Init_introduced then
    begin
      {$if declared(FC_SHA256_Init)}
      SHA256_Init := FC_SHA256_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Init_removed)}
    if SHA256_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Init)}
      SHA256_Init := _SHA256_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Init');
    {$ifend}
  end;
  
  SHA256_Update := LoadLibFunction(ADllHandle, SHA256_Update_procname);
  FuncLoadError := not assigned(SHA256_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Update_allownil)}
    SHA256_Update := ERR_SHA256_Update;
    {$ifend}
    {$if declared(SHA256_Update_introduced)}
    if LibVersion < SHA256_Update_introduced then
    begin
      {$if declared(FC_SHA256_Update)}
      SHA256_Update := FC_SHA256_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Update_removed)}
    if SHA256_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Update)}
      SHA256_Update := _SHA256_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Update');
    {$ifend}
  end;
  
  SHA256_Final := LoadLibFunction(ADllHandle, SHA256_Final_procname);
  FuncLoadError := not assigned(SHA256_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Final_allownil)}
    SHA256_Final := ERR_SHA256_Final;
    {$ifend}
    {$if declared(SHA256_Final_introduced)}
    if LibVersion < SHA256_Final_introduced then
    begin
      {$if declared(FC_SHA256_Final)}
      SHA256_Final := FC_SHA256_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Final_removed)}
    if SHA256_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Final)}
      SHA256_Final := _SHA256_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Final');
    {$ifend}
  end;
  
  SHA256_Transform := LoadLibFunction(ADllHandle, SHA256_Transform_procname);
  FuncLoadError := not assigned(SHA256_Transform);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_Transform_allownil)}
    SHA256_Transform := ERR_SHA256_Transform;
    {$ifend}
    {$if declared(SHA256_Transform_introduced)}
    if LibVersion < SHA256_Transform_introduced then
    begin
      {$if declared(FC_SHA256_Transform)}
      SHA256_Transform := FC_SHA256_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_Transform_removed)}
    if SHA256_Transform_removed <= LibVersion then
    begin
      {$if declared(_SHA256_Transform)}
      SHA256_Transform := _SHA256_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256_Transform');
    {$ifend}
  end;
  
  SHA224 := LoadLibFunction(ADllHandle, SHA224_procname);
  FuncLoadError := not assigned(SHA224);
  if FuncLoadError then
  begin
    {$if not defined(SHA224_allownil)}
    SHA224 := ERR_SHA224;
    {$ifend}
    {$if declared(SHA224_introduced)}
    if LibVersion < SHA224_introduced then
    begin
      {$if declared(FC_SHA224)}
      SHA224 := FC_SHA224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA224_removed)}
    if SHA224_removed <= LibVersion then
    begin
      {$if declared(_SHA224)}
      SHA224 := _SHA224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA224_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA224');
    {$ifend}
  end;
  
  SHA256 := LoadLibFunction(ADllHandle, SHA256_procname);
  FuncLoadError := not assigned(SHA256);
  if FuncLoadError then
  begin
    {$if not defined(SHA256_allownil)}
    SHA256 := ERR_SHA256;
    {$ifend}
    {$if declared(SHA256_introduced)}
    if LibVersion < SHA256_introduced then
    begin
      {$if declared(FC_SHA256)}
      SHA256 := FC_SHA256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA256_removed)}
    if SHA256_removed <= LibVersion then
    begin
      {$if declared(_SHA256)}
      SHA256 := _SHA256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA256_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA256');
    {$ifend}
  end;
  
  SHA384_Init := LoadLibFunction(ADllHandle, SHA384_Init_procname);
  FuncLoadError := not assigned(SHA384_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_Init_allownil)}
    SHA384_Init := ERR_SHA384_Init;
    {$ifend}
    {$if declared(SHA384_Init_introduced)}
    if LibVersion < SHA384_Init_introduced then
    begin
      {$if declared(FC_SHA384_Init)}
      SHA384_Init := FC_SHA384_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_Init_removed)}
    if SHA384_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA384_Init)}
      SHA384_Init := _SHA384_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384_Init');
    {$ifend}
  end;
  
  SHA384_Update := LoadLibFunction(ADllHandle, SHA384_Update_procname);
  FuncLoadError := not assigned(SHA384_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_Update_allownil)}
    SHA384_Update := ERR_SHA384_Update;
    {$ifend}
    {$if declared(SHA384_Update_introduced)}
    if LibVersion < SHA384_Update_introduced then
    begin
      {$if declared(FC_SHA384_Update)}
      SHA384_Update := FC_SHA384_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_Update_removed)}
    if SHA384_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA384_Update)}
      SHA384_Update := _SHA384_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384_Update');
    {$ifend}
  end;
  
  SHA384_Final := LoadLibFunction(ADllHandle, SHA384_Final_procname);
  FuncLoadError := not assigned(SHA384_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_Final_allownil)}
    SHA384_Final := ERR_SHA384_Final;
    {$ifend}
    {$if declared(SHA384_Final_introduced)}
    if LibVersion < SHA384_Final_introduced then
    begin
      {$if declared(FC_SHA384_Final)}
      SHA384_Final := FC_SHA384_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_Final_removed)}
    if SHA384_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA384_Final)}
      SHA384_Final := _SHA384_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384_Final');
    {$ifend}
  end;
  
  SHA512_Init := LoadLibFunction(ADllHandle, SHA512_Init_procname);
  FuncLoadError := not assigned(SHA512_Init);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Init_allownil)}
    SHA512_Init := ERR_SHA512_Init;
    {$ifend}
    {$if declared(SHA512_Init_introduced)}
    if LibVersion < SHA512_Init_introduced then
    begin
      {$if declared(FC_SHA512_Init)}
      SHA512_Init := FC_SHA512_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Init_removed)}
    if SHA512_Init_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Init)}
      SHA512_Init := _SHA512_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Init');
    {$ifend}
  end;
  
  SHA512_Update := LoadLibFunction(ADllHandle, SHA512_Update_procname);
  FuncLoadError := not assigned(SHA512_Update);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Update_allownil)}
    SHA512_Update := ERR_SHA512_Update;
    {$ifend}
    {$if declared(SHA512_Update_introduced)}
    if LibVersion < SHA512_Update_introduced then
    begin
      {$if declared(FC_SHA512_Update)}
      SHA512_Update := FC_SHA512_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Update_removed)}
    if SHA512_Update_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Update)}
      SHA512_Update := _SHA512_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Update');
    {$ifend}
  end;
  
  SHA512_Final := LoadLibFunction(ADllHandle, SHA512_Final_procname);
  FuncLoadError := not assigned(SHA512_Final);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Final_allownil)}
    SHA512_Final := ERR_SHA512_Final;
    {$ifend}
    {$if declared(SHA512_Final_introduced)}
    if LibVersion < SHA512_Final_introduced then
    begin
      {$if declared(FC_SHA512_Final)}
      SHA512_Final := FC_SHA512_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Final_removed)}
    if SHA512_Final_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Final)}
      SHA512_Final := _SHA512_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Final');
    {$ifend}
  end;
  
  SHA512_Transform := LoadLibFunction(ADllHandle, SHA512_Transform_procname);
  FuncLoadError := not assigned(SHA512_Transform);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_Transform_allownil)}
    SHA512_Transform := ERR_SHA512_Transform;
    {$ifend}
    {$if declared(SHA512_Transform_introduced)}
    if LibVersion < SHA512_Transform_introduced then
    begin
      {$if declared(FC_SHA512_Transform)}
      SHA512_Transform := FC_SHA512_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_Transform_removed)}
    if SHA512_Transform_removed <= LibVersion then
    begin
      {$if declared(_SHA512_Transform)}
      SHA512_Transform := _SHA512_Transform;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_Transform_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512_Transform');
    {$ifend}
  end;
  
  SHA384 := LoadLibFunction(ADllHandle, SHA384_procname);
  FuncLoadError := not assigned(SHA384);
  if FuncLoadError then
  begin
    {$if not defined(SHA384_allownil)}
    SHA384 := ERR_SHA384;
    {$ifend}
    {$if declared(SHA384_introduced)}
    if LibVersion < SHA384_introduced then
    begin
      {$if declared(FC_SHA384)}
      SHA384 := FC_SHA384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA384_removed)}
    if SHA384_removed <= LibVersion then
    begin
      {$if declared(_SHA384)}
      SHA384 := _SHA384;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA384_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA384');
    {$ifend}
  end;
  
  SHA512 := LoadLibFunction(ADllHandle, SHA512_procname);
  FuncLoadError := not assigned(SHA512);
  if FuncLoadError then
  begin
    {$if not defined(SHA512_allownil)}
    SHA512 := ERR_SHA512;
    {$ifend}
    {$if declared(SHA512_introduced)}
    if LibVersion < SHA512_introduced then
    begin
      {$if declared(FC_SHA512)}
      SHA512 := FC_SHA512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SHA512_removed)}
    if SHA512_removed <= LibVersion then
    begin
      {$if declared(_SHA512)}
      SHA512 := _SHA512;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SHA512_allownil)}
    if FuncLoadError then
      AFailed.Add('SHA512');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  SHA1_Init := nil;
  SHA1_Update := nil;
  SHA1_Final := nil;
  SHA1_Transform := nil;
  SHA1 := nil;
  SHA224_Init := nil;
  SHA224_Update := nil;
  SHA224_Final := nil;
  SHA256_Init := nil;
  SHA256_Update := nil;
  SHA256_Final := nil;
  SHA256_Transform := nil;
  SHA224 := nil;
  SHA256 := nil;
  SHA384_Init := nil;
  SHA384_Update := nil;
  SHA384_Final := nil;
  SHA512_Init := nil;
  SHA512_Update := nil;
  SHA512_Final := nil;
  SHA512_Transform := nil;
  SHA384 := nil;
  SHA512 := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.