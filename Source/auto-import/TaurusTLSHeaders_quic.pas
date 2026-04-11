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

unit TaurusTLSHeaders_quic;

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
  OSSL_QUIC_ERR_NO_ERROR = $00;
  OSSL_QUIC_ERR_INTERNAL_ERROR = $01;
  OSSL_QUIC_ERR_CONNECTION_REFUSED = $02;
  OSSL_QUIC_ERR_FLOW_CONTROL_ERROR = $03;
  OSSL_QUIC_ERR_STREAM_LIMIT_ERROR = $04;
  OSSL_QUIC_ERR_STREAM_STATE_ERROR = $05;
  OSSL_QUIC_ERR_FINAL_SIZE_ERROR = $06;
  OSSL_QUIC_ERR_FRAME_ENCODING_ERROR = $07;
  OSSL_QUIC_ERR_TRANSPORT_PARAMETER_ERROR = $08;
  OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR = $09;
  OSSL_QUIC_ERR_PROTOCOL_VIOLATION = $0A;
  OSSL_QUIC_ERR_INVALID_TOKEN = $0B;
  OSSL_QUIC_ERR_APPLICATION_ERROR = $0C;
  OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED = $0D;
  OSSL_QUIC_ERR_KEY_UPDATE_ERROR = $0E;
  OSSL_QUIC_ERR_AEAD_LIMIT_REACHED = $0F;
  OSSL_QUIC_ERR_NO_VIABLE_PATH = $10;
  OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN = $0100;
  OSSL_QUIC_ERR_CRYPTO_ERR_END = $01FF;
  OSSL_QUIC_LOCAL_ERR_IDLE_TIMEOUT = ((uint64_t)$FFFFFFFFFFFFFFFFULL);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_QUIC_client_method: function: PSSL_METHOD; cdecl = nil;
  {$EXTERNALSYM OSSL_QUIC_client_method}

  OSSL_QUIC_client_thread_method: function: PSSL_METHOD; cdecl = nil;
  {$EXTERNALSYM OSSL_QUIC_client_thread_method}

  OSSL_QUIC_server_method: function: PSSL_METHOD; cdecl = nil;
  {$EXTERNALSYM OSSL_QUIC_server_method}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_QUIC_client_method: PSSL_METHOD; cdecl;
function OSSL_QUIC_client_thread_method: PSSL_METHOD; cdecl;
function OSSL_QUIC_server_method: PSSL_METHOD; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OSSL_QUIC_ERR_CRYPTO_ERR(X: Pointer): TIdC_INT; cdecl;


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

function OSSL_QUIC_client_method: PSSL_METHOD; cdecl external CLibCrypto name 'OSSL_QUIC_client_method';
function OSSL_QUIC_client_thread_method: PSSL_METHOD; cdecl external CLibCrypto name 'OSSL_QUIC_client_thread_method';
function OSSL_QUIC_server_method: PSSL_METHOD; cdecl external CLibCrypto name 'OSSL_QUIC_server_method';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_QUIC_client_method_procname = 'OSSL_QUIC_client_method';
  OSSL_QUIC_client_method_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_QUIC_client_thread_method_procname = 'OSSL_QUIC_client_thread_method';
  OSSL_QUIC_client_thread_method_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_QUIC_server_method_procname = 'OSSL_QUIC_server_method';
  OSSL_QUIC_server_method_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OSSL_QUIC_ERR_CRYPTO_ERR(X: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_QUIC_ERR_CRYPTO_ERR(X) \
    (OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN + (X))
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_QUIC_client_method: PSSL_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_QUIC_client_method_procname);
end;

function ERR_OSSL_QUIC_client_thread_method: PSSL_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_QUIC_client_thread_method_procname);
end;

function ERR_OSSL_QUIC_server_method: PSSL_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_QUIC_server_method_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_QUIC_client_method := LoadLibFunction(ADllHandle, OSSL_QUIC_client_method_procname);
  FuncLoadError := not assigned(OSSL_QUIC_client_method);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_QUIC_client_method_allownil)}
    OSSL_QUIC_client_method := ERR_OSSL_QUIC_client_method;
    {$ifend}
    {$if declared(OSSL_QUIC_client_method_introduced)}
    if LibVersion < OSSL_QUIC_client_method_introduced then
    begin
      {$if declared(FC_OSSL_QUIC_client_method)}
      OSSL_QUIC_client_method := FC_OSSL_QUIC_client_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_QUIC_client_method_removed)}
    if OSSL_QUIC_client_method_removed <= LibVersion then
    begin
      {$if declared(_OSSL_QUIC_client_method)}
      OSSL_QUIC_client_method := _OSSL_QUIC_client_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_QUIC_client_method_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_QUIC_client_method');
    {$ifend}
  end;
  
  OSSL_QUIC_client_thread_method := LoadLibFunction(ADllHandle, OSSL_QUIC_client_thread_method_procname);
  FuncLoadError := not assigned(OSSL_QUIC_client_thread_method);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_QUIC_client_thread_method_allownil)}
    OSSL_QUIC_client_thread_method := ERR_OSSL_QUIC_client_thread_method;
    {$ifend}
    {$if declared(OSSL_QUIC_client_thread_method_introduced)}
    if LibVersion < OSSL_QUIC_client_thread_method_introduced then
    begin
      {$if declared(FC_OSSL_QUIC_client_thread_method)}
      OSSL_QUIC_client_thread_method := FC_OSSL_QUIC_client_thread_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_QUIC_client_thread_method_removed)}
    if OSSL_QUIC_client_thread_method_removed <= LibVersion then
    begin
      {$if declared(_OSSL_QUIC_client_thread_method)}
      OSSL_QUIC_client_thread_method := _OSSL_QUIC_client_thread_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_QUIC_client_thread_method_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_QUIC_client_thread_method');
    {$ifend}
  end;
  
  OSSL_QUIC_server_method := LoadLibFunction(ADllHandle, OSSL_QUIC_server_method_procname);
  FuncLoadError := not assigned(OSSL_QUIC_server_method);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_QUIC_server_method_allownil)}
    OSSL_QUIC_server_method := ERR_OSSL_QUIC_server_method;
    {$ifend}
    {$if declared(OSSL_QUIC_server_method_introduced)}
    if LibVersion < OSSL_QUIC_server_method_introduced then
    begin
      {$if declared(FC_OSSL_QUIC_server_method)}
      OSSL_QUIC_server_method := FC_OSSL_QUIC_server_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_QUIC_server_method_removed)}
    if OSSL_QUIC_server_method_removed <= LibVersion then
    begin
      {$if declared(_OSSL_QUIC_server_method)}
      OSSL_QUIC_server_method := _OSSL_QUIC_server_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_QUIC_server_method_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_QUIC_server_method');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_QUIC_client_method := nil;
  OSSL_QUIC_client_thread_method := nil;
  OSSL_QUIC_server_method := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.