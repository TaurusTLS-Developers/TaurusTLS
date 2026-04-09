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

unit TaurusTLSHeaders_trace;

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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_trace_cb_func_cb = function(arg1: PIdAnsiChar; arg2: TIdC_SIZET; arg3: TIdC_INT; arg4: TIdC_INT; arg5: Pointer): TIdC_SIZET; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_TRACE_CATEGORY_ALL = 0;
  OSSL_TRACE_CATEGORY_TRACE = 1;
  OSSL_TRACE_CATEGORY_INIT = 2;
  OSSL_TRACE_CATEGORY_TLS = 3;
  OSSL_TRACE_CATEGORY_TLS_CIPHER = 4;
  OSSL_TRACE_CATEGORY_CONF = 5;
  OSSL_TRACE_CATEGORY_ENGINE_TABLE = 6;
  OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT = 7;
  OSSL_TRACE_CATEGORY_PKCS5V2 = 8;
  OSSL_TRACE_CATEGORY_PKCS12_KEYGEN = 9;
  OSSL_TRACE_CATEGORY_PKCS12_DECRYPT = 10;
  OSSL_TRACE_CATEGORY_X509V3_POLICY = 11;
  OSSL_TRACE_CATEGORY_BN_CTX = 12;
  OSSL_TRACE_CATEGORY_CMP = 13;
  OSSL_TRACE_CATEGORY_STORE = 14;
  OSSL_TRACE_CATEGORY_DECODER = 15;
  OSSL_TRACE_CATEGORY_ENCODER = 16;
  OSSL_TRACE_CATEGORY_REF_COUNT = 17;
  OSSL_TRACE_CATEGORY_HTTP = 18;
  OSSL_TRACE_CATEGORY_PROVIDER = 19;
  OSSL_TRACE_CATEGORY_QUERY = 20;
  OSSL_TRACE_CATEGORY_NUM = 21;
  OSSL_TRACE_CTRL_BEGIN = 0;
  OSSL_TRACE_CTRL_WRITE = 1;
  OSSL_TRACE_CTRL_END = 2;
  OSSL_TRACE_STRING_MAX = 80;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_trace_get_category_num: function(name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_get_category_num}

  OSSL_trace_get_category_name: function(num: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_get_category_name}

  OSSL_trace_set_channel: function(category: TIdC_INT; channel: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_set_channel}

  OSSL_trace_set_prefix: function(category: TIdC_INT; prefix: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_set_prefix}

  OSSL_trace_set_suffix: function(category: TIdC_INT; suffix: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_set_suffix}

  OSSL_trace_set_callback: function(category: TIdC_INT; callback: TOSSL_trace_cb_func_cb; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_set_callback}

  OSSL_trace_enabled: function(category: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_enabled}

  OSSL_trace_begin: function(category: TIdC_INT): PBIO; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_begin}

  OSSL_trace_end: procedure(category: TIdC_INT; channel: PBIO); cdecl = nil;
  {$EXTERNALSYM OSSL_trace_end}

  OSSL_trace_string: function(_out: PBIO; text: TIdC_INT; full: TIdC_INT; data: PIdAnsiChar; size: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_trace_string}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_trace_get_category_num(name: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_trace_get_category_name(num: TIdC_INT): PIdAnsiChar; cdecl;
function OSSL_trace_set_channel(category: TIdC_INT; channel: PBIO): TIdC_INT; cdecl;
function OSSL_trace_set_prefix(category: TIdC_INT; prefix: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_trace_set_suffix(category: TIdC_INT; suffix: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_trace_set_callback(category: TIdC_INT; callback: TOSSL_trace_cb_func_cb; data: Pointer): TIdC_INT; cdecl;
function OSSL_trace_enabled(category: TIdC_INT): TIdC_INT; cdecl;
function OSSL_trace_begin(category: TIdC_INT): PBIO; cdecl;
procedure OSSL_trace_end(category: TIdC_INT; channel: PBIO); cdecl;
function OSSL_trace_string(_out: PBIO; text: TIdC_INT; full: TIdC_INT; data: PIdAnsiChar; size: TIdC_SIZET): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function OSSL_TRACE_BEGIN(category: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_TRACE_END(category: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_TRACE_CANCEL(category: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_TRACE1(category: Pointer; format: Pointer; arg1: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_TRACE2(category: Pointer; format: Pointer; arg1: Pointer; arg2: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function OSSL_TRACE9(category: Pointer; format: Pointer; arg1: Pointer; arg2: Pointer; arg3: Pointer; arg4: Pointer; arg5: Pointer; arg6: Pointer; arg7: Pointer; arg8: Pointer; arg9: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}


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

function OSSL_trace_get_category_num(name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_trace_get_category_num';
function OSSL_trace_get_category_name(num: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_trace_get_category_name';
function OSSL_trace_set_channel(category: TIdC_INT; channel: PBIO): TIdC_INT; cdecl external CLibCrypto name 'OSSL_trace_set_channel';
function OSSL_trace_set_prefix(category: TIdC_INT; prefix: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_trace_set_prefix';
function OSSL_trace_set_suffix(category: TIdC_INT; suffix: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_trace_set_suffix';
function OSSL_trace_set_callback(category: TIdC_INT; callback: TOSSL_trace_cb_func_cb; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_trace_set_callback';
function OSSL_trace_enabled(category: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_trace_enabled';
function OSSL_trace_begin(category: TIdC_INT): PBIO; cdecl external CLibCrypto name 'OSSL_trace_begin';
procedure OSSL_trace_end(category: TIdC_INT; channel: PBIO); cdecl external CLibCrypto name 'OSSL_trace_end';
function OSSL_trace_string(_out: PBIO; text: TIdC_INT; full: TIdC_INT; data: PIdAnsiChar; size: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_trace_string';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_trace_get_category_num_procname = 'OSSL_trace_get_category_num';
  OSSL_trace_get_category_num_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_get_category_name_procname = 'OSSL_trace_get_category_name';
  OSSL_trace_get_category_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_set_channel_procname = 'OSSL_trace_set_channel';
  OSSL_trace_set_channel_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_set_prefix_procname = 'OSSL_trace_set_prefix';
  OSSL_trace_set_prefix_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_set_suffix_procname = 'OSSL_trace_set_suffix';
  OSSL_trace_set_suffix_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_set_callback_procname = 'OSSL_trace_set_callback';
  OSSL_trace_set_callback_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_enabled_procname = 'OSSL_trace_enabled';
  OSSL_trace_enabled_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_begin_procname = 'OSSL_trace_begin';
  OSSL_trace_begin_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_end_procname = 'OSSL_trace_end';
  OSSL_trace_end_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_trace_string_procname = 'OSSL_trace_string';
  OSSL_trace_string_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OSSL_TRACE_BEGIN(category: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_TRACE_BEGIN(category) \
    do {                           \
        BIO *trc_out = NULL;       \
        if (0)
  }
end;

function OSSL_TRACE_END(category: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_TRACE_END(category) \
    }                            \
    while (0)
  }
end;

function OSSL_TRACE_CANCEL(category: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_TRACE_CANCEL(category) \
    ((void)0)
  }
end;

function OSSL_TRACE1(category: Pointer; format: Pointer; arg1: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_TRACE1(category, format, arg1) \
    OSSL_TRACEV(category, (trc_out, format, arg1))
  }
end;

function OSSL_TRACE2(category: Pointer; format: Pointer; arg1: Pointer; arg2: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_TRACE2(category, format, arg1, arg2) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2))
  }
end;

function OSSL_TRACE9(category: Pointer; format: Pointer; arg1: Pointer; arg2: Pointer; arg3: Pointer; arg4: Pointer; arg5: Pointer; arg6: Pointer; arg7: Pointer; arg8: Pointer; arg9: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_TRACE9(category, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) \
    OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_trace_get_category_num(name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_get_category_num_procname);
end;

function ERR_OSSL_trace_get_category_name(num: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_get_category_name_procname);
end;

function ERR_OSSL_trace_set_channel(category: TIdC_INT; channel: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_set_channel_procname);
end;

function ERR_OSSL_trace_set_prefix(category: TIdC_INT; prefix: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_set_prefix_procname);
end;

function ERR_OSSL_trace_set_suffix(category: TIdC_INT; suffix: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_set_suffix_procname);
end;

function ERR_OSSL_trace_set_callback(category: TIdC_INT; callback: TOSSL_trace_cb_func_cb; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_set_callback_procname);
end;

function ERR_OSSL_trace_enabled(category: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_enabled_procname);
end;

function ERR_OSSL_trace_begin(category: TIdC_INT): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_begin_procname);
end;

procedure ERR_OSSL_trace_end(category: TIdC_INT; channel: PBIO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_end_procname);
end;

function ERR_OSSL_trace_string(_out: PBIO; text: TIdC_INT; full: TIdC_INT; data: PIdAnsiChar; size: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_trace_string_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_trace_get_category_num := LoadLibFunction(ADllHandle, OSSL_trace_get_category_num_procname);
  FuncLoadError := not assigned(OSSL_trace_get_category_num);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_get_category_num_allownil)}
    OSSL_trace_get_category_num := ERR_OSSL_trace_get_category_num;
    {$ifend}
    {$if declared(OSSL_trace_get_category_num_introduced)}
    if LibVersion < OSSL_trace_get_category_num_introduced then
    begin
      {$if declared(FC_OSSL_trace_get_category_num)}
      OSSL_trace_get_category_num := FC_OSSL_trace_get_category_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_get_category_num_removed)}
    if OSSL_trace_get_category_num_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_get_category_num)}
      OSSL_trace_get_category_num := _OSSL_trace_get_category_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_get_category_num_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_get_category_num');
    {$ifend}
  end;
  
  OSSL_trace_get_category_name := LoadLibFunction(ADllHandle, OSSL_trace_get_category_name_procname);
  FuncLoadError := not assigned(OSSL_trace_get_category_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_get_category_name_allownil)}
    OSSL_trace_get_category_name := ERR_OSSL_trace_get_category_name;
    {$ifend}
    {$if declared(OSSL_trace_get_category_name_introduced)}
    if LibVersion < OSSL_trace_get_category_name_introduced then
    begin
      {$if declared(FC_OSSL_trace_get_category_name)}
      OSSL_trace_get_category_name := FC_OSSL_trace_get_category_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_get_category_name_removed)}
    if OSSL_trace_get_category_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_get_category_name)}
      OSSL_trace_get_category_name := _OSSL_trace_get_category_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_get_category_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_get_category_name');
    {$ifend}
  end;
  
  OSSL_trace_set_channel := LoadLibFunction(ADllHandle, OSSL_trace_set_channel_procname);
  FuncLoadError := not assigned(OSSL_trace_set_channel);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_set_channel_allownil)}
    OSSL_trace_set_channel := ERR_OSSL_trace_set_channel;
    {$ifend}
    {$if declared(OSSL_trace_set_channel_introduced)}
    if LibVersion < OSSL_trace_set_channel_introduced then
    begin
      {$if declared(FC_OSSL_trace_set_channel)}
      OSSL_trace_set_channel := FC_OSSL_trace_set_channel;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_set_channel_removed)}
    if OSSL_trace_set_channel_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_set_channel)}
      OSSL_trace_set_channel := _OSSL_trace_set_channel;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_set_channel_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_set_channel');
    {$ifend}
  end;
  
  OSSL_trace_set_prefix := LoadLibFunction(ADllHandle, OSSL_trace_set_prefix_procname);
  FuncLoadError := not assigned(OSSL_trace_set_prefix);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_set_prefix_allownil)}
    OSSL_trace_set_prefix := ERR_OSSL_trace_set_prefix;
    {$ifend}
    {$if declared(OSSL_trace_set_prefix_introduced)}
    if LibVersion < OSSL_trace_set_prefix_introduced then
    begin
      {$if declared(FC_OSSL_trace_set_prefix)}
      OSSL_trace_set_prefix := FC_OSSL_trace_set_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_set_prefix_removed)}
    if OSSL_trace_set_prefix_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_set_prefix)}
      OSSL_trace_set_prefix := _OSSL_trace_set_prefix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_set_prefix_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_set_prefix');
    {$ifend}
  end;
  
  OSSL_trace_set_suffix := LoadLibFunction(ADllHandle, OSSL_trace_set_suffix_procname);
  FuncLoadError := not assigned(OSSL_trace_set_suffix);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_set_suffix_allownil)}
    OSSL_trace_set_suffix := ERR_OSSL_trace_set_suffix;
    {$ifend}
    {$if declared(OSSL_trace_set_suffix_introduced)}
    if LibVersion < OSSL_trace_set_suffix_introduced then
    begin
      {$if declared(FC_OSSL_trace_set_suffix)}
      OSSL_trace_set_suffix := FC_OSSL_trace_set_suffix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_set_suffix_removed)}
    if OSSL_trace_set_suffix_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_set_suffix)}
      OSSL_trace_set_suffix := _OSSL_trace_set_suffix;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_set_suffix_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_set_suffix');
    {$ifend}
  end;
  
  OSSL_trace_set_callback := LoadLibFunction(ADllHandle, OSSL_trace_set_callback_procname);
  FuncLoadError := not assigned(OSSL_trace_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_set_callback_allownil)}
    OSSL_trace_set_callback := ERR_OSSL_trace_set_callback;
    {$ifend}
    {$if declared(OSSL_trace_set_callback_introduced)}
    if LibVersion < OSSL_trace_set_callback_introduced then
    begin
      {$if declared(FC_OSSL_trace_set_callback)}
      OSSL_trace_set_callback := FC_OSSL_trace_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_set_callback_removed)}
    if OSSL_trace_set_callback_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_set_callback)}
      OSSL_trace_set_callback := _OSSL_trace_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_set_callback');
    {$ifend}
  end;
  
  OSSL_trace_enabled := LoadLibFunction(ADllHandle, OSSL_trace_enabled_procname);
  FuncLoadError := not assigned(OSSL_trace_enabled);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_enabled_allownil)}
    OSSL_trace_enabled := ERR_OSSL_trace_enabled;
    {$ifend}
    {$if declared(OSSL_trace_enabled_introduced)}
    if LibVersion < OSSL_trace_enabled_introduced then
    begin
      {$if declared(FC_OSSL_trace_enabled)}
      OSSL_trace_enabled := FC_OSSL_trace_enabled;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_enabled_removed)}
    if OSSL_trace_enabled_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_enabled)}
      OSSL_trace_enabled := _OSSL_trace_enabled;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_enabled_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_enabled');
    {$ifend}
  end;
  
  OSSL_trace_begin := LoadLibFunction(ADllHandle, OSSL_trace_begin_procname);
  FuncLoadError := not assigned(OSSL_trace_begin);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_begin_allownil)}
    OSSL_trace_begin := ERR_OSSL_trace_begin;
    {$ifend}
    {$if declared(OSSL_trace_begin_introduced)}
    if LibVersion < OSSL_trace_begin_introduced then
    begin
      {$if declared(FC_OSSL_trace_begin)}
      OSSL_trace_begin := FC_OSSL_trace_begin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_begin_removed)}
    if OSSL_trace_begin_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_begin)}
      OSSL_trace_begin := _OSSL_trace_begin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_begin_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_begin');
    {$ifend}
  end;
  
  OSSL_trace_end := LoadLibFunction(ADllHandle, OSSL_trace_end_procname);
  FuncLoadError := not assigned(OSSL_trace_end);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_end_allownil)}
    OSSL_trace_end := ERR_OSSL_trace_end;
    {$ifend}
    {$if declared(OSSL_trace_end_introduced)}
    if LibVersion < OSSL_trace_end_introduced then
    begin
      {$if declared(FC_OSSL_trace_end)}
      OSSL_trace_end := FC_OSSL_trace_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_end_removed)}
    if OSSL_trace_end_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_end)}
      OSSL_trace_end := _OSSL_trace_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_end_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_end');
    {$ifend}
  end;
  
  OSSL_trace_string := LoadLibFunction(ADllHandle, OSSL_trace_string_procname);
  FuncLoadError := not assigned(OSSL_trace_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_trace_string_allownil)}
    OSSL_trace_string := ERR_OSSL_trace_string;
    {$ifend}
    {$if declared(OSSL_trace_string_introduced)}
    if LibVersion < OSSL_trace_string_introduced then
    begin
      {$if declared(FC_OSSL_trace_string)}
      OSSL_trace_string := FC_OSSL_trace_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_trace_string_removed)}
    if OSSL_trace_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_trace_string)}
      OSSL_trace_string := _OSSL_trace_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_trace_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_trace_string');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_trace_get_category_num := nil;
  OSSL_trace_get_category_name := nil;
  OSSL_trace_set_channel := nil;
  OSSL_trace_set_prefix := nil;
  OSSL_trace_set_suffix := nil;
  OSSL_trace_set_callback := nil;
  OSSL_trace_enabled := nil;
  OSSL_trace_begin := nil;
  OSSL_trace_end := nil;
  OSSL_trace_string := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.