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

unit TaurusTLSHeaders_txt_db;

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
  POPENSSL_PSTRING = ^TOPENSSL_PSTRING;
  TOPENSSL_PSTRING = POPENSSL_STRING;
  {$EXTERNALSYM POPENSSL_PSTRING}

  Pstack_st_OPENSSL_PSTRING = ^Tstack_st_OPENSSL_PSTRING;
  Tstack_st_OPENSSL_PSTRING = record end;
  {$EXTERNALSYM Pstack_st_OPENSSL_PSTRING}

  Ptxt_db_st = ^Ttxt_db_st;
  Ttxt_db_st = record end;
  {$EXTERNALSYM Ptxt_db_st}

  PXT_DB = ^TXT_DB;
  TXT_DB = Ttxt_db_st;
  {$EXTERNALSYM PXT_DB}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tsk_OPENSSL_PSTRING_compfunc_func_cb = function(arg1: PPOPENSSL_STRING; arg2: PPOPENSSL_STRING): TIdC_INT; cdecl;
  Tsk_OPENSSL_PSTRING_freefunc_func_cb = procedure(arg1: POPENSSL_STRING); cdecl;
  Tsk_OPENSSL_PSTRING_copyfunc_func_cb = function(arg1: POPENSSL_STRING): POPENSSL_STRING; cdecl;
  TXT_DB_create_index_qual_cb = function(arg1: POPENSSL_STRING): TIdC_INT; cdecl;
  TXT_DB_create_index_hash_cb = function: T; cdecl;
  TXT_DB_create_index_cmp_cb = function: T; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  DB_ERROR_OK = 0;
  DB_ERROR_MALLOC = 1;
  DB_ERROR_INDEX_CLASH = 2;
  DB_ERROR_INDEX_OUT_OF_RANGE = 3;
  DB_ERROR_NO_INDEX = 4;
  DB_ERROR_INSERT_INDEX_CLASH = 5;
  DB_ERROR_WRONG_NUM_FIELDS = 6;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  TXT_DB_read: function(_in: PBIO; num: TIdC_INT): PXT_DB; cdecl = nil;
  {$EXTERNALSYM TXT_DB_read}

  TXT_DB_write: function(_out: PBIO; db: PXT_DB): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM TXT_DB_write}

  TXT_DB_create_index: function(db: PXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual_cb; hash: TXT_DB_create_index_hash_cb; cmp: TXT_DB_create_index_cmp_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TXT_DB_create_index}

  TXT_DB_free: procedure(db: PXT_DB); cdecl = nil;
  {$EXTERNALSYM TXT_DB_free}

  TXT_DB_get_by_index: function(db: PXT_DB; idx: TIdC_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl = nil;
  {$EXTERNALSYM TXT_DB_get_by_index}

  TXT_DB_insert: function(db: PXT_DB; value: POPENSSL_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM TXT_DB_insert}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function TXT_DB_read(_in: PBIO; num: TIdC_INT): PXT_DB; cdecl;
function TXT_DB_write(_out: PBIO; db: PXT_DB): TIdC_LONG; cdecl;
function TXT_DB_create_index(db: PXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual_cb; hash: TXT_DB_create_index_hash_cb; cmp: TXT_DB_create_index_cmp_cb): TIdC_INT; cdecl;
procedure TXT_DB_free(db: PXT_DB); cdecl;
function TXT_DB_get_by_index(db: PXT_DB; idx: TIdC_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl;
function TXT_DB_insert(db: PXT_DB; value: POPENSSL_STRING): TIdC_INT; cdecl;
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

function TXT_DB_read(_in: PBIO; num: TIdC_INT): PXT_DB; cdecl external CLibCrypto name 'TXT_DB_read';
function TXT_DB_write(_out: PBIO; db: PXT_DB): TIdC_LONG; cdecl external CLibCrypto name 'TXT_DB_write';
function TXT_DB_create_index(db: PXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual_cb; hash: TXT_DB_create_index_hash_cb; cmp: TXT_DB_create_index_cmp_cb): TIdC_INT; cdecl external CLibCrypto name 'TXT_DB_create_index';
procedure TXT_DB_free(db: PXT_DB); cdecl external CLibCrypto name 'TXT_DB_free';
function TXT_DB_get_by_index(db: PXT_DB; idx: TIdC_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl external CLibCrypto name 'TXT_DB_get_by_index';
function TXT_DB_insert(db: PXT_DB; value: POPENSSL_STRING): TIdC_INT; cdecl external CLibCrypto name 'TXT_DB_insert';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  TXT_DB_read_procname = 'TXT_DB_read';
  TXT_DB_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TXT_DB_write_procname = 'TXT_DB_write';
  TXT_DB_write_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TXT_DB_create_index_procname = 'TXT_DB_create_index';
  TXT_DB_create_index_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TXT_DB_free_procname = 'TXT_DB_free';
  TXT_DB_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TXT_DB_get_by_index_procname = 'TXT_DB_get_by_index';
  TXT_DB_get_by_index_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  TXT_DB_insert_procname = 'TXT_DB_insert';
  TXT_DB_insert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_TXT_DB_read(_in: PBIO; num: TIdC_INT): PXT_DB; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_read_procname);
end;

function ERR_TXT_DB_write(_out: PBIO; db: PXT_DB): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_write_procname);
end;

function ERR_TXT_DB_create_index(db: PXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual_cb; hash: TXT_DB_create_index_hash_cb; cmp: TXT_DB_create_index_cmp_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_create_index_procname);
end;

procedure ERR_TXT_DB_free(db: PXT_DB); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_free_procname);
end;

function ERR_TXT_DB_get_by_index(db: PXT_DB; idx: TIdC_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_get_by_index_procname);
end;

function ERR_TXT_DB_insert(db: PXT_DB; value: POPENSSL_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_insert_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  TXT_DB_read := LoadLibFunction(ADllHandle, TXT_DB_read_procname);
  FuncLoadError := not assigned(TXT_DB_read);
  if FuncLoadError then
  begin
    {$if not defined(TXT_DB_read_allownil)}
    TXT_DB_read := ERR_TXT_DB_read;
    {$ifend}
    {$if declared(TXT_DB_read_introduced)}
    if LibVersion < TXT_DB_read_introduced then
    begin
      {$if declared(FC_TXT_DB_read)}
      TXT_DB_read := FC_TXT_DB_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TXT_DB_read_removed)}
    if TXT_DB_read_removed <= LibVersion then
    begin
      {$if declared(_TXT_DB_read)}
      TXT_DB_read := _TXT_DB_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TXT_DB_read_allownil)}
    if FuncLoadError then
      AFailed.Add('TXT_DB_read');
    {$ifend}
  end;
  
  TXT_DB_write := LoadLibFunction(ADllHandle, TXT_DB_write_procname);
  FuncLoadError := not assigned(TXT_DB_write);
  if FuncLoadError then
  begin
    {$if not defined(TXT_DB_write_allownil)}
    TXT_DB_write := ERR_TXT_DB_write;
    {$ifend}
    {$if declared(TXT_DB_write_introduced)}
    if LibVersion < TXT_DB_write_introduced then
    begin
      {$if declared(FC_TXT_DB_write)}
      TXT_DB_write := FC_TXT_DB_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TXT_DB_write_removed)}
    if TXT_DB_write_removed <= LibVersion then
    begin
      {$if declared(_TXT_DB_write)}
      TXT_DB_write := _TXT_DB_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TXT_DB_write_allownil)}
    if FuncLoadError then
      AFailed.Add('TXT_DB_write');
    {$ifend}
  end;
  
  TXT_DB_create_index := LoadLibFunction(ADllHandle, TXT_DB_create_index_procname);
  FuncLoadError := not assigned(TXT_DB_create_index);
  if FuncLoadError then
  begin
    {$if not defined(TXT_DB_create_index_allownil)}
    TXT_DB_create_index := ERR_TXT_DB_create_index;
    {$ifend}
    {$if declared(TXT_DB_create_index_introduced)}
    if LibVersion < TXT_DB_create_index_introduced then
    begin
      {$if declared(FC_TXT_DB_create_index)}
      TXT_DB_create_index := FC_TXT_DB_create_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TXT_DB_create_index_removed)}
    if TXT_DB_create_index_removed <= LibVersion then
    begin
      {$if declared(_TXT_DB_create_index)}
      TXT_DB_create_index := _TXT_DB_create_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TXT_DB_create_index_allownil)}
    if FuncLoadError then
      AFailed.Add('TXT_DB_create_index');
    {$ifend}
  end;
  
  TXT_DB_free := LoadLibFunction(ADllHandle, TXT_DB_free_procname);
  FuncLoadError := not assigned(TXT_DB_free);
  if FuncLoadError then
  begin
    {$if not defined(TXT_DB_free_allownil)}
    TXT_DB_free := ERR_TXT_DB_free;
    {$ifend}
    {$if declared(TXT_DB_free_introduced)}
    if LibVersion < TXT_DB_free_introduced then
    begin
      {$if declared(FC_TXT_DB_free)}
      TXT_DB_free := FC_TXT_DB_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TXT_DB_free_removed)}
    if TXT_DB_free_removed <= LibVersion then
    begin
      {$if declared(_TXT_DB_free)}
      TXT_DB_free := _TXT_DB_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TXT_DB_free_allownil)}
    if FuncLoadError then
      AFailed.Add('TXT_DB_free');
    {$ifend}
  end;
  
  TXT_DB_get_by_index := LoadLibFunction(ADllHandle, TXT_DB_get_by_index_procname);
  FuncLoadError := not assigned(TXT_DB_get_by_index);
  if FuncLoadError then
  begin
    {$if not defined(TXT_DB_get_by_index_allownil)}
    TXT_DB_get_by_index := ERR_TXT_DB_get_by_index;
    {$ifend}
    {$if declared(TXT_DB_get_by_index_introduced)}
    if LibVersion < TXT_DB_get_by_index_introduced then
    begin
      {$if declared(FC_TXT_DB_get_by_index)}
      TXT_DB_get_by_index := FC_TXT_DB_get_by_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TXT_DB_get_by_index_removed)}
    if TXT_DB_get_by_index_removed <= LibVersion then
    begin
      {$if declared(_TXT_DB_get_by_index)}
      TXT_DB_get_by_index := _TXT_DB_get_by_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TXT_DB_get_by_index_allownil)}
    if FuncLoadError then
      AFailed.Add('TXT_DB_get_by_index');
    {$ifend}
  end;
  
  TXT_DB_insert := LoadLibFunction(ADllHandle, TXT_DB_insert_procname);
  FuncLoadError := not assigned(TXT_DB_insert);
  if FuncLoadError then
  begin
    {$if not defined(TXT_DB_insert_allownil)}
    TXT_DB_insert := ERR_TXT_DB_insert;
    {$ifend}
    {$if declared(TXT_DB_insert_introduced)}
    if LibVersion < TXT_DB_insert_introduced then
    begin
      {$if declared(FC_TXT_DB_insert)}
      TXT_DB_insert := FC_TXT_DB_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(TXT_DB_insert_removed)}
    if TXT_DB_insert_removed <= LibVersion then
    begin
      {$if declared(_TXT_DB_insert)}
      TXT_DB_insert := _TXT_DB_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(TXT_DB_insert_allownil)}
    if FuncLoadError then
      AFailed.Add('TXT_DB_insert');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  TXT_DB_read := nil;
  TXT_DB_write := nil;
  TXT_DB_create_index := nil;
  TXT_DB_free := nil;
  TXT_DB_get_by_index := nil;
  TXT_DB_insert := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.