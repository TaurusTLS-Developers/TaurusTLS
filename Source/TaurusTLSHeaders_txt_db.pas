/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_txt_db.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_txt_db.h2pas
     and this file regenerated. TaurusTLSHeaders_txt_db.h2pas is distributed with the full Indy
     Distribution.
   *)
   
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

// Headers for OpenSSL 1.1.1
// txt_db.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL }
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_safestack,
  TaurusTLSHeaders_types;

const
  {$EXTERNALSYM DB_ERROR_OK}
  DB_ERROR_OK = 0;
  {$EXTERNALSYM DB_ERROR_MALLOC}
  DB_ERROR_MALLOC = 1;
  {$EXTERNALSYM DB_ERROR_INDEX_CLASH}
  DB_ERROR_INDEX_CLASH = 2;
  {$EXTERNALSYM DB_ERROR_INDEX_OUT_OF_RANGE}
  DB_ERROR_INDEX_OUT_OF_RANGE = 3;
  {$EXTERNALSYM DB_ERROR_NO_INDEX}
  DB_ERROR_NO_INDEX = 4;
  {$EXTERNALSYM DB_ERROR_INSERT_INDEX_CLASH}
  DB_ERROR_INSERT_INDEX_CLASH = 5;
  {$EXTERNALSYM DB_ERROR_WRONG_NUM_FIELDS}
  DB_ERROR_WRONG_NUM_FIELDS = 6;

type
// DEFINE_SPECIAL_STACK_OF(OPENSSL_PSTRING, OPENSSL_STRING)

  {$EXTERNALSYM qual_func}
  qual_func =  function (v1: POPENSSL_STRING): TIdC_INT;
  {$EXTERNALSYM txt_db_st}
  txt_db_st = record
    num_fields: TIdC_INT;
    data: Pointer; // STACK_OF(OPENSSL_PSTRING) *
    index: Pointer; // LHASH_OF(OPENSSL_STRING) **
    qual: qual_func;
    _error: TIdC_LONG;
    arg1: TIdC_LONG;
    arg2: TIdC_LONG;
    arg_row: POPENSSL_STRING;
  end;
  {$EXTERNALSYM TXT_DB}
  TXT_DB = txt_db_st;
  {$EXTERNALSYM PTXT_DB}
  PTXT_DB = ^TXT_DB;

  {$EXTERNALSYM TXT_DB_create_index_qual}
  TXT_DB_create_index_qual = function(v1: POPENSSL_STRING): TIdC_INT;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM TXT_DB_read}
  TXT_DB_read: function (in_: PBIO; num: TIdC_INT): PTXT_DB; cdecl = nil;
  {$EXTERNALSYM TXT_DB_write}
  TXT_DB_write: function (out_: PBIO; db: PTXT_DB): TIdC_LONG; cdecl = nil;
  //function TXT_DB_create_index(db: PTXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual; hash: OPENSSL_LH_HashFunc; cmp: OPENSSL_LH_COMPFUNC): TIdC_INT;
  {$EXTERNALSYM TXT_DB_free}
  TXT_DB_free: procedure (db: PTXT_DB); cdecl = nil;
  {$EXTERNALSYM TXT_DB_get_by_index}
  TXT_DB_get_by_index: function (db: PTXT_DB; idx: TIdC_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl = nil;
  {$EXTERNALSYM TXT_DB_insert}
  TXT_DB_insert: function (db: PTXT_DB; value: POPENSSL_STRING): TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM TXT_DB_read}
  function TXT_DB_read(in_: PBIO; num: TIdC_INT): PTXT_DB cdecl; external CLibCrypto;
  {$EXTERNALSYM TXT_DB_write}
  function TXT_DB_write(out_: PBIO; db: PTXT_DB): TIdC_LONG cdecl; external CLibCrypto;
  //function TXT_DB_create_index(db: PTXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual; hash: OPENSSL_LH_HashFunc; cmp: OPENSSL_LH_COMPFUNC): TIdC_INT;
  {$EXTERNALSYM TXT_DB_free}
  procedure TXT_DB_free(db: PTXT_DB) cdecl; external CLibCrypto;
  {$EXTERNALSYM TXT_DB_get_by_index}
  function TXT_DB_get_by_index(db: PTXT_DB; idx: TIdC_INT; value: POPENSSL_STRING): POPENSSL_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM TXT_DB_insert}
  function TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  TXT_DB_read_procname = 'TXT_DB_read';
  TXT_DB_write_procname = 'TXT_DB_write';
  //function TXT_DB_create_index(db: PTXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual; hash: OPENSSL_LH_HashFunc; cmp: OPENSSL_LH_COMPFUNC): TIdC_INT;
  TXT_DB_free_procname = 'TXT_DB_free';
  TXT_DB_get_by_index_procname = 'TXT_DB_get_by_index';
  TXT_DB_insert_procname = 'TXT_DB_insert';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_TXT_DB_read(in_: PBIO; num: TIdC_INT): PTXT_DB;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_read_procname);
end;


function  ERR_TXT_DB_write(out_: PBIO; db: PTXT_DB): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_write_procname);
end;


  //function TXT_DB_create_index(db: PTXT_DB; field: TIdC_INT; qual: TXT_DB_create_index_qual; hash: OPENSSL_LH_HashFunc; cmp: OPENSSL_LH_COMPFUNC): TIdC_INT;
procedure  ERR_TXT_DB_free(db: PTXT_DB);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_free_procname);
end;


function  ERR_TXT_DB_get_by_index(db: PTXT_DB; idx: TIdC_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_get_by_index_procname);
end;


function  ERR_TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(TXT_DB_insert_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

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
  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  TXT_DB_read := nil;
  TXT_DB_write := nil;
  TXT_DB_free := nil;
  TXT_DB_get_by_index := nil;
  TXT_DB_insert := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
