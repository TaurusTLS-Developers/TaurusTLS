/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_rand.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_rand.h2pas
     and this file regenerated. TaurusTLSHeaders_rand.h2pas is distributed with the full Indy
     Distribution.
   *)
   
{$i TaurusTLSCompilerDefines.inc} 
{$i TaurusTLSLinkDefines.inc} 
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
unit TaurusTLSHeaders_rand;

interface

// Headers for OpenSSL 1.1.1
// rand.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types;

const
  RAND_DRBG_STRENGTH = 256; // Openssl default RANDOM strength value.
  RAND_DEFAULT_STRENGTH = RAND_DRBG_STRENGTH;

type
  rand_meth_st_seed = function (const buf: Pointer; num: TIdC_INT): TIdC_INT; cdecl;
  rand_meth_st_bytes = function (buf: PByte; num: TIdC_INT): TIdC_INT; cdecl;
  rand_meth_st_cleanup = procedure; cdecl;
  rand_meth_st_add = function (const buf: Pointer; num: TIdC_INT; randomness: TIdC_DOUBLE): TIdC_INT; cdecl;
  rand_meth_st_pseudorand = function (buf: PByte; num: TIdC_INT): TIdC_INT; cdecl;
  rand_meth_st_status = function: TIdC_INT; cdecl;

  rand_meth_st = record
    seed: rand_meth_st_seed;
    bytes: rand_meth_st_bytes;
    cleanup: rand_meth_st_cleanup;
    add: rand_meth_st_add;
    pseudorand: rand_meth_st_pseudorand;
    status: rand_meth_st_status;
  end;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$EXTERNALSYM RAND_set_rand_method}
  {$EXTERNALSYM RAND_get_rand_method}
  {$EXTERNALSYM RAND_set_rand_engine}
  {$EXTERNALSYM RAND_OpenSSL}
  {$EXTERNALSYM RAND_bytes}
  {$EXTERNALSYM RAND_priv_bytes}
  {$EXTERNALSYM RAND_priv_bytes_ex}
  {$EXTERNALSYM RAND_seed}
  {$EXTERNALSYM RAND_keep_random_devices_open}
  {$EXTERNALSYM RAND_add}
  {$EXTERNALSYM RAND_load_file}
  {$EXTERNALSYM RAND_write_file}
  {$EXTERNALSYM RAND_status}
  {$IFNDEF OPENSSL_NO_EGD}
  {$EXTERNALSYM RAND_query_egd_bytes}
  {$EXTERNALSYM RAND_egd}
  {$EXTERNALSYM RAND_egd_bytes}
  {$ENDIF}
  {$EXTERNALSYM RAND_poll}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  RAND_set_rand_method: function (const meth: PRAND_METHOD): TIdC_INT; cdecl = nil;
  RAND_get_rand_method: function : PRAND_METHOD; cdecl = nil;
  RAND_set_rand_engine: function (engine: PENGINE): TIdC_INT; cdecl = nil;

  RAND_OpenSSL: function : PRAND_METHOD; cdecl = nil;

  RAND_bytes: function (buf: PByte; num: TIdC_INT): TIdC_INT; cdecl = nil;
  RAND_bytes_ex: function(ctx : POSSL_LIB_CTX; buf : PIdAnsiChar;
     num : TIdC_SIZET; strength : TIdC_UINT) : TIdC_INT; cdecl = nil;
  RAND_priv_bytes: function (buf: PByte; num: TIdC_INT): TIdC_INT; cdecl = nil;
  RAND_priv_bytes_ex : function(ctx : POSSL_LIB_CTX; buf : PIdAnsiChar;
     num : TIdC_SIZET;  strength : TIdC_UINT) : TIdC_INT; cdecl = nil;

  RAND_seed: procedure (const buf: Pointer; num: TIdC_INT); cdecl = nil;
  RAND_keep_random_devices_open: procedure (keep: TIdC_INT); cdecl = nil;

  RAND_add: procedure (const buf: Pointer; num: TIdC_INT; randomness: TIdC_DOUBLE); cdecl = nil;
  RAND_load_file: function (const file_: PIdAnsiChar; max_bytes: TIdC_LONG): TIdC_INT; cdecl = nil;
  RAND_write_file: function (const file_: PIdAnsiChar): TIdC_INT; cdecl = nil;
  RAND_status: function : TIdC_INT; cdecl = nil;

  {$IFNDEF OPENSSL_NO_EGD}
  RAND_query_egd_bytes: function (const path: PIdAnsiChar; buf: PByte; bytes: TIdC_INT): TIdC_INT; cdecl = nil;
  RAND_egd: function (const path: PIdAnsiChar): TIdC_INT; cdecl = nil;
  RAND_egd_bytes: function (const path: PIdAnsiChar; bytes: TIdC_INT): TIdC_INT; cdecl = nil;
  {$ENDIF}

  RAND_poll: function : TIdC_INT; cdecl = nil;

{$ELSE}
  function RAND_set_rand_method(const meth: PRAND_METHOD): TIdC_INT cdecl; external CLibCrypto;
  function RAND_get_rand_method: PRAND_METHOD cdecl; external CLibCrypto;
  function RAND_set_rand_engine(engine: PENGINE): TIdC_INT cdecl; external CLibCrypto;

  function RAND_OpenSSL: PRAND_METHOD cdecl; external CLibCrypto;

  function RAND_bytes(buf: PByte; num: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function RAND_bytes_ex(ctx : POSSL_LIB_CTX; buf : PIdAnsiChar;
     num : TIdC_SIZET; strength : TIdC_UINT) : TIdC_INT cdecl; external CLibCrypto;
  function RAND_priv_bytes(buf: PByte; num: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function RAND_priv_bytes_ex(ctx : POSSL_LIB_CTX; buf : PIdAnsiChar;
     num : TIdC_SIZET;  strength : TIdC_UINT) : TIdC_INT; cdecl; external CLibCrypto;

  procedure RAND_seed(const buf: Pointer; num: TIdC_INT) cdecl; external CLibCrypto;
  procedure RAND_keep_random_devices_open(keep: TIdC_INT) cdecl; external CLibCrypto;

  procedure RAND_add(const buf: Pointer; num: TIdC_INT; randomness: TIdC_DOUBLE) cdecl; external CLibCrypto;
  function RAND_load_file(const file_: PIdAnsiChar; max_bytes: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto;
  function RAND_write_file(const file_: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function RAND_status: TIdC_INT cdecl; external CLibCrypto;

 {$IFNDEF OPENSSL_NO_EGD}
  function RAND_query_egd_bytes(const path: PIdAnsiChar; buf: PByte; bytes: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  function RAND_egd(const path: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  function RAND_egd_bytes(const path: PIdAnsiChar; bytes: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$ENDIF}

  function RAND_poll: TIdC_INT cdecl; external CLibCrypto;

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
  RAND_bytes_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  RAND_priv_bytes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RAND_priv_bytes_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

const
  RAND_set_rand_method_procname = 'RAND_set_rand_method';
  RAND_get_rand_method_procname = 'RAND_get_rand_method';
  RAND_set_rand_engine_procname = 'RAND_set_rand_engine';

  RAND_OpenSSL_procname = 'RAND_OpenSSL';

  RAND_bytes_procname = 'RAND_bytes';
  RAND_bytes_ex_procname = 'RAND_bytes_ex';
  RAND_priv_bytes_procname = 'RAND_priv_bytes';
  RAND_priv_bytes_ex_procname = 'RAND_priv_bytes_ex';

  RAND_seed_procname = 'RAND_seed';
  RAND_keep_random_devices_open_procname = 'RAND_keep_random_devices_open';

  RAND_add_procname = 'RAND_add';
  RAND_load_file_procname = 'RAND_load_file';
  RAND_write_file_procname = 'RAND_write_file';
  RAND_status_procname = 'RAND_status';

  {$IFNDEF OPENSSL_NO_EGD}
  RAND_query_egd_bytes_procname = 'RAND_query_egd_bytes';
  RAND_egd_procname = 'RAND_egd';
  RAND_egd_bytes_procname = 'RAND_egd_bytes';
  {$ENDIF}

  RAND_poll_procname = 'RAND_poll';


  {$i TaurusTLSNoRetValOff.inc} 
function  ERR_RAND_set_rand_method(const meth: PRAND_METHOD): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set_rand_method_procname);
end;


function  ERR_RAND_get_rand_method: PRAND_METHOD; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_get_rand_method_procname);
end;


function  ERR_RAND_set_rand_engine(engine: PENGINE): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_set_rand_engine_procname);
end;



function  ERR_RAND_OpenSSL: PRAND_METHOD;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_OpenSSL_procname);
end;

function  ERR_RAND_bytes(buf: PByte; num: TIdC_INT): TIdC_INT;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_bytes_procname);
end;

function ERR_RAND_bytes_ex(ctx : POSSL_LIB_CTX; buf : PIdAnsiChar;
     num : TIdC_SIZET;  strength : TIdC_UINT) : TIdC_INT;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_bytes_ex_procname);
end;

function  ERR_RAND_priv_bytes(buf: PByte; num: TIdC_INT): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_priv_bytes_procname);
end;

function ERR_RAND_priv_bytes_ex(ctx : POSSL_LIB_CTX; buf : PIdAnsiChar;
     num : TIdC_SIZET;  strength : TIdC_UINT) : TIdC_INT;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_priv_bytes_ex_procname);
end;

procedure  ERR_RAND_seed(const buf: Pointer; num: TIdC_INT); 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_seed_procname);
end;


procedure  ERR_RAND_keep_random_devices_open(keep: TIdC_INT); 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_keep_random_devices_open_procname);
end;



procedure  ERR_RAND_add(const buf: Pointer; num: TIdC_INT; randomness: TIdC_DOUBLE); 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_add_procname);
end;


function  ERR_RAND_load_file(const file_: PIdAnsiChar; max_bytes: TIdC_LONG): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_load_file_procname);
end;


function  ERR_RAND_write_file(const file_: PIdAnsiChar): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_write_file_procname);
end;


function  ERR_RAND_status: TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_status_procname);
end;


 {$IFNDEF OPENSSL_NO_EGD}
function  ERR_RAND_query_egd_bytes(const path: PIdAnsiChar; buf: PByte; bytes: TIdC_INT): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_query_egd_bytes_procname);
end;


function  ERR_RAND_egd(const path: PIdAnsiChar): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_egd_procname);
end;


function  ERR_RAND_egd_bytes(const path: PIdAnsiChar; bytes: TIdC_INT): TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_egd_bytes_procname);
end;

  {$ENDIF}

function  ERR_RAND_poll: TIdC_INT; 
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RAND_poll_procname);
end;



  {$i TaurusTLSNoRetValOn.inc} 
  {$i TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  RAND_set_rand_method := LoadLibFunction(ADllHandle, RAND_set_rand_method_procname);
  FuncLoadError := not assigned(RAND_set_rand_method);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set_rand_method_allownil)}
    RAND_set_rand_method := @ERR_RAND_set_rand_method;
    {$ifend}
    {$if declared(RAND_set_rand_method_introduced)}
    if LibVersion < RAND_set_rand_method_introduced then
    begin
      {$if declared(FC_RAND_set_rand_method)}
      RAND_set_rand_method := @FC_RAND_set_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set_rand_method_removed)}
    if RAND_set_rand_method_removed <= LibVersion then
    begin
      {$if declared(_RAND_set_rand_method)}
      RAND_set_rand_method := @_RAND_set_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set_rand_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set_rand_method');
    {$ifend}
  end;


  RAND_get_rand_method := LoadLibFunction(ADllHandle, RAND_get_rand_method_procname);
  FuncLoadError := not assigned(RAND_get_rand_method);
  if FuncLoadError then
  begin
    {$if not defined(RAND_get_rand_method_allownil)}
    RAND_get_rand_method := @ERR_RAND_get_rand_method;
    {$ifend}
    {$if declared(RAND_get_rand_method_introduced)}
    if LibVersion < RAND_get_rand_method_introduced then
    begin
      {$if declared(FC_RAND_get_rand_method)}
      RAND_get_rand_method := @FC_RAND_get_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_get_rand_method_removed)}
    if RAND_get_rand_method_removed <= LibVersion then
    begin
      {$if declared(_RAND_get_rand_method)}
      RAND_get_rand_method := @_RAND_get_rand_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_get_rand_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_get_rand_method');
    {$ifend}
  end;


  RAND_set_rand_engine := LoadLibFunction(ADllHandle, RAND_set_rand_engine_procname);
  FuncLoadError := not assigned(RAND_set_rand_engine);
  if FuncLoadError then
  begin
    {$if not defined(RAND_set_rand_engine_allownil)}
    RAND_set_rand_engine := @ERR_RAND_set_rand_engine;
    {$ifend}
    {$if declared(RAND_set_rand_engine_introduced)}
    if LibVersion < RAND_set_rand_engine_introduced then
    begin
      {$if declared(FC_RAND_set_rand_engine)}
      RAND_set_rand_engine := @FC_RAND_set_rand_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_set_rand_engine_removed)}
    if RAND_set_rand_engine_removed <= LibVersion then
    begin
      {$if declared(_RAND_set_rand_engine)}
      RAND_set_rand_engine := @_RAND_set_rand_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_set_rand_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_set_rand_engine');
    {$ifend}
  end;


  RAND_OpenSSL := LoadLibFunction(ADllHandle, RAND_OpenSSL_procname);
  FuncLoadError := not assigned(RAND_OpenSSL);
  if FuncLoadError then
  begin
    {$if not defined(RAND_OpenSSL_allownil)}
    RAND_OpenSSL := @ERR_RAND_OpenSSL;
    {$ifend}
    {$if declared(RAND_OpenSSL_introduced)}
    if LibVersion < RAND_OpenSSL_introduced then
    begin
      {$if declared(FC_RAND_OpenSSL)}
      RAND_OpenSSL := @FC_RAND_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_OpenSSL_removed)}
    if RAND_OpenSSL_removed <= LibVersion then
    begin
      {$if declared(_RAND_OpenSSL)}
      RAND_OpenSSL := @_RAND_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_OpenSSL_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_OpenSSL');
    {$ifend}
  end;


  RAND_bytes := LoadLibFunction(ADllHandle, RAND_bytes_procname);
  FuncLoadError := not assigned(RAND_bytes);
  if FuncLoadError then
  begin
    {$if not defined(RAND_bytes_allownil)}
    RAND_bytes := @ERR_RAND_bytes;
    {$ifend}
    {$if declared(RAND_bytes_introduced)}
    if LibVersion < RAND_bytes_introduced then
    begin
      {$if declared(FC_RAND_bytes)}
      RAND_bytes := @FC_RAND_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_bytes_removed)}
    if RAND_bytes_removed <= LibVersion then
    begin
      {$if declared(_RAND_bytes)}
      RAND_bytes := @_RAND_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_bytes');
    {$ifend}
  end;

  RAND_bytes_ex := LoadLibFunction(ADllHandle, RAND_bytes_ex_procname);
  FuncLoadError := not assigned(RAND_bytes_ex);
  if FuncLoadError then
  begin
    {$if not defined(RAND_bytes_ex_allownil)}
    RAND_bytes_ex := @ERR_RAND_bytes_ex;
    {$ifend}
    {$if declared(RAND_bytes_ex_introduced)}
    if LibVersion < RAND_bytes_ex_introduced then
    begin
      {$if declared(FC_RAND_bytes_ex)}
      RAND_bytes_ex := @FC_RAND_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_bytes_ex_removed)}
    if RAND_bytes_ex_removed <= LibVersion then
    begin
      {$if declared(_RAND_bytes_ex)}
      RAND_bytes_ex := @_RAND_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_bytes_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_bytes_ex');
    {$ifend}
  end;

  RAND_priv_bytes := LoadLibFunction(ADllHandle, RAND_priv_bytes_procname);
  FuncLoadError := not assigned(RAND_priv_bytes);
  if FuncLoadError then
  begin
    {$if not defined(RAND_priv_bytes_allownil)}
    RAND_priv_bytes := @ERR_RAND_priv_bytes;
    {$ifend}
    {$if declared(RAND_priv_bytes_introduced)}
    if LibVersion < RAND_priv_bytes_introduced then
    begin
      {$if declared(FC_RAND_priv_bytes)}
      RAND_priv_bytes := @FC_RAND_priv_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_priv_bytes_removed)}
    if RAND_priv_bytes_removed <= LibVersion then
    begin
      {$if declared(_RAND_priv_bytes)}
      RAND_priv_bytes := @_RAND_priv_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_priv_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_priv_bytes');
    {$ifend}
  end;

  RAND_priv_bytes_ex := LoadLibFunction(ADllHandle, RAND_priv_bytes_ex_procname);
  FuncLoadError := not assigned(RAND_priv_bytes_ex);
  if FuncLoadError then
  begin
    {$if not defined(RAND_priv_bytes_ex_allownil)}
    RAND_priv_bytes_ex := @ERR_RAND_priv_bytes_ex;
    {$ifend}
    {$if declared(RAND_priv_bytes_ex_introduced)}
    if LibVersion < RAND_priv_bytes_ex_introduced then
    begin
      {$if declared(FC_RAND_priv_bytes_ex)}
      RAND_priv_bytes_ex := @FC_RAND_priv_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_priv_bytes_ex_removed)}
    if RAND_priv_bytes_ex_removed <= LibVersion then
    begin
      {$if declared(_RAND_priv_bytes_ex)}
      RAND_priv_bytes_ex := @_RAND_priv_bytes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_priv_bytes_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_priv_bytes_ex');
    {$ifend}
  end;


  RAND_seed := LoadLibFunction(ADllHandle, RAND_seed_procname);
  FuncLoadError := not assigned(RAND_seed);
  if FuncLoadError then
  begin
    {$if not defined(RAND_seed_allownil)}
    RAND_seed := @ERR_RAND_seed;
    {$ifend}
    {$if declared(RAND_seed_introduced)}
    if LibVersion < RAND_seed_introduced then
    begin
      {$if declared(FC_RAND_seed)}
      RAND_seed := @FC_RAND_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_seed_removed)}
    if RAND_seed_removed <= LibVersion then
    begin
      {$if declared(_RAND_seed)}
      RAND_seed := @_RAND_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_seed_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_seed');
    {$ifend}
  end;


  RAND_keep_random_devices_open := LoadLibFunction(ADllHandle, RAND_keep_random_devices_open_procname);
  FuncLoadError := not assigned(RAND_keep_random_devices_open);
  if FuncLoadError then
  begin
    {$if not defined(RAND_keep_random_devices_open_allownil)}
    RAND_keep_random_devices_open := @ERR_RAND_keep_random_devices_open;
    {$ifend}
    {$if declared(RAND_keep_random_devices_open_introduced)}
    if LibVersion < RAND_keep_random_devices_open_introduced then
    begin
      {$if declared(FC_RAND_keep_random_devices_open)}
      RAND_keep_random_devices_open := @FC_RAND_keep_random_devices_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_keep_random_devices_open_removed)}
    if RAND_keep_random_devices_open_removed <= LibVersion then
    begin
      {$if declared(_RAND_keep_random_devices_open)}
      RAND_keep_random_devices_open := @_RAND_keep_random_devices_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_keep_random_devices_open_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_keep_random_devices_open');
    {$ifend}
  end;


  RAND_add := LoadLibFunction(ADllHandle, RAND_add_procname);
  FuncLoadError := not assigned(RAND_add);
  if FuncLoadError then
  begin
    {$if not defined(RAND_add_allownil)}
    RAND_add := @ERR_RAND_add;
    {$ifend}
    {$if declared(RAND_add_introduced)}
    if LibVersion < RAND_add_introduced then
    begin
      {$if declared(FC_RAND_add)}
      RAND_add := @FC_RAND_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_add_removed)}
    if RAND_add_removed <= LibVersion then
    begin
      {$if declared(_RAND_add)}
      RAND_add := @_RAND_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_add_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_add');
    {$ifend}
  end;


  RAND_load_file := LoadLibFunction(ADllHandle, RAND_load_file_procname);
  FuncLoadError := not assigned(RAND_load_file);
  if FuncLoadError then
  begin
    {$if not defined(RAND_load_file_allownil)}
    RAND_load_file := @ERR_RAND_load_file;
    {$ifend}
    {$if declared(RAND_load_file_introduced)}
    if LibVersion < RAND_load_file_introduced then
    begin
      {$if declared(FC_RAND_load_file)}
      RAND_load_file := @FC_RAND_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_load_file_removed)}
    if RAND_load_file_removed <= LibVersion then
    begin
      {$if declared(_RAND_load_file)}
      RAND_load_file := @_RAND_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_load_file_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_load_file');
    {$ifend}
  end;


  RAND_write_file := LoadLibFunction(ADllHandle, RAND_write_file_procname);
  FuncLoadError := not assigned(RAND_write_file);
  if FuncLoadError then
  begin
    {$if not defined(RAND_write_file_allownil)}
    RAND_write_file := @ERR_RAND_write_file;
    {$ifend}
    {$if declared(RAND_write_file_introduced)}
    if LibVersion < RAND_write_file_introduced then
    begin
      {$if declared(FC_RAND_write_file)}
      RAND_write_file := @FC_RAND_write_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_write_file_removed)}
    if RAND_write_file_removed <= LibVersion then
    begin
      {$if declared(_RAND_write_file)}
      RAND_write_file := @_RAND_write_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_write_file_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_write_file');
    {$ifend}
  end;


  RAND_status := LoadLibFunction(ADllHandle, RAND_status_procname);
  FuncLoadError := not assigned(RAND_status);
  if FuncLoadError then
  begin
    {$if not defined(RAND_status_allownil)}
    RAND_status := @ERR_RAND_status;
    {$ifend}
    {$if declared(RAND_status_introduced)}
    if LibVersion < RAND_status_introduced then
    begin
      {$if declared(FC_RAND_status)}
      RAND_status := @FC_RAND_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_status_removed)}
    if RAND_status_removed <= LibVersion then
    begin
      {$if declared(_RAND_status)}
      RAND_status := @_RAND_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_status_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_status');
    {$ifend}
  end;

  {$IFNDEF OPENSSL_NO_EGD}
  RAND_query_egd_bytes := LoadLibFunction(ADllHandle, RAND_query_egd_bytes_procname);
  FuncLoadError := not assigned(RAND_query_egd_bytes);
  if FuncLoadError then
  begin
    {$if not defined(RAND_query_egd_bytes_allownil)}
    RAND_query_egd_bytes := @ERR_RAND_query_egd_bytes;
    {$ifend}
    {$if declared(RAND_query_egd_bytes_introduced)}
    if LibVersion < RAND_query_egd_bytes_introduced then
    begin
      {$if declared(FC_RAND_query_egd_bytes)}
      RAND_query_egd_bytes := @FC_RAND_query_egd_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_query_egd_bytes_removed)}
    if RAND_query_egd_bytes_removed <= LibVersion then
    begin
      {$if declared(_RAND_query_egd_bytes)}
      RAND_query_egd_bytes := @_RAND_query_egd_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_query_egd_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_query_egd_bytes');
    {$ifend}
  end;


  RAND_egd := LoadLibFunction(ADllHandle, RAND_egd_procname);
  FuncLoadError := not assigned(RAND_egd);
  if FuncLoadError then
  begin
    {$if not defined(RAND_egd_allownil)}
    RAND_egd := @ERR_RAND_egd;
    {$ifend}
    {$if declared(RAND_egd_introduced)}
    if LibVersion < RAND_egd_introduced then
    begin
      {$if declared(FC_RAND_egd)}
      RAND_egd := @FC_RAND_egd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_egd_removed)}
    if RAND_egd_removed <= LibVersion then
    begin
      {$if declared(_RAND_egd)}
      RAND_egd := @_RAND_egd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_egd_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_egd');
    {$ifend}
  end;


  RAND_egd_bytes := LoadLibFunction(ADllHandle, RAND_egd_bytes_procname);
  FuncLoadError := not assigned(RAND_egd_bytes);
  if FuncLoadError then
  begin
    {$if not defined(RAND_egd_bytes_allownil)}
    RAND_egd_bytes := @ERR_RAND_egd_bytes;
    {$ifend}
    {$if declared(RAND_egd_bytes_introduced)}
    if LibVersion < RAND_egd_bytes_introduced then
    begin
      {$if declared(FC_RAND_egd_bytes)}
      RAND_egd_bytes := @FC_RAND_egd_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_egd_bytes_removed)}
    if RAND_egd_bytes_removed <= LibVersion then
    begin
      {$if declared(_RAND_egd_bytes)}
      RAND_egd_bytes := @_RAND_egd_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_egd_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_egd_bytes');
    {$ifend}
  end;
  {$ENDIF}

  RAND_poll := LoadLibFunction(ADllHandle, RAND_poll_procname);
  FuncLoadError := not assigned(RAND_poll);
  if FuncLoadError then
  begin
    {$if not defined(RAND_poll_allownil)}
    RAND_poll := @ERR_RAND_poll;
    {$ifend}
    {$if declared(RAND_poll_introduced)}
    if LibVersion < RAND_poll_introduced then
    begin
      {$if declared(FC_RAND_poll)}
      RAND_poll := @FC_RAND_poll;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RAND_poll_removed)}
    if RAND_poll_removed <= LibVersion then
    begin
      {$if declared(_RAND_poll)}
      RAND_poll := @_RAND_poll;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RAND_poll_allownil)}
    if FuncLoadError then
      AFailed.Add('RAND_poll');
    {$ifend}
  end;
end;
  {$i TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  RAND_set_rand_method := nil;
  RAND_get_rand_method := nil;
  RAND_set_rand_engine := nil;
  RAND_OpenSSL := nil;
  RAND_bytes := nil;
  RAND_bytes_ex := nil;
  RAND_priv_bytes := nil;
  RAND_priv_bytes_ex := nil;
  RAND_seed := nil;
  RAND_keep_random_devices_open := nil;
  RAND_add := nil;
  RAND_load_file := nil;
  RAND_write_file := nil;
  RAND_status := nil;
   {$IFNDEF OPENSSL_NO_EGD}
  RAND_query_egd_bytes := nil;
  RAND_egd := nil;
  RAND_egd_bytes := nil;
   {$ENDIF}
  RAND_poll := nil;
end;
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(@Load,'LibCrypto');
  Register_SSLUnloader(@Unload);
{$ENDIF}
end.
