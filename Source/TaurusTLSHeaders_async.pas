/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_async.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_async.h2pas
     and this file regenerated. TaurusTLSHeaders_async.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_async;

interface

// Headers for OpenSSL 1.1.1
// async.h


{$I TaurusTLSUnusedUnitOff.inc}
uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types;
{$I TaurusTLSUnusedUnitOn.inc}

const
  {$EXTERNALSYM ASYNC_ERR}
  ASYNC_ERR = 0;
  {$EXTERNALSYM ASYNC_NO_JOBS}
  ASYNC_NO_JOBS = 0;
  {$EXTERNALSYM ASYNC_PAUSE}
  ASYNC_PAUSE = 2;
  {$EXTERNALSYM ASYNC_FINISH}
  ASYNC_FINISH = 3;

type
  {$EXTERNALSYM async_job_st}
  async_job_st = record end;
  {$EXTERNALSYM ASYNC_JOB}
  ASYNC_JOB = async_job_st;
  {$EXTERNALSYM PASYNC_JOB}
  PASYNC_JOB = ^ASYNC_JOB;
  {$EXTERNALSYM PPASYNC_JOB}
  PPASYNC_JOB = ^PASYNC_JOB;

  {$EXTERNALSYM async_wait_ctx_st}
  async_wait_ctx_st = record end;
  {$EXTERNALSYM ASYNC_WAIT_CTX}
  ASYNC_WAIT_CTX = async_wait_ctx_st;
  {$EXTERNALSYM PASYNC_WAIT_CTX}
  PASYNC_WAIT_CTX = ^ASYNC_WAIT_CTX;

  {$EXTERNALSYM OSSL_ASYNC_FD}
  OSSL_ASYNC_FD = type TIdC_INT;
  {$EXTERNALSYM POSSL_ASYNC_FD}
  POSSL_ASYNC_FD = ^OSSL_ASYNC_FD;

  {$EXTERNALSYM ASYNC_WAIT_CTX_set_wait_fd_cleanup}
  ASYNC_WAIT_CTX_set_wait_fd_cleanup = procedure(v1: PASYNC_WAIT_CTX;
    const v2: Pointer; v3: OSSL_ASYNC_FD; v4: Pointer);
  {$EXTERNALSYM ASYNC_start_job_cb}
  ASYNC_start_job_cb = function(v1: Pointer): TIdC_INT;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ASYNC_init_thread}
  ASYNC_init_thread: function (max_size: TIdC_SIZET; init_size: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_cleanup_thread}
  ASYNC_cleanup_thread: procedure ; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_WAIT_CTX_new}
  ASYNC_WAIT_CTX_new: function : PASYNC_WAIT_CTX; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_free}
  ASYNC_WAIT_CTX_free: procedure (ctx: PASYNC_WAIT_CTX); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_wait_fd}
  ASYNC_WAIT_CTX_set_wait_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_fd}
  ASYNC_WAIT_CTX_get_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_all_fds}
  ASYNC_WAIT_CTX_get_all_fds: function (ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_changed_fds}
  ASYNC_WAIT_CTX_get_changed_fds: function (ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: PIdC_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: PIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_clear_fd}
  ASYNC_WAIT_CTX_clear_fd: function (ctx: PASYNC_WAIT_CTX; const key: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_is_capable}
  ASYNC_is_capable: function : TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_start_job}
  ASYNC_start_job: function (job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: PIdC_INT; func: ASYNC_start_job_cb; args: Pointer; size: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_pause_job}
  ASYNC_pause_job: function : TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_get_current_job}
  ASYNC_get_current_job: function : PASYNC_JOB; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_get_wait_ctx}
  ASYNC_get_wait_ctx: function (job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_block_pause}
  ASYNC_block_pause: procedure ; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_unblock_pause}
  ASYNC_unblock_pause: procedure ; cdecl = nil; {introduced 1.1.0}

{$ELSE}
  {$EXTERNALSYM ASYNC_init_thread}
  function ASYNC_init_thread(max_size: TIdC_SIZET; init_size: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_cleanup_thread}
  procedure ASYNC_cleanup_thread cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_WAIT_CTX_new}
  function ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_free}
  procedure ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_wait_fd}
  function ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_fd}
  function ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD; custom_data: PPointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_all_fds}
  function ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD; numfds: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_changed_fds}
  function ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD; numaddfds: PIdC_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: PIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_WAIT_CTX_clear_fd}
  function ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_is_capable}
  function ASYNC_is_capable: TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_start_job}
  function ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: PIdC_INT; func: ASYNC_start_job_cb; args: Pointer; size: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_pause_job}
  function ASYNC_pause_job: TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ASYNC_get_current_job}
  function ASYNC_get_current_job: PASYNC_JOB cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_get_wait_ctx}
  function ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_block_pause}
  procedure ASYNC_block_pause cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ASYNC_unblock_pause}
  procedure ASYNC_unblock_pause cdecl; external CLibCrypto; {introduced 1.1.0}

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
const
  ASYNC_init_thread_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_cleanup_thread_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_WAIT_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_WAIT_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_WAIT_CTX_set_wait_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_WAIT_CTX_get_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_WAIT_CTX_get_all_fds_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_WAIT_CTX_get_changed_fds_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_WAIT_CTX_clear_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_is_capable_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_start_job_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_pause_job_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_get_current_job_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_get_wait_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_block_pause_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASYNC_unblock_pause_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  ASYNC_init_thread_procname = 'ASYNC_init_thread'; {introduced 1.1.0}
  ASYNC_cleanup_thread_procname = 'ASYNC_cleanup_thread'; {introduced 1.1.0}

  ASYNC_WAIT_CTX_new_procname = 'ASYNC_WAIT_CTX_new'; {introduced 1.1.0}
  ASYNC_WAIT_CTX_free_procname = 'ASYNC_WAIT_CTX_free'; {introduced 1.1.0}
  ASYNC_WAIT_CTX_set_wait_fd_procname = 'ASYNC_WAIT_CTX_set_wait_fd'; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_fd_procname = 'ASYNC_WAIT_CTX_get_fd'; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_all_fds_procname = 'ASYNC_WAIT_CTX_get_all_fds'; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_changed_fds_procname = 'ASYNC_WAIT_CTX_get_changed_fds'; {introduced 1.1.0}
  ASYNC_WAIT_CTX_clear_fd_procname = 'ASYNC_WAIT_CTX_clear_fd'; {introduced 1.1.0}

  ASYNC_is_capable_procname = 'ASYNC_is_capable'; {introduced 1.1.0}

  ASYNC_start_job_procname = 'ASYNC_start_job'; {introduced 1.1.0}
  ASYNC_pause_job_procname = 'ASYNC_pause_job'; {introduced 1.1.0}

  ASYNC_get_current_job_procname = 'ASYNC_get_current_job'; {introduced 1.1.0}
  ASYNC_get_wait_ctx_procname = 'ASYNC_get_wait_ctx'; {introduced 1.1.0}
  ASYNC_block_pause_procname = 'ASYNC_block_pause'; {introduced 1.1.0}
  ASYNC_unblock_pause_procname = 'ASYNC_unblock_pause'; {introduced 1.1.0}

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}
function  ERR_ASYNC_init_thread(max_size: TIdC_SIZET; init_size: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_init_thread_procname);
end;

 {introduced 1.1.0}
procedure  ERR_ASYNC_cleanup_thread; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_cleanup_thread_procname);
end;

 {introduced 1.1.0}

function  ERR_ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_new_procname);
end;

 {introduced 1.1.0}
procedure  ERR_ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_free_procname);
end;

 {introduced 1.1.0}
function  ERR_ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer;
  fd: OSSL_ASYNC_FD; custom_data: Pointer; cleanup_cb: ASYNC_WAIT_CTX_set_wait_fd_cleanup): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_set_wait_fd_procname);
end;

 {introduced 1.1.0}
function  ERR_ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer; fd: POSSL_ASYNC_FD;
  custom_data: PPointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_fd_procname);
end;

 {introduced 1.1.0}
function  ERR_ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: POSSL_ASYNC_FD;
  numfds: PIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_all_fds_procname);
end;

 {introduced 1.1.0}
function  ERR_ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: POSSL_ASYNC_FD;
  numaddfds: PIdC_SIZET; delfd: POSSL_ASYNC_FD; numdelfds: PIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_changed_fds_procname);
end;

 {introduced 1.1.0}
function  ERR_ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; const key: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_clear_fd_procname);
end;

 {introduced 1.1.0}

function  ERR_ASYNC_is_capable: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_is_capable_procname);
end;

 {introduced 1.1.0}

function  ERR_ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: PIdC_INT;
  func: ASYNC_start_job_cb; args: Pointer; size: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_start_job_procname);
end;

 {introduced 1.1.0}
function  ERR_ASYNC_pause_job: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_pause_job_procname);
end;

 {introduced 1.1.0}

function  ERR_ASYNC_get_current_job: PASYNC_JOB; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_get_current_job_procname);
end;

 {introduced 1.1.0}
function  ERR_ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_get_wait_ctx_procname);
end;

 {introduced 1.1.0}
procedure  ERR_ASYNC_block_pause; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_block_pause_procname);
end;

 {introduced 1.1.0}
procedure  ERR_ASYNC_unblock_pause; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_unblock_pause_procname);
end;

 {introduced 1.1.0}

 {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ASYNC_init_thread := LoadLibFunction(ADllHandle, ASYNC_init_thread_procname);
  FuncLoadError := not assigned(ASYNC_init_thread);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_init_thread_allownil)}
    ASYNC_init_thread := ERR_ASYNC_init_thread;
    {$ifend}
    {$if declared(ASYNC_init_thread_introduced)}
    if LibVersion < ASYNC_init_thread_introduced then
    begin
      {$if declared(FC_ASYNC_init_thread)}
      ASYNC_init_thread := FC_ASYNC_init_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_init_thread_removed)}
    if ASYNC_init_thread_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_init_thread)}
      ASYNC_init_thread := _ASYNC_init_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_init_thread_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_init_thread');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_cleanup_thread := LoadLibFunction(ADllHandle, ASYNC_cleanup_thread_procname);
  FuncLoadError := not assigned(ASYNC_cleanup_thread);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_cleanup_thread_allownil)}
    ASYNC_cleanup_thread := ERR_ASYNC_cleanup_thread;
    {$ifend}
    {$if declared(ASYNC_cleanup_thread_introduced)}
    if LibVersion < ASYNC_cleanup_thread_introduced then
    begin
      {$if declared(FC_ASYNC_cleanup_thread)}
      ASYNC_cleanup_thread := FC_ASYNC_cleanup_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_cleanup_thread_removed)}
    if ASYNC_cleanup_thread_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_cleanup_thread)}
      ASYNC_cleanup_thread := _ASYNC_cleanup_thread;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_cleanup_thread_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_cleanup_thread');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_WAIT_CTX_new := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_new_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_new_allownil)}
    ASYNC_WAIT_CTX_new := ERR_ASYNC_WAIT_CTX_new;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_new_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_new_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_new)}
      ASYNC_WAIT_CTX_new := FC_ASYNC_WAIT_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_new_removed)}
    if ASYNC_WAIT_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_new)}
      ASYNC_WAIT_CTX_new := _ASYNC_WAIT_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_WAIT_CTX_free := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_free_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_free_allownil)}
    ASYNC_WAIT_CTX_free := ERR_ASYNC_WAIT_CTX_free;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_free_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_free_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_free)}
      ASYNC_WAIT_CTX_free := FC_ASYNC_WAIT_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_free_removed)}
    if ASYNC_WAIT_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_free)}
      ASYNC_WAIT_CTX_free := _ASYNC_WAIT_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_WAIT_CTX_set_wait_fd := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_set_wait_fd_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_set_wait_fd);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_set_wait_fd_allownil)}
    ASYNC_WAIT_CTX_set_wait_fd := ERR_ASYNC_WAIT_CTX_set_wait_fd;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_set_wait_fd_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_set_wait_fd_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_set_wait_fd)}
      ASYNC_WAIT_CTX_set_wait_fd := FC_ASYNC_WAIT_CTX_set_wait_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_set_wait_fd_removed)}
    if ASYNC_WAIT_CTX_set_wait_fd_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_set_wait_fd)}
      ASYNC_WAIT_CTX_set_wait_fd := _ASYNC_WAIT_CTX_set_wait_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_set_wait_fd_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_set_wait_fd');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_fd := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_get_fd_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_fd);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_get_fd_allownil)}
    ASYNC_WAIT_CTX_get_fd := ERR_ASYNC_WAIT_CTX_get_fd;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_fd_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_get_fd_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_get_fd)}
      ASYNC_WAIT_CTX_get_fd := FC_ASYNC_WAIT_CTX_get_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_fd_removed)}
    if ASYNC_WAIT_CTX_get_fd_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_get_fd)}
      ASYNC_WAIT_CTX_get_fd := _ASYNC_WAIT_CTX_get_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_get_fd_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_get_fd');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_all_fds := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_get_all_fds_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_all_fds);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_get_all_fds_allownil)}
    ASYNC_WAIT_CTX_get_all_fds := ERR_ASYNC_WAIT_CTX_get_all_fds;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_all_fds_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_get_all_fds_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_get_all_fds)}
      ASYNC_WAIT_CTX_get_all_fds := FC_ASYNC_WAIT_CTX_get_all_fds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_all_fds_removed)}
    if ASYNC_WAIT_CTX_get_all_fds_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_get_all_fds)}
      ASYNC_WAIT_CTX_get_all_fds := _ASYNC_WAIT_CTX_get_all_fds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_get_all_fds_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_get_all_fds');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_changed_fds := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_get_changed_fds_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_changed_fds);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_get_changed_fds_allownil)}
    ASYNC_WAIT_CTX_get_changed_fds := ERR_ASYNC_WAIT_CTX_get_changed_fds;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_changed_fds_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_get_changed_fds_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_get_changed_fds)}
      ASYNC_WAIT_CTX_get_changed_fds := FC_ASYNC_WAIT_CTX_get_changed_fds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_changed_fds_removed)}
    if ASYNC_WAIT_CTX_get_changed_fds_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_get_changed_fds)}
      ASYNC_WAIT_CTX_get_changed_fds := _ASYNC_WAIT_CTX_get_changed_fds;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_get_changed_fds_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_get_changed_fds');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_WAIT_CTX_clear_fd := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_clear_fd_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_clear_fd);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_clear_fd_allownil)}
    ASYNC_WAIT_CTX_clear_fd := ERR_ASYNC_WAIT_CTX_clear_fd;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_clear_fd_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_clear_fd_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_clear_fd)}
      ASYNC_WAIT_CTX_clear_fd := FC_ASYNC_WAIT_CTX_clear_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_clear_fd_removed)}
    if ASYNC_WAIT_CTX_clear_fd_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_clear_fd)}
      ASYNC_WAIT_CTX_clear_fd := _ASYNC_WAIT_CTX_clear_fd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_clear_fd_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_clear_fd');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_is_capable := LoadLibFunction(ADllHandle, ASYNC_is_capable_procname);
  FuncLoadError := not assigned(ASYNC_is_capable);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_is_capable_allownil)}
    ASYNC_is_capable := ERR_ASYNC_is_capable;
    {$ifend}
    {$if declared(ASYNC_is_capable_introduced)}
    if LibVersion < ASYNC_is_capable_introduced then
    begin
      {$if declared(FC_ASYNC_is_capable)}
      ASYNC_is_capable := FC_ASYNC_is_capable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_is_capable_removed)}
    if ASYNC_is_capable_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_is_capable)}
      ASYNC_is_capable := _ASYNC_is_capable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_is_capable_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_is_capable');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_start_job := LoadLibFunction(ADllHandle, ASYNC_start_job_procname);
  FuncLoadError := not assigned(ASYNC_start_job);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_start_job_allownil)}
    ASYNC_start_job := ERR_ASYNC_start_job;
    {$ifend}
    {$if declared(ASYNC_start_job_introduced)}
    if LibVersion < ASYNC_start_job_introduced then
    begin
      {$if declared(FC_ASYNC_start_job)}
      ASYNC_start_job := FC_ASYNC_start_job;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_start_job_removed)}
    if ASYNC_start_job_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_start_job)}
      ASYNC_start_job := _ASYNC_start_job;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_start_job_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_start_job');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_pause_job := LoadLibFunction(ADllHandle, ASYNC_pause_job_procname);
  FuncLoadError := not assigned(ASYNC_pause_job);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_pause_job_allownil)}
    ASYNC_pause_job := ERR_ASYNC_pause_job;
    {$ifend}
    {$if declared(ASYNC_pause_job_introduced)}
    if LibVersion < ASYNC_pause_job_introduced then
    begin
      {$if declared(FC_ASYNC_pause_job)}
      ASYNC_pause_job := FC_ASYNC_pause_job;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_pause_job_removed)}
    if ASYNC_pause_job_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_pause_job)}
      ASYNC_pause_job := _ASYNC_pause_job;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_pause_job_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_pause_job');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_get_current_job := LoadLibFunction(ADllHandle, ASYNC_get_current_job_procname);
  FuncLoadError := not assigned(ASYNC_get_current_job);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_get_current_job_allownil)}
    ASYNC_get_current_job := ERR_ASYNC_get_current_job;
    {$ifend}
    {$if declared(ASYNC_get_current_job_introduced)}
    if LibVersion < ASYNC_get_current_job_introduced then
    begin
      {$if declared(FC_ASYNC_get_current_job)}
      ASYNC_get_current_job := FC_ASYNC_get_current_job;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_get_current_job_removed)}
    if ASYNC_get_current_job_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_get_current_job)}
      ASYNC_get_current_job := _ASYNC_get_current_job;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_get_current_job_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_get_current_job');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_get_wait_ctx := LoadLibFunction(ADllHandle, ASYNC_get_wait_ctx_procname);
  FuncLoadError := not assigned(ASYNC_get_wait_ctx);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_get_wait_ctx_allownil)}
    ASYNC_get_wait_ctx := ERR_ASYNC_get_wait_ctx;
    {$ifend}
    {$if declared(ASYNC_get_wait_ctx_introduced)}
    if LibVersion < ASYNC_get_wait_ctx_introduced then
    begin
      {$if declared(FC_ASYNC_get_wait_ctx)}
      ASYNC_get_wait_ctx := FC_ASYNC_get_wait_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_get_wait_ctx_removed)}
    if ASYNC_get_wait_ctx_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_get_wait_ctx)}
      ASYNC_get_wait_ctx := _ASYNC_get_wait_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_get_wait_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_get_wait_ctx');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_block_pause := LoadLibFunction(ADllHandle, ASYNC_block_pause_procname);
  FuncLoadError := not assigned(ASYNC_block_pause);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_block_pause_allownil)}
    ASYNC_block_pause := ERR_ASYNC_block_pause;
    {$ifend}
    {$if declared(ASYNC_block_pause_introduced)}
    if LibVersion < ASYNC_block_pause_introduced then
    begin
      {$if declared(FC_ASYNC_block_pause)}
      ASYNC_block_pause := FC_ASYNC_block_pause;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_block_pause_removed)}
    if ASYNC_block_pause_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_block_pause)}
      ASYNC_block_pause := _ASYNC_block_pause;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_block_pause_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_block_pause');
    {$ifend}
  end;

 {introduced 1.1.0}
  ASYNC_unblock_pause := LoadLibFunction(ADllHandle, ASYNC_unblock_pause_procname);
  FuncLoadError := not assigned(ASYNC_unblock_pause);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_unblock_pause_allownil)}
    ASYNC_unblock_pause := ERR_ASYNC_unblock_pause;
    {$ifend}
    {$if declared(ASYNC_unblock_pause_introduced)}
    if LibVersion < ASYNC_unblock_pause_introduced then
    begin
      {$if declared(FC_ASYNC_unblock_pause)}
      ASYNC_unblock_pause := FC_ASYNC_unblock_pause;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_unblock_pause_removed)}
    if ASYNC_unblock_pause_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_unblock_pause)}
      ASYNC_unblock_pause := _ASYNC_unblock_pause;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_unblock_pause_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_unblock_pause');
    {$ifend}
  end;

 {introduced 1.1.0}
end;

procedure Unload;
begin
  ASYNC_init_thread := nil; {introduced 1.1.0}
  ASYNC_cleanup_thread := nil; {introduced 1.1.0}
  ASYNC_WAIT_CTX_new := nil; {introduced 1.1.0}
  ASYNC_WAIT_CTX_free := nil; {introduced 1.1.0}
  ASYNC_WAIT_CTX_set_wait_fd := nil; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_fd := nil; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_all_fds := nil; {introduced 1.1.0}
  ASYNC_WAIT_CTX_get_changed_fds := nil; {introduced 1.1.0}
  ASYNC_WAIT_CTX_clear_fd := nil; {introduced 1.1.0}
  ASYNC_is_capable := nil; {introduced 1.1.0}
  ASYNC_start_job := nil; {introduced 1.1.0}
  ASYNC_pause_job := nil; {introduced 1.1.0}
  ASYNC_get_current_job := nil; {introduced 1.1.0}
  ASYNC_get_wait_ctx := nil; {introduced 1.1.0}
  ASYNC_block_pause := nil; {introduced 1.1.0}
  ASYNC_unblock_pause := nil; {introduced 1.1.0}
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
