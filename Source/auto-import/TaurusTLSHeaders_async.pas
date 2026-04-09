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
  Pasync_job_st = ^Tasync_job_st;
  Tasync_job_st = record end;
  {$EXTERNALSYM Pasync_job_st}

  PASYNC_JOB = ^TASYNC_JOB;
  TASYNC_JOB = Tasync_job_st;
  {$EXTERNALSYM PASYNC_JOB}

  Pasync_wait_ctx_st = ^Tasync_wait_ctx_st;
  Tasync_wait_ctx_st = record end;
  {$EXTERNALSYM Pasync_wait_ctx_st}

  PASYNC_WAIT_CTX = ^TASYNC_WAIT_CTX;
  TASYNC_WAIT_CTX = Tasync_wait_ctx_st;
  {$EXTERNALSYM PASYNC_WAIT_CTX}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TASYNC_callback_fn_func_cb = function(arg1: Pointer): TIdC_INT; cdecl;
  TASYNC_WAIT_CTX_set_wait_fd_cleanup_cb = procedure(arg1: PASYNC_WAIT_CTX; arg2: Pointer; arg3: TIdC_INT; arg4: Pointer); cdecl;
  TASYNC_stack_alloc_fn_func_cb = function(arg1: PIdC_SIZET): Pointer; cdecl;
  TASYNC_stack_free_fn_func_cb = procedure(arg1: Pointer); cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_ASYNC_FD = int;
  OSSL_BAD_ASYNC_FD = -1;
  ASYNC_ERR = 0;
  ASYNC_NO_JOBS = 1;
  ASYNC_PAUSE = 2;
  ASYNC_FINISH = 3;
  ASYNC_STATUS_UNSUPPORTED = 0;
  ASYNC_STATUS_ERR = 1;
  ASYNC_STATUS_OK = 2;
  ASYNC_STATUS_EAGAIN = 3;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  ASYNC_init_thread: function(max_size: TIdC_SIZET; init_size: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_init_thread}

  ASYNC_cleanup_thread: procedure; cdecl = nil;
  {$EXTERNALSYM ASYNC_cleanup_thread}

  ASYNC_WAIT_CTX_new: function: PASYNC_WAIT_CTX; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_new}

  ASYNC_WAIT_CTX_free: procedure(ctx: PASYNC_WAIT_CTX); cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_free}

  ASYNC_WAIT_CTX_set_wait_fd: function(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: TIdC_INT; custom_data: Pointer; cleanup: TASYNC_WAIT_CTX_set_wait_fd_cleanup_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_wait_fd}

  ASYNC_WAIT_CTX_get_fd: function(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: PIdC_INT; custom_data: PPointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_fd}

  ASYNC_WAIT_CTX_get_all_fds: function(ctx: PASYNC_WAIT_CTX; fd: PIdC_INT; numfds: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_all_fds}

  ASYNC_WAIT_CTX_get_callback: function(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: PPointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_callback}

  ASYNC_WAIT_CTX_set_callback: function(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn_func_cb; callback_arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_callback}

  ASYNC_WAIT_CTX_set_status: function(ctx: PASYNC_WAIT_CTX; status: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_set_status}

  ASYNC_WAIT_CTX_get_status: function(ctx: PASYNC_WAIT_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_status}

  ASYNC_WAIT_CTX_get_changed_fds: function(ctx: PASYNC_WAIT_CTX; addfd: PIdC_INT; numaddfds: PIdC_SIZET; delfd: PIdC_INT; numdelfds: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_get_changed_fds}

  ASYNC_WAIT_CTX_clear_fd: function(ctx: PASYNC_WAIT_CTX; key: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_WAIT_CTX_clear_fd}

  ASYNC_is_capable: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_is_capable}

  ASYNC_set_mem_functions: function(alloc_fn: TASYNC_stack_alloc_fn_func_cb; free_fn: TASYNC_stack_free_fn_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_set_mem_functions}

  ASYNC_get_mem_functions: procedure(alloc_fn: PASYNC_stack_alloc_fn; free_fn: PASYNC_stack_free_fn); cdecl = nil;
  {$EXTERNALSYM ASYNC_get_mem_functions}

  ASYNC_start_job: function(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: PIdC_INT; func: TASYNC_callback_fn_func_cb; args: Pointer; size: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_start_job}

  ASYNC_pause_job: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASYNC_pause_job}

  ASYNC_get_current_job: function: PASYNC_JOB; cdecl = nil;
  {$EXTERNALSYM ASYNC_get_current_job}

  ASYNC_get_wait_ctx: function(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl = nil;
  {$EXTERNALSYM ASYNC_get_wait_ctx}

  ASYNC_block_pause: procedure; cdecl = nil;
  {$EXTERNALSYM ASYNC_block_pause}

  ASYNC_unblock_pause: procedure; cdecl = nil;
  {$EXTERNALSYM ASYNC_unblock_pause}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function ASYNC_init_thread(max_size: TIdC_SIZET; init_size: TIdC_SIZET): TIdC_INT; cdecl;
procedure ASYNC_cleanup_thread; cdecl;
function ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl;
procedure ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl;
function ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: TIdC_INT; custom_data: Pointer; cleanup: TASYNC_WAIT_CTX_set_wait_fd_cleanup_cb): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: PIdC_INT; custom_data: PPointer): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: PIdC_INT; numfds: PIdC_SIZET): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_get_callback(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: PPointer): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_set_callback(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn_func_cb; callback_arg: Pointer): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_set_status(ctx: PASYNC_WAIT_CTX; status: TIdC_INT): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_get_status(ctx: PASYNC_WAIT_CTX): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: PIdC_INT; numaddfds: PIdC_SIZET; delfd: PIdC_INT; numdelfds: PIdC_SIZET): TIdC_INT; cdecl;
function ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; key: Pointer): TIdC_INT; cdecl;
function ASYNC_is_capable: TIdC_INT; cdecl;
function ASYNC_set_mem_functions(alloc_fn: TASYNC_stack_alloc_fn_func_cb; free_fn: TASYNC_stack_free_fn_func_cb): TIdC_INT; cdecl;
procedure ASYNC_get_mem_functions(alloc_fn: PASYNC_stack_alloc_fn; free_fn: PASYNC_stack_free_fn); cdecl;
function ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: PIdC_INT; func: TASYNC_callback_fn_func_cb; args: Pointer; size: TIdC_SIZET): TIdC_INT; cdecl;
function ASYNC_pause_job: TIdC_INT; cdecl;
function ASYNC_get_current_job: PASYNC_JOB; cdecl;
function ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl;
procedure ASYNC_block_pause; cdecl;
procedure ASYNC_unblock_pause; cdecl;
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

function ASYNC_init_thread(max_size: TIdC_SIZET; init_size: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_init_thread';
procedure ASYNC_cleanup_thread; cdecl external CLibCrypto name 'ASYNC_cleanup_thread';
function ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_new';
procedure ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_free';
function ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: TIdC_INT; custom_data: Pointer; cleanup: TASYNC_WAIT_CTX_set_wait_fd_cleanup_cb): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_set_wait_fd';
function ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: PIdC_INT; custom_data: PPointer): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_get_fd';
function ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: PIdC_INT; numfds: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_get_all_fds';
function ASYNC_WAIT_CTX_get_callback(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: PPointer): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_get_callback';
function ASYNC_WAIT_CTX_set_callback(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn_func_cb; callback_arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_set_callback';
function ASYNC_WAIT_CTX_set_status(ctx: PASYNC_WAIT_CTX; status: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_set_status';
function ASYNC_WAIT_CTX_get_status(ctx: PASYNC_WAIT_CTX): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_get_status';
function ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: PIdC_INT; numaddfds: PIdC_SIZET; delfd: PIdC_INT; numdelfds: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_get_changed_fds';
function ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; key: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_WAIT_CTX_clear_fd';
function ASYNC_is_capable: TIdC_INT; cdecl external CLibCrypto name 'ASYNC_is_capable';
function ASYNC_set_mem_functions(alloc_fn: TASYNC_stack_alloc_fn_func_cb; free_fn: TASYNC_stack_free_fn_func_cb): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_set_mem_functions';
procedure ASYNC_get_mem_functions(alloc_fn: PASYNC_stack_alloc_fn; free_fn: PASYNC_stack_free_fn); cdecl external CLibCrypto name 'ASYNC_get_mem_functions';
function ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: PIdC_INT; func: TASYNC_callback_fn_func_cb; args: Pointer; size: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'ASYNC_start_job';
function ASYNC_pause_job: TIdC_INT; cdecl external CLibCrypto name 'ASYNC_pause_job';
function ASYNC_get_current_job: PASYNC_JOB; cdecl external CLibCrypto name 'ASYNC_get_current_job';
function ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl external CLibCrypto name 'ASYNC_get_wait_ctx';
procedure ASYNC_block_pause; cdecl external CLibCrypto name 'ASYNC_block_pause';
procedure ASYNC_unblock_pause; cdecl external CLibCrypto name 'ASYNC_unblock_pause';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  ASYNC_init_thread_procname = 'ASYNC_init_thread';
  ASYNC_init_thread_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_cleanup_thread_procname = 'ASYNC_cleanup_thread';
  ASYNC_cleanup_thread_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_new_procname = 'ASYNC_WAIT_CTX_new';
  ASYNC_WAIT_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_free_procname = 'ASYNC_WAIT_CTX_free';
  ASYNC_WAIT_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_set_wait_fd_procname = 'ASYNC_WAIT_CTX_set_wait_fd';
  ASYNC_WAIT_CTX_set_wait_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_get_fd_procname = 'ASYNC_WAIT_CTX_get_fd';
  ASYNC_WAIT_CTX_get_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_get_all_fds_procname = 'ASYNC_WAIT_CTX_get_all_fds';
  ASYNC_WAIT_CTX_get_all_fds_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_get_callback_procname = 'ASYNC_WAIT_CTX_get_callback';
  ASYNC_WAIT_CTX_get_callback_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_set_callback_procname = 'ASYNC_WAIT_CTX_set_callback';
  ASYNC_WAIT_CTX_set_callback_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_set_status_procname = 'ASYNC_WAIT_CTX_set_status';
  ASYNC_WAIT_CTX_set_status_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_get_status_procname = 'ASYNC_WAIT_CTX_get_status';
  ASYNC_WAIT_CTX_get_status_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_get_changed_fds_procname = 'ASYNC_WAIT_CTX_get_changed_fds';
  ASYNC_WAIT_CTX_get_changed_fds_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_WAIT_CTX_clear_fd_procname = 'ASYNC_WAIT_CTX_clear_fd';
  ASYNC_WAIT_CTX_clear_fd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_is_capable_procname = 'ASYNC_is_capable';
  ASYNC_is_capable_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_set_mem_functions_procname = 'ASYNC_set_mem_functions';
  ASYNC_set_mem_functions_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  ASYNC_get_mem_functions_procname = 'ASYNC_get_mem_functions';
  ASYNC_get_mem_functions_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  ASYNC_start_job_procname = 'ASYNC_start_job';
  ASYNC_start_job_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_pause_job_procname = 'ASYNC_pause_job';
  ASYNC_pause_job_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_get_current_job_procname = 'ASYNC_get_current_job';
  ASYNC_get_current_job_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_get_wait_ctx_procname = 'ASYNC_get_wait_ctx';
  ASYNC_get_wait_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_block_pause_procname = 'ASYNC_block_pause';
  ASYNC_block_pause_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASYNC_unblock_pause_procname = 'ASYNC_unblock_pause';
  ASYNC_unblock_pause_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_ASYNC_init_thread(max_size: TIdC_SIZET; init_size: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_init_thread_procname);
end;

procedure ERR_ASYNC_cleanup_thread; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_cleanup_thread_procname);
end;

function ERR_ASYNC_WAIT_CTX_new: PASYNC_WAIT_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_new_procname);
end;

procedure ERR_ASYNC_WAIT_CTX_free(ctx: PASYNC_WAIT_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_free_procname);
end;

function ERR_ASYNC_WAIT_CTX_set_wait_fd(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: TIdC_INT; custom_data: Pointer; cleanup: TASYNC_WAIT_CTX_set_wait_fd_cleanup_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_set_wait_fd_procname);
end;

function ERR_ASYNC_WAIT_CTX_get_fd(ctx: PASYNC_WAIT_CTX; key: Pointer; fd: PIdC_INT; custom_data: PPointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_fd_procname);
end;

function ERR_ASYNC_WAIT_CTX_get_all_fds(ctx: PASYNC_WAIT_CTX; fd: PIdC_INT; numfds: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_all_fds_procname);
end;

function ERR_ASYNC_WAIT_CTX_get_callback(ctx: PASYNC_WAIT_CTX; callback: PASYNC_callback_fn; callback_arg: PPointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_callback_procname);
end;

function ERR_ASYNC_WAIT_CTX_set_callback(ctx: PASYNC_WAIT_CTX; callback: TASYNC_callback_fn_func_cb; callback_arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_set_callback_procname);
end;

function ERR_ASYNC_WAIT_CTX_set_status(ctx: PASYNC_WAIT_CTX; status: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_set_status_procname);
end;

function ERR_ASYNC_WAIT_CTX_get_status(ctx: PASYNC_WAIT_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_status_procname);
end;

function ERR_ASYNC_WAIT_CTX_get_changed_fds(ctx: PASYNC_WAIT_CTX; addfd: PIdC_INT; numaddfds: PIdC_SIZET; delfd: PIdC_INT; numdelfds: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_get_changed_fds_procname);
end;

function ERR_ASYNC_WAIT_CTX_clear_fd(ctx: PASYNC_WAIT_CTX; key: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_WAIT_CTX_clear_fd_procname);
end;

function ERR_ASYNC_is_capable: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_is_capable_procname);
end;

function ERR_ASYNC_set_mem_functions(alloc_fn: TASYNC_stack_alloc_fn_func_cb; free_fn: TASYNC_stack_free_fn_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_set_mem_functions_procname);
end;

procedure ERR_ASYNC_get_mem_functions(alloc_fn: PASYNC_stack_alloc_fn; free_fn: PASYNC_stack_free_fn); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_get_mem_functions_procname);
end;

function ERR_ASYNC_start_job(job: PPASYNC_JOB; ctx: PASYNC_WAIT_CTX; ret: PIdC_INT; func: TASYNC_callback_fn_func_cb; args: Pointer; size: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_start_job_procname);
end;

function ERR_ASYNC_pause_job: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_pause_job_procname);
end;

function ERR_ASYNC_get_current_job: PASYNC_JOB; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_get_current_job_procname);
end;

function ERR_ASYNC_get_wait_ctx(job: PASYNC_JOB): PASYNC_WAIT_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_get_wait_ctx_procname);
end;

procedure ERR_ASYNC_block_pause; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_block_pause_procname);
end;

procedure ERR_ASYNC_unblock_pause; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASYNC_unblock_pause_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
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
  
  ASYNC_WAIT_CTX_get_callback := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_get_callback_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_callback);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_get_callback_allownil)}
    ASYNC_WAIT_CTX_get_callback := ERR_ASYNC_WAIT_CTX_get_callback;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_callback_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_get_callback_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_get_callback)}
      ASYNC_WAIT_CTX_get_callback := FC_ASYNC_WAIT_CTX_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_callback_removed)}
    if ASYNC_WAIT_CTX_get_callback_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_get_callback)}
      ASYNC_WAIT_CTX_get_callback := _ASYNC_WAIT_CTX_get_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_get_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_get_callback');
    {$ifend}
  end;
  
  ASYNC_WAIT_CTX_set_callback := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_set_callback_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_set_callback);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_set_callback_allownil)}
    ASYNC_WAIT_CTX_set_callback := ERR_ASYNC_WAIT_CTX_set_callback;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_set_callback_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_set_callback_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_set_callback)}
      ASYNC_WAIT_CTX_set_callback := FC_ASYNC_WAIT_CTX_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_set_callback_removed)}
    if ASYNC_WAIT_CTX_set_callback_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_set_callback)}
      ASYNC_WAIT_CTX_set_callback := _ASYNC_WAIT_CTX_set_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_set_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_set_callback');
    {$ifend}
  end;
  
  ASYNC_WAIT_CTX_set_status := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_set_status_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_set_status);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_set_status_allownil)}
    ASYNC_WAIT_CTX_set_status := ERR_ASYNC_WAIT_CTX_set_status;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_set_status_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_set_status_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_set_status)}
      ASYNC_WAIT_CTX_set_status := FC_ASYNC_WAIT_CTX_set_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_set_status_removed)}
    if ASYNC_WAIT_CTX_set_status_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_set_status)}
      ASYNC_WAIT_CTX_set_status := _ASYNC_WAIT_CTX_set_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_set_status_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_set_status');
    {$ifend}
  end;
  
  ASYNC_WAIT_CTX_get_status := LoadLibFunction(ADllHandle, ASYNC_WAIT_CTX_get_status_procname);
  FuncLoadError := not assigned(ASYNC_WAIT_CTX_get_status);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_WAIT_CTX_get_status_allownil)}
    ASYNC_WAIT_CTX_get_status := ERR_ASYNC_WAIT_CTX_get_status;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_status_introduced)}
    if LibVersion < ASYNC_WAIT_CTX_get_status_introduced then
    begin
      {$if declared(FC_ASYNC_WAIT_CTX_get_status)}
      ASYNC_WAIT_CTX_get_status := FC_ASYNC_WAIT_CTX_get_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_WAIT_CTX_get_status_removed)}
    if ASYNC_WAIT_CTX_get_status_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_WAIT_CTX_get_status)}
      ASYNC_WAIT_CTX_get_status := _ASYNC_WAIT_CTX_get_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_WAIT_CTX_get_status_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_WAIT_CTX_get_status');
    {$ifend}
  end;
  
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
  
  ASYNC_set_mem_functions := LoadLibFunction(ADllHandle, ASYNC_set_mem_functions_procname);
  FuncLoadError := not assigned(ASYNC_set_mem_functions);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_set_mem_functions_allownil)}
    ASYNC_set_mem_functions := ERR_ASYNC_set_mem_functions;
    {$ifend}
    {$if declared(ASYNC_set_mem_functions_introduced)}
    if LibVersion < ASYNC_set_mem_functions_introduced then
    begin
      {$if declared(FC_ASYNC_set_mem_functions)}
      ASYNC_set_mem_functions := FC_ASYNC_set_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_set_mem_functions_removed)}
    if ASYNC_set_mem_functions_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_set_mem_functions)}
      ASYNC_set_mem_functions := _ASYNC_set_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_set_mem_functions_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_set_mem_functions');
    {$ifend}
  end;
  
  ASYNC_get_mem_functions := LoadLibFunction(ADllHandle, ASYNC_get_mem_functions_procname);
  FuncLoadError := not assigned(ASYNC_get_mem_functions);
  if FuncLoadError then
  begin
    {$if not defined(ASYNC_get_mem_functions_allownil)}
    ASYNC_get_mem_functions := ERR_ASYNC_get_mem_functions;
    {$ifend}
    {$if declared(ASYNC_get_mem_functions_introduced)}
    if LibVersion < ASYNC_get_mem_functions_introduced then
    begin
      {$if declared(FC_ASYNC_get_mem_functions)}
      ASYNC_get_mem_functions := FC_ASYNC_get_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASYNC_get_mem_functions_removed)}
    if ASYNC_get_mem_functions_removed <= LibVersion then
    begin
      {$if declared(_ASYNC_get_mem_functions)}
      ASYNC_get_mem_functions := _ASYNC_get_mem_functions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASYNC_get_mem_functions_allownil)}
    if FuncLoadError then
      AFailed.Add('ASYNC_get_mem_functions');
    {$ifend}
  end;
  
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
  
end;

procedure Unload;
begin
  ASYNC_init_thread := nil;
  ASYNC_cleanup_thread := nil;
  ASYNC_WAIT_CTX_new := nil;
  ASYNC_WAIT_CTX_free := nil;
  ASYNC_WAIT_CTX_set_wait_fd := nil;
  ASYNC_WAIT_CTX_get_fd := nil;
  ASYNC_WAIT_CTX_get_all_fds := nil;
  ASYNC_WAIT_CTX_get_callback := nil;
  ASYNC_WAIT_CTX_set_callback := nil;
  ASYNC_WAIT_CTX_set_status := nil;
  ASYNC_WAIT_CTX_get_status := nil;
  ASYNC_WAIT_CTX_get_changed_fds := nil;
  ASYNC_WAIT_CTX_clear_fd := nil;
  ASYNC_is_capable := nil;
  ASYNC_set_mem_functions := nil;
  ASYNC_get_mem_functions := nil;
  ASYNC_start_job := nil;
  ASYNC_pause_job := nil;
  ASYNC_get_current_job := nil;
  ASYNC_get_wait_ctx := nil;
  ASYNC_block_pause := nil;
  ASYNC_unblock_pause := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.