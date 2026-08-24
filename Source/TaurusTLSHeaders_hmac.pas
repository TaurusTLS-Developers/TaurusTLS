/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_hmac.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_hmac.h2pas
     and this file regenerated. TaurusTLSHeaders_hmac.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_hmac;

interface

// Headers for OpenSSL 1.1.1
// hmac.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_evp;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM HMAC_CTX_init}
  HMAC_CTX_init: procedure (ctx : PHMAC_CTX); cdecl = nil; {removed 1.1.0}
  {$EXTERNALSYM HMAC_size}
  HMAC_size: function (const e: PHMAC_CTX): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM HMAC_CTX_new}
  HMAC_CTX_new: function : PHMAC_CTX; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM HMAC_CTX_reset}
  HMAC_CTX_reset: function (ctx: PHMAC_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM HMAC_CTX_cleanup}
  HMAC_CTX_cleanup: procedure (ctx : PHMAC_CTX); cdecl = nil; {removed 1.1.0}
  {$EXTERNALSYM HMAC_CTX_free}
  HMAC_CTX_free: procedure (ctx: PHMAC_CTX); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM HMAC_Init_ex}
  HMAC_Init_ex: function (ctx: PHMAC_CTX; const key: Pointer; len: TIdC_INT; const md: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM HMAC_Update}
  HMAC_Update: function (ctx: PHMAC_CTX; const data: PByte; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM HMAC_Final}
  HMAC_Final: function (ctx: PHMAC_CTX; md: PByte; len: PByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM HMAC}
  HMAC: function (const evp_md: PEVP_MD; const key: Pointer; key_len: TIdC_INT; const d: PByte; n: TIdC_SIZET; md: PByte; md_len: PIdC_INT): PByte; cdecl = nil;
  {$EXTERNALSYM HMAC_CTX_copy}
  HMAC_CTX_copy: function (dctx: PHMAC_CTX; sctx: PHMAC_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM HMAC_CTX_set_flags}
  HMAC_CTX_set_flags: procedure (ctx: PHMAC_CTX; flags: TIdC_ULONG); cdecl = nil;
  {$EXTERNALSYM HMAC_CTX_get_md}
  HMAC_CTX_get_md: function (const ctx: PHMAC_CTX): PEVP_MD; cdecl = nil; {introduced 1.1.0}

{$ELSE}
  {$EXTERNALSYM HMAC_size}
  function HMAC_size(const e: PHMAC_CTX): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM HMAC_CTX_new}
  function HMAC_CTX_new: PHMAC_CTX cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM HMAC_CTX_reset}
  function HMAC_CTX_reset(ctx: PHMAC_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM HMAC_CTX_free}
  procedure HMAC_CTX_free(ctx: PHMAC_CTX) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM HMAC_Init_ex}
  function HMAC_Init_ex(ctx: PHMAC_CTX; const key: Pointer; len: TIdC_INT; const md: PEVP_MD; impl: PENGINE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM HMAC_Update}
  function HMAC_Update(ctx: PHMAC_CTX; const data: PByte; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM HMAC_Final}
  function HMAC_Final(ctx: PHMAC_CTX; md: PByte; len: PByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM HMAC}
  function HMAC(const evp_md: PEVP_MD; const key: Pointer; key_len: TIdC_INT; const d: PByte; n: TIdC_SIZET; md: PByte; md_len: PIdC_INT): PByte cdecl; external CLibCrypto;
  {$EXTERNALSYM HMAC_CTX_copy}
  function HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM HMAC_CTX_set_flags}
  procedure HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TIdC_ULONG) cdecl; external CLibCrypto;
  {$EXTERNALSYM HMAC_CTX_get_md}
  function HMAC_CTX_get_md(const ctx: PHMAC_CTX): PEVP_MD cdecl; external CLibCrypto; {introduced 1.1.0}

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
const
  HMAC_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_reset_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_get_md_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_init_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  HMAC_CTX_cleanup_removed = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);



{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  HMAC_CTX_init_procname = 'HMAC_CTX_init'; {removed 1.1.0}
  HMAC_size_procname = 'HMAC_size'; {introduced 1.1.0}
  HMAC_CTX_new_procname = 'HMAC_CTX_new'; {introduced 1.1.0}
  HMAC_CTX_reset_procname = 'HMAC_CTX_reset'; {introduced 1.1.0}
  HMAC_CTX_cleanup_procname = 'HMAC_CTX_cleanup'; {removed 1.1.0}
  HMAC_CTX_free_procname = 'HMAC_CTX_free'; {introduced 1.1.0}

  HMAC_Init_ex_procname = 'HMAC_Init_ex';
  HMAC_Update_procname = 'HMAC_Update';
  HMAC_Final_procname = 'HMAC_Final';
  HMAC_procname = 'HMAC';
  HMAC_CTX_copy_procname = 'HMAC_CTX_copy';

  HMAC_CTX_set_flags_procname = 'HMAC_CTX_set_flags';
  HMAC_CTX_get_md_procname = 'HMAC_CTX_get_md'; {introduced 1.1.0}


(*
typedef struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX i_ctx;
    EVP_MD_CTX o_ctx;
    unsigned int key_length;
    unsigned char key[HMAC_MAX_MD_CBLOCK];
} HMAC_CTX;
*)

const
  HMAC_MAX_MD_CBLOCK = 128; {largest known is SHA512}


{/forward_compatibility}
   {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
procedure  ERR_HMAC_CTX_init(ctx : PHMAC_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_init_procname);
end;


function  ERR_HMAC_size(const e: PHMAC_CTX): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_size_procname);
end;

 {introduced 1.1.0}
function  ERR_HMAC_CTX_new: PHMAC_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_new_procname);
end;

 {introduced 1.1.0}
function  ERR_HMAC_CTX_reset(ctx: PHMAC_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_reset_procname);
end;

 {introduced 1.1.0}
procedure  ERR_HMAC_CTX_cleanup(ctx : PHMAC_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_cleanup_procname);
end;


procedure  ERR_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_free_procname);
end;

 {introduced 1.1.0}

function  ERR_HMAC_Init_ex(ctx: PHMAC_CTX; const key: Pointer; len: TIdC_INT;
  const md: PEVP_MD; impl: PENGINE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_Init_ex_procname);
end;


function  ERR_HMAC_Update(ctx: PHMAC_CTX; const data: PByte; len: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_Update_procname);
end;


function  ERR_HMAC_Final(ctx: PHMAC_CTX; md: PByte; len: PByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_Final_procname);
end;


function  ERR_HMAC(const evp_md: PEVP_MD; const key: Pointer; key_len: TIdC_INT;
  const d: PByte; n: TIdC_SIZET; md: PByte; md_len: PIdC_INT): PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_procname);
end;


function  ERR_HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_copy_procname);
end;



procedure  ERR_HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TIdC_ULONG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_set_flags_procname);
end;


function  ERR_HMAC_CTX_get_md(const ctx: PHMAC_CTX): PEVP_MD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(HMAC_CTX_get_md_procname);
end;

 {introduced 1.1.0}

  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  HMAC_CTX_init := LoadLibFunction(ADllHandle, HMAC_CTX_init_procname);
  FuncLoadError := not assigned(HMAC_CTX_init);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_init_allownil)}
    HMAC_CTX_init := ERR_HMAC_CTX_init;
    {$ifend}
    {$if declared(HMAC_CTX_init_introduced)}
    if LibVersion < HMAC_CTX_init_introduced then
    begin
      {$if declared(FC_HMAC_CTX_init)}
      HMAC_CTX_init := FC_HMAC_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_init_removed)}
    if HMAC_CTX_init_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_init)}
      HMAC_CTX_init := _HMAC_CTX_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_init_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_init');
    {$ifend}
  end;

 
  HMAC_size := LoadLibFunction(ADllHandle, HMAC_size_procname);
  FuncLoadError := not assigned(HMAC_size);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_size_allownil)}
    HMAC_size := ERR_HMAC_size;
    {$ifend}
    {$if declared(HMAC_size_introduced)}
    if LibVersion < HMAC_size_introduced then
    begin
      {$if declared(FC_HMAC_size)}
      HMAC_size := FC_HMAC_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_size_removed)}
    if HMAC_size_removed <= LibVersion then
    begin
      {$if declared(_HMAC_size)}
      HMAC_size := _HMAC_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_size_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_size');
    {$ifend}
  end;

 {introduced 1.1.0}
  HMAC_CTX_new := LoadLibFunction(ADllHandle, HMAC_CTX_new_procname);
  FuncLoadError := not assigned(HMAC_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_new_allownil)}
    HMAC_CTX_new := ERR_HMAC_CTX_new;
    {$ifend}
    {$if declared(HMAC_CTX_new_introduced)}
    if LibVersion < HMAC_CTX_new_introduced then
    begin
      {$if declared(FC_HMAC_CTX_new)}
      HMAC_CTX_new := FC_HMAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_new_removed)}
    if HMAC_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_new)}
      HMAC_CTX_new := _HMAC_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  HMAC_CTX_reset := LoadLibFunction(ADllHandle, HMAC_CTX_reset_procname);
  FuncLoadError := not assigned(HMAC_CTX_reset);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_reset_allownil)}
    HMAC_CTX_reset := ERR_HMAC_CTX_reset;
    {$ifend}
    {$if declared(HMAC_CTX_reset_introduced)}
    if LibVersion < HMAC_CTX_reset_introduced then
    begin
      {$if declared(FC_HMAC_CTX_reset)}
      HMAC_CTX_reset := FC_HMAC_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_reset_removed)}
    if HMAC_CTX_reset_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_reset)}
      HMAC_CTX_reset := _HMAC_CTX_reset;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_reset_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_reset');
    {$ifend}
  end;

 {introduced 1.1.0}
  HMAC_CTX_cleanup := LoadLibFunction(ADllHandle, HMAC_CTX_cleanup_procname);
  FuncLoadError := not assigned(HMAC_CTX_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_cleanup_allownil)}
    HMAC_CTX_cleanup := ERR_HMAC_CTX_cleanup;
    {$ifend}
    {$if declared(HMAC_CTX_cleanup_introduced)}
    if LibVersion < HMAC_CTX_cleanup_introduced then
    begin
      {$if declared(FC_HMAC_CTX_cleanup)}
      HMAC_CTX_cleanup := FC_HMAC_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_cleanup_removed)}
    if HMAC_CTX_cleanup_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_cleanup)}
      HMAC_CTX_cleanup := _HMAC_CTX_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_cleanup');
    {$ifend}
  end;

 
  HMAC_CTX_free := LoadLibFunction(ADllHandle, HMAC_CTX_free_procname);
  FuncLoadError := not assigned(HMAC_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_free_allownil)}
    HMAC_CTX_free := ERR_HMAC_CTX_free;
    {$ifend}
    {$if declared(HMAC_CTX_free_introduced)}
    if LibVersion < HMAC_CTX_free_introduced then
    begin
      {$if declared(FC_HMAC_CTX_free)}
      HMAC_CTX_free := FC_HMAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_free_removed)}
    if HMAC_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_free)}
      HMAC_CTX_free := _HMAC_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  HMAC_Init_ex := LoadLibFunction(ADllHandle, HMAC_Init_ex_procname);
  FuncLoadError := not assigned(HMAC_Init_ex);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_Init_ex_allownil)}
    HMAC_Init_ex := ERR_HMAC_Init_ex;
    {$ifend}
    {$if declared(HMAC_Init_ex_introduced)}
    if LibVersion < HMAC_Init_ex_introduced then
    begin
      {$if declared(FC_HMAC_Init_ex)}
      HMAC_Init_ex := FC_HMAC_Init_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_Init_ex_removed)}
    if HMAC_Init_ex_removed <= LibVersion then
    begin
      {$if declared(_HMAC_Init_ex)}
      HMAC_Init_ex := _HMAC_Init_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_Init_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_Init_ex');
    {$ifend}
  end;


  HMAC_Update := LoadLibFunction(ADllHandle, HMAC_Update_procname);
  FuncLoadError := not assigned(HMAC_Update);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_Update_allownil)}
    HMAC_Update := ERR_HMAC_Update;
    {$ifend}
    {$if declared(HMAC_Update_introduced)}
    if LibVersion < HMAC_Update_introduced then
    begin
      {$if declared(FC_HMAC_Update)}
      HMAC_Update := FC_HMAC_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_Update_removed)}
    if HMAC_Update_removed <= LibVersion then
    begin
      {$if declared(_HMAC_Update)}
      HMAC_Update := _HMAC_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_Update');
    {$ifend}
  end;


  HMAC_Final := LoadLibFunction(ADllHandle, HMAC_Final_procname);
  FuncLoadError := not assigned(HMAC_Final);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_Final_allownil)}
    HMAC_Final := ERR_HMAC_Final;
    {$ifend}
    {$if declared(HMAC_Final_introduced)}
    if LibVersion < HMAC_Final_introduced then
    begin
      {$if declared(FC_HMAC_Final)}
      HMAC_Final := FC_HMAC_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_Final_removed)}
    if HMAC_Final_removed <= LibVersion then
    begin
      {$if declared(_HMAC_Final)}
      HMAC_Final := _HMAC_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_Final');
    {$ifend}
  end;


  HMAC := LoadLibFunction(ADllHandle, HMAC_procname);
  FuncLoadError := not assigned(HMAC);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_allownil)}
    HMAC := ERR_HMAC;
    {$ifend}
    {$if declared(HMAC_introduced)}
    if LibVersion < HMAC_introduced then
    begin
      {$if declared(FC_HMAC)}
      HMAC := FC_HMAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_removed)}
    if HMAC_removed <= LibVersion then
    begin
      {$if declared(_HMAC)}
      HMAC := _HMAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC');
    {$ifend}
  end;


  HMAC_CTX_copy := LoadLibFunction(ADllHandle, HMAC_CTX_copy_procname);
  FuncLoadError := not assigned(HMAC_CTX_copy);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_copy_allownil)}
    HMAC_CTX_copy := ERR_HMAC_CTX_copy;
    {$ifend}
    {$if declared(HMAC_CTX_copy_introduced)}
    if LibVersion < HMAC_CTX_copy_introduced then
    begin
      {$if declared(FC_HMAC_CTX_copy)}
      HMAC_CTX_copy := FC_HMAC_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_copy_removed)}
    if HMAC_CTX_copy_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_copy)}
      HMAC_CTX_copy := _HMAC_CTX_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_copy');
    {$ifend}
  end;


  HMAC_CTX_set_flags := LoadLibFunction(ADllHandle, HMAC_CTX_set_flags_procname);
  FuncLoadError := not assigned(HMAC_CTX_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_set_flags_allownil)}
    HMAC_CTX_set_flags := ERR_HMAC_CTX_set_flags;
    {$ifend}
    {$if declared(HMAC_CTX_set_flags_introduced)}
    if LibVersion < HMAC_CTX_set_flags_introduced then
    begin
      {$if declared(FC_HMAC_CTX_set_flags)}
      HMAC_CTX_set_flags := FC_HMAC_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_set_flags_removed)}
    if HMAC_CTX_set_flags_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_set_flags)}
      HMAC_CTX_set_flags := _HMAC_CTX_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_set_flags');
    {$ifend}
  end;


  HMAC_CTX_get_md := LoadLibFunction(ADllHandle, HMAC_CTX_get_md_procname);
  FuncLoadError := not assigned(HMAC_CTX_get_md);
  if FuncLoadError then
  begin
    {$if not defined(HMAC_CTX_get_md_allownil)}
    HMAC_CTX_get_md := ERR_HMAC_CTX_get_md;
    {$ifend}
    {$if declared(HMAC_CTX_get_md_introduced)}
    if LibVersion < HMAC_CTX_get_md_introduced then
    begin
      {$if declared(FC_HMAC_CTX_get_md)}
      HMAC_CTX_get_md := FC_HMAC_CTX_get_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(HMAC_CTX_get_md_removed)}
    if HMAC_CTX_get_md_removed <= LibVersion then
    begin
      {$if declared(_HMAC_CTX_get_md)}
      HMAC_CTX_get_md := _HMAC_CTX_get_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(HMAC_CTX_get_md_allownil)}
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_get_md');
    {$ifend}
  end;

 {introduced 1.1.0}
end;

procedure Unload;
begin
  HMAC_CTX_init := nil; {removed 1.1.0}
  HMAC_size := nil; {introduced 1.1.0}
  HMAC_CTX_new := nil; {introduced 1.1.0}
  HMAC_CTX_reset := nil; {introduced 1.1.0}
  HMAC_CTX_cleanup := nil; {removed 1.1.0}
  HMAC_CTX_free := nil; {introduced 1.1.0}
  HMAC_Init_ex := nil;
  HMAC_Update := nil;
  HMAC_Final := nil;
  HMAC := nil;
  HMAC_CTX_copy := nil;
  HMAC_CTX_set_flags := nil;
  HMAC_CTX_get_md := nil; {introduced 1.1.0}
end;
  {$ENDIF}
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
