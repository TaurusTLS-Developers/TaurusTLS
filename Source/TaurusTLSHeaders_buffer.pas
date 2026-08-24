/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_buffer.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_buffer.h2pas
     and this file regenerated. TaurusTLSHeaders_buffer.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_buffer;

interface

// Headers for OpenSSL 1.1.1
// buffer.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types;

const
  {$EXTERNALSYM BUF_MEM_FLAG_SECURE}
  BUF_MEM_FLAG_SECURE = $01;

type
  {$EXTERNALSYM buf_mem_st}
  buf_mem_st = record
    _length: TIdC_SIZET;
    data: PIdAnsiChar;
    max: TIdC_SIZET;
    flags: TIdC_ULONG;
  end;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM BUF_MEM_new}
  BUF_MEM_new: function : PBUF_MEM; cdecl = nil;
  {$EXTERNALSYM BUF_MEM_new_ex}
  BUF_MEM_new_ex: function (flags: TIdC_ULONG): PBUF_MEM; cdecl = nil;
  {$EXTERNALSYM BUF_MEM_free}
  BUF_MEM_free: procedure (a: PBUF_MEM); cdecl = nil;
  {$EXTERNALSYM BUF_MEM_grow}
  BUF_MEM_grow: function (_str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BUF_MEM_grow_clean}
  BUF_MEM_grow_clean: function (_str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM BUF_reverse}
  BUF_reverse: procedure (out_: PByte; const in_: PByte; siz: TIdC_SIZET); cdecl = nil;

{$ELSE}
  {$EXTERNALSYM BUF_MEM_new}
  function BUF_MEM_new: PBUF_MEM cdecl; external CLibCrypto;
  {$EXTERNALSYM BUF_MEM_new_ex}
  function BUF_MEM_new_ex(flags: TIdC_ULONG): PBUF_MEM cdecl; external CLibCrypto;
  {$EXTERNALSYM BUF_MEM_free}
  procedure BUF_MEM_free(a: PBUF_MEM) cdecl; external CLibCrypto;
  {$EXTERNALSYM BUF_MEM_grow}
  function BUF_MEM_grow(_str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto;
  {$EXTERNALSYM BUF_MEM_grow_clean}
  function BUF_MEM_grow_clean(_str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto;
  {$EXTERNALSYM BUF_reverse}
  procedure BUF_reverse(out_: PByte; const in_: PByte; siz: TIdC_SIZET) cdecl; external CLibCrypto;

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
  BUF_MEM_new_procname = 'BUF_MEM_new';
  BUF_MEM_new_ex_procname = 'BUF_MEM_new_ex';
  BUF_MEM_free_procname = 'BUF_MEM_free';
  BUF_MEM_grow_procname = 'BUF_MEM_grow';
  BUF_MEM_grow_clean_procname = 'BUF_MEM_grow_clean';
  BUF_reverse_procname = 'BUF_reverse';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_BUF_MEM_new: PBUF_MEM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_new_procname);
end;


function  ERR_BUF_MEM_new_ex(flags: TIdC_ULONG): PBUF_MEM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_new_ex_procname);
end;


procedure  ERR_BUF_MEM_free(a: PBUF_MEM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_free_procname);
end;


function  ERR_BUF_MEM_grow(_str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_grow_procname);
end;


function  ERR_BUF_MEM_grow_clean(_str: PBUF_MEM; len: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_MEM_grow_clean_procname);
end;


procedure  ERR_BUF_reverse(out_: PByte; const in_: PByte; siz: TIdC_SIZET); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BUF_reverse_procname);
end;



  {$I TaurusTLSNoRetValOn.inc}
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  BUF_MEM_new := LoadLibFunction(ADllHandle, BUF_MEM_new_procname);
  FuncLoadError := not assigned(BUF_MEM_new);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_new_allownil)}
    BUF_MEM_new := ERR_BUF_MEM_new;
    {$ifend}
    {$if declared(BUF_MEM_new_introduced)}
    if LibVersion < BUF_MEM_new_introduced then
    begin
      {$if declared(FC_BUF_MEM_new)}
      BUF_MEM_new := FC_BUF_MEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_new_removed)}
    if BUF_MEM_new_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_new)}
      BUF_MEM_new := _BUF_MEM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_new');
    {$ifend}
  end;


  BUF_MEM_new_ex := LoadLibFunction(ADllHandle, BUF_MEM_new_ex_procname);
  FuncLoadError := not assigned(BUF_MEM_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_new_ex_allownil)}
    BUF_MEM_new_ex := ERR_BUF_MEM_new_ex;
    {$ifend}
    {$if declared(BUF_MEM_new_ex_introduced)}
    if LibVersion < BUF_MEM_new_ex_introduced then
    begin
      {$if declared(FC_BUF_MEM_new_ex)}
      BUF_MEM_new_ex := FC_BUF_MEM_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_new_ex_removed)}
    if BUF_MEM_new_ex_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_new_ex)}
      BUF_MEM_new_ex := _BUF_MEM_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_new_ex');
    {$ifend}
  end;


  BUF_MEM_free := LoadLibFunction(ADllHandle, BUF_MEM_free_procname);
  FuncLoadError := not assigned(BUF_MEM_free);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_free_allownil)}
    BUF_MEM_free := ERR_BUF_MEM_free;
    {$ifend}
    {$if declared(BUF_MEM_free_introduced)}
    if LibVersion < BUF_MEM_free_introduced then
    begin
      {$if declared(FC_BUF_MEM_free)}
      BUF_MEM_free := FC_BUF_MEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_free_removed)}
    if BUF_MEM_free_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_free)}
      BUF_MEM_free := _BUF_MEM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_free');
    {$ifend}
  end;


  BUF_MEM_grow := LoadLibFunction(ADllHandle, BUF_MEM_grow_procname);
  FuncLoadError := not assigned(BUF_MEM_grow);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_grow_allownil)}
    BUF_MEM_grow := ERR_BUF_MEM_grow;
    {$ifend}
    {$if declared(BUF_MEM_grow_introduced)}
    if LibVersion < BUF_MEM_grow_introduced then
    begin
      {$if declared(FC_BUF_MEM_grow)}
      BUF_MEM_grow := FC_BUF_MEM_grow;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_grow_removed)}
    if BUF_MEM_grow_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_grow)}
      BUF_MEM_grow := _BUF_MEM_grow;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_grow_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_grow');
    {$ifend}
  end;


  BUF_MEM_grow_clean := LoadLibFunction(ADllHandle, BUF_MEM_grow_clean_procname);
  FuncLoadError := not assigned(BUF_MEM_grow_clean);
  if FuncLoadError then
  begin
    {$if not defined(BUF_MEM_grow_clean_allownil)}
    BUF_MEM_grow_clean := ERR_BUF_MEM_grow_clean;
    {$ifend}
    {$if declared(BUF_MEM_grow_clean_introduced)}
    if LibVersion < BUF_MEM_grow_clean_introduced then
    begin
      {$if declared(FC_BUF_MEM_grow_clean)}
      BUF_MEM_grow_clean := FC_BUF_MEM_grow_clean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_MEM_grow_clean_removed)}
    if BUF_MEM_grow_clean_removed <= LibVersion then
    begin
      {$if declared(_BUF_MEM_grow_clean)}
      BUF_MEM_grow_clean := _BUF_MEM_grow_clean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_MEM_grow_clean_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_MEM_grow_clean');
    {$ifend}
  end;


  BUF_reverse := LoadLibFunction(ADllHandle, BUF_reverse_procname);
  FuncLoadError := not assigned(BUF_reverse);
  if FuncLoadError then
  begin
    {$if not defined(BUF_reverse_allownil)}
    BUF_reverse := ERR_BUF_reverse;
    {$ifend}
    {$if declared(BUF_reverse_introduced)}
    if LibVersion < BUF_reverse_introduced then
    begin
      {$if declared(FC_BUF_reverse)}
      BUF_reverse := FC_BUF_reverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BUF_reverse_removed)}
    if BUF_reverse_removed <= LibVersion then
    begin
      {$if declared(_BUF_reverse)}
      BUF_reverse := _BUF_reverse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BUF_reverse_allownil)}
    if FuncLoadError then
      AFailed.Add('BUF_reverse');
    {$ifend}
  end;


end;
  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  BUF_MEM_new := nil;
  BUF_MEM_new_ex := nil;
  BUF_MEM_free := nil;
  BUF_MEM_grow := nil;
  BUF_MEM_grow_clean := nil;
  BUF_reverse := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
