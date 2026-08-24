/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_comp.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_comp.h2pas
     and this file regenerated. TaurusTLSHeaders_comp.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_comp;

interface

// Headers for OpenSSL 1.1.1
// comp.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_types;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM COMP_CTX_new}
  COMP_CTX_new: function (meth: PCOMP_METHOD): PCOMP_CTX; cdecl = nil;
  {$EXTERNALSYM COMP_CTX_get_method}
  COMP_CTX_get_method: function (const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_CTX_get_type}
  COMP_CTX_get_type: function (const _comp: PCOMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM COMP_get_type}
  COMP_get_type: function (const meth: PCOMP_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM COMP_get_name}
  COMP_get_name: function (const meth: PCOMP_METHOD): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM COMP_CTX_free}
  COMP_CTX_free: procedure (ctx: PCOMP_CTX); cdecl = nil;

  {$EXTERNALSYM COMP_compress_block}
  COMP_compress_block: function (ctx: PCOMP_CTX; out_: PByte; olen: TIdC_INT; in_: PByte; ilen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM COMP_expand_block}
  COMP_expand_block: function (ctx: PCOMP_CTX; out_: PByte; olen: TIdC_INT; in_: PByte; ilen: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM COMP_zlib}
  COMP_zlib: function : PCOMP_METHOD; cdecl = nil;

  {$EXTERNALSYM BIO_f_zlib}
  BIO_f_zlib: function : PBIO_METHOD; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM COMP_CTX_new}
  function COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM COMP_CTX_get_method}
  function COMP_CTX_get_method(const ctx: PCOMP_CTX): PCOMP_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM COMP_CTX_get_type}
  function COMP_CTX_get_type(const _comp: PCOMP_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM COMP_get_type}
  function COMP_get_type(const meth: PCOMP_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM COMP_get_name}
  function COMP_get_name(const meth: PCOMP_METHOD): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM COMP_CTX_free}
  procedure COMP_CTX_free(ctx: PCOMP_CTX) cdecl; external CLibCrypto;

  {$EXTERNALSYM COMP_compress_block}
  function COMP_compress_block(ctx: PCOMP_CTX; out_: PByte; olen: TIdC_INT; in_: PByte; ilen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM COMP_expand_block}
  function COMP_expand_block(ctx: PCOMP_CTX; out_: PByte; olen: TIdC_INT; in_: PByte; ilen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM COMP_zlib}
  function COMP_zlib: PCOMP_METHOD cdecl; external CLibCrypto;

  {$EXTERNALSYM BIO_f_zlib}
  function BIO_f_zlib: PBIO_METHOD cdecl; external CLibCrypto;

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
  COMP_CTX_new_procname = 'COMP_CTX_new';
  COMP_CTX_get_method_procname = 'COMP_CTX_get_method';
  COMP_CTX_get_type_procname = 'COMP_CTX_get_type';
  COMP_get_type_procname = 'COMP_get_type';
  COMP_get_name_procname = 'COMP_get_name';
  COMP_CTX_free_procname = 'COMP_CTX_free';

  COMP_compress_block_procname = 'COMP_compress_block';
  COMP_expand_block_procname = 'COMP_expand_block';

  COMP_zlib_procname = 'COMP_zlib';

  BIO_f_zlib_procname = 'BIO_f_zlib';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}
function  ERR_COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_new_procname);
end;


function  ERR_COMP_CTX_get_method(const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_get_method_procname);
end;


function  ERR_COMP_CTX_get_type(const _comp: PCOMP_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_get_type_procname);
end;


function  ERR_COMP_get_type(const meth: PCOMP_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_get_type_procname);
end;


function  ERR_COMP_get_name(const meth: PCOMP_METHOD): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_get_name_procname);
end;


procedure  ERR_COMP_CTX_free(ctx: PCOMP_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_free_procname);
end;



function  ERR_COMP_compress_block(ctx: PCOMP_CTX; out_: PByte; olen: TIdC_INT; in_: PByte;
  ilen: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_compress_block_procname);
end;


function  ERR_COMP_expand_block(ctx: PCOMP_CTX; out_: PByte; olen: TIdC_INT; in_: PByte;
  ilen: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_expand_block_procname);
end;



function  ERR_COMP_zlib: PCOMP_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_zlib_procname);
end;



function  ERR_BIO_f_zlib: PBIO_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_f_zlib_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  COMP_CTX_new := LoadLibFunction(ADllHandle, COMP_CTX_new_procname);
  FuncLoadError := not assigned(COMP_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_new_allownil)}
    COMP_CTX_new := ERR_COMP_CTX_new;
    {$ifend}
    {$if declared(COMP_CTX_new_introduced)}
    if LibVersion < COMP_CTX_new_introduced then
    begin
      {$if declared(FC_COMP_CTX_new)}
      COMP_CTX_new := FC_COMP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_new_removed)}
    if COMP_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_new)}
      COMP_CTX_new := _COMP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_new');
    {$ifend}
  end;


  COMP_CTX_get_method := LoadLibFunction(ADllHandle, COMP_CTX_get_method_procname);
  FuncLoadError := not assigned(COMP_CTX_get_method);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_get_method_allownil)}
    COMP_CTX_get_method := ERR_COMP_CTX_get_method;
    {$ifend}
    {$if declared(COMP_CTX_get_method_introduced)}
    if LibVersion < COMP_CTX_get_method_introduced then
    begin
      {$if declared(FC_COMP_CTX_get_method)}
      COMP_CTX_get_method := FC_COMP_CTX_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_get_method_removed)}
    if COMP_CTX_get_method_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_get_method)}
      COMP_CTX_get_method := _COMP_CTX_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_get_method');
    {$ifend}
  end;


  COMP_CTX_get_type := LoadLibFunction(ADllHandle, COMP_CTX_get_type_procname);
  FuncLoadError := not assigned(COMP_CTX_get_type);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_get_type_allownil)}
    COMP_CTX_get_type := ERR_COMP_CTX_get_type;
    {$ifend}
    {$if declared(COMP_CTX_get_type_introduced)}
    if LibVersion < COMP_CTX_get_type_introduced then
    begin
      {$if declared(FC_COMP_CTX_get_type)}
      COMP_CTX_get_type := FC_COMP_CTX_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_get_type_removed)}
    if COMP_CTX_get_type_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_get_type)}
      COMP_CTX_get_type := _COMP_CTX_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_get_type');
    {$ifend}
  end;


  COMP_get_type := LoadLibFunction(ADllHandle, COMP_get_type_procname);
  FuncLoadError := not assigned(COMP_get_type);
  if FuncLoadError then
  begin
    {$if not defined(COMP_get_type_allownil)}
    COMP_get_type := ERR_COMP_get_type;
    {$ifend}
    {$if declared(COMP_get_type_introduced)}
    if LibVersion < COMP_get_type_introduced then
    begin
      {$if declared(FC_COMP_get_type)}
      COMP_get_type := FC_COMP_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_get_type_removed)}
    if COMP_get_type_removed <= LibVersion then
    begin
      {$if declared(_COMP_get_type)}
      COMP_get_type := _COMP_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_get_type');
    {$ifend}
  end;


  COMP_get_name := LoadLibFunction(ADllHandle, COMP_get_name_procname);
  FuncLoadError := not assigned(COMP_get_name);
  if FuncLoadError then
  begin
    {$if not defined(COMP_get_name_allownil)}
    COMP_get_name := ERR_COMP_get_name;
    {$ifend}
    {$if declared(COMP_get_name_introduced)}
    if LibVersion < COMP_get_name_introduced then
    begin
      {$if declared(FC_COMP_get_name)}
      COMP_get_name := FC_COMP_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_get_name_removed)}
    if COMP_get_name_removed <= LibVersion then
    begin
      {$if declared(_COMP_get_name)}
      COMP_get_name := _COMP_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_get_name_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_get_name');
    {$ifend}
  end;


  COMP_CTX_free := LoadLibFunction(ADllHandle, COMP_CTX_free_procname);
  FuncLoadError := not assigned(COMP_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_free_allownil)}
    COMP_CTX_free := ERR_COMP_CTX_free;
    {$ifend}
    {$if declared(COMP_CTX_free_introduced)}
    if LibVersion < COMP_CTX_free_introduced then
    begin
      {$if declared(FC_COMP_CTX_free)}
      COMP_CTX_free := FC_COMP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_free_removed)}
    if COMP_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_free)}
      COMP_CTX_free := _COMP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_free');
    {$ifend}
  end;


  COMP_compress_block := LoadLibFunction(ADllHandle, COMP_compress_block_procname);
  FuncLoadError := not assigned(COMP_compress_block);
  if FuncLoadError then
  begin
    {$if not defined(COMP_compress_block_allownil)}
    COMP_compress_block := ERR_COMP_compress_block;
    {$ifend}
    {$if declared(COMP_compress_block_introduced)}
    if LibVersion < COMP_compress_block_introduced then
    begin
      {$if declared(FC_COMP_compress_block)}
      COMP_compress_block := FC_COMP_compress_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_compress_block_removed)}
    if COMP_compress_block_removed <= LibVersion then
    begin
      {$if declared(_COMP_compress_block)}
      COMP_compress_block := _COMP_compress_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_compress_block_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_compress_block');
    {$ifend}
  end;


  COMP_expand_block := LoadLibFunction(ADllHandle, COMP_expand_block_procname);
  FuncLoadError := not assigned(COMP_expand_block);
  if FuncLoadError then
  begin
    {$if not defined(COMP_expand_block_allownil)}
    COMP_expand_block := ERR_COMP_expand_block;
    {$ifend}
    {$if declared(COMP_expand_block_introduced)}
    if LibVersion < COMP_expand_block_introduced then
    begin
      {$if declared(FC_COMP_expand_block)}
      COMP_expand_block := FC_COMP_expand_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_expand_block_removed)}
    if COMP_expand_block_removed <= LibVersion then
    begin
      {$if declared(_COMP_expand_block)}
      COMP_expand_block := _COMP_expand_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_expand_block_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_expand_block');
    {$ifend}
  end;


  COMP_zlib := LoadLibFunction(ADllHandle, COMP_zlib_procname);
  FuncLoadError := not assigned(COMP_zlib);
  if FuncLoadError then
  begin
    {$if not defined(COMP_zlib_allownil)}
    COMP_zlib := ERR_COMP_zlib;
    {$ifend}
    {$if declared(COMP_zlib_introduced)}
    if LibVersion < COMP_zlib_introduced then
    begin
      {$if declared(FC_COMP_zlib)}
      COMP_zlib := FC_COMP_zlib;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_zlib_removed)}
    if COMP_zlib_removed <= LibVersion then
    begin
      {$if declared(_COMP_zlib)}
      COMP_zlib := _COMP_zlib;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_zlib_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_zlib');
    {$ifend}
  end;


  BIO_f_zlib := LoadLibFunction(ADllHandle, BIO_f_zlib_procname);
  FuncLoadError := not assigned(BIO_f_zlib);
  if FuncLoadError then
  begin
    {$if not defined(BIO_f_zlib_allownil)}
    BIO_f_zlib := ERR_BIO_f_zlib;
    {$ifend}
    {$if declared(BIO_f_zlib_introduced)}
    if LibVersion < BIO_f_zlib_introduced then
    begin
      {$if declared(FC_BIO_f_zlib)}
      BIO_f_zlib := FC_BIO_f_zlib;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_f_zlib_removed)}
    if BIO_f_zlib_removed <= LibVersion then
    begin
      {$if declared(_BIO_f_zlib)}
      BIO_f_zlib := _BIO_f_zlib;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_f_zlib_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_f_zlib');
    {$ifend}
  end;


end;
  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  COMP_CTX_new := nil;
  COMP_CTX_get_method := nil;
  COMP_CTX_get_type := nil;
  COMP_get_type := nil;
  COMP_get_name := nil;
  COMP_CTX_free := nil;
  COMP_compress_block := nil;
  COMP_expand_block := nil;
  COMP_zlib := nil;
  BIO_f_zlib := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
