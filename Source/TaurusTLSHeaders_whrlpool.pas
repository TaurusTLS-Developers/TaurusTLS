/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_whrlpool.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_whrlpool.h2pas
     and this file regenerated. TaurusTLSHeaders_whrlpool.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_whrlpool;

interface

// Headers for OpenSSL 1.1.1
// whrlpool.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF}
  {$IFNDEF FPC}
  , TaurusTLSHeaders_types
  {$ENDIF};

const
  {$EXTERNALSYM WHIRLPOOL_DIGEST_LENGTH}
  WHIRLPOOL_DIGEST_LENGTH = 512 div 8;
  {$EXTERNALSYM WHIRLPOOL_BBLOCK}
  WHIRLPOOL_BBLOCK = 512;
  {$EXTERNALSYM WHIRLPOOL_COUNTER}
  WHIRLPOOL_COUNTER = 256 div 8;

type
  {$EXTERNALSYM WHIRLPOOL_CTX_union}
  WHIRLPOOL_CTX_union = record
    case Byte of
      0: (c: array[0 .. WHIRLPOOL_DIGEST_LENGTH -1] of Byte);
      (* double q is here to ensure 64-bit alignment *)
      1: (q: array[0 .. (WHIRLPOOL_DIGEST_LENGTH div SizeOf(TIdC_DOUBLE)) -1] of TIdC_DOUBLE);
  end;
  {$EXTERNALSYM WHIRLPOOL_CTX}
  WHIRLPOOL_CTX = record
    H: WHIRLPOOL_CTX_union;
    data: array[0 .. (WHIRLPOOL_BBLOCK div 8) -1] of Byte;
    bitoff: TIdC_UINT;
    bitlen: array[0 .. (WHIRLPOOL_COUNTER div SizeOf(TIdC_SIZET)) -1] of TIdC_SIZET;
  end;
  {$EXTERNALSYM PWHIRLPOOL_CTX}
  PWHIRLPOOL_CTX = ^WHIRLPOOL_CTX;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM WHIRLPOOL_Init}
  WHIRLPOOL_Init: function (c: PWHIRLPOOL_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM WHIRLPOOL_Update}
  WHIRLPOOL_Update: function (c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM WHIRLPOOL_BitUpdate}
  WHIRLPOOL_BitUpdate: procedure (c: PWHIRLPOOL_CTX; inp: Pointer; bits: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM WHIRLPOOL_Final}
  WHIRLPOOL_Final: function (md: PByte; c: PWHIRLPOOL_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM WHIRLPOOL}
  WHIRLPOOL: function (inp: Pointer; bytes: TIdC_SIZET; md: PByte): PByte; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM WHIRLPOOL_Init}
  function WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM WHIRLPOOL_Update}
  function WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM WHIRLPOOL_BitUpdate}
  procedure WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TIdC_SIZET) cdecl; external CLibCrypto;
  {$EXTERNALSYM WHIRLPOOL_Final}
  function WHIRLPOOL_Final(md: PByte; c: PWHIRLPOOL_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM WHIRLPOOL}
  function WHIRLPOOL(inp: Pointer; bytes: TIdC_SIZET; md: PByte): PByte cdecl; external CLibCrypto;

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
  WHIRLPOOL_Init_procname = 'WHIRLPOOL_Init';
  WHIRLPOOL_Update_procname = 'WHIRLPOOL_Update';
  WHIRLPOOL_BitUpdate_procname = 'WHIRLPOOL_BitUpdate';
  WHIRLPOOL_Final_procname = 'WHIRLPOOL_Final';
  WHIRLPOOL_procname = 'WHIRLPOOL';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}

function  ERR_WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_Init_procname);
end;


function  ERR_WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TIdC_SIZET): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_Update_procname);
end;


procedure  ERR_WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TIdC_SIZET);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_BitUpdate_procname);
end;


function  ERR_WHIRLPOOL_Final(md: PByte; c: PWHIRLPOOL_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_Final_procname);
end;


function  ERR_WHIRLPOOL(inp: Pointer; bytes: TIdC_SIZET; md: PByte): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(WHIRLPOOL_procname);
end;

  {$I TaurusTLSNoRetValOn.inc} 

{$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;

begin
  WHIRLPOOL_Init := LoadLibFunction(ADllHandle, WHIRLPOOL_Init_procname);
  FuncLoadError := not assigned(WHIRLPOOL_Init);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_Init_allownil)}
    WHIRLPOOL_Init := ERR_WHIRLPOOL_Init;
    {$ifend}
    {$if declared(WHIRLPOOL_Init_introduced)}
    if LibVersion < WHIRLPOOL_Init_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_Init)}
      WHIRLPOOL_Init := FC_WHIRLPOOL_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_Init_removed)}
    if WHIRLPOOL_Init_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_Init)}
      WHIRLPOOL_Init := _WHIRLPOOL_Init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_Init_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_Init');
    {$ifend}
  end;


  WHIRLPOOL_Update := LoadLibFunction(ADllHandle, WHIRLPOOL_Update_procname);
  FuncLoadError := not assigned(WHIRLPOOL_Update);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_Update_allownil)}
    WHIRLPOOL_Update := ERR_WHIRLPOOL_Update;
    {$ifend}
    {$if declared(WHIRLPOOL_Update_introduced)}
    if LibVersion < WHIRLPOOL_Update_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_Update)}
      WHIRLPOOL_Update := FC_WHIRLPOOL_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_Update_removed)}
    if WHIRLPOOL_Update_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_Update)}
      WHIRLPOOL_Update := _WHIRLPOOL_Update;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_Update_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_Update');
    {$ifend}
  end;


  WHIRLPOOL_BitUpdate := LoadLibFunction(ADllHandle, WHIRLPOOL_BitUpdate_procname);
  FuncLoadError := not assigned(WHIRLPOOL_BitUpdate);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_BitUpdate_allownil)}
    WHIRLPOOL_BitUpdate := ERR_WHIRLPOOL_BitUpdate;
    {$ifend}
    {$if declared(WHIRLPOOL_BitUpdate_introduced)}
    if LibVersion < WHIRLPOOL_BitUpdate_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_BitUpdate)}
      WHIRLPOOL_BitUpdate := FC_WHIRLPOOL_BitUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_BitUpdate_removed)}
    if WHIRLPOOL_BitUpdate_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_BitUpdate)}
      WHIRLPOOL_BitUpdate := _WHIRLPOOL_BitUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_BitUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_BitUpdate');
    {$ifend}
  end;


  WHIRLPOOL_Final := LoadLibFunction(ADllHandle, WHIRLPOOL_Final_procname);
  FuncLoadError := not assigned(WHIRLPOOL_Final);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_Final_allownil)}
    WHIRLPOOL_Final := ERR_WHIRLPOOL_Final;
    {$ifend}
    {$if declared(WHIRLPOOL_Final_introduced)}
    if LibVersion < WHIRLPOOL_Final_introduced then
    begin
      {$if declared(FC_WHIRLPOOL_Final)}
      WHIRLPOOL_Final := FC_WHIRLPOOL_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_Final_removed)}
    if WHIRLPOOL_Final_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL_Final)}
      WHIRLPOOL_Final := _WHIRLPOOL_Final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_Final_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL_Final');
    {$ifend}
  end;


  WHIRLPOOL := LoadLibFunction(ADllHandle, WHIRLPOOL_procname);
  FuncLoadError := not assigned(WHIRLPOOL);
  if FuncLoadError then
  begin
    {$if not defined(WHIRLPOOL_allownil)}
    WHIRLPOOL := ERR_WHIRLPOOL;
    {$ifend}
    {$if declared(WHIRLPOOL_introduced)}
    if LibVersion < WHIRLPOOL_introduced then
    begin
      {$if declared(FC_WHIRLPOOL)}
      WHIRLPOOL := FC_WHIRLPOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(WHIRLPOOL_removed)}
    if WHIRLPOOL_removed <= LibVersion then
    begin
      {$if declared(_WHIRLPOOL)}
      WHIRLPOOL := _WHIRLPOOL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(WHIRLPOOL_allownil)}
    if FuncLoadError then
      AFailed.Add('WHIRLPOOL');
    {$ifend}
  end;


end;
{$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  WHIRLPOOL_Init := nil;
  WHIRLPOOL_Update := nil;
  WHIRLPOOL_BitUpdate := nil;
  WHIRLPOOL_Final := nil;
  WHIRLPOOL := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
