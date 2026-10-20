{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 - 2025 TaurusTLS Developers, All Rights Reserved       * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I TaurusTLSUTCompilerDefines.inc}
/// <summary>
/// Unit-Test for the TaurusTLS.UT.Utils (DUnitX API extention framework)
/// </summary>
unit TaurusTLS.UT.Utils.Tests;
{$i ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  T00OsslLoaderTests = class
  private
    class function SetTrailingSlash(const APath: string): string; static;
    class function CanExecLoadedFuncs: boolean; static;
    procedure VerifyUnload(AMustUnload: boolean); overload;
  public
    [Test]
    [IgnoreMemoryLeaks(True)]
    procedure VerifyPath;
    [Test]
    [IgnoreMemoryLeaks(True)]
    procedure VerifyLoad;
    [Test]
    [IgnoreMemoryLeaks(True)]
    procedure VerifyUnload; overload;
    [TestCase('MultipleLoadUnload#1', '1')]
    [TestCase('MultipleLoadUnload#256', '8')]
    [IgnoreMemoryLeaks(True)]
    procedure StackedLoadUnload(ACount: cardinal);
  end;

implementation

uses
  System.SysUtils, System.Classes, System.Generics.Collections, System.SyncObjs,
  DUnitX.CommandLine.Options, TaurusTLS.UT.Utils,
  TaurusTLSHeaders_types, TaurusTLSHeaders_buffer;

{ TOsslLoaderTests }

procedure T00OsslLoaderTests.VerifyPath;
var
  lLongOpt: string;
  lShortOpt: string;
  lEnvVar: string;

begin
  lLongOpt:='';
  lShortOpt:='';
  lEnvVar:='';

  if FindCmdLineSwitch(TOsslLoader.cLongOptName, lLongOpt) then
  begin
    Log(TLogLevel.Information,
      Format('Command-line switch "-%s" found with value "%s"',
             [TOsslLoader.cLongOptName, lLongOpt]));
      lLongOpt:=SetTrailingSlash(lLongOpt);
  end;
  if FindCmdLineSwitch(TOsslLoader.cShortOptName, lShortOpt) then
  begin
    Log(TLogLevel.Information,
      Format('Command-line switch "-%s" found with value "%s"',
             [TOsslLoader.cShortOptName, lShortOpt]));
      lShortOpt:=SetTrailingSlash(lShortOpt);
  end;
  lEnvVar:=GetEnvironmentVariable(TOsslLoader.cEnvVarName);
  if not lEnvVar.IsEmpty then
  begin
    Log(TLogLevel.Information,
      Format('Environenment Variable "%s" found with value "%s"',
             [TOsslLoader.cEnvVarName, lEnvVar]));
      lEnvVar:=SetTrailingSlash(lEnvVar);
  end;
  if lLongOpt.IsEmpty and lShortOpt.IsEmpty and lEnvVar.IsEmpty then
    Log('Nor command-line switch, nor environment variable provided.');

  if not (lLongOpt.IsEmpty and lShortOpt.IsEmpty) then
{$IFDEF MSWINDOWS}
    Assert.IsTrue((CompareText(lLongOpt, TOsslLoader.Path) = 0) or
      (CompareText(lShortOpt, TOsslLoader.Path) = 0),
{$ELSE}
    Assert.IsTrue((CompareStr(lLongOpt, TOsslLoader.Path) = 0) or
      (CompareStr(lShortOpt, TOsslLoader.Path) = 0),
{$ENDIF}
      Format('Expected "%s" or "%s" from a command-line switch(es) value, got "%s"',
        [TOsslLoader.cLongOptName, TOsslLoader.cShortOptName, TOsslLoader.Path]))
  else if not lEnvVar.IsEmpty then
    Assert.AreEqual(lEnvVar, TOsslLoader.Path,
      'OpenSSL Path is not equal to "'+TOsslLoader.cEnvVarName+'" environment variable value.')
  else
    Assert.AreEqual('', TOsslLoader.Path,
      'OpenSSL Path is not empty.')
end;

class function T00OsslLoaderTests.CanExecLoadedFuncs: boolean;
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
var
  lPtr: PBUF_MEM;
{$ENDIF}

begin
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result:=Assigned(BUF_MEM_new) and Assigned(BUF_MEM_free);
{$ELSE}
  Result:=True;
  try
    lPtr := BUF_MEM_new;
    BUF_MEM_free(lPtr);
  except
    Result:=False;
  end;
{$ENDIF}
end;

class function T00OsslLoaderTests.SetTrailingSlash(const APath: string): string;
const
{$IFDEF MSWINDOWS}
  cTrailSlash = '\';
{$ELSE}
  cTrailSlash = '/';
{$ENDIF}

begin
  Result:=APath;
  if Result.IsEmpty then
    Exit;
  if not Result.EndsWith(cTrailSlash) then
    Result:=Result+cTrailSlash;
end;

procedure T00OsslLoaderTests.VerifyLoad;
begin
  Assert.WillNotRaise(
    procedure
    begin
      TOsslLoader.Load;
    end,
    nil,
    'Openssl library fails to load.'
  );
  Assert.IsTrue(TOsslLoader.Loaded, 'Openssl library has not been loaded.');
  Assert.IsTrue(CanExecLoadedFuncs, 'Openssl library function are not exported.');
end;

procedure T00OsslLoaderTests.VerifyUnload(AMustUnload: boolean);
begin
  Assert.WillNotRaise(
    procedure
    begin
      TOsslLoader.UnLoad;
    end
  );
  if AMustUnload then
  begin
    Assert.IsFalse(TOsslLoader.Loaded, 'Openssl library has not been unloaded.');
    Assert.IsFalse(CanExecLoadedFuncs, 'Openssl library function are still be exported.');
  end;
end;

procedure T00OsslLoaderTests.VerifyUnLoad;
begin
  VerifyUnload(True);
end;

procedure T00OsslLoaderTests.StackedLoadUnload(ACount: cardinal);
var
  lCounter: cardinal;

begin
  if ACount = 0 then
  begin
    Assert.Pass('Zero loads-unloads requested. Nothing to do.');
    Exit;
  end;

  lCounter := 0;
  repeat
    Inc(lCounter);
    Log(Format('Load request #%d.', [lCounter]));
    VerifyLoad;
  until lCounter >= ACount;

  repeat
    Log(Format('Unload request #%d.', [lCounter]));
    VerifyUnload(lCounter = 1);
    Dec(lCounter);
  until lCounter = 0;
end;

initialization
  TDUnitX.RegisterTestFixture(T00OsslLoaderTests);

end.
