program TaurusTLSHeaderCheck;

{$APPTYPE CONSOLE}

{
  TaurusTLS header consistency checker
  ------------------------------------

  Every OpenSSL routine in the TaurusTLS headers is declared up to three times
  in the same unit:

    1. the dynamic-load function pointer  T<Name> = function(...) cdecl;
    2. the static link declaration        function <Name>(...) cdecl; external CLib...;
    3. the "not present" stub             function ERR_<Name>(...) cdecl;

  All three must agree. When they do not, the mismatch stays invisible until a
  consumer happens to compile that particular path: a wrong static declaration
  breaks only OPENSSL_STATIC_LINK_MODEL builds (iOS/Android), and a wrong
  dynamic declaration breaks only the loader builds (Windows/desktop).

  This tool parses the units and reports every routine whose declarations
  disagree on parameter count, parameter type, parameter modifier or return
  type. Parameter *names* are ignored, since they do not affect the ABI.

  Usage:
    TaurusTLSHeaderCheck [options] [<dir-or-file> ...]

  Exit codes:
    0  no mismatches
    1  mismatches found
    2  usage error / nothing to scan

  Same licence terms as TaurusTLS. Contributed by Parker Hannifin.
}

uses
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.IOUtils,
  System.Math,
  System.Generics.Collections,
  System.Generics.Defaults;

type
  TDeclKind = (dkDynamic, dkStatic, dkErrStub);

  TParam = record
    Modifier: string;   // '', 'const', 'var', 'out'
    ParamType: string;  // normalised, lower case; '' when untyped
  end;

  TDecl = class
  public
    Kind: TDeclKind;
    RoutineName: string;
    IsFunction: Boolean;
    ReturnType: string;
    Params: TArray<TParam>;
    FileName: string;
    Line: Integer;
    function SignatureText: string;
  end;

  TRoutine = class
  public
    Name: string;
    Decls: array[TDeclKind] of TDecl;
    destructor Destroy; override;
  end;

const
  CKindName: array[TDeclKind] of string =
    ('dynamic typedef', 'static external', 'ERR_ stub');

const
  { Pairs of type names that are genuinely the same type under a different
    spelling. Comparing these textually would report a difference that has no
    effect on the ABI, so they are folded together before comparison.
    Left-hand name is rewritten to the right-hand name. Lower case. }
  CTypeAliases: array[0..7, 0..1] of string = (
    ('tidansichar',  'ansichar'),
    ('tidc_char',    'ansichar'),
    ('pidansichar',  'pansichar'),
    ('tidc_int8',    'shortint'),
    ('tidc_uint8',   'byte'),
    ('pidc_int8',    'pshortint'),
    ('pidc_uint8',   'pbyte'),
    ('tidc_bool',    'tidc_int')
  );

var
  GQuiet: Boolean = False;
  GVerbose: Boolean = False;
  GRecursive: Boolean = False;
  GUseColor: Boolean = True;
  GStrict: Boolean = False;
  GFilesScanned: Integer = 0;
  GRoutinesChecked: Integer = 0;
  GMismatches: Integer = 0;
  GWarnings: Integer = 0;

{ Fold known-equivalent spellings together so that a purely cosmetic naming
  difference is not reported as an ABI mismatch. }
function CanonType(const AType: string): string;
var
  I: Integer;
begin
  Result := AType;
  for I := Low(CTypeAliases) to High(CTypeAliases) do
    if Result = CTypeAliases[I, 0] then
      Exit(CTypeAliases[I, 1]);
end;

{ ---------------------------------------------------------------------------
  Helpers
  --------------------------------------------------------------------------- }

procedure WriteColor(const AText, AColor: string);
begin
  if GUseColor then
    Write(AColor, AText, #27'[0m')
  else
    Write(AText);
end;

procedure WriteLnColor(const AText, AColor: string);
begin
  WriteColor(AText, AColor);
  WriteLn;
end;

function CollapseWhitespace(const S: string): string;
var
  I: Integer;
  LWasSpace: Boolean;
  LSb: TStringBuilder;
begin
  LSb := TStringBuilder.Create;
  try
    LWasSpace := True;
    for I := 1 to Length(S) do
      if CharInSet(S[I], [' ', #9, #10, #13]) then
        LWasSpace := True
      else
      begin
        if LWasSpace and (LSb.Length > 0) then
          LSb.Append(' ');
        LWasSpace := False;
        LSb.Append(S[I]);
      end;
    Result := LSb.ToString;
  finally
    LSb.Free;
  end;
end;

function IsIdentChar(C: Char): Boolean;
begin
  Result := CharInSet(C, ['a'..'z', 'A'..'Z', '0'..'9', '_']);
end;

{ Replace every comment and quoted string with spaces, preserving length so
  offsets still map to the original line numbers. Quoted strings are blanked
  because they can contain braces or semicolons, e.g.
  external CLibCrypto name 'OPENSSL_sk_value'; }
function BlankCommentsAndStrings(const ASource: string): string;
var
  I, L: Integer;
begin
  Result := ASource;
  L := Length(Result);
  I := 1;
  while I <= L do
  begin
    if (I < L) and (Result[I] = '/') and (Result[I + 1] = '/') then
    begin
      while (I <= L) and not CharInSet(Result[I], [#10, #13]) do
      begin
        Result[I] := ' ';
        Inc(I);
      end;
    end
    else if Result[I] = '{' then
    begin
      while (I <= L) and (Result[I] <> '}') do
      begin
        if not CharInSet(Result[I], [#10, #13]) then
          Result[I] := ' ';
        Inc(I);
      end;
      if I <= L then
      begin
        Result[I] := ' ';
        Inc(I);
      end;
    end
    else if (I < L) and (Result[I] = '(') and (Result[I + 1] = '*') then
    begin
      while (I < L) and not ((Result[I] = '*') and (Result[I + 1] = ')')) do
      begin
        if not CharInSet(Result[I], [#10, #13]) then
          Result[I] := ' ';
        Inc(I);
      end;
      if I <= L then
      begin
        Result[I] := ' ';
        Inc(I);
      end;
      if I <= L then
      begin
        Result[I] := ' ';
        Inc(I);
      end;
    end
    else if Result[I] = '''' then
    begin
      Result[I] := ' ';
      Inc(I);
      while I <= L do
      begin
        if Result[I] = '''' then
        begin
          Result[I] := ' ';
          Inc(I);
          if (I <= L) and (Result[I] = '''') then
          begin
            Result[I] := ' ';
            Inc(I);
          end
          else
            Break;
        end
        else
        begin
          if not CharInSet(Result[I], [#10, #13]) then
            Result[I] := ' ';
          Inc(I);
        end;
      end;
    end
    else
      Inc(I);
  end;
end;

function LineOfOffset(const AText: string; AOffset: Integer): Integer;
var
  I: Integer;
begin
  Result := 1;
  for I := 1 to Min(AOffset, Length(AText)) do
    if AText[I] = #10 then
      Inc(Result);
end;

function MatchParen(const AText: string; AStart: Integer): Integer;
var
  I, LDepth: Integer;
begin
  Result := 0;
  LDepth := 0;
  for I := AStart to Length(AText) do
  begin
    if AText[I] = '(' then
      Inc(LDepth)
    else if AText[I] = ')' then
    begin
      Dec(LDepth);
      if LDepth = 0 then
        Exit(I);
    end;
  end;
end;

function NextTopLevelSemi(const AText: string; AFrom: Integer): Integer;
var
  I, LDepth: Integer;
begin
  Result := 0;
  LDepth := 0;
  for I := AFrom to Length(AText) do
  begin
    case AText[I] of
      '(', '[': Inc(LDepth);
      ')', ']': Dec(LDepth);
      ';':
        if LDepth <= 0 then
          Exit(I);
    end;
  end;
end;

function SplitTopLevel(const AText: string): TArray<string>;
var
  I, LDepth, LStart: Integer;
  LList: TList<string>;
begin
  LList := TList<string>.Create;
  try
    LDepth := 0;
    LStart := 1;
    for I := 1 to Length(AText) do
    begin
      case AText[I] of
        '(', '[': Inc(LDepth);
        ')', ']': Dec(LDepth);
        ';':
          if LDepth <= 0 then
          begin
            LList.Add(Copy(AText, LStart, I - LStart));
            LStart := I + 1;
          end;
      end;
    end;
    if LStart <= Length(AText) then
      LList.Add(Copy(AText, LStart, Length(AText) - LStart + 1));
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

{ ---------------------------------------------------------------------------
  TDecl / TRoutine
  --------------------------------------------------------------------------- }

function TDecl.SignatureText: string;
var
  I: Integer;
begin
  Result := '(';
  for I := 0 to High(Params) do
  begin
    if I > 0 then
      Result := Result + '; ';
    if Params[I].Modifier <> '' then
      Result := Result + Params[I].Modifier + ' ';
    if Params[I].ParamType = '' then
      Result := Result + '<untyped>'
    else
      Result := Result + Params[I].ParamType;
  end;
  Result := Result + ')';
  if IsFunction then
    Result := Result + ': ' + ReturnType;
end;

destructor TRoutine.Destroy;
var
  K: TDeclKind;
begin
  for K := Low(TDeclKind) to High(TDeclKind) do
    Decls[K].Free;
  inherited;
end;

{ ---------------------------------------------------------------------------
  Parameter parsing
  --------------------------------------------------------------------------- }

function ParseParams(const AParamText: string): TArray<TParam>;
var
  LGroups: TArray<string>;
  LGroup, LNames, LType, LModifier: string;
  LColon, LEq, I, LCount, J: Integer;
  LList: TList<TParam>;
  LParam: TParam;
begin
  LList := TList<TParam>.Create;
  try
    if Trim(AParamText) <> '' then
    begin
      LGroups := SplitTopLevel(AParamText);
      for LGroup in LGroups do
      begin
        if Trim(LGroup) = '' then
          Continue;

        LNames := CollapseWhitespace(LGroup);

        LEq := Pos('=', LNames);
        if LEq > 0 then
          LNames := Trim(Copy(LNames, 1, LEq - 1));

        LModifier := '';
        if StartsText('const ', LNames) then
          LModifier := 'const'
        else if StartsText('var ', LNames) then
          LModifier := 'var'
        else if StartsText('out ', LNames) then
          LModifier := 'out';
        if LModifier <> '' then
          LNames := Trim(Copy(LNames, Length(LModifier) + 1, MaxInt));

        LColon := Pos(':', LNames);
        if LColon > 0 then
        begin
          LType := LowerCase(Trim(Copy(LNames, LColon + 1, MaxInt)));
          LNames := Copy(LNames, 1, LColon - 1);
        end
        else
          LType := '';

        LCount := 1;
        for J := 1 to Length(LNames) do
          if LNames[J] = ',' then
            Inc(LCount);

        LParam.Modifier := LModifier;
        LParam.ParamType := CollapseWhitespace(LType);
        for I := 1 to LCount do
          LList.Add(LParam);
      end;
    end;
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

{ ---------------------------------------------------------------------------
  Scanner
  --------------------------------------------------------------------------- }

type
  TScanner = class
  private
    FRoutines: TObjectDictionary<string, TRoutine>;
    procedure AddDecl(ADecl: TDecl);
  public
    constructor Create;
    destructor Destroy; override;
    procedure ScanFile(const AFileName: string);
    procedure ResolveErrStubs;
    procedure Report;
  end;

constructor TScanner.Create;
begin
  inherited;
  FRoutines := TObjectDictionary<string, TRoutine>.Create([doOwnsValues]);
end;

destructor TScanner.Destroy;
begin
  FRoutines.Free;
  inherited;
end;

procedure TScanner.AddDecl(ADecl: TDecl);
var
  LRoutine: TRoutine;
begin
  if not FRoutines.TryGetValue(ADecl.RoutineName, LRoutine) then
  begin
    LRoutine := TRoutine.Create;
    LRoutine.Name := ADecl.RoutineName;
    FRoutines.Add(ADecl.RoutineName, LRoutine);
  end;

  { Keep the first declaration of each kind. Duplicates come from conditional
    compilation variants of the same routine and would only add noise. }
  if LRoutine.Decls[ADecl.Kind] = nil then
    LRoutine.Decls[ADecl.Kind] := ADecl
  else
    ADecl.Free;
end;

procedure TScanner.ScanFile(const AFileName: string);
var
  LRaw, LText, LHead, LName, LModWord, LParamText, LReturn, LModifiers: string;
  I, L, LNameStart, LNameEnd, LOpen, LClose, LSemi, LColon, LDeclStart: Integer;
  LIsFunction, LIsTypedef, LHasCdecl, LIsExternal, LDone: Boolean;
  LDecl: TDecl;
  LPrevChar: Char;
begin
  try
    { The headers are ANSI (cp1252) with no BOM. ReadAllText with an explicit
      encoding avoids mangling the copyright header. }
    LRaw := TFile.ReadAllText(AFileName, TEncoding.ANSI);
  except
    on E: Exception do
    begin
      WriteLn(ErrOutput, Format('  ! cannot read %s: %s', [AFileName, E.Message]));
      Exit;
    end;
  end;

  Inc(GFilesScanned);
  LText := BlankCommentsAndStrings(LRaw);
  L := Length(LText);
  I := 1;

  while I <= L do
  begin
    if not CharInSet(LText[I], ['f', 'F', 'p', 'P']) then
    begin
      Inc(I);
      Continue;
    end;

    if I > 1 then
      LPrevChar := LText[I - 1]
    else
      LPrevChar := ' ';
    if IsIdentChar(LPrevChar) then
    begin
      Inc(I);
      Continue;
    end;

    LIsFunction := SameText(Copy(LText, I, 8), 'function') and
      ((I + 8 > L) or not IsIdentChar(LText[I + 8]));
    if LIsFunction then
      LDeclStart := I + 8
    else if SameText(Copy(LText, I, 9), 'procedure') and
      ((I + 9 > L) or not IsIdentChar(LText[I + 9])) then
      LDeclStart := I + 9
    else
    begin
      Inc(I);
      Continue;
    end;

    { A dynamic pointer type looks like  T<RoutineName> = function(... }
    LIsTypedef := False;
    LName := '';
    LNameEnd := I - 1;
    while (LNameEnd >= 1) and CharInSet(LText[LNameEnd], [' ', #9, #10, #13]) do
      Dec(LNameEnd);
    if (LNameEnd >= 1) and (LText[LNameEnd] = '=') then
    begin
      Dec(LNameEnd);
      while (LNameEnd >= 1) and CharInSet(LText[LNameEnd], [' ', #9, #10, #13]) do
        Dec(LNameEnd);
      LNameStart := LNameEnd;
      while (LNameStart >= 1) and IsIdentChar(LText[LNameStart]) do
        Dec(LNameStart);
      Inc(LNameStart);
      if LNameEnd >= LNameStart then
      begin
        LName := Copy(LText, LNameStart, LNameEnd - LNameStart + 1);
        if (Length(LName) > 1) and CharInSet(LName[1], ['T', 't']) then
        begin
          LIsTypedef := True;
          LName := Copy(LName, 2, MaxInt);
        end;
      end;
    end;

    if not LIsTypedef then
    begin
      LNameStart := LDeclStart;
      while (LNameStart <= L) and CharInSet(LText[LNameStart], [' ', #9, #10, #13]) do
        Inc(LNameStart);
      LNameEnd := LNameStart;
      while (LNameEnd <= L) and IsIdentChar(LText[LNameEnd]) do
        Inc(LNameEnd);
      if LNameEnd = LNameStart then
      begin
        Inc(I);
        Continue;
      end;
      LName := Copy(LText, LNameStart, LNameEnd - LNameStart);
      LDeclStart := LNameEnd;
      { skip qualified names such as TFoo.Bar - those are implementations }
      if (LDeclStart <= L) and (LText[LDeclStart] = '.') then
      begin
        Inc(I);
        Continue;
      end;
    end;

    LParamText := '';
    LOpen := LDeclStart;
    while (LOpen <= L) and CharInSet(LText[LOpen], [' ', #9, #10, #13]) do
      Inc(LOpen);
    if (LOpen <= L) and (LText[LOpen] = '(') then
    begin
      LClose := MatchParen(LText, LOpen);
      if LClose = 0 then
      begin
        Inc(I);
        Continue;
      end;
      LParamText := Copy(LText, LOpen + 1, LClose - LOpen - 1);
      LDeclStart := LClose + 1;
    end
    else
      LDeclStart := LOpen;

    LSemi := NextTopLevelSemi(LText, LDeclStart);
    if LSemi = 0 then
    begin
      Inc(I);
      Continue;
    end;
    LHead := Copy(LText, LDeclStart, LSemi - LDeclStart);

    LReturn := '';
    if LIsFunction then
    begin
      LColon := Pos(':', LHead);
      if LColon = 0 then
      begin
        Inc(I);
        Continue;
      end;
      LReturn := Trim(Copy(LHead, LColon + 1, MaxInt));
      { a typedef carries its calling convention in the same statement }
      LReturn := StringReplace(LReturn, 'cdecl', '', [rfReplaceAll, rfIgnoreCase]);
      LReturn := StringReplace(LReturn, 'stdcall', '', [rfReplaceAll, rfIgnoreCase]);
      LReturn := StringReplace(LReturn, 'varargs', '', [rfReplaceAll, rfIgnoreCase]);
      LReturn := LowerCase(CollapseWhitespace(LReturn));
    end;

    { Gather the trailing modifier clauses, e.g.
        ; cdecl; external CLibCrypto name 'OPENSSL_sk_value'; }
    LModifiers := LowerCase(LHead);
    LDone := False;
    LOpen := LSemi + 1;
    while not LDone do
    begin
      while (LOpen <= L) and CharInSet(LText[LOpen], [' ', #9, #10, #13]) do
        Inc(LOpen);
      LNameEnd := LOpen;
      while (LNameEnd <= L) and IsIdentChar(LText[LNameEnd]) do
        Inc(LNameEnd);
      LModWord := LowerCase(Copy(LText, LOpen, LNameEnd - LOpen));
      if (LModWord = 'cdecl') or (LModWord = 'stdcall') or (LModWord = 'external') or
         (LModWord = 'overload') or (LModWord = 'inline') or (LModWord = 'forward') or
         (LModWord = 'deprecated') or (LModWord = 'varargs') or (LModWord = 'platform') or
         (LModWord = 'register') or (LModWord = 'safecall') or (LModWord = 'pascal') or
         (LModWord = 'experimental') or (LModWord = 'assembler') then
      begin
        LSemi := NextTopLevelSemi(LText, LNameEnd);
        if LSemi = 0 then
          Break;
        LModifiers := LModifiers + ' ' + LowerCase(Copy(LText, LOpen, LSemi - LOpen));
        LOpen := LSemi + 1;
      end
      else
        LDone := True;
    end;

    LHasCdecl := ContainsText(LModifiers, 'cdecl');
    LIsExternal := ContainsText(LModifiers, 'external');

    { every OpenSSL binding is cdecl - anything else is not our business }
    if LHasCdecl and (LName <> '') then
    begin
      LDecl := TDecl.Create;
      LDecl.RoutineName := LName;
      LDecl.IsFunction := LIsFunction;
      LDecl.ReturnType := LReturn;
      LDecl.Params := ParseParams(LParamText);
      LDecl.FileName := AFileName;
      LDecl.Line := LineOfOffset(LText, I);

      if LIsTypedef then
        LDecl.Kind := dkDynamic
      else if LIsExternal then
        LDecl.Kind := dkStatic
      else
        LDecl.Kind := dkErrStub;

      AddDecl(LDecl);
    end;

    I := LOpen;
  end;
end;

{ ERR_ stubs are named ERR_<RoutineName>. OpenSSL itself has routines called
  ERR_* (ERR_get_error and friends) whose stubs are therefore ERR_ERR_*, so a
  name may only be treated as a stub when the remainder is a routine that was
  actually seen declared elsewhere. }
procedure TScanner.ResolveErrStubs;
var
  LPair: TPair<string, TRoutine>;
  LMoves: TObjectList<TDecl>;
  LNames: TStringList;
  LDecl: TDecl;
  LBase: string;
  I: Integer;
  LTarget: TRoutine;
begin
  LMoves := TObjectList<TDecl>.Create(False);
  LNames := TStringList.Create;
  try
    for LPair in FRoutines do
    begin
      if not StartsText('ERR_', LPair.Key) then
        Continue;
      LBase := Copy(LPair.Key, 5, MaxInt);
      if not FRoutines.ContainsKey(LBase) then
        Continue;
      LDecl := LPair.Value.Decls[dkErrStub];
      if LDecl <> nil then
      begin
        LMoves.Add(LDecl);
        LNames.Add(LBase);
        LPair.Value.Decls[dkErrStub] := nil; // detach; re-homed below
      end;
    end;

    for I := 0 to LMoves.Count - 1 do
    begin
      LDecl := LMoves[I];
      if FRoutines.TryGetValue(LNames[I], LTarget) and
         (LTarget.Decls[dkErrStub] = nil) then
      begin
        LDecl.Kind := dkErrStub;
        LTarget.Decls[dkErrStub] := LDecl;
      end
      else
        LDecl.Free;
    end;
  finally
    LMoves.Free;
    LNames.Free;
  end;
end;

procedure TScanner.Report;
var
  LRoutine: TRoutine;
  LKeys: TArray<string>;
  LKey: string;
  LRef, LOther: TDecl;
  K, KRef: TDeclKind;
  LProblems: TStringList;
  I, LPresent: Integer;
  LHeaderWritten: Boolean;
  LIsError: Boolean;
begin
  LKeys := FRoutines.Keys.ToArray;
  TArray.Sort<string>(LKeys, TComparer<string>.Construct(
    function(const A, B: string): Integer
    begin
      Result := CompareText(A, B);
    end));

  LProblems := TStringList.Create;
  try
    for LKey in LKeys do
    begin
      LRoutine := FRoutines[LKey];

      LRef := nil;
      KRef := dkDynamic;
      LPresent := 0;
      for K := Low(TDeclKind) to High(TDeclKind) do
        if LRoutine.Decls[K] <> nil then
        begin
          Inc(LPresent);
          if LRef = nil then
          begin
            LRef := LRoutine.Decls[K];
            KRef := K;
          end;
        end;

      { a single declaration has nothing to disagree with }
      if LPresent < 2 then
        Continue;

      Inc(GRoutinesChecked);
      LProblems.Clear;
      LIsError := False;

      for K := Low(TDeclKind) to High(TDeclKind) do
      begin
        if (K = KRef) or (LRoutine.Decls[K] = nil) then
          Continue;
        LOther := LRoutine.Decls[K];

        if LOther.IsFunction <> LRef.IsFunction then
        begin
          LIsError := True;
          LProblems.Add(Format('%s is a %s but %s is a %s',
            [CKindName[KRef], IfThen(LRef.IsFunction, 'function', 'procedure'),
             CKindName[K], IfThen(LOther.IsFunction, 'function', 'procedure')]));
        end
        else
        begin
          if LRef.IsFunction and
             (CanonType(LRef.ReturnType) <> CanonType(LOther.ReturnType)) then
          begin
            LIsError := True;
            LProblems.Add(Format('return type: %s says %s, %s says %s',
              [CKindName[KRef], LRef.ReturnType, CKindName[K], LOther.ReturnType]));
          end;

          if Length(LRef.Params) <> Length(LOther.Params) then
          begin
            LIsError := True;
            LProblems.Add(Format('parameter count: %s has %d, %s has %d',
              [CKindName[KRef], Length(LRef.Params), CKindName[K], Length(LOther.Params)]));
          end
          else
            for I := 0 to High(LRef.Params) do
            begin
              if CanonType(LRef.Params[I].ParamType) <>
                 CanonType(LOther.Params[I].ParamType) then
              begin
                LIsError := True;
                LProblems.Add(Format('parameter %d type: %s says %s, %s says %s',
                  [I + 1, CKindName[KRef], LRef.Params[I].ParamType,
                   CKindName[K], LOther.Params[I].ParamType]));
              end;
              { A const/var/out difference does not change how a pointer is
                passed, so it is reported as a style warning rather than an
                ABI error unless --strict is given. }
              if LRef.Params[I].Modifier <> LOther.Params[I].Modifier then
              begin
                if GStrict then
                  LIsError := True;
                LProblems.Add(Format('parameter %d modifier: %s says "%s", %s says "%s"%s',
                  [I + 1, CKindName[KRef], LRef.Params[I].Modifier,
                   CKindName[K], LOther.Params[I].Modifier,
                   IfThen(GStrict, '', '  (cosmetic)')]));
              end;
            end;
        end;
      end;

      if LProblems.Count > 0 then
      begin
        if LIsError then
          Inc(GMismatches)
        else
          Inc(GWarnings);
        WriteLn;
        WriteColor(LRoutine.Name, IfThen(LIsError, #27'[1;31m', #27'[1;33m'));
        if LIsError then
          WriteLn(' - declarations disagree')
        else
          WriteLn(' - declarations differ cosmetically');
        for I := 0 to LProblems.Count - 1 do
          WriteLn('    * ' + LProblems[I]);
        LHeaderWritten := False;
        for K := Low(TDeclKind) to High(TDeclKind) do
          if LRoutine.Decls[K] <> nil then
          begin
            if not LHeaderWritten then
            begin
              LHeaderWritten := True;
              WriteLn('    declared at:');
            end;
            WriteLn(Format('      %-16s %s:%d', [CKindName[K],
              ExtractFileName(LRoutine.Decls[K].FileName), LRoutine.Decls[K].Line]));
            WriteLn(Format('      %-16s   %s', ['', LRoutine.Decls[K].SignatureText]));
          end;
      end;
    end;
  finally
    LProblems.Free;
  end;
end;

{ ---------------------------------------------------------------------------
  Main
  --------------------------------------------------------------------------- }

procedure ShowHelp;
begin
  WriteLn('TaurusTLS header consistency checker');
  WriteLn;
  WriteLn('Verifies that the dynamic-load typedef, the static external declaration');
  WriteLn('and the ERR_ stub of every OpenSSL binding agree with each other.');
  WriteLn;
  WriteLn('Usage: TaurusTLSHeaderCheck [options] [<dir-or-file> ...]');
  WriteLn;
  WriteLn('  -r, --recursive   recurse into subdirectories');
  WriteLn('  -q, --quiet       only print mismatches and the summary');
  WriteLn('  -v, --verbose     print each file as it is scanned');
  WriteLn('      --no-color    disable ANSI colour');
  WriteLn('      --strict      also fail on cosmetic const/var/out differences');
  WriteLn('  -h, --help        this text');
  WriteLn;
  WriteLn('With no path given the current directory is scanned.');
  WriteLn('Exit codes: 0 = consistent, 1 = mismatches found, 2 = usage error.');
end;

var
  GScanner: TScanner;
  GInputs: TStringList;
  GFiles: TStringList;

procedure CollectInputs;
var
  I: Integer;
  LArg: string;
begin
  for I := 1 to ParamCount do
  begin
    LArg := ParamStr(I);
    if (LArg = '-q') or (LArg = '--quiet') then
      GQuiet := True
    else if (LArg = '-v') or (LArg = '--verbose') then
      GVerbose := True
    else if (LArg = '-r') or (LArg = '--recursive') then
      GRecursive := True
    else if LArg = '--no-color' then
      GUseColor := False
    else if LArg = '--strict' then
      GStrict := True
    else if (LArg = '-h') or (LArg = '--help') or (LArg = '/?') then
    begin
      ShowHelp;
      Halt(0);
    end
    else if StartsStr('-', LArg) then
    begin
      WriteLn(ErrOutput, 'Unknown option: ' + LArg);
      Halt(2);
    end
    else
      GInputs.Add(LArg);
  end;

  if GInputs.Count = 0 then
    GInputs.Add(GetCurrentDir);
end;

procedure ExpandInputs;
var
  LInput, LFile: string;
  LFound: TArray<string>;
  LOption: TSearchOption;
begin
  if GRecursive then
    LOption := TSearchOption.soAllDirectories
  else
    LOption := TSearchOption.soTopDirectoryOnly;

  for LInput in GInputs do
  begin
    if TFile.Exists(LInput) then
      GFiles.Add(LInput)
    else if TDirectory.Exists(LInput) then
    begin
      LFound := TDirectory.GetFiles(LInput, '*.pas', LOption);
      for LFile in LFound do
        GFiles.Add(LFile);
    end
    else
      WriteLn(ErrOutput, 'Not found: ' + LInput);
  end;
end;

var
  I: Integer;
begin
  GInputs := TStringList.Create;
  GFiles := TStringList.Create;
  GScanner := TScanner.Create;
  try
    try
      CollectInputs;
      ExpandInputs;

      if GFiles.Count = 0 then
      begin
        WriteLn(ErrOutput, 'No .pas files to scan.');
        Halt(2);
      end;

      GFiles.Sort;
      for I := 0 to GFiles.Count - 1 do
      begin
        if GVerbose then
          WriteLn('scanning ' + ExtractFileName(GFiles[I]));
        GScanner.ScanFile(GFiles[I]);
      end;

      GScanner.ResolveErrStubs;
      GScanner.Report;

      if not GQuiet then
        WriteLn;
      WriteLn(Format('%d file(s), %d routine(s) declared in more than one place.',
        [GFilesScanned, GRoutinesChecked]));
      if GWarnings > 0 then
        WriteLnColor(Format('%d routine(s) with cosmetic differences only.',
          [GWarnings]), #27'[1;33m');
      if GMismatches = 0 then
      begin
        WriteLnColor('OK - all declarations are consistent.', #27'[1;32m');
        ExitCode := 0;
      end
      else
      begin
        WriteLnColor(Format('FAILED - %d routine(s) with inconsistent declarations.',
          [GMismatches]), #27'[1;31m');
        ExitCode := 1;
      end;
    except
      on E: Exception do
      begin
        WriteLn(ErrOutput, E.ClassName + ': ' + E.Message);
        ExitCode := 2;
      end;
    end;
  finally
    GScanner.Free;
    GFiles.Free;
    GInputs.Free;
  end;
end.
