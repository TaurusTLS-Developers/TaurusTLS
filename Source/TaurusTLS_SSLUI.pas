{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 � 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew � http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I TaurusTLSCompilerDefines.inc}

/// <summary>
///   This unit implements <see
///   href="https://docs.openssl.org/3.0/man7/ossl_store/#ui_method-and-pass-phrases">
///   OpenSSL UI_METHOD</see> wrappers that allows to implement unified Passphrase
///   management.
/// </summary>
unit TaurusTLS_SSLUI;
{$I TaurusTLSLinkDefines.inc}

interface

uses
  SysUtils,
  Classes,
  Types,
  SyncObjs,
  Generics.Collections,
  Generics.Defaults,
  IdCTypes,
  IdGlobal,
  TaurusTLSHeaders_types,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_ui;

type
  /// <summary>
  ///   Exception raised when registration of a native OpenSSL <c>UI_METHOD</c> structure fails.
  /// </summary>
  ETaurusTLSRegisterMethod = class(ETaurusTLSAPICryptoError);

  /// <summary>
  ///   Exception raised when allocation of a native OpenSSL <c>UI</c> session structure fails.
  /// </summary>
  ETaurusTLSCreateUi = class(ETaurusTLSError);

  /// <summary>
  ///   Defines the status results returned to the unmanaged OpenSSL <c>UI_METHOD</c> callbacks.
  /// </summary>
  TTaurusTLS_UiResult = (
    /// <summary>The prompt operation was explicitly canceled by the user.</summary>
    uirCanceled = -1,
    /// <summary>An error occurred during the prompt operation.</summary>
    uirError    = 0,
    /// <summary>The prompt operation completed successfully.</summary>
    uirSuccess  = 1
  );

  /// <summary>
  ///   Helper record providing seamless, type-safe integer conversions for
  ///   <see cref="TTaurusTLS_UiResult" /> when interacting with the OpenSSL C-API.
  /// </summary>
  TTaurusTLS_UiResultHelper = record helper for TTaurusTLS_UiResult
  private
    function GetAsInt: TIdC_INT; {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    /// <summary>
    ///   Returns the raw integer representation of the result required by native
    ///   OpenSSL <c>UI_METHOD</c> callbacks.
    /// </summary>
    property AsInt: TIdC_INT read GetAsInt;
  end;

  /// <summary>
  ///   Implements a managed class wrapper around the native OpenSSL <c>UI_STRING</c> structure,
  ///   representing an active prompt element (e.g. password input, message, or boolean check).
  /// </summary>
  /// <seealso href="https://docs.openssl.org/master/man3/UI_STRING/">OpenSSL UI_STRING APIs</seealso>
  TTaurusTLS_UiString = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FString: PUI_STRING;
    FFlags: TIdC_Int;
    FType: UI_string_types;
    FUi: PUI;
    function GetIsBooleanPrompt: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetIsDefaultPwd: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetEcho: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetIsPrompt: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetIsResult: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetResultMaxSize: TIdC_Int; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetResultMinSize: TIdC_Int; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetPrompt: PIdAnsiChar; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetAction: PIdAnsiChar; {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    /// <summary>
    ///   Initializes a new instance of <see cref="TTaurusTLS_UiString" /> wrapping a
    ///   native OpenSSL UI string.
    /// </summary>
    /// <param name="AString">The native <c>PUI_STRING</c> pointer passed by OpenSSL.</param>
    /// <param name="ui">The native <c>PUI</c> prompt session pointer passed by OpenSSL.</param>
    constructor Create(AString: PUI_STRING; ui: PUI);

    /// <summary>
    ///   Directly writes a raw, sized character buffer to the native OpenSSL UI string result.
    /// </summary>
    /// <param name="APass">A raw pointer to the Ansi character buffer containing the passphrase.</param>
    /// <param name="ALen">The exact length of the passphrase character array.</param>
    /// <returns><c>True</c> if the password was successfully accepted; <c>False</c> otherwise.</returns>
    /// <remarks>
    ///   This is a wrapper around the native <c>UI_set_result_ex</c> routine. It can only be called on
    ///   elements where <see cref="IsResult" /> is <c>True</c>.
    /// </remarks>
    function SetPassword(APass: PIdAnsiChar; ALen: TIdC_Int): boolean; overload;

    /// <summary>
    ///   Writes a null-terminated C-string to the native OpenSSL UI string result.
    /// </summary>
    /// <param name="APass">A null-terminated <c>PIdAnsiChar</c> buffer containing the passphrase.</param>
    /// <returns><c>True</c> if the password was successfully accepted; <c>False</c> otherwise.</returns>
    /// <remarks>
    ///   Bypasses managed Delphi string allocations. Determines length safely in-memory using <c>StrLen</c>.
    /// </remarks>
    function SetPassword(const APass: PIdAnsiChar): boolean; overload;

    /// <summary>
    ///   Writes a managed RawByteString to the native OpenSSL UI string result.
    /// </summary>
    /// <param name="APass">The managed <c>RawByteString</c> containing the passphrase.</param>
    /// <returns><c>True</c> if the password was successfully accepted; <c>False</c> otherwise.</returns>
    function SetPassword(const APass: RawByteString): boolean; overload;

    /// <summary>
    ///   Writes a managed TBytes byte array to the native OpenSSL UI string result.
    /// </summary>
    /// <param name="APass">The <c>TBytes</c> array containing the passphrase bytes.</param>
    /// <returns><c>True</c> if the password was successfully accepted; <c>False</c> otherwise.</returns>
    function SetPassword(const APass: TBytes): boolean; overload;

    /// <summary>
    ///   Provides direct, read-only access to the underlying native OpenSSL <c>PUI_STRING</c> pointer.
    /// </summary>
    property UIString: PUI_STRING read FString;

    /// <summary>
    ///   Returns the native, underlying type of this UI string (e.g. prompt, verify, or message).
    /// </summary>
    property &Type: UI_string_types read FType;

    /// <summary>
    ///   Retrieves the descriptive output prompt text to display to the user.
    /// </summary>
    /// <returns>A read-only pointer to the null-terminated Ansi prompt string.</returns>
    /// <remarks>Wraps the native OpenSSL <c>UI_get0_output_string</c> API.</remarks>
    property Prompt: PIdAnsiChar read GetPrompt;

    /// <summary>
    ///   Retrieves the action prefix text associated with this prompt (e.g. "Entering").
    /// </summary>
    /// <returns>A read-only pointer to the null-terminated Ansi action string.</returns>
    /// <remarks>Wraps the native OpenSSL <c>UI_get0_action_string</c> API.</remarks>
    property Action: PIdAnsiChar read GetAction;

    /// <summary>
    ///   Provides access to the native, active OpenSSL <c>PUI</c> session handle.
    /// </summary>
    property Ui: PUI read FUi;

    /// <summary>
    ///   Indicates whether the user's input should be echoed to the console screen.
    /// </summary>
    /// <returns><c>True</c> if input echo is enabled; <c>False</c> (e.g. for secure passwords) otherwise.</returns>
    property Echo: boolean read GetEcho;

    /// <summary>
    ///   Indicates whether OpenSSL should fall back to a default, pre-configured test password.
    /// </summary>
    property DefaultPwd: boolean read GetIsDefaultPwd;

    /// <summary>
    ///   Indicates whether this prompt expects a boolean (Yes/No) decision from the user.
    /// </summary>
    property IsBooleanPrompt: boolean read GetIsBooleanPrompt;

    /// <summary>
    ///   Indicates whether this element represents any active user prompt type.
    /// </summary>
    property IsPrompt: boolean read GetIsPrompt;

    /// <summary>
    ///   Indicates whether this element can accept a written passphrase result (i.e. is a prompt or verify type).
    /// </summary>
    property IsResult: boolean read GetIsResult;

    /// <summary>
    ///   The minimum acceptable length of the passphrase input (excluding the null terminator).
    /// </summary>
    property ResultMinSize: TIdC_Int read GetResultMinSize;

    /// <summary>
    ///   The maximum acceptable length of the passphrase input (excluding the null terminator).
    /// </summary>
    property ResultMaxSize: TIdC_Int read GetResultMaxSize;
  end;

  TTaurusTLSOsslUiMethod = class;

  /// <summary>
  ///   Manages the state and tracks all mapped UI string elements of a single, active
  ///   OpenSSL prompt session.
  /// </summary>
  /// <remarks>
  ///   To prevent memory leaks, the underlying string list is a <c>TObjectDictionary</c>
  ///   configured with value ownership, ensuring all temporary wrapper classes are automatically
  ///   reclaimed when the session is closed or cleared.
  /// </remarks>
  TTaurusTLS_UICtx = class
  protected type
    /// <summary>Reference-counted, value-owning dictionary of active UI prompt elements.</summary>
    TUIStrings = TObjectDictionary<PUI_STRING, TTaurusTLS_UiString>;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FUi: PUI;
    FUiMeth: TTaurusTLSOsslUiMethod;
    FUIStrings: TUIStrings;
  protected
    /// <summary>Adds an active UI string wrapper to the session tracking list.</summary>
    procedure AddUIString(AString: TTaurusTLS_UiString); {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>Safely clears and deallocates all tracked UI string wrappers.</summary>
    procedure Clear; {$IFDEF USE_INLINE}inline;{$ENDIF}

    /// <summary>Gets the raw OpenSSL UI session handle.</summary>
    property Ui: PUI read FUi;
    /// <summary>Gets the parent unmanaged UI method wrapper definition.</summary>
    property UIMeth: TTaurusTLSOsslUiMethod read FUiMeth;
  public
    /// <summary>
    ///   Initializes a new instance of <see cref="TTaurusTLS_UICtx" /> mapped to a specific
    ///   UI method.
    /// </summary>
    /// <param name="AUiMeth">The parent UI method wrapper object.</param>
    constructor Create(AUiMeth: TTaurusTLSOsslUiMethod);
    /// <summary>Releases all allocated resources and clears the string tracking dictionary.</summary>
    destructor Destroy; override;

    /// <summary>Attempts to retrieve a tracked UI string wrapper by its native key.</summary>
    function TryGetUIString(const Key: PUI_STRING; out AValue: TTaurusTLS_UiString): boolean;

    /// <summary>Exposes the active string dictionary of the session.</summary>
    property UIStrings: TUIStrings read FUIStrings;
  end;

  /// <summary>
  ///   Abstract base class wrapping OpenSSL's custom <c>UI_METHOD</c> callback structure,
  ///   allowing Delphi-level objects to handle unmanaged passphrase prompts natively.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/master/man3/UI_create_method/">OpenSSL UI_METHOD APIs</seealso>
  TTaurusTLSOsslUiMethod = class abstract
  private const
    cMethNameFmt = '%s %p';
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FUiMeth: PUI_METHOD;

    class function Opener(ui: PUI): TIdC_INT; static; cdecl;
    class function Writer(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Flusher(ui: PUI): TIdC_INT; static; cdecl;
    class function Reader(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Closer(ui: PUI): TIdC_INT; static; cdecl;
    class function NewUiString(uis: PUI_STRING; ui: PUI): TTaurusTLS_UiString; static; {$IFDEF USE_INLINE}inline;{$ENDIF}

    procedure RegisterMethods;
    procedure UnregisterMethods;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    /// <summary>Retrieves the Delphi UI Context instance bound to an active OpenSSL UI handle.</summary>
    class function GetUiCtx(AUi: PUI): TTaurusTLS_UICtx; static; {$IFDEF USE_INLINE}inline;{$ENDIF}

    /// <summary>Virtual hook executed when OpenSSL opens a prompt session.</summary>
    function DoPromptInit(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; virtual;
    /// <summary>Virtual hook executed when OpenSSL registers a prompt element.</summary>
    function DoPromptSetup(AUiCtx: TTaurusTLS_UICtx; AString: TTaurusTLS_UiString): TTaurusTLS_UiResult; virtual;
    /// <summary>Virtual hook executed when OpenSSL displays active prompts.</summary>
    function DoPromptDisplay(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; virtual;
    /// <summary>Virtual hook executed when OpenSSL requests input data for a prompt.</summary>
    function DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx; AString: TTaurusTLS_UiString): TTaurusTLS_UiResult; virtual;
    /// <summary>Virtual hook executed when OpenSSL terminates and closes a prompt session.</summary>
    function DoPromptRelease(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; virtual;
  protected
    /// <summary>Allocates a new native OpenSSL UI session handle using this method structure.</summary>
    function NewUI: PUI;
  public
    /// <summary>Registers the unmanaged callbacks and creates the UI_METHOD structure.</summary>
    constructor Create;
    /// <summary>Safely unbinds callbacks and destroys the unmanaged UI_METHOD structure.</summary>
    destructor Destroy; override;
    /// <summary>Helper creating a new Delphi UI context session wrapper.</summary>
    function NewUICtx: TTaurusTLS_UICtx;

    /// <summary>Provides direct access to the compiled native OpenSSL <c>PUI_METHOD</c> handle.</summary>
    property UiMethod: PUI_METHOD read FUIMeth;
  end;

  /// <summary>Event fired during prompt session initialization.</summary>
  TTaurusTLS_UISimpleEvent = procedure(ASender: TObject; var AResult: TTaurusTLS_UiResult) of object;
  /// <summary>Event fired when prompts are displayed to the user.</summary>
  TTaurusTLS_UIDisplayEvent = procedure(ASender: TObject; ACtx: TTaurusTLS_UICtx; var AResult: TTaurusTLS_UiResult) of object;
  /// <summary>Event fired when a prompt is registered or set.</summary>
  TTaurusTLS_UISetupEvent = procedure(ASender: TObject; AString: TTaurusTLS_UiString; var AResult: TTaurusTLS_UiResult) of object;
  /// <summary>Event fired when input data is requested for a prompt.</summary>
  TTaurusTLS_UIResultEvent = TTaurusTLS_UISetupEvent;

  /// <summary>
  ///   Concrete implementation of <see cref="TTaurusTLSOsslUiMethod" /> that delegates
  ///   unmanaged OpenSSL prompts directly to standard Delphi event handlers.
  /// </summary>
  TTaurusTLS_DelegatedUI = class(TTaurusTLSOsslUiMethod)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOnPrepareUI: TTaurusTLS_UISimpleEvent;
    FOnSetupUI: TTaurusTLS_UISetupEvent;
    FOnDisplayUI: TTaurusTLS_UIDisplayEvent;
    FOnResultUI: TTaurusTLS_UIResultEvent;
    FOnReleaseUI: TTaurusTLS_UISimpleEvent;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    function DoPromptInit(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; override;
    function DoPromptSetup(AUiCtx: TTaurusTLS_UICtx; AString: TTaurusTLS_UiString): TTaurusTLS_UiResult; override;
    function DoPromptDisplay(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; override;
    function DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx; AString: TTaurusTLS_UiString): TTaurusTLS_UiResult; override;
    function DoPromptRelease(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; override;
  public
    /// <summary>Fires when OpenSSL initializes the prompt session.</summary>
    property OnPrepareUI: TTaurusTLS_UISimpleEvent read FOnPrepareUI write FOnPrepareUI;
    /// <summary>Fires when OpenSSL registers a specific prompt string.</summary>
    property OnSetupUI: TTaurusTLS_UISetupEvent read FOnSetupUI write FOnSetupUI;
    /// <summary>Fires when OpenSSL flushes and displays prompts.</summary>
    property OnDisplayUI: TTaurusTLS_UIDisplayEvent read FOnDisplayUI write FOnDisplayUI;
    /// <summary>Fires when OpenSSL requests input data for a prompt.</summary>
    property OnResultUI: TTaurusTLS_UIResultEvent read FOnResultUI write FOnResultUI;
    /// <summary>Fires when OpenSSL terminates and closes the prompt session.</summary>
    property OnReleaseUI: TTaurusTLS_UISimpleEvent read FOnReleaseUI write FOnReleaseUI;
  end;

implementation

uses
{$IF Defined(DCC) and Defined(STRING_IS_UNICODE)}
  System.AnsiStrings,
{$IFEND}
  TaurusTLS_ResourceStrings;

procedure CheckOSSLMethError(Result: TIdC_INT; SuccessCode: TIdC_INT;
  const AMethName: string); overload;
begin
  if Result <> SuccessCode then
    ETaurusTLSAPICryptoError.RaiseWithMessageFmt(
      RMSG_RegisterUIMeth_err, [AMethName]);
end;

{ TTaurusTLS_UiResultHelper }

function TTaurusTLS_UiResultHelper.GetAsInt: TIdC_INT;
begin
  Result:=TIdC_INT(Ord(Self));
end;

{ TTaurusTLS_UiString }

constructor TTaurusTLS_UiString.Create(AString: PUI_STRING;
  ui: PUI);
begin
  FString:=AString;
  FType:=UI_get_string_type(AString);
  FFlags:=UI_get_input_flags(AString);
  FUi:=ui;
end;

function TTaurusTLS_UiString.GetIsDefaultPwd: boolean;
begin
  Result:=FFlags and UI_INPUT_FLAG_DEFAULT_PWD <> 0;
end;

function TTaurusTLS_UiString.GetEcho: boolean;
begin
  Result:=FFlags and UI_INPUT_FLAG_ECHO <> 0;
end;

function TTaurusTLS_UiString.GetIsPrompt: boolean;
begin
  Result:=FType in [UIT_PROMPT, UIT_VERIFY, UIT_BOOLEAN];
end;

function TTaurusTLS_UiString.GetIsResult: boolean;
begin
  Result:=FType in [UIT_PROMPT, UIT_VERIFY];
end;

function TTaurusTLS_UiString.GetResultMaxSize: TIdC_Int;
begin
  Result:=UI_get_result_maxsize(FString);
end;

function TTaurusTLS_UiString.GetResultMinSize: TIdC_Int;
begin
  Result:=UI_get_result_minsize(FString);
end;

function TTaurusTLS_UiString.GetIsBooleanPrompt: boolean;
begin
  Result:=FType = UIT_BOOLEAN;
end;

function TTaurusTLS_UiString.GetPrompt: PIdAnsiChar;
begin
  Result:=UI_get0_output_string(FString);
end;

function TTaurusTLS_UiString.GetAction: PIdAnsiChar;
begin
  Result:=UI_get0_action_string(FString);
end;

function TTaurusTLS_UiString.SetPassword(APass: PIdAnsiChar;
  ALen: TIdC_Int): boolean;
begin
  Result:=IsResult and Assigned(Ui);
  if Result then
    Result:=UI_set_result_ex(Ui, FString, APass, ALen) = 0;
end;

function TTaurusTLS_UiString.SetPassword(const APass: RawByteString): boolean;
begin
  Result:=SetPassword(PIdAnsiChar(APass), Length(APass));
end;

function TTaurusTLS_UiString.SetPassword(const APass: TBytes): boolean;
var
  lLen: TIdC_Long;
  lPass: PAnsiChar;

begin
  lLen:=Length(APass);
  if lLen > 0 then
    lPass:=PIdAnsiChar(@APass[0])
  else
    lPass:=nil;
  Result:=SetPassword(lPass, lLen);
end;

function TTaurusTLS_UiString.SetPassword(const APass: PIdAnsiChar): boolean;
var
  lLen: TIdC_INT;

begin
{$IFDEF STRING_IS_UNICODE}
  lLen:=System.AnsiStrings.StrLen(APass);
{$ELSE}
  lLen:=StrLen(APass);
{$ENDIF}
  Result:=SetPassword(APass, lLen);
end;

{ TTaurusTLS_UICtx }

constructor TTaurusTLS_UICtx.Create(AUiMeth: TTaurusTLSOsslUiMethod);
begin
  Assert(Assigned(AUiMeth), 'Parameter ''AUi'' must not be ''nil''.'); // Do not localize
  FUIStrings:=TUIStrings.Create([doOwnsValues]);
  FUi:=AUiMeth.NewUi;
  UI_add_user_data(FUi, Self);
end;

destructor TTaurusTLS_UICtx.Destroy;
begin
  if Assigned(FUi) then
  begin
    UI_add_user_data(FUi, nil);
    UI_free(FUi);
    FUi:=nil;
  end;
  FreeAndNil(FUIStrings);
  inherited;
end;

function TTaurusTLS_UICtx.TryGetUIString(const Key: PUI_STRING;
  out AValue: TTaurusTLS_UIString): boolean;
begin
  if Assigned(Key) then
    Result:=FUIStrings.TryGetValue(Key, AValue)
  else
    Result:=False;
end;

procedure TTaurusTLS_UICtx.AddUIString(AString: TTaurusTLS_UIString);
begin
  if Assigned(AString) then
    FUIStrings.Add(AString.UIString, AString);
end;

procedure TTaurusTLS_UICtx.Clear;
begin
  FUIStrings.Clear;
end;

{ TTaurusTLSOsslUiMethod }

constructor TTaurusTLSOsslUiMethod.Create;
begin
  RegisterMethods;
end;

destructor TTaurusTLSOsslUiMethod.Destroy;
begin
  UnregisterMethods;
  inherited;
end;

class function TTaurusTLSOsslUiMethod.Opener(ui: PUI): TIdC_INT;
var
  lUiMeth: TTaurusTLSOsslUiMethod;
  lUiCtx: TTaurusTLS_UICtx;

begin
  Result:=0;
  try
    lUiCtx:=GetUiCtx(ui);
    if not Assigned(lUiCtx) then
      Exit;

    lUiMeth:=lUiCtx.UiMeth;
    lUiCtx.Clear;
    if Assigned(lUiMeth) then
      Result:=lUiMeth.DoPromptInit(lUiCtx).AsInt
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSOsslUiMethod.Writer(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lUiMeth: TTaurusTLSOsslUiMethod;
  lUiCtx: TTaurusTLS_UICtx;
  lStr: TTaurusTLS_UiString; // PALOFF 'Created and freed objects'

begin
  Result:=0;
  try
    lUiCtx:=GetUiCtx(ui);
    if not Assigned(lUiCtx) then
      Exit;

    lUiMeth:=lUiCtx.UiMeth;
    if Assigned(lUiMeth) then
    begin
      lStr:=NewUiString(uis, ui);
      lUiCtx.AddUIString(lStr);
      Result:=lUiMeth.DoPromptSetup(lUiCtx, lStr).AsInt;
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSOsslUiMethod.Flusher(ui: PUI): TIdC_INT;
var
  lUiMeth: TTaurusTLSOsslUiMethod;
  lUiCtx: TTaurusTLS_UICtx;

begin
  Result:=0;
  try
    lUiCtx:=GetUiCtx(ui);
    if not Assigned(lUiCtx) then
      Exit;

    lUiMeth:=lUiCtx.UiMeth;
    if Assigned(lUiMeth) then
      Result:=lUiMeth.DoPromptDisplay(lUiCtx).AsInt;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSOsslUiMethod.Reader(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lUiMeth: TTaurusTLSOsslUiMethod;
  lUiCtx: TTaurusTLS_UICtx;
  lStr, lTmp: TTaurusTLS_UiString; // PALOFF 'Created and freed objects'

begin
  Result:=0;
  lTmp:=nil;
  try
    try
      lUiCtx:=GetUiCtx(ui);
      if not Assigned(lUiCtx) then
        Exit;

      lUiMeth:=lUiCtx.UiMeth;
      if Assigned(lUiMeth) then
      begin
        if not lUiCtx.TryGetUIString(uis, lStr) then
        begin
          // if the string is not found in the saved strings for unknown reason
          // this should not happen ever
          lStr:=NewUiString(uis, ui);
          lTmp:=lStr;
        end;
        Result:=lUiMeth.DoPromptSetResult(lUiCtx, lStr).AsInt;
      end;
    except //PALOFF "Empty except-block"
      // We must not raise the exception to the OpenSSL stack
    end;
  finally
    lTmp.Free;
  end;
end;

class function TTaurusTLSOsslUiMethod.Closer(ui: PUI): TIdC_INT;
var
  lUiMeth: TTaurusTLSOsslUiMethod;
  lUiCtx: TTaurusTLS_UICtx;

begin
  Result:=0;
  lUiCtx:=nil;
  try
    try
      lUiCtx:=GetUiCtx(ui);
      if not Assigned(lUiCtx) then
        Exit;

      lUiMeth:=lUiCtx.UiMeth;
      if Assigned(lUiMeth) then
        Result:=lUiMeth.DoPromptRelease(lUiCtx).AsInt;
    except //PALOFF "Empty except-block"
      // We must not raise the exception to the OpenSSL stack
    end;
  finally
    if Assigned(lUiCtx) then
      lUiCtx.Clear;
  end;
end;

class function TTaurusTLSOsslUiMethod.GetUiCtx(AUi: PUI): TTaurusTLS_UICtx;
var
  lUiCtx: pointer;

begin
  lUiCtx:=UI_get0_user_data(AUi);
  Result:=TObject(lUiCtx) as TTaurusTLS_UICtx;
end;

procedure TTaurusTLSOsslUiMethod.RegisterMethods;
var
  lMeth: PUI_METHOD;

begin
  lMeth:=UI_create_method(
    PIdAnsiChar(RawByteString(Format(cMethNameFmt, [ClassName, Pointer(Self)]))));

  FUIMeth:=lMeth;
  if Assigned(lMeth) then
  try
    CheckOSSLMethError(UI_method_set_opener(lMeth, Opener), 0, 'Opener'); // Do not localize
    CheckOSSLMethError(UI_method_set_writer(lMeth, Writer), 0, 'Writer'); // Do not localize
    CheckOSSLMethError(UI_method_set_flusher(lMeth, Flusher), 0, 'Flusher'); // Do not localize
    CheckOSSLMethError(UI_method_set_reader(lMeth, Reader), 0, 'Reader'); // Do not localize
    CheckOSSLMethError(UI_method_set_closer(lMeth, Closer), 0, 'Closer'); // Do not localize
  except
    UnregisterMethods;
    Raise;
  end
  else
    ETaurusTLSRegisterMethod.RaiseWithMessage(RMSG_RegisterUIMeth_err)
end;

procedure TTaurusTLSOsslUiMethod.UnregisterMethods;
var
  lMeth: PUI_METHOD;

begin
  lMeth:=FUIMeth;
  if Assigned(lMeth) then
  try
    FUIMeth:=nil;
    UI_method_set_opener(lMeth, nil);
    UI_method_set_writer(lMeth, nil);
    UI_method_set_flusher(lMeth, nil);
    UI_method_set_reader(lMeth, nil);
    UI_method_set_closer(lMeth, nil);
  finally
    UI_destroy_method(lMeth);
  end;
end;

function TTaurusTLSOsslUiMethod.NewUI: PUI;
begin
  Result:=UI_new_method(FUIMeth);
  if not Assigned(Result) then
    ETaurusTLSCreateUi.RaiseWithMessage(RMSG_CreateUI_err);
end;

function TTaurusTLSOsslUiMethod.NewUICtx: TTaurusTLS_UICtx;
begin
  Result:=TTaurusTLS_UICtx.Create(Self);
end;

class function TTaurusTLSOsslUiMethod.NewUiString(
  uis: PUI_STRING; ui: PUI): TTaurusTLS_UiString;
begin
  Result:=TTaurusTLS_UiString.Create(uis, ui);
end;

function TTaurusTLSOsslUiMethod.DoPromptInit(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSOsslUiMethod.DoPromptSetup(AUiCtx: TTaurusTLS_UICtx;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSOsslUiMethod.DoPromptDisplay(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSOsslUiMethod.DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  if AString.&Type = UIT_PROMPT then
    AString.SetPassword(PIdAnsiChar(''));  // PALOFF 'Functions called as procedures'
  Result:=uirSuccess;
end;

function TTaurusTLSOsslUiMethod.DoPromptRelease(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

{ TTaurusTLS_DelegatedUI }

function TTaurusTLS_DelegatedUI.DoPromptInit(
  AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  if Assigned(FOnDisplayUI) then
    FOnDisplayUI(Self, AUiCtx, Result)
  else
    Result:=inherited;
end;

function TTaurusTLS_DelegatedUI.DoPromptSetup(AUiCtx: TTaurusTLS_UICtx;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  if Assigned(FOnSetupUI) then
    FOnSetupUI(Self, AString, Result)
  else
    Result:=inherited;
end;

function TTaurusTLS_DelegatedUI.DoPromptDisplay(
  AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  if Assigned(FOnDisplayUI) then
    FOnDisplayUI(Self, AUiCtx, Result)
  else
    Result:=inherited;
end;

function TTaurusTLS_DelegatedUI.DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  if Assigned(FOnResultUI) then
    FOnResultUI(Self, AString, Result)
  else
    Result:=inherited;
end;

function TTaurusTLS_DelegatedUI.DoPromptRelease(
  AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  if Assigned(FOnReleaseUI) then
    FOnReleaseUI(Self, Result)
  else
    Result:=inherited;
end;

end.
