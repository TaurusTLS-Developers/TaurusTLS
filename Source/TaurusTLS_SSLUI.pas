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
{$IFDEF DCC}
  AnsiStrings,
{$ENDIF}
  SysUtils,
  Classes,
  Types,
  SyncObjs,
  Generics.Collections,
  Generics.Defaults,
  IdCTypes,
  IdGlobal,
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSLoader,
{$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_ui;

type
  ETaurusTLSRegisterMethod = class(ETaurusTLSAPICryptoError);

  ///  <summary>
  ///  Defines result returned to the OpenSSL UI_METHOD callbacks.
  ///  </summary>
  TTaurusTLS_UiResult = (uirCanceled=0, uirError, uirSuccess);

  /// <summary> Implements class wrapper for
  /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
  /// routines
  /// </summary>
  TTaurusTLS_UiString = class
  private
    FString: PUI_STRING;
    FFlags: TIdC_Int;
    FType: UI_string_types;
    FUi: PUI;
    function GetIsBooleanPrompt: boolean;
    function GetIsDefaultPwd: boolean;
    function GetEcho: boolean;
    function GetIsPrompt: boolean;
    function GetResultMaxSize: TIdC_Int;
    function GetResultMinSize: TIdC_Int;
    function GetPrompt: PIdAnsiChar;
    function GetAction: PIdAnsiChar;
  public
    /// <summary> Creates <see cref="TTaurusTLS_UiString" /> instance.
    /// <param name="AString"> An value of type <see cref="PUI_STRING" /> passed by
    /// OpenSSL to the callback routine.
    /// </param>
    /// <param name="ui"> An value of type <see cref="PUI" /> passed by OpenSSL to the
    /// callback routine.
    /// </param>
    /// </summary>
    constructor Create(AString: PUI_STRING; ui: PUI);

    /// <summary>
    /// Wrapper for <c>UI_set_result_ex</c> routine. Sets the <b>password</b> value for
    /// the UI_STRING.
    /// <remarks>
    /// The <b>password</b> value can be set only for the string type <c>UIT_PROMPT</c>
    /// or <c>UIT_VERIFY</c>.
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    /// <param name="APass">
    /// A pointer to the buffer contaning array of Ansi characters.
    /// </param>
    /// <param name="ALen">
    /// Size of Ansi characters array.
    /// </param>
    /// <returns>
    /// <c>True</c> if operation succeed, <c>False</c> otherwise.
    /// </returns>
    /// </summary>
    function SetPassword(APass: PIdAnsiChar; ALen: TIdC_Int): boolean;
      overload;

    /// <summary> Wrapper for <c>UI_set_result_ex</c> routine. Sets the <b>password</b>
    /// value for the UI_STRING.
    /// <remarks> The <b>password</b> value can be set only for the string type
    /// <c>UIT_PROMPT</c> or <c>UIT_VERIFY</c>.
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    /// <param name="APass"> A pointer to the null-terminated array of Ansi characters.
    /// </param>
    /// <returns>
    /// <c>True</c> if operation succeed, <c>False</c> otherwise.
    /// </returns>
    /// </summary>
    function SetPassword(const APass: PIdAnsiChar): boolean;
      overload;

    /// <summary> Wrapper for <c>UI_set_result_ex</c> routine. Sets the <b>password</b>
    /// value for the UI_STRING.
    /// <remarks> The <b>password</b> value can be set only for the string type
    /// <c>UIT_PROMPT</c> or <c>UIT_VERIFY</c>.
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    /// <param name="APass"> A pointer to the null-terminated array of Ansi characters.
    /// </param>
    /// <returns>
    /// <c>True</c> if operation succeed, <c>False</c> otherwise.
    /// </returns>
    /// </summary>
    function SetPassword(const APass: RawByteString): boolean;
      overload;

    /// <summary>
    ///   <para>
    ///     Wrapper for <c>UI_set_result_ex</c> routine. Sets the <b>password
    ///     </b> value for the UI_STRING.
    ///   </para>
    ///   <para>
    ///     The <b>password</b> value can be set only for the string type <c>
    ///     UIT_PROMPT</c> or <c>UIT_VERIFY</c>. <see
    ///     href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    ///   </para>
    /// </summary>
    /// <param name="APass">
    ///   A <see cref="System.SysUtils.TBytes" /> array containing a <b>password
    ///   </b> value.
    /// </param>
    /// <returns>
    ///   <c>True</c> if operation succeed, <c>False</c> otherwise.
    /// </returns>
    function SetPassword(const APass: TBytes): boolean; overload;

    /// <summary> Returns UI_STRING type. See <see cref="UI_string_types" /> and <see
    /// href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </summary>
    property &Type: UI_string_types read FType;

    /// <summary> Wrapper for the <c>UI_get0_output_string</c>.
    /// </summary>
    /// <returns>
    /// <see cref="UI_STRING" /> value as a pointer to nill-terminated array of Ansi
    /// characters.
    /// </returns>
    property Prompt: PIdAnsiChar read GetPrompt;

    /// <summary> Wrapper for the <c>UI_get0_action_string</c>.
    /// </summary>
    /// <returns>
    /// <see cref="UI_STRING" /> value as a pointer to nill-terminated array of Ansi
    /// characters.
    /// </returns>
    property Action: PIdAnsiChar read GetAction;

    /// <summary>
    /// Returns <see cref="PUI">value</see> associated with a OpenSSL callback.
    /// </summary>
    property Ui: PUI read FUi;

    /// <summary> Returns <c>True</c> if <c>UI_INPUT_FLAG_ECHO</c> is set, otherwise -
    /// <c>False</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    property Echo: boolean read GetEcho;

    /// <summary> Returns <c>True</c> if <c>UI_INPUT_FLAG_DEFAULT_PWD</c> is set,
    /// otherwise - <c>False</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    property DefaultPwd: boolean read GetIsDefaultPwd;

    /// <summary>
    /// Returns <c>True</c> when the string <c>Type</c> is <c>UIT_BOOLEAN</c>, otherwise
    /// <c>False</c>
    /// </summary>
    /// <remarks>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    property IsBooleanPrompt: boolean read GetIsBooleanPrompt;

    /// <summary> Returns <c>True</c> when the string <c>Type</c> is <c>UIT_PROMPT</c>,
    /// <c>UIT_VERIFY</c>, or <c>UIT_BOOLEAN</c>, otherwise <c>False</c>
    /// </summary>
    /// <remarks>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    property IsPrompt: boolean read GetIsPrompt;

    /// <summary> Returns <c>True</c> when the string <c>Type</c> is <c>UIT_PROMPT</c> or
    /// <c>UIT_VERIFY</c>, otherwise <c>False</c>
    /// </summary>
    /// <remarks>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    property IsResult: boolean read GetIsPrompt;

    /// <summary>
    /// Return minimal requested password lenght excluding terminated <c>null</c>
    /// character.
    /// </summary>
    property ResultMinSize: TIdC_Int read GetResultMinSize;
    /// <summary>
    /// Return maximal requested password lenght excluding terminated <c>null</c>
    /// character.
    /// </summary>
    property ResultMaxSize: TIdC_Int read GetResultMaxSize;
  end;

  TTaurusTLSCustomOsslUi = class;

  /// <summary>
  /// Manages the state of a single OpenSSL prompt session, tracking associated UI strings.
  /// </summary>
  TTaurusTLS_UICtx = class
  protected type
    TUIStrings = TObjectList<TTaurusTLS_UIString>;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FUi: TTaurusTLSCustomOsslUi;
    FUIStrings: TUIStrings;
  protected
    /// <summary>
    /// Adds a <see cref="TTaurusTLS_UIString" /> to the context tracking list.
    /// </summary>
    /// <param name="AString"> The UI string to add. </param>
    procedure AddUIString(AString: TTaurusTLS_UIString);
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    /// Clears the list of tracked UI strings.
    /// </summary>
    procedure Clear; {$IFDEF USE_INLINE}inline;{$ENDIF}

    /// <summary>
    /// Gets the UI handler associated with this context.
    /// </summary>
    property Ui: TTaurusTLSCustomOsslUi read FUi;
  public
    /// <summary>
    /// Creates a new <see cref="TTaurusTLS_UICtx" /> associated with the provided UI handler.
    /// </summary>
    /// <param name="AUi"> The UI handler implementation. </param>
    constructor Create(AUi: TTaurusTLSCustomOsslUi);
    /// <summary>
    /// Releases resources used by the <see cref="TTaurusTLS_UICtx" />.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Gets the list of UI strings currently associated with this context.
    /// </summary>
    property UIStrings: TUIStrings read FUIStrings;
  end;

  /// <summary> The TTaurusTLSCustomOsslUi class implements the OpenSSL
  /// <c>UI_METHOD</c> callbacks wrapper.
  /// The application can use this class's descendants in OpenSSL routines like
  /// <c>OSSL_STORE_open" </c>, <c>OSSL_STORE_open_ex" </c>, <c>OSSL_STORE_attach" </c>, etc.
  /// </summary>
  TTaurusTLSCustomOsslUi = class abstract
  private const
    cMethStrFormat = '%s-%p';

  private var
    FUiMeth: PUI_METHOD;

  private
    class function Opener(ui: PUI): TIdC_INT; static; cdecl;
    class function Writer(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Flusher(ui: PUI): TIdC_INT; static; cdecl;
    class function Reader(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Closer(ui: PUI): TIdC_INT; static; cdecl;
    class function NewUiString(uis: PUI_STRING; ui: PUI): TTaurusTLS_UiString;
      static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function RegisterMethods: PUI_METHOD;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure UnregisterMethods;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    function GetIsRegistered: boolean; {$IFDEF USE_INLINE}inline;{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    procedure OnSSLLibEvent(AAction: TOpenSSLLoadAction);
{$ENDIF}

  protected
    /// <summary>
    /// Retrieves the <see cref="TTaurusTLS_UICtx" /> associated with the OpenSSL UI pointer.
    /// </summary>
    /// <param name="AUi"> The OpenSSL UI pointer. </param>
    /// <returns> The associated UI context. </returns>
    class function GetUiCtx(AUi: PUI): TTaurusTLS_UICtx; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    /// <summary>
    /// Called by OpenSSL to initialize a prompt session.
    /// <para>
    /// This method is called by the <c>Opener</c> OpenSSL callback.
    /// </para>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
    /// </summary>
    /// <param name="AUiCtx"> The current UI context. </param>
    /// <returns> A <see cref="TTaurusTLS_UiResult" /> indicating the outcome. </returns>
    function DoPromptInit(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; virtual;
    /// <summary>
    /// Called by OpenSSL to set up a specific UI string (prompt).
    /// <para>
    /// This method is called by the <c>Writer</c> OpenSSL callback.
    /// </para>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
    /// </summary>
    /// <param name="AUiCtx"> The current UI context. </param>
    /// <param name="AString"> The UI string being set up. </param>
    /// <returns> A <see cref="TTaurusTLS_UiResult" /> indicating the outcome. </returns>
    function DoPromptSetup(AUiCtx: TTaurusTLS_UICtx;
      AString: TTaurusTLS_UiString): TTaurusTLS_UiResult; virtual;
    /// <summary>
    /// Called by OpenSSL to display the prompt to the user.
    /// <para>
    /// This method is called by the <c>Flusher</c> OpenSSL callback.
    /// </para>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
    /// </summary>
    /// <param name="AUiCtx"> The current UI context. </param>
    /// <returns> A <see cref="TTaurusTLS_UiResult" /> indicating the outcome. </returns>
    function DoPromptDisplay(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; virtual;
    /// <summary>
    /// Called by OpenSSL to request the result (e.g., password) from the UI.
    /// <para>
    /// This method is called by the <c>Reader</c> OpenSSL callback.
    /// </para>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
    /// </summary>
    /// <param name="AUiCtx"> The current UI context. </param>
    /// <param name="AString"> The UI string for which the result is requested. </param>
    /// <returns> A <see cref="TTaurusTLS_UiResult" /> indicating the outcome. </returns>
    function DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx;
      AString: TTaurusTLS_UiString): TTaurusTLS_UiResult; virtual;
    /// <summary>
    /// Called by OpenSSL to release the prompt session.
    /// <para>
    /// This method is called by the <c>Closer</c> OpenSSL callback.
    /// </para>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
    /// </summary>
    /// <param name="AUiCtx"> The current UI context. </param>
    /// <returns> A <see cref="TTaurusTLS_UiResult" /> indicating the outcome. </returns>
    function DoPromptRelease(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult; virtual;
    /// <summary>
    /// Indicates whether the UI methods are currently registered with the OpenSSL library.
    /// </summary>
    property IsRegistered: boolean read GetIsRegistered;

  public
    /// <summary>
    /// Initializes a new instance of the <see cref="TTaurusTLSCustomOsslUi" /> class.
    /// </summary>
    constructor Create;
    /// <summary>
    /// Releases resources used by the <see cref="TTaurusTLSCustomOsslUi" />.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// Creates a new <see cref="TTaurusTLS_UICtx" /> for a prompt session.
    /// </summary>
    /// <returns> A new UI context instance. </returns>
    function NewUICtx: TTaurusTLS_UICtx;

    property UiMethod: PUI_METHOD read FUIMeth;
  end;

  /// <summary>
  /// Provides a simple UI implementation that automatically supplies a pre-configured password.
  /// </summary>
  TTaurusTLS_SimplePasswordUI = class(TTaurusTLSCustomOsslUi)
  strict private
    FPass: RawByteString;
  protected
    /// <summary>
    /// Provides the pre-configured password as the result for the prompt.
    /// <para>
    /// This method is called by the <c>Reader</c> OpenSSL callback.
    /// </para>
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
    /// </summary>
    /// <param name="AUiCtx"> The current UI context. </param>
    /// <param name="AString"> The UI string for which the result is requested. </param>
    /// <returns> A <see cref="TTaurusTLS_UiResult" /> indicating whether the password was set successfully. </returns>
    function DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx;
      AString: TTaurusTLS_UiString): TTaurusTLS_UiResult; override;
  public
    /// <summary>
    /// Initializes a new instance of the <see cref="TTaurusTLS_SimplePasswordUI" /> class with a specific password.
    /// </summary>
    /// <param name="APass"> The password to be provided to OpenSSL prompts. </param>
    constructor Create(const APass: RawByteString);
  end;

implementation

uses
  TaurusTLS_ResourceStrings;

procedure CheckOSSLMethError(Result: TIdC_INT; SuccessCode: TIdC_INT;
  const AMethName: string); overload;
begin
  if Result <> SuccessCode then
    ETaurusTLSAPICryptoError.RaiseWithMessageFmt(
      RMSG_RegisterUIMeth_err, [AMethName]);
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
  Result:=SetPassword(PIdAnsiChar(APass));
end;

function TTaurusTLS_UiString.SetPassword(const APass: TBytes): boolean;
var
  lLen: TIdC_Long;
  var lPass: PAnsiChar;

begin
  Result:=True;
  lLen:=Length(APass);
  if lLen > 0 then
    lPass:=PAnsiChar(@APass[0])
  else
    lPass:=nil;
  SetPassword(lPass, lLen); // PALOFF 'Functions called as procedures'
end;

function TTaurusTLS_UiString.SetPassword(const APass: PIdAnsiChar): boolean;
begin
  Result:=SetPassword(APass, Length(APass));
end;

{ TTaurusTLS_UICtx }

constructor TTaurusTLS_UICtx.Create(AUi: TTaurusTLSCustomOsslUi);
begin
  Assert(Assigned(AUi), 'Parameter ''AUi'' must not be ''nil''.'); // Do not localize
  FUi:=AUi;
  FUIStrings:=TUIStrings.Create(True);
end;

destructor TTaurusTLS_UICtx.Destroy;
begin
  FreeAndNil(FUIStrings);
  inherited;
end;

procedure TTaurusTLS_UICtx.AddUIString(AString: TTaurusTLS_UIString);
begin
  if Assigned(AString) then
    FUIStrings.Add(AString);
end;

procedure TTaurusTLS_UICtx.Clear;
begin
  FUIStrings.Clear;
end;

{ TTaurusTLSCustomOsslUi }

constructor TTaurusTLSCustomOsslUi.Create;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  lLoader: IOpenSSLLoader;

begin
  lLoader:=GetOpenSSLLoader;
  lLoader.RegisterLoaderMethod(OnSSLLibEvent);
end;
{$ELSE}
begin
  RegisterMethods;  // PALOFF 'Functions called as procedures'
end;
{$ENDIF}

destructor TTaurusTLSCustomOsslUi.Destroy;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  lLoader: IOpenSSLLoader;

begin
  lLoader:=GetOpenSSLLoader;
  lLoader.UnRegisterLoaderMethod(OnSSLLibEvent);
  inherited;
end;
{$ELSE}
begin
  UnregisterMethods;  // PALOFF 'Functions called as procedures'
  inherited;
end;
{$ENDIF}

class function TTaurusTLSCustomOsslUi.Opener(ui: PUI): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;
  lUiCtx: TTaurusTLS_UICtx;

begin
  Result:=0;
  try
    lUiCtx:=GetUiCtx(ui);
    if not Assigned(lUiCtx) then
      Exit;

    lUi:=lUiCtx.Ui;
    lUiCtx.Clear;
    if Assigned(lUi) then
    begin
      Result:=Pred(Ord(lUi.DoPromptInit(lUiCtx)));
      if Result < 0 then
        Result:=0;
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSCustomOsslUi.Writer(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;
  lUiCtx: TTaurusTLS_UICtx;
  lStr: TTaurusTLS_UiString; // PALOFF 'Created and freed objects'

begin
  Result:=0;
  lStr:=nil;
  try
    try
      lUiCtx:=GetUiCtx(ui);
      if not Assigned(lUiCtx) then
        Exit;

      lUi:=lUiCtx.Ui;
      if Assigned(lUi) then
      begin
        lStr:=NewUiString(uis, ui);
        lUiCtx.AddUIString(lStr);
        Result:=Pred(Ord(lUi.DoPromptSetup(lUiCtx, lStr)));
        if Result < 0 then
          Result:=0;
      end;
    except //PALOFF "Empty except-block"
      // We must not raise the exception to the OpenSSL stack
    end;
  finally
    lStr.Free;
  end;
end;

class function TTaurusTLSCustomOsslUi.Flusher(ui: PUI): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;
  lUiCtx: TTaurusTLS_UICtx;

begin
  Result:=0;
  try
    lUiCtx:=GetUiCtx(ui);
    if not Assigned(lUiCtx) then
      Exit;

    lUi:=lUiCtx.Ui;
    if Assigned(lUi) then
    begin
      Result:=Pred(Ord(lUi.DoPromptDisplay(lUiCtx)));
      if Result < 0 then
        Result:=0;
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSCustomOsslUi.Reader(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;
  lUiCtx: TTaurusTLS_UICtx;
  lStr: TTaurusTLS_UiString; // PALOFF 'Created and freed objects'

begin
  Result:=0;
  lStr:=nil;
  try
    try
      lUiCtx:=GetUiCtx(ui);
      if not Assigned(lUiCtx) then
        Exit;

      lUi:=lUiCtx.Ui;
      if Assigned(lUi) then
      begin
        lStr:=NewUiString(uis, ui);
        if Assigned(lUi) then
          Result:=Pred(Ord(lUi.DoPromptSetResult(lUiCtx, lStr)));
      end;
    except //PALOFF "Empty except-block"
      // We must not raise the exception to the OpenSSL stack
    end;
  finally
    lStr.Free;
  end;
end;

class function TTaurusTLSCustomOsslUi.Closer(ui: PUI): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;
  lUiCtx: TTaurusTLS_UICtx;

begin
  Result:=0;
  lUiCtx:=nil;
  try
    try
      lUiCtx:=GetUiCtx(ui);
      if not Assigned(lUiCtx) then
        Exit;

      lUi:=lUiCtx.Ui;
      if Assigned(lUi) then
      begin
        Result:=Pred(Ord(lUi.DoPromptRelease(lUiCtx)));
        if Result < 0 then
          Result:=0;
      end;
    except //PALOFF "Empty except-block"
      // We must not raise the exception to the OpenSSL stack
    end;
  finally
    if Assigned(lUiCtx) then
      lUiCtx.Clear;
  end;
end;

function TTaurusTLSCustomOsslUi.GetIsRegistered: boolean;
begin
  Result:=Assigned(FUIMeth);
end;

class function TTaurusTLSCustomOsslUi.GetUiCtx(AUi: PUI): TTaurusTLS_UICtx;
var
  lUiCtx: pointer;

begin
  lUiCtx:=UI_get0_user_data(AUi);
  Result:=TObject(lUiCtx) as TTaurusTLS_UICtx;
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TTaurusTLSCustomOsslUi.OnSSLLibEvent(AAction: TOpenSSLLoadAction);
begin
  case AAction of
    osaLoad:
      if not IsRegistered then
        RegisterMethods;
    osaUnload:
      if IsRegistered then
        UnregisterMethods;
  end;
end;
{$ENDIF}

function TTaurusTLSCustomOsslUi.RegisterMethods: PUI_METHOD;
begin
  FUIMeth:=nil;
  Result:=UI_create_method(
    PIdAnsiChar(RawByteString(Format(cMethStrFormat, [ClassName, Self]))));
  FUIMeth:=Result;
  if Assigned(Result) then
  try
    CheckOSSLMethError(UI_method_set_opener(Result, Opener), 0, 'Opener'); // Do not localize
    CheckOSSLMethError(UI_method_set_writer(Result, Writer), 0, 'Writer'); // Do not localize
    CheckOSSLMethError(UI_method_set_flusher(Result, Flusher), 0, 'Flusher'); // Do not localize
    CheckOSSLMethError(UI_method_set_reader(Result, Reader), 0, 'Reader'); // Do not localize
    CheckOSSLMethError(UI_method_set_closer(Result, Closer), 0, 'Closer'); // Do not localize
    FUIMeth:=Result;
  except
    UnregisterMethods;
    Raise;
  end;
end;

procedure TTaurusTLSCustomOsslUi.UnregisterMethods;
var
  lMeth: PUI_METHOD;

begin
  lMeth:=FUIMeth;
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

function TTaurusTLSCustomOsslUi.NewUICtx: TTaurusTLS_UICtx;
begin
  Result:=TTaurusTLS_UICtx.Create(Self);
end;

class function TTaurusTLSCustomOsslUi.NewUiString(
  uis: PUI_STRING; ui: PUI): TTaurusTLS_UiString;
begin
  Result:=TTaurusTLS_UiString.Create(uis, ui);
end;

function TTaurusTLSCustomOsslUi.DoPromptInit(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoPromptSetup(AUiCtx: TTaurusTLS_UICtx;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoPromptDisplay(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  if AString.&Type = UIT_PROMPT then
    AString.SetPassword(PIdAnsiChar(''));  // PALOFF 'Functions called as procedures'
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoPromptRelease(AUiCtx: TTaurusTLS_UICtx): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

{ TTaurusTLS_SimplePasswordUI }

constructor TTaurusTLS_SimplePasswordUI.Create(const APass: RawByteString);
begin
  FPass:=APass;
  inherited Create;
end;

function TTaurusTLS_SimplePasswordUI.DoPromptSetResult(AUiCtx: TTaurusTLS_UICtx;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  if (AString.&Type <> UIT_PROMPT) or
    AString.SetPassword(FPass) then
    Result:=uirSuccess
  else
    Result:=uirError;
end;

end.
