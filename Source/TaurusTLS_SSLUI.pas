{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I TaurusTLSCompilerDefines.inc}

/// <summary>
///   This unit implements <see
///   href="https://docs.openssl.org/3.0/man7/ossl_store/#ui_method-and-pass-phrases">
///   OpenSSL UI_METHOD</see> wrappers that allows to implement unified Passphrase
///   management.
/// </summary>
unit TaurusTLS_SSLUI;

interface

uses
  AnsiStrings,
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
    function GetValue: PIdAnsiChar;
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
    function SetPassword(APass: PIdAnsiChar): boolean;
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
    function SetPassword(APass: RawByteString): boolean;
      overload;

    /// <summary> Wrapper for <c>UI_set_result_ex</c> routine. Sets the <b>password</b>
    /// value for the UI_STRING.
    /// <remarks> The <b>password</b> value can be set only for the string type
    /// <c>UIT_PROMPT</c> or <c>UIT_VERIFY</c>.
    /// <see href="https://docs.openssl.org/master/man3/UI_STRING/#synopsis" />
    /// </remarks>
    /// </summary>
    /// <param name="APass"> A <see cref="TBytes" /> array containing a <b>password</b>
    /// value.
    /// </param>
    /// <returns>
    /// <c>True</c> if operation succeed, <c>False</c> otherwise.
    /// </returns>
    function SetPassword(APass: TBytes): boolean; overload;

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
    property Value: PIdAnsiChar read GetValue;

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

  /// <summary> The <c>TTaurusTLS_DefaultUI</c> class implements OpenSSL
  /// <see href="https://docs.openssl.org/master/man3/UI_create_method/">UI_METHOD</see> callbacks.
  /// It register itself as a <b>Default</b> <see cref="UI_METHOD" />  and intercepts
  ///  all OpenSSL requests for <b>password</b> or <b>passphrases</b> and requests
  /// the instance assigned to <see cref="UiHandler" /> to handle them.
  /// </summary>
  /// <remarks> To handle <b>password</b> or <b>passphrases</b> requests application
  /// must implement
  /// <see cref="TTaurusTLS_DefaultUI.TCustomUiHandler" /> class descendant(s).
  /// </remarks>
  TTaurusTLS_DefaultUI = class
  public type

    /// <summary> A base <b>abstract</b> class Instance to handle OpenSSL requests for
    /// <b>password</b> or <b>passphrase</b>.
    /// </summary>
    /// <remarks>
    /// <see cref="TTaurusTLS_DefaultUI" /> calls the <see cref="TCustomUiHandler" />
    /// descendant's methods in  the order:
    /// <list type="number">
    /// <item>
    /// <term>DoPrepare</term>
    /// <description> Method needs to initialize resources required for request the
    /// <b>password</b> or <b>passphrase</b>, and associate it with the <c>ui</c>
    /// parameter value. For example to create password request dialog instance in GUI
    /// application.
    /// </description>
    /// </item>
    /// <item>
    /// <term>DoSetString</term>
    /// <description>This method called to provide string information needs to be
    /// displayed for the end-user. It usually <b>password</b> prompt. However, it
    /// could be a <b>confirmation</c>,
    /// <b>error</b> or <b>informational</b> message(s).
    /// <see href="https://docs.openssl.
    /// org/master/man3/UI_create_method/#description">See</see> for more details.
    /// <b>Note:</b> this method can be called multiple times per one UI call.
    /// </description>
    /// </item>
    /// <item>
    /// <term>DoDisplay</term>
    /// <description>This method is called to display a <b>password</b> or
    /// <b>passphrase</b> prompt, <b>error</b> message, etc.
    /// </description>
    /// </item>
    /// <item>
    /// <term>DoCheckString</term>
    /// <description>The application should provide <b>password</b> or
    /// <b>passphrase</b> for string with type
    /// <c>UIT_PROMPT</c> or <c>UIT_VERIFY</c> using <see cref="TTaurusTLS_UiString.
    /// SetPassword" /> method.
    /// <b>Note:</b> this method can be called multiple times per one UI call.
    /// </description>
    /// </item>
    /// <item>
    /// <term>DoRelease</term>
    /// <description> Method called to deinitialize the resources prepared by the
    /// <see cref="TTaurusTLS_DefaultUI.DoPrepare" /> method associated with the
    /// <c>ui</c> parameter value.
    /// </description>
    /// </item>
    /// </list>
    /// </remarks>
    /// <remarks> Please note: the instance can be activated from any thread. A
    /// descendant(s) implementing interactive request handling must serialize its
    /// activation from different threads. For example, using
    /// <see cref="TThread.Synchronize" /> for GUI application(s), or using
    /// synchronization primitives in console application(s).
    /// </remarks>
    TCustomUiHandler = class abstract
    protected

      /// <summary>
      /// <see cref="TTaurusTLS_DefaultUI" /> calls this method to request application to
      /// initialize resources needed for requesting <b>password</b> or <b>passphrase</b>
      /// and associate them with the <c>ui</c> parameter value.
      /// </summary>
      /// <param name="ui"><see href="https://docs.openssl.org/master/man3/UI_new/" />
      /// </param>
      function DoPrepare(ui: PUI): TTaurusTLS_UiResult; virtual;

      /// <summary>
      /// <see cref="TTaurusTLS_DefaultUI" /> calls this method to request application to
      /// add specific type of <c>UI_STRING</c> to the user interface.
      /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
      /// </summary>
      /// <remarks> This method can be called multiple times.
      /// </remarks>
      /// <param name="ui"><see href="https://docs.openssl.org/master/man3/UI_new/" />
      /// </param>
      /// <param name="AString"> <see cref="TTaurusTLS_UiString" />
      /// </param>
      function DoSetString(ui: PUI; AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
        virtual;

      /// <summary>
      /// <see cref="TTaurusTLS_DefaultUI" /> calls this method to request application to
      /// request
      /// a <b>password</b> or <b>passphrase</b> request user interface.
      /// </summary>
      /// <param name="ui"><see href="https://docs.openssl.org/master/man3/UI_new/" />
      /// </param>
      function DoDisplay(ui: PUI): TTaurusTLS_UiResult; virtual;

      /// <summary>
      /// <see cref="TTaurusTLS_DefaultUI" /> calls this method to provide
      /// <b>password</b> or
      /// <b>passphrase</b> for string with type <c>UIT_PROMPT</c> or <c>UIT_VERIFY</c>
      /// using <see cref="TTaurusTLS_UiString. SetPassword" /> method.
      /// <see href="https://docs.openssl.org/master/man3/UI_STRING/" />
      /// </summary>
      /// <remarks> This method can be called multiple times.
      /// </remarks>
      /// <param name="ui"><see href="https://docs.openssl.org/master/man3/UI_new/" />
      /// </param>
      /// <param name="AString"> <see cref="TTaurusTLS_UiString" />
      /// </param>
      function DoCheckString(ui: PUI; AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
        virtual;

      /// <summary>
      /// <see cref="TTaurusTLS_DefaultUI" /> calls this method to request application
      /// releasing resources allocated in
      /// <see cref="DoPrepare" /> method and associated with the <c>ui</c> parameter
      /// value.
      /// </summary>
      /// <param name="ui"><see href="https://docs.openssl.org/master/man3/UI_new/" />
      /// </param>
      function DoRelease(ui: PUI): TTaurusTLS_UiResult; virtual;
    end;

    /// <inherited />
    /// <summary>
    /// This class implements serialization using <c>Critical Section</c> locking
    /// primitive.
    /// All callbacks are serialized per one <c>ui</c> parameter value.
    /// </summary>
    TSyncHandler = class abstract(TCustomUiHandler)
    strict private
      FLock: TIdCriticalSection;
    protected

      /// <inherited />
      /// <summary> This method overrides
      /// <see cref="TTaurusTLS_DefaultUI.TCustomUiHandler.DoPrepare" />. It enters to the
      /// <c>Critical Section</c> to propect other threads to interrupt OpenSSL <c>UI</c>
      /// processing.
      /// </summary>
      function DoPrepare(ui: PUI): TTaurusTLS_UiResult; override;
      /// <inherited />
      /// <summary> This method overrides
      /// <see cref="TTaurusTLS_DefaultUI.TCustomUiHandler.DoRelease" />.
      /// It exit from the <c>Critical Section</c> and allow other thread(s) to process
      /// OpenSSL <c>UI</c>.
      /// </summary>
      function DoRelease(ui: PUI): TTaurusTLS_UiResult; override;

      procedure Lock; {$IFDEF USE_INLINE}inline;{$ENDIF}
      procedure Unlock; {$IFDEF USE_INLINE}inline;{$ENDIF}
    public
      constructor Create;
      destructor Destroy; override;
    end;

  private const
    cUiMethodName: AnsiString = 'TaurusTLS Default UI Method';

  private class var
    FUiMethod: PUI_METHOD;
    FPrevUiMethod: PUI_METHOD;
    FHandler: TCustomUiHandler;
    FLock: TIdCriticalSection;
    FRegistered: boolean;

  private
    class function Opener(ui: PUI): TIdC_INT; static; cdecl;
    class function Writer(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Flusher(ui: PUI): TIdC_INT; static; cdecl;
    class function Reader(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Closer(ui: PUI): TIdC_INT; static; cdecl;
    class function RegisterMethod: PUI_METHOD; static;
    class procedure UnregisterMethod; static;
    class procedure SetHandler(AHandler: TCustomUIHandler); static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
  protected
    class procedure Lock; {$IFDEF USE_INLINE}inline;{$ENDIF}
    class procedure Unlock; {$IFDEF USE_INLINE}inline;{$ENDIF}

    /// <summary>
    /// Returns a <see cref="AnsiString" /> to be used in
    /// <see cref="UI_create_method" /> routine.
    /// <see href="https://docs.openssl.org/master/man3/UI_create_method/#synopsis" />
    /// for more details.
    /// </summary>
    class function GetUiMethodName: AnsiString; virtual;
  public
    /// <inherited />
    class constructor Create;

    /// <inherited />
    class destructor Destroy;

    /// <summary> Sets or gets <see cref="TTaurusTLS_DefaultUI.TCustomUiHandler" />
    /// instance that proceses
    /// <c>OpenSSL</c> <b>password</b> or <b>passphrase</b> requests.
    /// </summary>
    class property UiHandler: TCustomUiHandler read FHandler write SetHandler;

    /// <summary>
    /// Returns <c>True</c> when <see cref="TCustomUiHandler" /> registered as an
    /// <c>OpenSSL</c> <c>Default UI_METHOD</c>, otherwise returns <c>False</c>.
    /// </summary>
    class property Registered: boolean read FRegistered;
  end;

  /// <summary> The TTaurusTLSCustomOsslUi class implements the OpenSSL
  /// <c>UI_METHOD</c> callbacks.
  /// The application can use this class's descendants in OpenSSL routines like
  /// <c>OSSL_STORE_open" </c>, <c>OSSL_STORE_open_ex" </c>, <c>OSSL_STORE_attach" </c>, etc.
  /// <para>
  ///
  /// </para>
  /// </summary>
  TTaurusTLSCustomOsslUi = class abstract
  private const
    cUiMethodName: AnsiString = 'TaurusTLS UI Method';

  private class var
    FUiMeth: PUI_METHOD;

  strict private
    FUi: PUI;
    procedure SetUi(ui: PUI); {$IFDEF USE_INLINE}inline;{$ENDIF}

  private
    class function Opener(ui: PUI): TIdC_INT; static; cdecl;
    class function Writer(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Flusher(ui: PUI): TIdC_INT; static; cdecl;
    class function Reader(ui: PUI; uis: PUI_STRING): TIdC_INT; static; cdecl;
    class function Closer(ui: PUI): TIdC_INT; static; cdecl;
    class function RegisterMethods: PUI_METHOD; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    class function GetUiMethod: PUI_METHOD; static;
      {$IFDEF USE_INLINE}inline;{$ENDIF}
    class function NewUiString(uis: PUI_STRING; ui: PUI): TTaurusTLS_UiString;
      static; {$IFDEF USE_INLINE}inline;{$ENDIF}
    class function GetUi(ui: PUI): TTaurusTLSCustomOsslUi;
  protected

    function DoPrepare: TTaurusTLS_UiResult; virtual;
    function DoSetString(AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
      virtual;
    function DoDisplay: TTaurusTLS_UiResult; virtual;
    function DoCheckString(AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
      virtual;
    function DoRelease: TTaurusTLS_UiResult; virtual;

    property Ui: PUi read FUi;
  public
    class destructor Destroy;

    class property UiMethod: PUI_METHOD read GetUiMethod;
  end;

  TTaurusTLS_SimplePasswordUI = class(TTaurusTLSCustomOsslUi)
  strict private
    FPass: RawByteString;
  protected
    function DoCheckString(AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
      override;
  public
    constructor Create(APass: RawByteString);
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

function TTaurusTLS_UiString.GetValue: PIdAnsiChar;
begin
  Result:=UI_get0_output_string(FString);
end;

function TTaurusTLS_UiString.SetPassword(APass: PIdAnsiChar;
  ALen: TIdC_Int): boolean;
begin
  Result:=IsResult and Assigned(Ui);
  if Result then
    Result:=UI_set_result_ex(Ui, FString, APass, ALen) = 0;
end;

function TTaurusTLS_UiString.SetPassword(APass: RawByteString): boolean;
begin
  Result:=SetPassword(PIdAnsiChar(APass));
end;

function TTaurusTLS_UiString.SetPassword(APass: TBytes): boolean;
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
  SetPassword(lPass, lLen);
end;

function TTaurusTLS_UiString.SetPassword(APass: PIdAnsiChar): boolean;
begin
  Result:=SetPassword(APass, Length(APass));
end;

{ TTaurusTLS_DefaultUI.TCustomUiHandler }

function TTaurusTLS_DefaultUI.TCustomUiHandler.DoPrepare(
  ui: PUI): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLS_DefaultUI.TCustomUiHandler.DoSetString(ui: PUI;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLS_DefaultUI.TCustomUiHandler.DoDisplay(
  ui: PUI): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLS_DefaultUI.TCustomUiHandler.DoCheckString(ui: PUI;
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLS_DefaultUI.TCustomUiHandler.DoRelease(
  ui: PUI): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

{ TTaurusTLS_DefaultUI.TSyncHandler }

constructor TTaurusTLS_DefaultUI.TSyncHandler.Create;
begin
  inherited;
  FLock:=TIdCriticalSection.Create;
end;

destructor TTaurusTLS_DefaultUI.TSyncHandler.Destroy;
begin
  FreeAndNil(FLock);
  inherited;
end;

function TTaurusTLS_DefaultUI.TSyncHandler.DoPrepare(
  ui: PUI): TTaurusTLS_UiResult;
begin
  Lock;
  Result:=uirSuccess;
end;

function TTaurusTLS_DefaultUI.TSyncHandler.DoRelease(
  ui: PUI): TTaurusTLS_UiResult;
begin
  Unlock;
  Result:=uirSuccess;
end;

procedure TTaurusTLS_DefaultUI.TSyncHandler.Lock;
begin
  FLock.Enter;
end;

procedure TTaurusTLS_DefaultUI.TSyncHandler.Unlock;
begin
  FLock.Release;
end;

{ TTaurusTLS_DefaultUI }

class constructor TTaurusTLS_DefaultUI.Create;
begin
  FLock:=TIdCriticalSection.Create;
end;

class destructor TTaurusTLS_DefaultUI.Destroy;
begin
  UiHandler:=nil;
  FreeAndNil(FLock);
end;

class function TTaurusTLS_DefaultUI.Opener(ui: PUI): TIdC_INT;
begin
  Result:=0;
  if not Assigned(FHandler) then
    Exit;
  try
    Result:=Pred(Ord(FHandler.DoPrepare(ui)));
    if Result < 0 then
      Result:=0;
  except
    // Do nothing for now
    // Need to think about custom OpenSSL Error codes and messages
  end;
end;

class function TTaurusTLS_DefaultUI.Writer(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lStr: TTaurusTLS_UiString;

begin
  Result:=0;
  if not Assigned(FHandler) then
    Exit;
  lStr:=nil;
  try
    lStr:=TTaurusTLS_UiString.Create(uis, ui);
    try
      Result:=Pred(Ord(FHandler.DoSetString(ui, lStr)));
      if Result < 0 then
        Result:=0;
    except
      // Do nothing for now
      // Need to think about custom OpenSSL Error codes and messages
    end;
  finally
    lStr.Free;
  end;
end;

class function TTaurusTLS_DefaultUI.Flusher(ui: PUI): TIdC_INT;
begin
  Result:=0;
  if not Assigned(FHandler) then
    Exit;
  try
    Result:=Pred(Ord(FHandler.DoPrepare(ui)));
  except
    // Do nothing for now
    // Need to think about custom OpenSSL Error codes and messages
  end;
end;

class function TTaurusTLS_DefaultUI.Reader(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lStr: TTaurusTLS_UiString;

begin
  Result:=0;
  if not Assigned(FHandler) then
    Exit;
  lStr:=nil;
  try
    lStr:=TTaurusTLS_UiString.Create(uis, ui);
    try
      Result:=Pred(Ord(FHandler.DoCheckString(ui, lStr)));
    except
      // Do nothing for now
      // Need to think about custom OpenSSL Error codes and messages
    end;
  finally
    lStr.Free;
  end;
end;

class function TTaurusTLS_DefaultUI.Closer(ui: PUI): TIdC_INT;
begin
  Result:=0;
  if not Assigned(FHandler) then
    Exit;
  try
    Result:=Pred(Ord(FHandler.DoPrepare(ui)));
    if Result < 0 then
      Result:=0;
  except
    // Do nothing for now
    // Need to think about custom OpenSSL Error codes and messages
  end;
end;

class function TTaurusTLS_DefaultUI.GetUiMethodName: AnsiString;
begin
  Result:=cUiMethodName;
end;

class procedure TTaurusTLS_DefaultUI.SetHandler(AHandler: TCustomUIHandler);
var
  lHandler: TCustomUIHandler;
begin
  if FHandler = AHandler then
    Exit;
  Lock;
  try
    lHandler:=FHandler;
    if not Assigned(AHandler) then
      UnregisterMethod
    else if not Registered then
      RegisterMethod;
    lHandler.Free;
    FHandler:=AHandler;
  finally
    UnLock;
  end;
end;

class function TTaurusTLS_DefaultUI.RegisterMethod: PUI_METHOD;
begin
  Result:=UI_create_method(PAnsiChar(GetUiMethodName));
  if Assigned(Result) then
  try
    FPrevUiMethod:=UI_get_default_method;

    CheckOSSLMethError(UI_method_set_opener(Result, Opener), 0, 'Opener'); // Do not localize
    CheckOSSLMethError(UI_method_set_writer(Result, Writer), 0, 'Writer'); // Do not localize
    CheckOSSLMethError(UI_method_set_flusher(Result, Flusher), 0, 'Flusher'); // Do not localize
    CheckOSSLMethError(UI_method_set_reader(Result, Reader), 0, 'Reader'); // Do not localize
    CheckOSSLMethError(UI_method_set_closer(Result, Closer), 0, 'Closer'); // Do not localize
    UI_set_default_method(Result);
    FUiMethod:=Result;
  except
    UnregisterMethod;
    Raise;
  end;
end;

class procedure TTaurusTLS_DefaultUI.UnregisterMethod;
begin
  UI_set_default_method(FPrevUiMethod);
  UI_destroy_method(FUiMethod);
  FRegistered:=False;
end;

class procedure TTaurusTLS_DefaultUI.Lock;
begin
  FLock.Enter;
end;

class procedure TTaurusTLS_DefaultUI.Unlock;
begin
  FLock.Leave;
end;

{ TTaurusTLSCustomOsslUi }

class destructor TTaurusTLSCustomOsslUi.Destroy;
begin
  if Assigned(FUiMeth) then
    UI_destroy_method(FUiMeth);
end;

class function TTaurusTLSCustomOsslUi.Opener(ui: PUI): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;

begin
  Result:=0;
  try
    lUi:=GetUi(ui);
    if Assigned(lUi) then
    begin
      lUi.SetUi(ui);
      Result:=Pred(Ord(lUi.DoPrepare));
      if Result < 0 then
        Result:=0;
    end;
  except
    // Do nothing for now
    // Need to think about custom OpenSSL Error codes and messages
  end;
end;

class function TTaurusTLSCustomOsslUi.Writer(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;
  lStr: TTaurusTLS_UiString;

begin
  Result:=0;
  lStr:=nil;
  try
    try
      lUi:=GetUi(ui);
      if Assigned(lUi) then
      begin
        lStr:=NewUiString(uis, ui);
        if Assigned(lUi) then
          Result:=Pred(Ord(lUi.DoSetString(lStr)));
        if Result < 0 then
          Result:=0;
      end;
    except
      // Do nothing for now
      // Need to think about custom OpenSSL Error codes and messages
    end;
  finally
    lStr.Free;
  end;
end;

class function TTaurusTLSCustomOsslUi.Flusher(ui: PUI): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;

begin
  Result:=0;
  try
    lUi:=GetUi(ui);
    if Assigned(lUi) then
    begin
      Result:=Pred(Ord(lUi.DoDisplay));
      if Result < 0 then
        Result:=0;
    end;
  except
    // Do nothing for now
    // Need to think about custom OpenSSL Error codes and messages
  end;
end;

class function TTaurusTLSCustomOsslUi.Reader(ui: PUI;
  uis: PUI_STRING): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;
  lStr: TTaurusTLS_UiString;

begin
  Result:=0;
  lStr:=nil;
  try
    try
      lUi:=GetUi(ui);
      if Assigned(lUi) then
      begin
        lStr:=NewUiString(uis, ui);
        if Assigned(lUi) then
          Result:=Pred(Ord(lUi.DoCheckString(lStr)));
      end;
    except
      // Do nothing for now
      // Need to think about custom OpenSSL Error codes and messages
    end;
  finally
    lStr.Free;
  end;
end;

class function TTaurusTLSCustomOsslUi.Closer(ui: PUI): TIdC_INT;
var
  lUi: TTaurusTLSCustomOsslUi;

begin
  Result:=0;
  try
    lUi:=nil;
    try
      lUi:=GetUi(ui);
      if Assigned(lUi) then
      begin
        Result:=Pred(Ord(lUi.DoRelease));
        if Result < 0 then
          Result:=0;
      end;
    finally
      if Assigned(lUi) then
        lUi.SetUi(nil);
    end;
  except
    // Do nothing for now
    // Need to think about custom OpenSSL Error codes and messages
  end;
end;

class function TTaurusTLSCustomOsslUi.RegisterMethods: PUI_METHOD;
begin
  Result:=UI_create_method(PAnsiChar(cUiMethodName));
  if Assigned(Result) then
  try
    CheckOSSLMethError(UI_method_set_opener(Result, Opener), 0, 'Opener'); // Do not localize
    CheckOSSLMethError(UI_method_set_writer(Result, Writer), 0, 'Writer'); // Do not localize
    CheckOSSLMethError(UI_method_set_flusher(Result, Flusher), 0, 'Flusher'); // Do not localize
    CheckOSSLMethError(UI_method_set_reader(Result, Reader), 0, 'Reader'); // Do not localize
    CheckOSSLMethError(UI_method_set_closer(Result, Closer), 0, 'Closer'); // Do not localize
  except
    UI_destroy_method(Result);
    Raise;
  end;
end;

procedure TTaurusTLSCustomOsslUi.SetUi(ui: PUI);
begin
  if FUi <> ui then
    FUi:=ui;
end;

class function TTaurusTLSCustomOsslUi.GetUi(
  ui: PUI): TTaurusTLSCustomOsslUi;
begin
  Result:=UI_get0_user_data(ui);
  Result.SetUi(ui);
end;

class function TTaurusTLSCustomOsslUi.GetUiMethod: PUI_METHOD;
begin
  if not Assigned(FUiMeth) then
  begin
    Result:=RegisterMethods;
    if Assigned(Result) then
    begin
      {$IFDEF DCC}
      if TInterlocked.CompareExchange(Pointer(FUiMeth), Result, nil) <> nil then
      {$ELSE}
      if InterlockedCompareExchange(Pointer(FUiMeth), Result, nil)  <> nil then
      {$ENDIF}
        UI_destroy_method(Result);
    end;
  end;
  Result:=FUiMeth;
end;

class function TTaurusTLSCustomOsslUi.NewUiString(
  uis: PUI_STRING; ui: PUI): TTaurusTLS_UiString;
begin
  Result:=TTaurusTLS_UiString.Create(uis, ui);
end;

function TTaurusTLSCustomOsslUi.DoPrepare: TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoSetString(
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoDisplay: TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoCheckString(
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  if AString.&Type = UIT_PROMPT then
    AString.SetPassword(PAnsiChar(''));
  Result:=uirSuccess;
end;

function TTaurusTLSCustomOsslUi.DoRelease: TTaurusTLS_UiResult;
begin
  Result:=uirSuccess;
end;

{ TTaurusTLS_SimplePasswordUI }

constructor TTaurusTLS_SimplePasswordUI.Create(APass: RawByteString);
begin
  FPass:=APass;
  inherited Create;
end;

function TTaurusTLS_SimplePasswordUI.DoCheckString(
  AString: TTaurusTLS_UiString): TTaurusTLS_UiResult;
begin
  if (AString.&Type <> UIT_PROMPT) or
    AString.SetPassword(FPass) then
    Result:=uirSuccess
  else
    Result:=uirError;
end;

end.
