/// <exclude />
(* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_ui.h2pas
  It should not be modified directly. All changes should be made to TaurusTLSHeaders_ui.h2pas
  and this file regenerated. TaurusTLSHeaders_ui.h2pas is distributed with the full Indy
  Distribution.
*)

{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
unit TaurusTLSHeaders_ui;

interface

// Headers for OpenSSL 1.1.1
// ui.h

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL }
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_uierr;

{$MINENUMSIZE 4}

const
  (* These are the possible flags.  They can be or'ed together. *)
  (* Use to have echoing of input *)
  {$EXTERNALSYM UI_INPUT_FLAG_ECHO}
  UI_INPUT_FLAG_ECHO = $01;
  (*
    * Use a default password.  Where that password is found is completely up to
    * the application, it might for example be in the user data set with
    * UI_add_user_data().  It is not recommended to have more than one input in
    * each UI being marked with this flag, or the application might get
    * confused.
  *)
  {$EXTERNALSYM UI_INPUT_FLAG_DEFAULT_PWD}
  UI_INPUT_FLAG_DEFAULT_PWD = $02;

  (*
    * The user of these routines may want to define flags of their own.  The core
    * UI won't look at those, but will pass them on to the method routines.  They
    * must use higher bits so they don't get confused with the UI bits above.
    * UI_INPUT_FLAG_USER_BASE tells which is the lowest bit to use.  A good
    * example of use is this:
    *
    *    #define MY_UI_FLAG1       (0x01 << UI_INPUT_FLAG_USER_BASE)
    *
  *)
  {$EXTERNALSYM UI_INPUT_FLAG_USER_BASE}
  UI_INPUT_FLAG_USER_BASE = 16;

  (* The commands *)
  (*
    * Use UI_CONTROL_PRINT_ERRORS with the value 1 to have UI_process print the
    * TaurusTLS error stack before printing any info or added error messages and
    * before any prompting.
  *)
  {$EXTERNALSYM UI_CTRL_PRINT_ERRORS}
  UI_CTRL_PRINT_ERRORS = 1;
  (*
    * Check if a UI_process() is possible to do again with the same instance of
    * a user interface.  This makes UI_ctrl() return 1 if it is redoable, and 0
    * if not.
  *)
  {$EXTERNALSYM UI_CTRL_IS_REDOABLE}
  UI_CTRL_IS_REDOABLE = 2;

type
  (*
    * Give a user interface parameterised control commands.  This can be used to
    * send down an integer, a data pointer or a function pointer, as well as be
    * used to get information from a UI.
  *)
  {$EXTERNALSYM UI_ctrl_f}
  UI_ctrl_f = procedure; cdecl;

  (*
    * The UI_STRING type is the data structure that contains all the needed info
    * about a string or a prompt, including test data for a verification prompt.
  *)
  {$EXTERNALSYM ui_string_st}
  ui_string_st = record end;
  {$EXTERNALSYM UI_STRING}
  UI_STRING = ui_string_st;
  {$EXTERNALSYM PUI_STRING}
  PUI_STRING = ^UI_STRING;
  // DEFINE_STACK_OF(UI_STRING)

  (*
    * The different types of strings that are currently supported. This is only
    * needed by method authors.
  *)
  {$EXTERNALSYM UI_string_type}
  UI_string_type = (UIT_NONE = 0, UIT_PROMPT, (* Prompt for a string *)
    UIT_VERIFY, (* Prompt for a string and verify *)
    UIT_BOOLEAN, (* Prompt for a yes/no response *)
    UIT_INFO, (* Send info to the user *)
    UIT_ERROR (* Send an error message to the user *)
    );

  {$EXTERNALSYM UI_string_types}
  UI_string_types = set of UI_string_type;

  (* Create and manipulate methods *)
  {$EXTERNALSYM UI_method_opener_cb}
  UI_method_opener_cb = function(ui: PUI): TIdC_INT; cdecl;
  {$EXTERNALSYM UI_method_writer_cb}
  UI_method_writer_cb = function(ui: PUI; uis: PUI_STRING): TIdC_INT; cdecl;
  {$EXTERNALSYM UI_method_flusher_cb}
  UI_method_flusher_cb = function(ui: PUI): TIdC_INT; cdecl;
  {$EXTERNALSYM UI_method_reader_cb}
  UI_method_reader_cb = function(ui: PUI; uis: PUI_STRING): TIdC_INT; cdecl;
  {$EXTERNALSYM UI_method_closer_cb}
  UI_method_closer_cb = function(ui: PUI): TIdC_INT; cdecl;
  {$EXTERNALSYM UI_method_data_duplicator_cb}
  UI_method_data_duplicator_cb = function(ui: PUI; ui_data: Pointer): Pointer;
    cdecl;
  {$EXTERNALSYM UI_method_data_destructor_cb}
  UI_method_data_destructor_cb = procedure(ui: PUI; ui_data: Pointer); cdecl;
  {$EXTERNALSYM UI_method_prompt_constructor_cb}
  UI_method_prompt_constructor_cb = function(ui: PUI;
    const object_desc: PIdAnsiChar; const object_name: PIdAnsiChar)
    : PIdAnsiChar; cdecl;

  (*
    * All the following functions return -1 or NULL on error and in some cases
    * (UI_process()) -2 if interrupted or in some other way cancelled. When
    * everything is fine, they return 0, a positive value or a non-NULL pointer,
    * all depending on their purpose.
  *)

  (* Creators and destructor. *)
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

    The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
    files generated for C++. }

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

var
  {$EXTERNALSYM UI_new}
  UI_new: function: PUI;
cdecl = nil;
  {$EXTERNALSYM UI_new_method}
UI_new_method:
function(const method: PUI_Method): PUI;
cdecl = nil;
  {$EXTERNALSYM UI_free}
UI_free:
procedure(ui: PUI);
cdecl = nil;

(*
  * The following functions are used to add strings to be printed and prompt
  * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
  * and UI_{add,dup}_input_boolean.
  *
  * UI_{add,dup}_<function>_string have the following meanings:
  *      add     add a text or prompt string.  The pointers given to these
  *              functions are used verbatim, no copying is done.
  *      dup     make a copy of the text or prompt string, then add the copy
  *              to the collection of strings in the user interface.
  *      <function>
  *              The function is a name for the functionality that the given
  *              string shall be used for.  It can be one of:
  *                      input   use the string as data prompt.
  *                      verify  use the string as verification prompt.  This
  *                              is used to verify a previous input.
  *                      info    use the string for informational output.
  *                      error   use the string for error output.
  * Honestly, there's currently no difference between info and error for the
  * moment.
  *
  * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
  * and are typically used when one wants to prompt for a yes/no response.
  *
  * All of the functions in this group take a UI and a prompt string.
  * The string input and verify addition functions also take a flag argument,
  * a buffer for the result to end up with, a minimum input size and a maximum
  * input size (the result buffer MUST be large enough to be able to contain
  * the maximum number of characters).  Additionally, the verify addition
  * functions takes another buffer to compare the result against.
  * The boolean input functions take an action description string (which should
  * be safe to ignore if the expected user action is obvious, for example with
  * a dialog box with an OK button and a Cancel button), a string of acceptable
  * characters to mean OK and to mean Cancel.  The two last strings are checked
  * to make sure they don't have common characters.  Additionally, the same
  * flag argument as for the string input is taken, as well as a result buffer.
  * The result buffer is required to be at least one byte long.  Depending on
  * the answer, the first character from the OK or the Cancel character strings
  * will be stored in the first byte of the result buffer.  No NUL will be
  * added, so the result is *not* a string.
  *
  * On success, the all return an index of the added information.  That index
  * is useful when retrieving results with UI_get0_result(). *)

  {$EXTERNALSYM UI_add_input_string}
UI_add_input_string:
function(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT;
  result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_dup_input_string}
UI_dup_input_string: function(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT;
  result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT;   cdecl = nil;
  {$EXTERNALSYM UI_add_verify_string}
UI_add_verify_string: function(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT;
  result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT;
  const test_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
{$EXTERNALSYM UI_dup_verify_string}
UI_dup_verify_string: function(ui: PUI; const prompt: PIdAnsiChar; flags: TIdC_INT;
  result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT;
  const test_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
{$EXTERNALSYM UI_add_input_boolean}
UI_add_input_boolean: function(ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar;
  const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT;
  result_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
{$EXTERNALSYM  UI_dup_input_boolean}
UI_dup_input_boolean: function(ui: PUI; const prompt: PIdAnsiChar; const action_desc: PIdAnsiChar;
  const ok_chars: PIdAnsiChar; const cancel_chars: PIdAnsiChar; flags: TIdC_INT;
  result_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
{$EXTERNALSYM  UI_add_info_string}
UI_add_info_string: function(ui: PUI; const _text: PIdAnsiChar): TIdC_INT; cdecl = nil;
{$EXTERNALSYM UI_dup_info_string}
UI_dup_info_string: function(ui: PUI; const _text: PIdAnsiChar): TIdC_INT; cdecl = nil;
{$EXTERNALSYM UI_add_error_string}
UI_add_error_string:  function(ui: PUI; const _text: PIdAnsiChar): TIdC_INT; cdecl = nil;
{$EXTERNALSYM UI_dup_error_string}
UI_dup_error_string: function(ui: PUI; const _text: PIdAnsiChar): TIdC_INT;  cdecl = nil;

(*
  * The following function helps construct a prompt.  object_desc is a
  * textual short description of the object, for example "pass phrase",
  * and object_name is the name of the object (might be a card name or
  * a file name.
  * The returned string shall always be allocated on the heap with
  * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
  *
  * If the ui_method doesn't contain a pointer to a user-defined prompt
  * constructor, a default string is built, looking like this:
  *
  *       "Enter {object_desc} for {object_name}:"
  *
  * So, if object_desc has the value "pass phrase" and object_name has
  * the value "foo.key", the resulting string is:
  *
  *       "Enter pass phrase for foo.key:"
*)
{$EXTERNALSYM UI_construct_prompt}
UI_construct_prompt: function(ui_method: PUI; const object_desc: PIdAnsiChar;
  const object_name: PIdAnsiChar): PIdAnsiChar; cdecl = nil;

(*
  * The following function is used to store a pointer to user-specific data.
  * Any previous such pointer will be returned and replaced.
  *
  * For callback purposes, this function makes a lot more sense than using
  * ex_data, since the latter requires that different parts of TaurusTLS or
  * applications share the same ex_data index.
  *
  * Note that the UI_TaurusTLS() method completely ignores the user data. Other
  * methods may not, however.
*)
  {$EXTERNALSYM UI_add_user_data}
  UI_add_user_data: function(ui: PUI; user_data: Pointer): Pointer; cdecl = nil;
(*
  * Alternatively, this function is used to duplicate the user data.
  * This uses the duplicator method function.  The destroy function will
  * be used to free the user data in this case.
*)
  {$EXTERNALSYM  UI_dup_user_data}
UI_dup_user_data: function(ui: PUI; user_data: Pointer): TIdC_INT; cdecl = nil;
(* We need a user data retrieving function as well. *)
  {$EXTERNALSYM UI_get0_user_data}
UI_get0_user_data: function(ui: PUI): Pointer; cdecl = nil;

(* Return the result associated with a prompt given with the index i. *)
  {$EXTERNALSYM UI_get0_result}
UI_get0_result: function(ui: PUI; i: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_get_result_length}
UI_get_result_length: function(ui: PUI; i: TIdC_INT): TIdC_INT; cdecl = nil;

(* When all strings have been added, process the whole thing. *)
  {$EXTERNALSYM  UI_process}
UI_process:  function(ui: PUI): TIdC_INT; cdecl = nil;

(*
  * Give a user interface parameterised control commands.  This can be used to
  * send down an integer, a data pointer or a function pointer, as well as be
  * used to get information from a UI.
*)
  {$EXTERNALSYM UI_ctrl}
UI_ctrl: function(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: UI_ctrl_f)
  : TIdC_INT; cdecl = nil;

(* Some methods may use extra data *)
// # define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
// # define UI_get_app_data(s)             UI_get_ex_data(s,0)

// # define UI_get_ex_new_index(l, p, newf, dupf, freef) \
// CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
{$EXTERNALSYM UI_set_ex_data}
UI_set_ex_data: function(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT;  cdecl = nil;
{$EXTERNALSYM UI_get_ex_data}
UI_get_ex_data: function(r: PUI; idx: TIdC_INT): Pointer; cdecl = nil;

(* Use specific methods instead of the built-in one *)
{$EXTERNALSYM  UI_set_default_method}
UI_set_default_method: procedure(const meth: PUI_Method); cdecl = nil;
{$EXTERNALSYM  UI_get_default_method}
UI_get_default_method: function: PUI_Method; cdecl = nil;
{$EXTERNALSYM  UI_get_method}
UI_get_method: function(ui: PUI): PUI_Method; cdecl = nil;
{$EXTERNALSYM UI_set_method}
UI_set_method: function(ui: PUI; const meth: PUI_Method): PUI_Method;
cdecl = nil;

(* The method with all the built-in thingies *)
{$EXTERNALSYM UI_TaurusTLS}
UI_TaurusTLS: function: PUI_Method; cdecl = nil;

(*
  * NULL method.  Literally does nothing, but may serve as a placeholder
  * to avoid internal default.
*)
  {$EXTERNALSYM UI_null}
UI_null:  function: PUI_Method; cdecl = nil;

(* ---------- For method writers ---------- *)
(*
  A method contains a number of functions that implement the low level
  of the User Interface.  The functions are:

  an opener       This function starts a session, maybe by opening
  a channel to a tty, or by opening a window.
  a writer        This function is called to write a given string,
  maybe to the tty, maybe as a field label in a
  window.
  a flusher       This function is called to flush everything that
  has been output so far.  It can be used to actually
  display a dialog box after it has been built.
  a reader        This function is called to read a given prompt,
  maybe from the tty, maybe from a field in a
  window.  Note that it's called with all string
  structures, not only the prompt ones, so it must
  check such things itself.
  a closer        This function closes the session, maybe by closing
  the channel to the tty, or closing the window.

  All these functions are expected to return:

  0       on error.
  1       on success.
  -1      on out-of-band events, for example if some prompting has
  been canceled (by pressing Ctrl-C, for example).  This is
  only checked when returned by the flusher or the reader.

  The way this is used, the opener is first called, then the writer for all
  strings, then the flusher, then the reader for all strings and finally the
  closer.  Note that if you want to prompt from a terminal or other command
  line interface, the best is to have the reader also write the prompts
  instead of having the writer do it.  If you want to prompt from a dialog
  box, the writer can be used to build up the contents of the box, and the
  flusher to actually display the box and run the event loop until all data
  has been given, after which the reader only grabs the given data and puts
  them back into the UI strings.

  All method functions take a UI as argument.  Additionally, the writer and
  the reader take a UI_STRING.
*)

  {$EXTERNALSYM UI_create_method}
UI_create_method: function(const name: PIdAnsiChar): PUI_Method;  cdecl = nil;
  {$EXTERNALSYM UI_destroy_method}
UI_destroy_method: procedure(ui_method: PUI_Method); cdecl = nil;

  {$EXTERNALSYM UI_method_set_opener}
UI_method_set_opener: function(method: PUI_Method; opener: UI_method_opener_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_writer}
UI_method_set_writer: function(method: PUI_Method; writer: UI_method_writer_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_flusher}
UI_method_set_flusher: function(method: PUI_Method; flusher: UI_method_flusher_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_reader}
UI_method_set_reader: function(method: PUI_Method; reader: UI_method_reader_cb): TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM UI_method_set_closer}
UI_method_set_closer: function(method: PUI_Method; closer: UI_method_closer_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_data_duplicator}
UI_method_set_data_duplicator: function(method: PUI_Method; duplicator: UI_method_data_duplicator_cb;
  destructor_: UI_method_data_destructor_cb): TIdC_INT; cdecl = nil;
{$EXTERNALSYM UI_method_set_prompt_constructor}
UI_method_set_prompt_constructor: function(method: PUI_Method;
  prompt_constructor: UI_method_prompt_constructor_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_ex_data}
UI_method_set_ex_data: function(method: PUI_Method; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM UI_method_get_opener}
UI_method_get_opener: function(const method: PUI_Method): UI_method_opener_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_writer}
UI_method_get_writer: function(const method: PUI_Method): UI_method_writer_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_flusher}
UI_method_get_flusher: function(const method: PUI_Method): UI_method_flusher_cb;  cdecl = nil;
  {$EXTERNALSYM UI_method_get_reader}
UI_method_get_reader:  function(const method: PUI_Method): UI_method_reader_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_closer}
UI_method_get_closer:  function(const method: PUI_Method): UI_method_closer_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_prompt_constructor}
UI_method_get_prompt_constructor: function(const method: PUI_Method): UI_method_prompt_constructor_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_data_duplicator}
UI_method_get_data_duplicator: function(const method: PUI_Method): UI_method_data_duplicator_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_data_destructor}
UI_method_get_data_destructor:  function(const method: PUI_Method): UI_method_data_destructor_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_ex_data}
UI_method_get_ex_data:  function(const method: PUI_Method; idx: TIdC_INT): Pointer; cdecl = nil;

(*
  * The following functions are helpers for method writers to access relevant
  * data from a UI_STRING.
*)

(* Return type of the UI_STRING *)
  {$EXTERNALSYM UI_get_string_type}
UI_get_string_type: function(uis: PUI_STRING): UI_string_type; cdecl = nil;
(* Return input flags of the UI_STRING *)
  {$EXTERNALSYM UI_get_input_flags}
UI_get_input_flags: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
(* Return the actual string to output (the prompt, info or error) *)
  {$EXTERNALSYM UI_get0_output_string}
UI_get0_output_string: function(uis: PUI_STRING): PIdAnsiChar; cdecl = nil;
(*
  * Return the optional action string to output (the boolean prompt
  * instruction)
*)
  {$EXTERNALSYM UI_get0_action_string}
UI_get0_action_string: function(uis: PUI_STRING): PIdAnsiChar; cdecl = nil;
(* Return the result of a prompt *)
  {$EXTERNALSYM UI_get0_result_string}
UI_get0_result_string: function(uis: PUI_STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_get_result_string_length}
UI_get_result_string_length: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
(*
  * Return the string to test the result against.  Only useful with verifies.
*)
  {$EXTERNALSYM UI_get0_test_string}
UI_get0_test_string: function(uis: PUI_STRING): PIdAnsiChar;  cdecl = nil;
(* Return the required minimum size of the result *)
  {$EXTERNALSYM UI_get_result_minsize}
UI_get_result_minsize: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
(* Return the required maximum size of the result *)
  {$EXTERNALSYM UI_get_result_maxsize}
UI_get_result_maxsize: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
(* Set the result of a UI_STRING. *)
  {$EXTERNALSYM UI_set_result}
UI_set_result:  function(ui: PUI; uis: PUI_STRING; const result: PIdAnsiChar): TIdC_INT;  cdecl = nil;
  {$EXTERNALSYM UI_set_result_ex}
UI_set_result_ex: function(ui: PUI; uis: PUI_STRING; const result: PIdAnsiChar; len: TIdC_INT)  : TIdC_INT;  cdecl = nil;

(* A couple of popular utility functions *)
  {$EXTERNALSYM UI_UTIL_read_pw_string}
  UI_UTIL_read_pw_string: function(buf: PIdAnsiChar; _length: TIdC_INT; const prompt: PIdAnsiChar;
    verify: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_UTIL_read_pw}
  UI_UTIL_read_pw:  function(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT;
    const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT;
  cdecl = nil;
  {$EXTERNALSYM UI_UTIL_wrap_read_pem_callback}
UI_UTIL_wrap_read_pem_callback: function(cb: pem_password_cb; rwflag: TIdC_INT): PUI_Method;
  cdecl = nil;

{$ELSE}
  {$EXTERNALSYM UI_new}
function UI_new: PUI cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_new_method}
function UI_new_method(const method: PUI_Method): PUI cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_free}
procedure UI_free(ui: PUI)cdecl; external CLibCrypto;

(*
  * The following functions are used to add strings to be printed and prompt
  * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
  * and UI_{add,dup}_input_boolean.
  *
  * UI_{add,dup}_<function>_string have the following meanings:
  *      add     add a text or prompt string.  The pointers given to these
  *              functions are used verbatim, no copying is done.
  *      dup     make a copy of the text or prompt string, then add the copy
  *              to the collection of strings in the user interface.
  *      <function>
  *              The function is a name for the functionality that the given
  *              string shall be used for.  It can be one of:
  *                      input   use the string as data prompt.
  *                      verify  use the string as verification prompt.  This
  *                              is used to verify a previous input.
  *                      info    use the string for informational output.
  *                      error   use the string for error output.
  * Honestly, there's currently no difference between info and error for the
  * moment.
  *
  * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
  * and are typically used when one wants to prompt for a yes/no response.
  *
  * All of the functions in this group take a UI and a prompt string.
  * The string input and verify addition functions also take a flag argument,
  * a buffer for the result to end up with, a minimum input size and a maximum
  * input size (the result buffer MUST be large enough to be able to contain
  * the maximum number of characters).  Additionally, the verify addition
  * functions takes another buffer to compare the result against.
  * The boolean input functions take an action description string (which should
  * be safe to ignore if the expected user action is obvious, for example with
  * a dialog box with an OK button and a Cancel button), a string of acceptable
  * characters to mean OK and to mean Cancel.  The two last strings are checked
  * to make sure they don't have common characters.  Additionally, the same
  * flag argument as for the string input is taken, as well as a result buffer.
  * The result buffer is required to be at least one byte long.  Depending on
  * the answer, the first character from the OK or the Cancel character strings
  * will be stored in the first byte of the result buffer.  No NUL will be
  * added, so the result is *not* a string.
  *
  * On success, the all return an index of the added information.  That index
  * is useful when retrieving results with UI_get0_result(). *)

  {$EXTERNALSYM UI_add_input_string}
function UI_add_input_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_dup_input_string}
function UI_dup_input_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_add_verify_string}
function UI_add_verify_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_dup_verify_string}
function UI_dup_verify_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_add_input_boolean}
function UI_add_input_boolean(ui: PUI; const prompt: PIdAnsiChar;
  const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar;
  const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar)
  : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_dup_input_boolean}
function UI_dup_input_boolean(ui: PUI; const prompt: PIdAnsiChar;
  const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar;
  const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar)
  : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_add_info_string}
function UI_add_info_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_dup_info_string}
function UI_dup_info_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_add_error_string}
function UI_add_error_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_dup_error_string}
function UI_dup_error_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT cdecl;
  external CLibCrypto;

(*
  * The following function helps construct a prompt.  object_desc is a
  * textual short description of the object, for example "pass phrase",
  * and object_name is the name of the object (might be a card name or
  * a file name.
  * The returned string shall always be allocated on the heap with
  * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
  *
  * If the ui_method doesn't contain a pointer to a user-defined prompt
  * constructor, a default string is built, looking like this:
  *
  *       "Enter {object_desc} for {object_name}:"
  *
  * So, if object_desc has the value "pass phrase" and object_name has
  * the value "foo.key", the resulting string is:
  *
  *       "Enter pass phrase for foo.key:"
*)
  {$EXTERNALSYM UI_construct_prompt}
function UI_construct_prompt(ui_method: PUI; const object_desc: PIdAnsiChar;
  const object_name: PIdAnsiChar): PIdAnsiChar cdecl; external CLibCrypto;

(*
  * The following function is used to store a pointer to user-specific data.
  * Any previous such pointer will be returned and replaced.
  *
  * For callback purposes, this function makes a lot more sense than using
  * ex_data, since the latter requires that different parts of TaurusTLS or
  * applications share the same ex_data index.
  *
  * Note that the UI_TaurusTLS() method completely ignores the user data. Other
  * methods may not, however.
*)
  {$EXTERNALSYM UI_add_user_data}
function UI_add_user_data(ui: PUI; user_data: Pointer): Pointer cdecl;
  external CLibCrypto;
(*
  * Alternatively, this function is used to duplicate the user data.
  * This uses the duplicator method function.  The destroy function will
  * be used to free the user data in this case.
*)
  {$EXTERNALSYM UI_dup_user_data}
function UI_dup_user_data(ui: PUI; user_data: Pointer): TIdC_INT cdecl;
  external CLibCrypto;
(* We need a user data retrieving function as well. *)
  {$EXTERNALSYM UI_get0_user_data}
function UI_get0_user_data(ui: PUI): Pointer cdecl; external CLibCrypto;

(* Return the result associated with a prompt given with the index i. *)
  {$EXTERNALSYM UI_get0_result}
function UI_get0_result(ui: PUI; i: TIdC_INT): PIdAnsiChar cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_get_result_length}
function UI_get_result_length(ui: PUI; i: TIdC_INT): TIdC_INT cdecl;
  external CLibCrypto;

(* When all strings have been added, process the whole thing. *)
  {$EXTERNALSYM UI_process}
function UI_process(ui: PUI): TIdC_INT cdecl; external CLibCrypto;

(*
  * Give a user interface parameterised control commands.  This can be used to
  * send down an integer, a data pointer or a function pointer, as well as be
  * used to get information from a UI.
*)
  {$EXTERNALSYM UI_ctrl}
function UI_ctrl(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: UI_ctrl_f)
  : TIdC_INT cdecl; external CLibCrypto;

(* Some methods may use extra data *)
// # define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
// # define UI_get_app_data(s)             UI_get_ex_data(s,0)

// # define UI_get_ex_new_index(l, p, newf, dupf, freef) \
// CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
  {$EXTERNALSYM UI_set_ex_data}
function UI_set_ex_data(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_get_ex_data}
function UI_get_ex_data(r: PUI; idx: TIdC_INT): Pointer cdecl;
  external CLibCrypto;

(* Use specific methods instead of the built-in one *)
  {$EXTERNALSYM UI_set_default_method}
procedure UI_set_default_method(const meth: PUI_Method)cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_get_default_method}
function UI_get_default_method: PUI_Method cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_get_method}
function UI_get_method(ui: PUI): PUI_Method cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_set_method}
function UI_set_method(ui: PUI; const meth: PUI_Method): PUI_Method cdecl;
  external CLibCrypto;

(* The method with all the built-in thingies *)
  {$EXTERNALSYM UI_TaurusTLS}
function UI_TaurusTLS: PUI_Method cdecl; external CLibCrypto;

(*
  * NULL method.  Literally does nothing, but may serve as a placeholder
  * to avoid internal default.
*)
  {$EXTERNALSYM UI_null}
function UI_null: PUI_Method cdecl; external CLibCrypto;

(* ---------- For method writers ---------- *)
(*
  A method contains a number of functions that implement the low level
  of the User Interface.  The functions are:

  an opener       This function starts a session, maybe by opening
  a channel to a tty, or by opening a window.
  a writer        This function is called to write a given string,
  maybe to the tty, maybe as a field label in a
  window.
  a flusher       This function is called to flush everything that
  has been output so far.  It can be used to actually
  display a dialog box after it has been built.
  a reader        This function is called to read a given prompt,
  maybe from the tty, maybe from a field in a
  window.  Note that it's called with all string
  structures, not only the prompt ones, so it must
  check such things itself.
  a closer        This function closes the session, maybe by closing
  the channel to the tty, or closing the window.

  All these functions are expected to return:

  0       on error.
  1       on success.
  -1      on out-of-band events, for example if some prompting has
  been canceled (by pressing Ctrl-C, for example).  This is
  only checked when returned by the flusher or the reader.

  The way this is used, the opener is first called, then the writer for all
  strings, then the flusher, then the reader for all strings and finally the
  closer.  Note that if you want to prompt from a terminal or other command
  line interface, the best is to have the reader also write the prompts
  instead of having the writer do it.  If you want to prompt from a dialog
  box, the writer can be used to build up the contents of the box, and the
  flusher to actually display the box and run the event loop until all data
  has been given, after which the reader only grabs the given data and puts
  them back into the UI strings.

  All method functions take a UI as argument.  Additionally, the writer and
  the reader take a UI_STRING.
*)

  {$EXTERNALSYM UI_create_method}
function UI_create_method(const name: PIdAnsiChar): PUI_Method cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_destroy_method}
procedure UI_destroy_method(ui_method: PUI_Method)cdecl; external CLibCrypto;

  {$EXTERNALSYM UI_method_set_opener}
function UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb)
  : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_set_writer}
function UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb)
  : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_set_flusher}
function UI_method_set_flusher(method: PUI_Method;
  flusher: UI_method_flusher_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_set_reader}
function UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb)
  : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_set_closer}
function UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb)
  : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_set_data_duplicator}
function UI_method_set_data_duplicator(method: PUI_Method;
  duplicator: UI_method_data_duplicator_cb;
  destructor_: UI_method_data_destructor_cb): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_method_set_prompt_constructor}
function UI_method_set_prompt_constructor(method: PUI_Method;
  prompt_constructor: UI_method_prompt_constructor_cb): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_method_set_ex_data}
function UI_method_set_ex_data(method: PUI_Method; idx: TIdC_INT; data: Pointer)
  : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM UI_method_get_opener}
function UI_method_get_opener(const method: PUI_Method)
  : UI_method_opener_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_writer}
function UI_method_get_writer(const method: PUI_Method)
  : UI_method_writer_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_flusher}
function UI_method_get_flusher(const method: PUI_Method)
  : UI_method_flusher_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_reader}
function UI_method_get_reader(const method: PUI_Method)
  : UI_method_reader_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_closer}
function UI_method_get_closer(const method: PUI_Method)
  : UI_method_closer_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_prompt_constructor}
function UI_method_get_prompt_constructor(const method: PUI_Method)
  : UI_method_prompt_constructor_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_data_duplicator}
function UI_method_get_data_duplicator(const method: PUI_Method)
  : UI_method_data_duplicator_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_data_destructor}
function UI_method_get_data_destructor(const method: PUI_Method)
  : UI_method_data_destructor_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_method_get_ex_data}
function UI_method_get_ex_data(const method: PUI_Method; idx: TIdC_INT)
  : Pointer cdecl; external CLibCrypto;

(*
  * The following functions are helpers for method writers to access relevant
  * data from a UI_STRING.
*)

(* Return type of the UI_STRING *)
  {$EXTERNALSYM UI_get_string_type}
function UI_get_string_type(uis: PUI_STRING): UI_string_type cdecl;
  external CLibCrypto;
(* Return input flags of the UI_STRING *)
  {$EXTERNALSYM UI_get_input_flags}
function UI_get_input_flags(uis: PUI_STRING): TIdC_INT cdecl;
  external CLibCrypto;
(* Return the actual string to output (the prompt, info or error) *)
  {$EXTERNALSYM UI_get0_output_string}
function UI_get0_output_string(uis: PUI_STRING): PIdAnsiChar cdecl;
  external CLibCrypto;
(*
  * Return the optional action string to output (the boolean prompt
  * instruction)
*)
  {$EXTERNALSYM UI_get0_action_string}
function UI_get0_action_string(uis: PUI_STRING): PIdAnsiChar cdecl;
  external CLibCrypto;
(* Return the result of a prompt *)
  {$EXTERNALSYM UI_get0_result_string}
function UI_get0_result_string(uis: PUI_STRING): PIdAnsiChar cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_get_result_string_length}
function UI_get_result_string_length(uis: PUI_STRING): TIdC_INT cdecl;
  external CLibCrypto;
(*
  * Return the string to test the result against.  Only useful with verifies.
*)
  {$EXTERNALSYM UI_get0_test_string}
function UI_get0_test_string(uis: PUI_STRING): PIdAnsiChar cdecl;
  external CLibCrypto;
(* Return the required minimum size of the result *)
  {$EXTERNALSYM UI_get_result_minsize}
function UI_get_result_minsize(uis: PUI_STRING): TIdC_INT cdecl;
  external CLibCrypto;
(* Return the required maximum size of the result *)
  {$EXTERNALSYM UI_get_result_maxsize}
function UI_get_result_maxsize(uis: PUI_STRING): TIdC_INT cdecl;
  external CLibCrypto;
(* Set the result of a UI_STRING. *)
  {$EXTERNALSYM UI_set_result}
function UI_set_result(ui: PUI; uis: PUI_STRING; const result: PIdAnsiChar)
  : TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM UI_set_result_ex}
function UI_set_result_ex(ui: PUI; uis: PUI_STRING; const result: PIdAnsiChar;
  len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

(* A couple of popular utility functions *)
  {$EXTERNALSYM UI_UTIL_read_pw_string}
function UI_UTIL_read_pw_string(buf: PIdAnsiChar; _length: TIdC_INT;
  const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_UTIL_read_pw}
function UI_UTIL_read_pw(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT;
  const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM UI_UTIL_wrap_read_pem_callback}
function UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TIdC_INT)
  : PUI_Method cdecl; external CLibCrypto;

{$ENDIF}
  {$EXTERNALSYM UI_get_ex_new_index}
function UI_get_ex_new_index(l : TIdC_LONG; p : PUI;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;

implementation

uses
  classes,
  TaurusTLSExceptionHandlers
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    , TaurusTLSLoader
{$ENDIF};

// # define UI_get_ex_new_index(l, p, newf, dupf, freef) \
// CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
function UI_get_ex_new_index(l : TIdC_LONG; p : PUI;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef);
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

const
  UI_new_procname = 'UI_new';
  UI_new_method_procname = 'UI_new_method';
  UI_free_procname = 'UI_free';

  (*
    * The following functions are used to add strings to be printed and prompt
    * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
    * and UI_{add,dup}_input_boolean.
    *
    * UI_{add,dup}_<function>_string have the following meanings:
    *      add     add a text or prompt string.  The pointers given to these
    *              functions are used verbatim, no copying is done.
    *      dup     make a copy of the text or prompt string, then add the copy
    *              to the collection of strings in the user interface.
    *      <function>
    *              The function is a name for the functionality that the given
    *              string shall be used for.  It can be one of:
    *                      input   use the string as data prompt.
    *                      verify  use the string as verification prompt.  This
    *                              is used to verify a previous input.
    *                      info    use the string for informational output.
    *                      error   use the string for error output.
    * Honestly, there's currently no difference between info and error for the
    * moment.
    *
    * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
    * and are typically used when one wants to prompt for a yes/no response.
    *
    * All of the functions in this group take a UI and a prompt string.
    * The string input and verify addition functions also take a flag argument,
    * a buffer for the result to end up with, a minimum input size and a maximum
    * input size (the result buffer MUST be large enough to be able to contain
    * the maximum number of characters).  Additionally, the verify addition
    * functions takes another buffer to compare the result against.
    * The boolean input functions take an action description string (which should
    * be safe to ignore if the expected user action is obvious, for example with
    * a dialog box with an OK button and a Cancel button), a string of acceptable
    * characters to mean OK and to mean Cancel.  The two last strings are checked
    * to make sure they don't have common characters.  Additionally, the same
    * flag argument as for the string input is taken, as well as a result buffer.
    * The result buffer is required to be at least one byte long.  Depending on
    * the answer, the first character from the OK or the Cancel character strings
    * will be stored in the first byte of the result buffer.  No NUL will be
    * added, so the result is *not* a string.
    *
    * On success, the all return an index of the added information.  That index
    * is useful when retrieving results with UI_get0_result(). *)

  UI_add_input_string_procname = 'UI_add_input_string';
  UI_dup_input_string_procname = 'UI_dup_input_string';
  UI_add_verify_string_procname = 'UI_add_verify_string';
  UI_dup_verify_string_procname = 'UI_dup_verify_string';
  UI_add_input_boolean_procname = 'UI_add_input_boolean';
  UI_dup_input_boolean_procname = 'UI_dup_input_boolean';
  UI_add_info_string_procname = 'UI_add_info_string';
  UI_dup_info_string_procname = 'UI_dup_info_string';
  UI_add_error_string_procname = 'UI_add_error_string';
  UI_dup_error_string_procname = 'UI_dup_error_string';

  (*
    * The following function helps construct a prompt.  object_desc is a
    * textual short description of the object, for example "pass phrase",
    * and object_name is the name of the object (might be a card name or
    * a file name.
    * The returned string shall always be allocated on the heap with
    * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
    *
    * If the ui_method doesn't contain a pointer to a user-defined prompt
    * constructor, a default string is built, looking like this:
    *
    *       "Enter {object_desc} for {object_name}:"
    *
    * So, if object_desc has the value "pass phrase" and object_name has
    * the value "foo.key", the resulting string is:
    *
    *       "Enter pass phrase for foo.key:"
  *)
  UI_construct_prompt_procname = 'UI_construct_prompt';

  (*
    * The following function is used to store a pointer to user-specific data.
    * Any previous such pointer will be returned and replaced.
    *
    * For callback purposes, this function makes a lot more sense than using
    * ex_data, since the latter requires that different parts of TaurusTLS or
    * applications share the same ex_data index.
    *
    * Note that the UI_TaurusTLS() method completely ignores the user data. Other
    * methods may not, however.
  *)
  UI_add_user_data_procname = 'UI_add_user_data';
  (*
    * Alternatively, this function is used to duplicate the user data.
    * This uses the duplicator method function.  The destroy function will
    * be used to free the user data in this case.
  *)
  UI_dup_user_data_procname = 'UI_dup_user_data';
  (* We need a user data retrieving function as well. *)
  UI_get0_user_data_procname = 'UI_get0_user_data';

  (* Return the result associated with a prompt given with the index i. *)
  UI_get0_result_procname = 'UI_get0_result';
  UI_get_result_length_procname = 'UI_get_result_length';

  (* When all strings have been added, process the whole thing. *)
  UI_process_procname = 'UI_process';

  (*
    * Give a user interface parameterised control commands.  This can be used to
    * send down an integer, a data pointer or a function pointer, as well as be
    * used to get information from a UI.
  *)
  UI_ctrl_procname = 'UI_ctrl';

  (* Some methods may use extra data *)
  // # define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
  // # define UI_get_app_data(s)             UI_get_ex_data(s,0)

  // # define UI_get_ex_new_index(l, p, newf, dupf, freef) \
  // CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
  UI_set_ex_data_procname = 'UI_set_ex_data';
  UI_get_ex_data_procname = 'UI_get_ex_data';

  (* Use specific methods instead of the built-in one *)
  UI_set_default_method_procname = 'UI_set_default_method';
  UI_get_default_method_procname = 'UI_get_default_method';
  UI_get_method_procname = 'UI_get_method';
  UI_set_method_procname = 'UI_set_method';

  (* The method with all the built-in thingies *)
  UI_TaurusTLS_procname = 'UI_TaurusTLS';

  (*
    * NULL method.  Literally does nothing, but may serve as a placeholder
    * to avoid internal default.
  *)
  UI_null_procname = 'UI_null';

  (* ---------- For method writers ---------- *)
  (*
    A method contains a number of functions that implement the low level
    of the User Interface.  The functions are:

    an opener       This function starts a session, maybe by opening
    a channel to a tty, or by opening a window.
    a writer        This function is called to write a given string,
    maybe to the tty, maybe as a field label in a
    window.
    a flusher       This function is called to flush everything that
    has been output so far.  It can be used to actually
    display a dialog box after it has been built.
    a reader        This function is called to read a given prompt,
    maybe from the tty, maybe from a field in a
    window.  Note that it's called with all string
    structures, not only the prompt ones, so it must
    check such things itself.
    a closer        This function closes the session, maybe by closing
    the channel to the tty, or closing the window.

    All these functions are expected to return:

    0       on error.
    1       on success.
    -1      on out-of-band events, for example if some prompting has
    been canceled (by pressing Ctrl-C, for example).  This is
    only checked when returned by the flusher or the reader.

    The way this is used, the opener is first called, then the writer for all
    strings, then the flusher, then the reader for all strings and finally the
    closer.  Note that if you want to prompt from a terminal or other command
    line interface, the best is to have the reader also write the prompts
    instead of having the writer do it.  If you want to prompt from a dialog
    box, the writer can be used to build up the contents of the box, and the
    flusher to actually display the box and run the event loop until all data
    has been given, after which the reader only grabs the given data and puts
    them back into the UI strings.

    All method functions take a UI as argument.  Additionally, the writer and
    the reader take a UI_STRING.
  *)

  UI_create_method_procname = 'UI_create_method';
  UI_destroy_method_procname = 'UI_destroy_method';

  UI_method_set_opener_procname = 'UI_method_set_opener';
  UI_method_set_writer_procname = 'UI_method_set_writer';
  UI_method_set_flusher_procname = 'UI_method_set_flusher';
  UI_method_set_reader_procname = 'UI_method_set_reader';
  UI_method_set_closer_procname = 'UI_method_set_closer';
  UI_method_set_data_duplicator_procname = 'UI_method_set_data_duplicator';
  UI_method_set_prompt_constructor_procname =
    'UI_method_set_prompt_constructor';
  UI_method_set_ex_data_procname = 'UI_method_set_ex_data';

  UI_method_get_opener_procname = 'UI_method_get_opener';
  UI_method_get_writer_procname = 'UI_method_get_writer';
  UI_method_get_flusher_procname = 'UI_method_get_flusher';
  UI_method_get_reader_procname = 'UI_method_get_reader';
  UI_method_get_closer_procname = 'UI_method_get_closer';
  UI_method_get_prompt_constructor_procname =
    'UI_method_get_prompt_constructor';
  UI_method_get_data_duplicator_procname = 'UI_method_get_data_duplicator';
  UI_method_get_data_destructor_procname = 'UI_method_get_data_destructor';
  UI_method_get_ex_data_procname = 'UI_method_get_ex_data';

  (*
    * The following functions are helpers for method writers to access relevant
    * data from a UI_STRING.
  *)

  (* Return type of the UI_STRING *)
  UI_get_string_type_procname = 'UI_get_string_type';
  (* Return input flags of the UI_STRING *)
  UI_get_input_flags_procname = 'UI_get_input_flags';
  (* Return the actual string to output (the prompt, info or error) *)
  UI_get0_output_string_procname = 'UI_get0_output_string';
  (*
    * Return the optional action string to output (the boolean prompt
    * instruction)
  *)
  UI_get0_action_string_procname = 'UI_get0_action_string';
  (* Return the result of a prompt *)
  UI_get0_result_string_procname = 'UI_get0_result_string';
  UI_get_result_string_length_procname = 'UI_get_result_string_length';
  (*
    * Return the string to test the result against.  Only useful with verifies.
  *)
  UI_get0_test_string_procname = 'UI_get0_test_string';
  (* Return the required minimum size of the result *)
  UI_get_result_minsize_procname = 'UI_get_result_minsize';
  (* Return the required maximum size of the result *)
  UI_get_result_maxsize_procname = 'UI_get_result_maxsize';
  (* Set the result of a UI_STRING. *)
  UI_set_result_procname = 'UI_set_result';
  UI_set_result_ex_procname = 'UI_set_result_ex';

  (* A couple of popular utility functions *)
  UI_UTIL_read_pw_string_procname = 'UI_UTIL_read_pw_string';
  UI_UTIL_read_pw_procname = 'UI_UTIL_read_pw';
  UI_UTIL_wrap_read_pem_callback_procname = 'UI_UTIL_wrap_read_pem_callback';

{$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 

function ERR_UI_new: PUI; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_new_procname);
end;

function ERR_UI_new_method(const method: PUI_Method): PUI; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_new_method_procname);
end;

procedure ERR_UI_free(ui: PUI); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_free_procname);
end;

(*
  * The following functions are used to add strings to be printed and prompt
  * strings to prompt for data.  The names are UI_{add,dup}_<function>_string
  * and UI_{add,dup}_input_boolean.
  *
  * UI_{add,dup}_<function>_string have the following meanings:
  *      add     add a text or prompt string.  The pointers given to these
  *              functions are used verbatim, no copying is done.
  *      dup     make a copy of the text or prompt string, then add the copy
  *              to the collection of strings in the user interface.
  *      <function>
  *              The function is a name for the functionality that the given
  *              string shall be used for.  It can be one of:
  *                      input   use the string as data prompt.
  *                      verify  use the string as verification prompt.  This
  *                              is used to verify a previous input.
  *                      info    use the string for informational output.
  *                      error   use the string for error output.
  * Honestly, there's currently no difference between info and error for the
  * moment.
  *
  * UI_{add,dup}_input_boolean have the same semantics for "add" and "dup",
  * and are typically used when one wants to prompt for a yes/no response.
  *
  * All of the functions in this group take a UI and a prompt string.
  * The string input and verify addition functions also take a flag argument,
  * a buffer for the result to end up with, a minimum input size and a maximum
  * input size (the result buffer MUST be large enough to be able to contain
  * the maximum number of characters).  Additionally, the verify addition
  * functions takes another buffer to compare the result against.
  * The boolean input functions take an action description string (which should
  * be safe to ignore if the expected user action is obvious, for example with
  * a dialog box with an OK button and a Cancel button), a string of acceptable
  * characters to mean OK and to mean Cancel.  The two last strings are checked
  * to make sure they don't have common characters.  Additionally, the same
  * flag argument as for the string input is taken, as well as a result buffer.
  * The result buffer is required to be at least one byte long.  Depending on
  * the answer, the first character from the OK or the Cancel character strings
  * will be stored in the first byte of the result buffer.  No NUL will be
  * added, so the result is *not* a string.
  *
  * On success, the all return an index of the added information.  That index
  * is useful when retrieving results with UI_get0_result(). *)

function ERR_UI_add_input_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_input_string_procname);
end;

function ERR_UI_dup_input_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_input_string_procname);
end;

function ERR_UI_add_verify_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_verify_string_procname);
end;

function ERR_UI_dup_verify_string(ui: PUI; const prompt: PIdAnsiChar;
  flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT;
  maxsize: TIdC_INT; const test_buf: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_verify_string_procname);
end;

function ERR_UI_add_input_boolean(ui: PUI; const prompt: PIdAnsiChar;
  const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar;
  const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar)
  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_input_boolean_procname);
end;

function ERR_UI_dup_input_boolean(ui: PUI; const prompt: PIdAnsiChar;
  const action_desc: PIdAnsiChar; const ok_chars: PIdAnsiChar;
  const cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar)
  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_input_boolean_procname);
end;

function ERR_UI_add_info_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_info_string_procname);
end;

function ERR_UI_dup_info_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_info_string_procname);
end;

function ERR_UI_add_error_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_error_string_procname);
end;

function ERR_UI_dup_error_string(ui: PUI; const _text: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_error_string_procname);
end;

(*
  * The following function helps construct a prompt.  object_desc is a
  * textual short description of the object, for example "pass phrase",
  * and object_name is the name of the object (might be a card name or
  * a file name.
  * The returned string shall always be allocated on the heap with
  * OPENSSL_malloc(), and need to be free'd with OPENSSL_free().
  *
  * If the ui_method doesn't contain a pointer to a user-defined prompt
  * constructor, a default string is built, looking like this:
  *
  *       "Enter {object_desc} for {object_name}:"
  *
  * So, if object_desc has the value "pass phrase" and object_name has
  * the value "foo.key", the resulting string is:
  *
  *       "Enter pass phrase for foo.key:"
*)
function ERR_UI_construct_prompt(ui_method: PUI; const object_desc: PIdAnsiChar;
  const object_name: PIdAnsiChar): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_construct_prompt_procname);
end;

(*
  * The following function is used to store a pointer to user-specific data.
  * Any previous such pointer will be returned and replaced.
  *
  * For callback purposes, this function makes a lot more sense than using
  * ex_data, since the latter requires that different parts of TaurusTLS or
  * applications share the same ex_data index.
  *
  * Note that the UI_TaurusTLS() method completely ignores the user data. Other
  * methods may not, however.
*)
function ERR_UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_user_data_procname);
end;

(*
  * Alternatively, this function is used to duplicate the user data.
  * This uses the duplicator method function.  The destroy function will
  * be used to free the user data in this case.
*)
function ERR_UI_dup_user_data(ui: PUI; user_data: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_user_data_procname);
end;

(* We need a user data retrieving function as well. *)
function ERR_UI_get0_user_data(ui: PUI): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_user_data_procname);
end;

(* Return the result associated with a prompt given with the index i. *)
function ERR_UI_get0_result(ui: PUI; i: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_result_procname);
end;

function ERR_UI_get_result_length(ui: PUI; i: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_length_procname);
end;

(* When all strings have been added, process the whole thing. *)
function ERR_UI_process(ui: PUI): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_process_procname);
end;

(*
  * Give a user interface parameterised control commands.  This can be used to
  * send down an integer, a data pointer or a function pointer, as well as be
  * used to get information from a UI.
*)
function ERR_UI_ctrl(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer;
  f: UI_ctrl_f): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_ctrl_procname);
end;

(* Some methods may use extra data *)
// # define UI_set_app_data(s,arg)         UI_set_ex_data(s,0,arg)
// # define UI_get_app_data(s)             UI_get_ex_data(s,0)

// # define UI_get_ex_new_index(l, p, newf, dupf, freef) \
// CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, l, p, newf, dupf, freef)
function ERR_UI_set_ex_data(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_ex_data_procname);
end;

function ERR_UI_get_ex_data(r: PUI; idx: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_ex_data_procname);
end;

(* Use specific methods instead of the built-in one *)
procedure ERR_UI_set_default_method(const meth: PUI_Method); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_default_method_procname);
end;

function ERR_UI_get_default_method: PUI_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_default_method_procname);
end;

function ERR_UI_get_method(ui: PUI): PUI_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_method_procname);
end;

function ERR_UI_set_method(ui: PUI; const meth: PUI_Method): PUI_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_method_procname);
end;

(* The method with all the built-in thingies *)
function ERR_UI_TaurusTLS: PUI_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_TaurusTLS_procname);
end;

(*
  * NULL method.  Literally does nothing, but may serve as a placeholder
  * to avoid internal default.
*)
function ERR_UI_null: PUI_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_null_procname);
end;

(* ---------- For method writers ---------- *)
(*
  A method contains a number of functions that implement the low level
  of the User Interface.  The functions are:

  an opener       This function starts a session, maybe by opening
  a channel to a tty, or by opening a window.
  a writer        This function is called to write a given string,
  maybe to the tty, maybe as a field label in a
  window.
  a flusher       This function is called to flush everything that
  has been output so far.  It can be used to actually
  display a dialog box after it has been built.
  a reader        This function is called to read a given prompt,
  maybe from the tty, maybe from a field in a
  window.  Note that it's called with all string
  structures, not only the prompt ones, so it must
  check such things itself.
  a closer        This function closes the session, maybe by closing
  the channel to the tty, or closing the window.

  All these functions are expected to return:

  0       on error.
  1       on success.
  -1      on out-of-band events, for example if some prompting has
  been canceled (by pressing Ctrl-C, for example).  This is
  only checked when returned by the flusher or the reader.

  The way this is used, the opener is first called, then the writer for all
  strings, then the flusher, then the reader for all strings and finally the
  closer.  Note that if you want to prompt from a terminal or other command
  line interface, the best is to have the reader also write the prompts
  instead of having the writer do it.  If you want to prompt from a dialog
  box, the writer can be used to build up the contents of the box, and the
  flusher to actually display the box and run the event loop until all data
  has been given, after which the reader only grabs the given data and puts
  them back into the UI strings.

  All method functions take a UI as argument.  Additionally, the writer and
  the reader take a UI_STRING.
*)

function ERR_UI_create_method(const name: PIdAnsiChar): PUI_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_create_method_procname);
end;

procedure ERR_UI_destroy_method(ui_method: PUI_Method); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_destroy_method_procname);
end;

function ERR_UI_method_set_opener(method: PUI_Method;
  opener: UI_method_opener_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_opener_procname);
end;

function ERR_UI_method_set_writer(method: PUI_Method;
  writer: UI_method_writer_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_writer_procname);
end;

function ERR_UI_method_set_flusher(method: PUI_Method;
  flusher: UI_method_flusher_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_flusher_procname);
end;

function ERR_UI_method_set_reader(method: PUI_Method;
  reader: UI_method_reader_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_reader_procname);
end;

function ERR_UI_method_set_closer(method: PUI_Method;
  closer: UI_method_closer_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_closer_procname);
end;

function ERR_UI_method_set_data_duplicator(method: PUI_Method;
  duplicator: UI_method_data_duplicator_cb;
  destructor_: UI_method_data_destructor_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (UI_method_set_data_duplicator_procname);
end;

function ERR_UI_method_set_prompt_constructor(method: PUI_Method;
  prompt_constructor: UI_method_prompt_constructor_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (UI_method_set_prompt_constructor_procname);
end;

function ERR_UI_method_set_ex_data(method: PUI_Method; idx: TIdC_INT;
  data: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_ex_data_procname);
end;

function ERR_UI_method_get_opener(const method: PUI_Method)
  : UI_method_opener_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_opener_procname);
end;

function ERR_UI_method_get_writer(const method: PUI_Method)
  : UI_method_writer_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_writer_procname);
end;

function ERR_UI_method_get_flusher(const method: PUI_Method)
  : UI_method_flusher_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_flusher_procname);
end;

function ERR_UI_method_get_reader(const method: PUI_Method)
  : UI_method_reader_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_reader_procname);
end;

function ERR_UI_method_get_closer(const method: PUI_Method)
  : UI_method_closer_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_closer_procname);
end;

function ERR_UI_method_get_prompt_constructor(const method: PUI_Method)
  : UI_method_prompt_constructor_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (UI_method_get_prompt_constructor_procname);
end;

function ERR_UI_method_get_data_duplicator(const method: PUI_Method)
  : UI_method_data_duplicator_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (UI_method_get_data_duplicator_procname);
end;

function ERR_UI_method_get_data_destructor(const method: PUI_Method)
  : UI_method_data_destructor_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (UI_method_get_data_destructor_procname);
end;

function ERR_UI_method_get_ex_data(const method: PUI_Method; idx: TIdC_INT)
  : Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_ex_data_procname);
end;

(*
  * The following functions are helpers for method writers to access relevant
  * data from a UI_STRING.
*)

(* Return type of the UI_STRING *)
function ERR_UI_get_string_type(uis: PUI_STRING): UI_string_type; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_string_type_procname);
end;

(* Return input flags of the UI_STRING *)
function ERR_UI_get_input_flags(uis: PUI_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_input_flags_procname);
end;

(* Return the actual string to output (the prompt, info or error) *)
function ERR_UI_get0_output_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_output_string_procname);
end;

(*
  * Return the optional action string to output (the boolean prompt
  * instruction)
*)
function ERR_UI_get0_action_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_action_string_procname);
end;

(* Return the result of a prompt *)
function ERR_UI_get0_result_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_result_string_procname);
end;

function ERR_UI_get_result_string_length(uis: PUI_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_string_length_procname);
end;

(*
  * Return the string to test the result against.  Only useful with verifies.
*)
function ERR_UI_get0_test_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_test_string_procname);
end;

(* Return the required minimum size of the result *)
function ERR_UI_get_result_minsize(uis: PUI_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_minsize_procname);
end;

(* Return the required maximum size of the result *)
function ERR_UI_get_result_maxsize(uis: PUI_STRING): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_maxsize_procname);
end;

(* Set the result of a UI_STRING. *)
function ERR_UI_set_result(ui: PUI; uis: PUI_STRING; const _result: PIdAnsiChar)
  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_result_procname);
end;

function ERR_UI_set_result_ex(ui: PUI; uis: PUI_STRING;
  const _result: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_result_ex_procname);
end;

(* A couple of popular utility functions *)
function ERR_UI_UTIL_read_pw_string(buf: PIdAnsiChar; _length: TIdC_INT;
  const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_UTIL_read_pw_string_procname);
end;

function ERR_UI_UTIL_read_pw(buf: PIdAnsiChar; buff: PIdAnsiChar;
  size: TIdC_INT; const prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_UTIL_read_pw_procname);
end;

function ERR_UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb;
  rwflag: TIdC_INT): PUI_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (UI_UTIL_wrap_read_pem_callback_procname);
end;


  {$I TaurusTLSNoRetValOn.inc}
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);

var
  FuncLoadError: boolean;

begin
  UI_new := LoadLibFunction(ADllHandle, UI_new_procname);
  FuncLoadError := not assigned(UI_new);
  if FuncLoadError then
  begin
{$IF not defined(UI_new_allownil)}
    UI_new := ERR_UI_new;
{$IFEND}
{$IF declared(UI_new_introduced)}
    if LibVersion < UI_new_introduced then
    begin
{$IF declared(FC_UI_new)}
      UI_new := FC_UI_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_new_removed)}
    if UI_new_removed <= LibVersion then
    begin
{$IF declared(_UI_new)}
      UI_new := _UI_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_new_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_new');
{$IFEND}
  end;

  UI_new_method := LoadLibFunction(ADllHandle, UI_new_method_procname);
  FuncLoadError := not assigned(UI_new_method);
  if FuncLoadError then
  begin
{$IF not defined(UI_new_method_allownil)}
    UI_new_method := ERR_UI_new_method;
{$IFEND}
{$IF declared(UI_new_method_introduced)}
    if LibVersion < UI_new_method_introduced then
    begin
{$IF declared(FC_UI_new_method)}
      UI_new_method := FC_UI_new_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_new_method_removed)}
    if UI_new_method_removed <= LibVersion then
    begin
{$IF declared(_UI_new_method)}
      UI_new_method := _UI_new_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_new_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_new_method');
{$IFEND}
  end;

  UI_free := LoadLibFunction(ADllHandle, UI_free_procname);
  FuncLoadError := not assigned(UI_free);
  if FuncLoadError then
  begin
{$IF not defined(UI_free_allownil)}
    UI_free := ERR_UI_free;
{$IFEND}
{$IF declared(UI_free_introduced)}
    if LibVersion < UI_free_introduced then
    begin
{$IF declared(FC_UI_free)}
      UI_free := FC_UI_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_free_removed)}
    if UI_free_removed <= LibVersion then
    begin
{$IF declared(_UI_free)}
      UI_free := _UI_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_free_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_free');
{$IFEND}
  end;

  UI_add_input_string := LoadLibFunction(ADllHandle,
    UI_add_input_string_procname);
  FuncLoadError := not assigned(UI_add_input_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_add_input_string_allownil)}
    UI_add_input_string := ERR_UI_add_input_string;
{$IFEND}
{$IF declared(UI_add_input_string_introduced)}
    if LibVersion < UI_add_input_string_introduced then
    begin
{$IF declared(FC_UI_add_input_string)}
      UI_add_input_string := FC_UI_add_input_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_add_input_string_removed)}
    if UI_add_input_string_removed <= LibVersion then
    begin
{$IF declared(_UI_add_input_string)}
      UI_add_input_string := _UI_add_input_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_add_input_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_input_string');
{$IFEND}
  end;

  UI_dup_input_string := LoadLibFunction(ADllHandle,
    UI_dup_input_string_procname);
  FuncLoadError := not assigned(UI_dup_input_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_dup_input_string_allownil)}
    UI_dup_input_string := ERR_UI_dup_input_string;
{$IFEND}
{$IF declared(UI_dup_input_string_introduced)}
    if LibVersion < UI_dup_input_string_introduced then
    begin
{$IF declared(FC_UI_dup_input_string)}
      UI_dup_input_string := FC_UI_dup_input_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_dup_input_string_removed)}
    if UI_dup_input_string_removed <= LibVersion then
    begin
{$IF declared(_UI_dup_input_string)}
      UI_dup_input_string := _UI_dup_input_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_dup_input_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_input_string');
{$IFEND}
  end;

  UI_add_verify_string := LoadLibFunction(ADllHandle,
    UI_add_verify_string_procname);
  FuncLoadError := not assigned(UI_add_verify_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_add_verify_string_allownil)}
    UI_add_verify_string := ERR_UI_add_verify_string;
{$IFEND}
{$IF declared(UI_add_verify_string_introduced)}
    if LibVersion < UI_add_verify_string_introduced then
    begin
{$IF declared(FC_UI_add_verify_string)}
      UI_add_verify_string := FC_UI_add_verify_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_add_verify_string_removed)}
    if UI_add_verify_string_removed <= LibVersion then
    begin
{$IF declared(_UI_add_verify_string)}
      UI_add_verify_string := _UI_add_verify_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_add_verify_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_verify_string');
{$IFEND}
  end;

  UI_dup_verify_string := LoadLibFunction(ADllHandle,
    UI_dup_verify_string_procname);
  FuncLoadError := not assigned(UI_dup_verify_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_dup_verify_string_allownil)}
    UI_dup_verify_string := ERR_UI_dup_verify_string;
{$IFEND}
{$IF declared(UI_dup_verify_string_introduced)}
    if LibVersion < UI_dup_verify_string_introduced then
    begin
{$IF declared(FC_UI_dup_verify_string)}
      UI_dup_verify_string := FC_UI_dup_verify_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_dup_verify_string_removed)}
    if UI_dup_verify_string_removed <= LibVersion then
    begin
{$IF declared(_UI_dup_verify_string)}
      UI_dup_verify_string := _UI_dup_verify_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_dup_verify_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_verify_string');
{$IFEND}
  end;

  UI_add_input_boolean := LoadLibFunction(ADllHandle,
    UI_add_input_boolean_procname);
  FuncLoadError := not assigned(UI_add_input_boolean);
  if FuncLoadError then
  begin
{$IF not defined(UI_add_input_boolean_allownil)}
    UI_add_input_boolean := ERR_UI_add_input_boolean;
{$IFEND}
{$IF declared(UI_add_input_boolean_introduced)}
    if LibVersion < UI_add_input_boolean_introduced then
    begin
{$IF declared(FC_UI_add_input_boolean)}
      UI_add_input_boolean := FC_UI_add_input_boolean;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_add_input_boolean_removed)}
    if UI_add_input_boolean_removed <= LibVersion then
    begin
{$IF declared(_UI_add_input_boolean)}
      UI_add_input_boolean := _UI_add_input_boolean;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_add_input_boolean_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_input_boolean');
{$IFEND}
  end;

  UI_dup_input_boolean := LoadLibFunction(ADllHandle,
    UI_dup_input_boolean_procname);
  FuncLoadError := not assigned(UI_dup_input_boolean);
  if FuncLoadError then
  begin
{$IF not defined(UI_dup_input_boolean_allownil)}
    UI_dup_input_boolean := ERR_UI_dup_input_boolean;
{$IFEND}
{$IF declared(UI_dup_input_boolean_introduced)}
    if LibVersion < UI_dup_input_boolean_introduced then
    begin
{$IF declared(FC_UI_dup_input_boolean)}
      UI_dup_input_boolean := FC_UI_dup_input_boolean;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_dup_input_boolean_removed)}
    if UI_dup_input_boolean_removed <= LibVersion then
    begin
{$IF declared(_UI_dup_input_boolean)}
      UI_dup_input_boolean := _UI_dup_input_boolean;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_dup_input_boolean_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_input_boolean');
{$IFEND}
  end;

  UI_add_info_string := LoadLibFunction(ADllHandle,
    UI_add_info_string_procname);
  FuncLoadError := not assigned(UI_add_info_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_add_info_string_allownil)}
    UI_add_info_string := ERR_UI_add_info_string;
{$IFEND}
{$IF declared(UI_add_info_string_introduced)}
    if LibVersion < UI_add_info_string_introduced then
    begin
{$IF declared(FC_UI_add_info_string)}
      UI_add_info_string := FC_UI_add_info_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_add_info_string_removed)}
    if UI_add_info_string_removed <= LibVersion then
    begin
{$IF declared(_UI_add_info_string)}
      UI_add_info_string := _UI_add_info_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_add_info_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_info_string');
{$IFEND}
  end;

  UI_dup_info_string := LoadLibFunction(ADllHandle,
    UI_dup_info_string_procname);
  FuncLoadError := not assigned(UI_dup_info_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_dup_info_string_allownil)}
    UI_dup_info_string := ERR_UI_dup_info_string;
{$IFEND}
{$IF declared(UI_dup_info_string_introduced)}
    if LibVersion < UI_dup_info_string_introduced then
    begin
{$IF declared(FC_UI_dup_info_string)}
      UI_dup_info_string := FC_UI_dup_info_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_dup_info_string_removed)}
    if UI_dup_info_string_removed <= LibVersion then
    begin
{$IF declared(_UI_dup_info_string)}
      UI_dup_info_string := _UI_dup_info_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_dup_info_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_info_string');
{$IFEND}
  end;

  UI_add_error_string := LoadLibFunction(ADllHandle,
    UI_add_error_string_procname);
  FuncLoadError := not assigned(UI_add_error_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_add_error_string_allownil)}
    UI_add_error_string := ERR_UI_add_error_string;
{$IFEND}
{$IF declared(UI_add_error_string_introduced)}
    if LibVersion < UI_add_error_string_introduced then
    begin
{$IF declared(FC_UI_add_error_string)}
      UI_add_error_string := FC_UI_add_error_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_add_error_string_removed)}
    if UI_add_error_string_removed <= LibVersion then
    begin
{$IF declared(_UI_add_error_string)}
      UI_add_error_string := _UI_add_error_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_add_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_error_string');
{$IFEND}
  end;

  UI_dup_error_string := LoadLibFunction(ADllHandle,
    UI_dup_error_string_procname);
  FuncLoadError := not assigned(UI_dup_error_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_dup_error_string_allownil)}
    UI_dup_error_string := ERR_UI_dup_error_string;
{$IFEND}
{$IF declared(UI_dup_error_string_introduced)}
    if LibVersion < UI_dup_error_string_introduced then
    begin
{$IF declared(FC_UI_dup_error_string)}
      UI_dup_error_string := FC_UI_dup_error_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_dup_error_string_removed)}
    if UI_dup_error_string_removed <= LibVersion then
    begin
{$IF declared(_UI_dup_error_string)}
      UI_dup_error_string := _UI_dup_error_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_dup_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_error_string');
{$IFEND}
  end;

  UI_construct_prompt := LoadLibFunction(ADllHandle,
    UI_construct_prompt_procname);
  FuncLoadError := not assigned(UI_construct_prompt);
  if FuncLoadError then
  begin
{$IF not defined(UI_construct_prompt_allownil)}
    UI_construct_prompt := ERR_UI_construct_prompt;
{$IFEND}
{$IF declared(UI_construct_prompt_introduced)}
    if LibVersion < UI_construct_prompt_introduced then
    begin
{$IF declared(FC_UI_construct_prompt)}
      UI_construct_prompt := FC_UI_construct_prompt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_construct_prompt_removed)}
    if UI_construct_prompt_removed <= LibVersion then
    begin
{$IF declared(_UI_construct_prompt)}
      UI_construct_prompt := _UI_construct_prompt;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_construct_prompt_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_construct_prompt');
{$IFEND}
  end;

  UI_add_user_data := LoadLibFunction(ADllHandle, UI_add_user_data_procname);
  FuncLoadError := not assigned(UI_add_user_data);
  if FuncLoadError then
  begin
{$IF not defined(UI_add_user_data_allownil)}
    UI_add_user_data := ERR_UI_add_user_data;
{$IFEND}
{$IF declared(UI_add_user_data_introduced)}
    if LibVersion < UI_add_user_data_introduced then
    begin
{$IF declared(FC_UI_add_user_data)}
      UI_add_user_data := FC_UI_add_user_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_add_user_data_removed)}
    if UI_add_user_data_removed <= LibVersion then
    begin
{$IF declared(_UI_add_user_data)}
      UI_add_user_data := _UI_add_user_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_add_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_user_data');
{$IFEND}
  end;

  UI_dup_user_data := LoadLibFunction(ADllHandle, UI_dup_user_data_procname);
  FuncLoadError := not assigned(UI_dup_user_data);
  if FuncLoadError then
  begin
{$IF not defined(UI_dup_user_data_allownil)}
    UI_dup_user_data := ERR_UI_dup_user_data;
{$IFEND}
{$IF declared(UI_dup_user_data_introduced)}
    if LibVersion < UI_dup_user_data_introduced then
    begin
{$IF declared(FC_UI_dup_user_data)}
      UI_dup_user_data := FC_UI_dup_user_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_dup_user_data_removed)}
    if UI_dup_user_data_removed <= LibVersion then
    begin
{$IF declared(_UI_dup_user_data)}
      UI_dup_user_data := _UI_dup_user_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_dup_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_user_data');
{$IFEND}
  end;

  UI_get0_user_data := LoadLibFunction(ADllHandle, UI_get0_user_data_procname);
  FuncLoadError := not assigned(UI_get0_user_data);
  if FuncLoadError then
  begin
{$IF not defined(UI_get0_user_data_allownil)}
    UI_get0_user_data := ERR_UI_get0_user_data;
{$IFEND}
{$IF declared(UI_get0_user_data_introduced)}
    if LibVersion < UI_get0_user_data_introduced then
    begin
{$IF declared(FC_UI_get0_user_data)}
      UI_get0_user_data := FC_UI_get0_user_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get0_user_data_removed)}
    if UI_get0_user_data_removed <= LibVersion then
    begin
{$IF declared(_UI_get0_user_data)}
      UI_get0_user_data := _UI_get0_user_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get0_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_user_data');
{$IFEND}
  end;

  UI_get0_result := LoadLibFunction(ADllHandle, UI_get0_result_procname);
  FuncLoadError := not assigned(UI_get0_result);
  if FuncLoadError then
  begin
{$IF not defined(UI_get0_result_allownil)}
    UI_get0_result := ERR_UI_get0_result;
{$IFEND}
{$IF declared(UI_get0_result_introduced)}
    if LibVersion < UI_get0_result_introduced then
    begin
{$IF declared(FC_UI_get0_result)}
      UI_get0_result := FC_UI_get0_result;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get0_result_removed)}
    if UI_get0_result_removed <= LibVersion then
    begin
{$IF declared(_UI_get0_result)}
      UI_get0_result := _UI_get0_result;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get0_result_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_result');
{$IFEND}
  end;

  UI_get_result_length := LoadLibFunction(ADllHandle,
    UI_get_result_length_procname);
  FuncLoadError := not assigned(UI_get_result_length);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_result_length_allownil)}
    UI_get_result_length := ERR_UI_get_result_length;
{$IFEND}
{$IF declared(UI_get_result_length_introduced)}
    if LibVersion < UI_get_result_length_introduced then
    begin
{$IF declared(FC_UI_get_result_length)}
      UI_get_result_length := FC_UI_get_result_length;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_result_length_removed)}
    if UI_get_result_length_removed <= LibVersion then
    begin
{$IF declared(_UI_get_result_length)}
      UI_get_result_length := _UI_get_result_length;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_result_length_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_length');
{$IFEND}
  end;

  UI_process := LoadLibFunction(ADllHandle, UI_process_procname);
  FuncLoadError := not assigned(UI_process);
  if FuncLoadError then
  begin
{$IF not defined(UI_process_allownil)}
    UI_process := ERR_UI_process;
{$IFEND}
{$IF declared(UI_process_introduced)}
    if LibVersion < UI_process_introduced then
    begin
{$IF declared(FC_UI_process)}
      UI_process := FC_UI_process;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_process_removed)}
    if UI_process_removed <= LibVersion then
    begin
{$IF declared(_UI_process)}
      UI_process := _UI_process;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_process_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_process');
{$IFEND}
  end;

  UI_ctrl := LoadLibFunction(ADllHandle, UI_ctrl_procname);
  FuncLoadError := not assigned(UI_ctrl);
  if FuncLoadError then
  begin
{$IF not defined(UI_ctrl_allownil)}
    UI_ctrl := ERR_UI_ctrl;
{$IFEND}
{$IF declared(UI_ctrl_introduced)}
    if LibVersion < UI_ctrl_introduced then
    begin
{$IF declared(FC_UI_ctrl)}
      UI_ctrl := FC_UI_ctrl;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_ctrl_removed)}
    if UI_ctrl_removed <= LibVersion then
    begin
{$IF declared(_UI_ctrl)}
      UI_ctrl := _UI_ctrl;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_ctrl');
{$IFEND}
  end;

  UI_set_ex_data := LoadLibFunction(ADllHandle, UI_set_ex_data_procname);
  FuncLoadError := not assigned(UI_set_ex_data);
  if FuncLoadError then
  begin
{$IF not defined(UI_set_ex_data_allownil)}
    UI_set_ex_data := ERR_UI_set_ex_data;
{$IFEND}
{$IF declared(UI_set_ex_data_introduced)}
    if LibVersion < UI_set_ex_data_introduced then
    begin
{$IF declared(FC_UI_set_ex_data)}
      UI_set_ex_data := FC_UI_set_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_set_ex_data_removed)}
    if UI_set_ex_data_removed <= LibVersion then
    begin
{$IF declared(_UI_set_ex_data)}
      UI_set_ex_data := _UI_set_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_ex_data');
{$IFEND}
  end;

  UI_get_ex_data := LoadLibFunction(ADllHandle, UI_get_ex_data_procname);
  FuncLoadError := not assigned(UI_get_ex_data);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_ex_data_allownil)}
    UI_get_ex_data := ERR_UI_get_ex_data;
{$IFEND}
{$IF declared(UI_get_ex_data_introduced)}
    if LibVersion < UI_get_ex_data_introduced then
    begin
{$IF declared(FC_UI_get_ex_data)}
      UI_get_ex_data := FC_UI_get_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_ex_data_removed)}
    if UI_get_ex_data_removed <= LibVersion then
    begin
{$IF declared(_UI_get_ex_data)}
      UI_get_ex_data := _UI_get_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_ex_data');
{$IFEND}
  end;

  UI_set_default_method := LoadLibFunction(ADllHandle,
    UI_set_default_method_procname);
  FuncLoadError := not assigned(UI_set_default_method);
  if FuncLoadError then
  begin
{$IF not defined(UI_set_default_method_allownil)}
    UI_set_default_method := ERR_UI_set_default_method;
{$IFEND}
{$IF declared(UI_set_default_method_introduced)}
    if LibVersion < UI_set_default_method_introduced then
    begin
{$IF declared(FC_UI_set_default_method)}
      UI_set_default_method := FC_UI_set_default_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_set_default_method_removed)}
    if UI_set_default_method_removed <= LibVersion then
    begin
{$IF declared(_UI_set_default_method)}
      UI_set_default_method := _UI_set_default_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_default_method');
{$IFEND}
  end;

  UI_get_default_method := LoadLibFunction(ADllHandle,
    UI_get_default_method_procname);
  FuncLoadError := not assigned(UI_get_default_method);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_default_method_allownil)}
    UI_get_default_method := ERR_UI_get_default_method;
{$IFEND}
{$IF declared(UI_get_default_method_introduced)}
    if LibVersion < UI_get_default_method_introduced then
    begin
{$IF declared(FC_UI_get_default_method)}
      UI_get_default_method := FC_UI_get_default_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_default_method_removed)}
    if UI_get_default_method_removed <= LibVersion then
    begin
{$IF declared(_UI_get_default_method)}
      UI_get_default_method := _UI_get_default_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_default_method');
{$IFEND}
  end;

  UI_get_method := LoadLibFunction(ADllHandle, UI_get_method_procname);
  FuncLoadError := not assigned(UI_get_method);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_method_allownil)}
    UI_get_method := ERR_UI_get_method;
{$IFEND}
{$IF declared(UI_get_method_introduced)}
    if LibVersion < UI_get_method_introduced then
    begin
{$IF declared(FC_UI_get_method)}
      UI_get_method := FC_UI_get_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_method_removed)}
    if UI_get_method_removed <= LibVersion then
    begin
{$IF declared(_UI_get_method)}
      UI_get_method := _UI_get_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_method');
{$IFEND}
  end;

  UI_set_method := LoadLibFunction(ADllHandle, UI_set_method_procname);
  FuncLoadError := not assigned(UI_set_method);
  if FuncLoadError then
  begin
{$IF not defined(UI_set_method_allownil)}
    UI_set_method := ERR_UI_set_method;
{$IFEND}
{$IF declared(UI_set_method_introduced)}
    if LibVersion < UI_set_method_introduced then
    begin
{$IF declared(FC_UI_set_method)}
      UI_set_method := FC_UI_set_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_set_method_removed)}
    if UI_set_method_removed <= LibVersion then
    begin
{$IF declared(_UI_set_method)}
      UI_set_method := _UI_set_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_set_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_method');
{$IFEND}
  end;

  UI_TaurusTLS := LoadLibFunction(ADllHandle, UI_TaurusTLS_procname);
  FuncLoadError := not assigned(UI_TaurusTLS);
  if FuncLoadError then
  begin
{$IF not defined(UI_TaurusTLS_allownil)}
    UI_TaurusTLS := ERR_UI_TaurusTLS;
{$IFEND}
{$IF declared(UI_TaurusTLS_introduced)}
    if LibVersion < UI_TaurusTLS_introduced then
    begin
{$IF declared(FC_UI_TaurusTLS)}
      UI_TaurusTLS := FC_UI_TaurusTLS;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_TaurusTLS_removed)}
    if UI_TaurusTLS_removed <= LibVersion then
    begin
{$IF declared(_UI_TaurusTLS)}
      UI_TaurusTLS := _UI_TaurusTLS;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_TaurusTLS_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_TaurusTLS');
{$IFEND}
  end;

  UI_null := LoadLibFunction(ADllHandle, UI_null_procname);
  FuncLoadError := not assigned(UI_null);
  if FuncLoadError then
  begin
{$IF not defined(UI_null_allownil)}
    UI_null := ERR_UI_null;
{$IFEND}
{$IF declared(UI_null_introduced)}
    if LibVersion < UI_null_introduced then
    begin
{$IF declared(FC_UI_null)}
      UI_null := FC_UI_null;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_null_removed)}
    if UI_null_removed <= LibVersion then
    begin
{$IF declared(_UI_null)}
      UI_null := _UI_null;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_null_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_null');
{$IFEND}
  end;

  UI_create_method := LoadLibFunction(ADllHandle, UI_create_method_procname);
  FuncLoadError := not assigned(UI_create_method);
  if FuncLoadError then
  begin
{$IF not defined(UI_create_method_allownil)}
    UI_create_method := ERR_UI_create_method;
{$IFEND}
{$IF declared(UI_create_method_introduced)}
    if LibVersion < UI_create_method_introduced then
    begin
{$IF declared(FC_UI_create_method)}
      UI_create_method := FC_UI_create_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_create_method_removed)}
    if UI_create_method_removed <= LibVersion then
    begin
{$IF declared(_UI_create_method)}
      UI_create_method := _UI_create_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_create_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_create_method');
{$IFEND}
  end;

  UI_destroy_method := LoadLibFunction(ADllHandle, UI_destroy_method_procname);
  FuncLoadError := not assigned(UI_destroy_method);
  if FuncLoadError then
  begin
{$IF not defined(UI_destroy_method_allownil)}
    UI_destroy_method := ERR_UI_destroy_method;
{$IFEND}
{$IF declared(UI_destroy_method_introduced)}
    if LibVersion < UI_destroy_method_introduced then
    begin
{$IF declared(FC_UI_destroy_method)}
      UI_destroy_method := FC_UI_destroy_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_destroy_method_removed)}
    if UI_destroy_method_removed <= LibVersion then
    begin
{$IF declared(_UI_destroy_method)}
      UI_destroy_method := _UI_destroy_method;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_destroy_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_destroy_method');
{$IFEND}
  end;

  UI_method_set_opener := LoadLibFunction(ADllHandle,
    UI_method_set_opener_procname);
  FuncLoadError := not assigned(UI_method_set_opener);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_opener_allownil)}
    UI_method_set_opener := ERR_UI_method_set_opener;
{$IFEND}
{$IF declared(UI_method_set_opener_introduced)}
    if LibVersion < UI_method_set_opener_introduced then
    begin
{$IF declared(FC_UI_method_set_opener)}
      UI_method_set_opener := FC_UI_method_set_opener;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_opener_removed)}
    if UI_method_set_opener_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_opener)}
      UI_method_set_opener := _UI_method_set_opener;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_opener_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_opener');
{$IFEND}
  end;

  UI_method_set_writer := LoadLibFunction(ADllHandle,
    UI_method_set_writer_procname);
  FuncLoadError := not assigned(UI_method_set_writer);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_writer_allownil)}
    UI_method_set_writer := ERR_UI_method_set_writer;
{$IFEND}
{$IF declared(UI_method_set_writer_introduced)}
    if LibVersion < UI_method_set_writer_introduced then
    begin
{$IF declared(FC_UI_method_set_writer)}
      UI_method_set_writer := FC_UI_method_set_writer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_writer_removed)}
    if UI_method_set_writer_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_writer)}
      UI_method_set_writer := _UI_method_set_writer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_writer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_writer');
{$IFEND}
  end;

  UI_method_set_flusher := LoadLibFunction(ADllHandle,
    UI_method_set_flusher_procname);
  FuncLoadError := not assigned(UI_method_set_flusher);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_flusher_allownil)}
    UI_method_set_flusher := ERR_UI_method_set_flusher;
{$IFEND}
{$IF declared(UI_method_set_flusher_introduced)}
    if LibVersion < UI_method_set_flusher_introduced then
    begin
{$IF declared(FC_UI_method_set_flusher)}
      UI_method_set_flusher := FC_UI_method_set_flusher;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_flusher_removed)}
    if UI_method_set_flusher_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_flusher)}
      UI_method_set_flusher := _UI_method_set_flusher;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_flusher_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_flusher');
{$IFEND}
  end;

  UI_method_set_reader := LoadLibFunction(ADllHandle,
    UI_method_set_reader_procname);
  FuncLoadError := not assigned(UI_method_set_reader);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_reader_allownil)}
    UI_method_set_reader := ERR_UI_method_set_reader;
{$IFEND}
{$IF declared(UI_method_set_reader_introduced)}
    if LibVersion < UI_method_set_reader_introduced then
    begin
{$IF declared(FC_UI_method_set_reader)}
      UI_method_set_reader := FC_UI_method_set_reader;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_reader_removed)}
    if UI_method_set_reader_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_reader)}
      UI_method_set_reader := _UI_method_set_reader;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_reader_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_reader');
{$IFEND}
  end;

  UI_method_set_closer := LoadLibFunction(ADllHandle,
    UI_method_set_closer_procname);
  FuncLoadError := not assigned(UI_method_set_closer);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_closer_allownil)}
    UI_method_set_closer := ERR_UI_method_set_closer;
{$IFEND}
{$IF declared(UI_method_set_closer_introduced)}
    if LibVersion < UI_method_set_closer_introduced then
    begin
{$IF declared(FC_UI_method_set_closer)}
      UI_method_set_closer := FC_UI_method_set_closer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_closer_removed)}
    if UI_method_set_closer_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_closer)}
      UI_method_set_closer := _UI_method_set_closer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_closer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_closer');
{$IFEND}
  end;

  UI_method_set_data_duplicator := LoadLibFunction(ADllHandle,
    UI_method_set_data_duplicator_procname);
  FuncLoadError := not assigned(UI_method_set_data_duplicator);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_data_duplicator_allownil)}
    UI_method_set_data_duplicator := ERR_UI_method_set_data_duplicator;
{$IFEND}
{$IF declared(UI_method_set_data_duplicator_introduced)}
    if LibVersion < UI_method_set_data_duplicator_introduced then
    begin
{$IF declared(FC_UI_method_set_data_duplicator)}
      UI_method_set_data_duplicator := FC_UI_method_set_data_duplicator;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_data_duplicator_removed)}
    if UI_method_set_data_duplicator_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_data_duplicator)}
      UI_method_set_data_duplicator := _UI_method_set_data_duplicator;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_data_duplicator_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_data_duplicator');
{$IFEND}
  end;

  UI_method_set_prompt_constructor := LoadLibFunction(ADllHandle,
    UI_method_set_prompt_constructor_procname);
  FuncLoadError := not assigned(UI_method_set_prompt_constructor);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_prompt_constructor_allownil)}
    UI_method_set_prompt_constructor := ERR_UI_method_set_prompt_constructor;
{$IFEND}
{$IF declared(UI_method_set_prompt_constructor_introduced)}
    if LibVersion < UI_method_set_prompt_constructor_introduced then
    begin
{$IF declared(FC_UI_method_set_prompt_constructor)}
      UI_method_set_prompt_constructor := FC_UI_method_set_prompt_constructor;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_prompt_constructor_removed)}
    if UI_method_set_prompt_constructor_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_prompt_constructor)}
      UI_method_set_prompt_constructor := _UI_method_set_prompt_constructor;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_prompt_constructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_prompt_constructor');
{$IFEND}
  end;

  UI_method_set_ex_data := LoadLibFunction(ADllHandle,
    UI_method_set_ex_data_procname);
  FuncLoadError := not assigned(UI_method_set_ex_data);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_set_ex_data_allownil)}
    UI_method_set_ex_data := ERR_UI_method_set_ex_data;
{$IFEND}
{$IF declared(UI_method_set_ex_data_introduced)}
    if LibVersion < UI_method_set_ex_data_introduced then
    begin
{$IF declared(FC_UI_method_set_ex_data)}
      UI_method_set_ex_data := FC_UI_method_set_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_set_ex_data_removed)}
    if UI_method_set_ex_data_removed <= LibVersion then
    begin
{$IF declared(_UI_method_set_ex_data)}
      UI_method_set_ex_data := _UI_method_set_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_ex_data');
{$IFEND}
  end;

  UI_method_get_opener := LoadLibFunction(ADllHandle,
    UI_method_get_opener_procname);
  FuncLoadError := not assigned(UI_method_get_opener);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_opener_allownil)}
    UI_method_get_opener := ERR_UI_method_get_opener;
{$IFEND}
{$IF declared(UI_method_get_opener_introduced)}
    if LibVersion < UI_method_get_opener_introduced then
    begin
{$IF declared(FC_UI_method_get_opener)}
      UI_method_get_opener := FC_UI_method_get_opener;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_opener_removed)}
    if UI_method_get_opener_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_opener)}
      UI_method_get_opener := _UI_method_get_opener;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_opener_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_opener');
{$IFEND}
  end;

  UI_method_get_writer := LoadLibFunction(ADllHandle,
    UI_method_get_writer_procname);
  FuncLoadError := not assigned(UI_method_get_writer);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_writer_allownil)}
    UI_method_get_writer := ERR_UI_method_get_writer;
{$IFEND}
{$IF declared(UI_method_get_writer_introduced)}
    if LibVersion < UI_method_get_writer_introduced then
    begin
{$IF declared(FC_UI_method_get_writer)}
      UI_method_get_writer := FC_UI_method_get_writer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_writer_removed)}
    if UI_method_get_writer_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_writer)}
      UI_method_get_writer := _UI_method_get_writer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_writer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_writer');
{$IFEND}
  end;

  UI_method_get_flusher := LoadLibFunction(ADllHandle,
    UI_method_get_flusher_procname);
  FuncLoadError := not assigned(UI_method_get_flusher);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_flusher_allownil)}
    UI_method_get_flusher := ERR_UI_method_get_flusher;
{$IFEND}
{$IF declared(UI_method_get_flusher_introduced)}
    if LibVersion < UI_method_get_flusher_introduced then
    begin
{$IF declared(FC_UI_method_get_flusher)}
      UI_method_get_flusher := FC_UI_method_get_flusher;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_flusher_removed)}
    if UI_method_get_flusher_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_flusher)}
      UI_method_get_flusher := _UI_method_get_flusher;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_flusher_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_flusher');
{$IFEND}
  end;

  UI_method_get_reader := LoadLibFunction(ADllHandle,
    UI_method_get_reader_procname);
  FuncLoadError := not assigned(UI_method_get_reader);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_reader_allownil)}
    UI_method_get_reader := ERR_UI_method_get_reader;
{$IFEND}
{$IF declared(UI_method_get_reader_introduced)}
    if LibVersion < UI_method_get_reader_introduced then
    begin
{$IF declared(FC_UI_method_get_reader)}
      UI_method_get_reader := FC_UI_method_get_reader;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_reader_removed)}
    if UI_method_get_reader_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_reader)}
      UI_method_get_reader := _UI_method_get_reader;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_reader_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_reader');
{$IFEND}
  end;

  UI_method_get_closer := LoadLibFunction(ADllHandle,
    UI_method_get_closer_procname);
  FuncLoadError := not assigned(UI_method_get_closer);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_closer_allownil)}
    UI_method_get_closer := ERR_UI_method_get_closer;
{$IFEND}
{$IF declared(UI_method_get_closer_introduced)}
    if LibVersion < UI_method_get_closer_introduced then
    begin
{$IF declared(FC_UI_method_get_closer)}
      UI_method_get_closer := FC_UI_method_get_closer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_closer_removed)}
    if UI_method_get_closer_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_closer)}
      UI_method_get_closer := _UI_method_get_closer;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_closer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_closer');
{$IFEND}
  end;

  UI_method_get_prompt_constructor := LoadLibFunction(ADllHandle,
    UI_method_get_prompt_constructor_procname);
  FuncLoadError := not assigned(UI_method_get_prompt_constructor);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_prompt_constructor_allownil)}
    UI_method_get_prompt_constructor := ERR_UI_method_get_prompt_constructor;
{$IFEND}
{$IF declared(UI_method_get_prompt_constructor_introduced)}
    if LibVersion < UI_method_get_prompt_constructor_introduced then
    begin
{$IF declared(FC_UI_method_get_prompt_constructor)}
      UI_method_get_prompt_constructor := FC_UI_method_get_prompt_constructor;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_prompt_constructor_removed)}
    if UI_method_get_prompt_constructor_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_prompt_constructor)}
      UI_method_get_prompt_constructor := _UI_method_get_prompt_constructor;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_prompt_constructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_prompt_constructor');
{$IFEND}
  end;

  UI_method_get_data_duplicator := LoadLibFunction(ADllHandle,
    UI_method_get_data_duplicator_procname);
  FuncLoadError := not assigned(UI_method_get_data_duplicator);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_data_duplicator_allownil)}
    UI_method_get_data_duplicator := ERR_UI_method_get_data_duplicator;
{$IFEND}
{$IF declared(UI_method_get_data_duplicator_introduced)}
    if LibVersion < UI_method_get_data_duplicator_introduced then
    begin
{$IF declared(FC_UI_method_get_data_duplicator)}
      UI_method_get_data_duplicator := FC_UI_method_get_data_duplicator;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_data_duplicator_removed)}
    if UI_method_get_data_duplicator_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_data_duplicator)}
      UI_method_get_data_duplicator := _UI_method_get_data_duplicator;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_data_duplicator_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_data_duplicator');
{$IFEND}
  end;

  UI_method_get_data_destructor := LoadLibFunction(ADllHandle,
    UI_method_get_data_destructor_procname);
  FuncLoadError := not assigned(UI_method_get_data_destructor);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_data_destructor_allownil)}
    UI_method_get_data_destructor := ERR_UI_method_get_data_destructor;
{$IFEND}
{$IF declared(UI_method_get_data_destructor_introduced)}
    if LibVersion < UI_method_get_data_destructor_introduced then
    begin
{$IF declared(FC_UI_method_get_data_destructor)}
      UI_method_get_data_destructor := FC_UI_method_get_data_destructor;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_data_destructor_removed)}
    if UI_method_get_data_destructor_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_data_destructor)}
      UI_method_get_data_destructor := _UI_method_get_data_destructor;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_data_destructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_data_destructor');
{$IFEND}
  end;

  UI_method_get_ex_data := LoadLibFunction(ADllHandle,
    UI_method_get_ex_data_procname);
  FuncLoadError := not assigned(UI_method_get_ex_data);
  if FuncLoadError then
  begin
{$IF not defined(UI_method_get_ex_data_allownil)}
    UI_method_get_ex_data := ERR_UI_method_get_ex_data;
{$IFEND}
{$IF declared(UI_method_get_ex_data_introduced)}
    if LibVersion < UI_method_get_ex_data_introduced then
    begin
{$IF declared(FC_UI_method_get_ex_data)}
      UI_method_get_ex_data := FC_UI_method_get_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_method_get_ex_data_removed)}
    if UI_method_get_ex_data_removed <= LibVersion then
    begin
{$IF declared(_UI_method_get_ex_data)}
      UI_method_get_ex_data := _UI_method_get_ex_data;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_method_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_ex_data');
{$IFEND}
  end;

  UI_get_string_type := LoadLibFunction(ADllHandle,
    UI_get_string_type_procname);
  FuncLoadError := not assigned(UI_get_string_type);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_string_type_allownil)}
    UI_get_string_type := ERR_UI_get_string_type;
{$IFEND}
{$IF declared(UI_get_string_type_introduced)}
    if LibVersion < UI_get_string_type_introduced then
    begin
{$IF declared(FC_UI_get_string_type)}
      UI_get_string_type := FC_UI_get_string_type;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_string_type_removed)}
    if UI_get_string_type_removed <= LibVersion then
    begin
{$IF declared(_UI_get_string_type)}
      UI_get_string_type := _UI_get_string_type;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_string_type_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_string_type');
{$IFEND}
  end;

  UI_get_input_flags := LoadLibFunction(ADllHandle,
    UI_get_input_flags_procname);
  FuncLoadError := not assigned(UI_get_input_flags);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_input_flags_allownil)}
    UI_get_input_flags := ERR_UI_get_input_flags;
{$IFEND}
{$IF declared(UI_get_input_flags_introduced)}
    if LibVersion < UI_get_input_flags_introduced then
    begin
{$IF declared(FC_UI_get_input_flags)}
      UI_get_input_flags := FC_UI_get_input_flags;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_input_flags_removed)}
    if UI_get_input_flags_removed <= LibVersion then
    begin
{$IF declared(_UI_get_input_flags)}
      UI_get_input_flags := _UI_get_input_flags;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_input_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_input_flags');
{$IFEND}
  end;

  UI_get0_output_string := LoadLibFunction(ADllHandle,
    UI_get0_output_string_procname);
  FuncLoadError := not assigned(UI_get0_output_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_get0_output_string_allownil)}
    UI_get0_output_string := ERR_UI_get0_output_string;
{$IFEND}
{$IF declared(UI_get0_output_string_introduced)}
    if LibVersion < UI_get0_output_string_introduced then
    begin
{$IF declared(FC_UI_get0_output_string)}
      UI_get0_output_string := FC_UI_get0_output_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get0_output_string_removed)}
    if UI_get0_output_string_removed <= LibVersion then
    begin
{$IF declared(_UI_get0_output_string)}
      UI_get0_output_string := _UI_get0_output_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get0_output_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_output_string');
{$IFEND}
  end;

  UI_get0_action_string := LoadLibFunction(ADllHandle,
    UI_get0_action_string_procname);
  FuncLoadError := not assigned(UI_get0_action_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_get0_action_string_allownil)}
    UI_get0_action_string := ERR_UI_get0_action_string;
{$IFEND}
{$IF declared(UI_get0_action_string_introduced)}
    if LibVersion < UI_get0_action_string_introduced then
    begin
{$IF declared(FC_UI_get0_action_string)}
      UI_get0_action_string := FC_UI_get0_action_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get0_action_string_removed)}
    if UI_get0_action_string_removed <= LibVersion then
    begin
{$IF declared(_UI_get0_action_string)}
      UI_get0_action_string := _UI_get0_action_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get0_action_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_action_string');
{$IFEND}
  end;

  UI_get0_result_string := LoadLibFunction(ADllHandle,
    UI_get0_result_string_procname);
  FuncLoadError := not assigned(UI_get0_result_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_get0_result_string_allownil)}
    UI_get0_result_string := ERR_UI_get0_result_string;
{$IFEND}
{$IF declared(UI_get0_result_string_introduced)}
    if LibVersion < UI_get0_result_string_introduced then
    begin
{$IF declared(FC_UI_get0_result_string)}
      UI_get0_result_string := FC_UI_get0_result_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get0_result_string_removed)}
    if UI_get0_result_string_removed <= LibVersion then
    begin
{$IF declared(_UI_get0_result_string)}
      UI_get0_result_string := _UI_get0_result_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get0_result_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_result_string');
{$IFEND}
  end;

  UI_get_result_string_length := LoadLibFunction(ADllHandle,
    UI_get_result_string_length_procname);
  FuncLoadError := not assigned(UI_get_result_string_length);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_result_string_length_allownil)}
    UI_get_result_string_length := ERR_UI_get_result_string_length;
{$IFEND}
{$IF declared(UI_get_result_string_length_introduced)}
    if LibVersion < UI_get_result_string_length_introduced then
    begin
{$IF declared(FC_UI_get_result_string_length)}
      UI_get_result_string_length := FC_UI_get_result_string_length;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_result_string_length_removed)}
    if UI_get_result_string_length_removed <= LibVersion then
    begin
{$IF declared(_UI_get_result_string_length)}
      UI_get_result_string_length := _UI_get_result_string_length;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_result_string_length_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_string_length');
{$IFEND}
  end;

  UI_get0_test_string := LoadLibFunction(ADllHandle,
    UI_get0_test_string_procname);
  FuncLoadError := not assigned(UI_get0_test_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_get0_test_string_allownil)}
    UI_get0_test_string := ERR_UI_get0_test_string;
{$IFEND}
{$IF declared(UI_get0_test_string_introduced)}
    if LibVersion < UI_get0_test_string_introduced then
    begin
{$IF declared(FC_UI_get0_test_string)}
      UI_get0_test_string := FC_UI_get0_test_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get0_test_string_removed)}
    if UI_get0_test_string_removed <= LibVersion then
    begin
{$IF declared(_UI_get0_test_string)}
      UI_get0_test_string := _UI_get0_test_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get0_test_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_test_string');
{$IFEND}
  end;

  UI_get_result_minsize := LoadLibFunction(ADllHandle,
    UI_get_result_minsize_procname);
  FuncLoadError := not assigned(UI_get_result_minsize);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_result_minsize_allownil)}
    UI_get_result_minsize := ERR_UI_get_result_minsize;
{$IFEND}
{$IF declared(UI_get_result_minsize_introduced)}
    if LibVersion < UI_get_result_minsize_introduced then
    begin
{$IF declared(FC_UI_get_result_minsize)}
      UI_get_result_minsize := FC_UI_get_result_minsize;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_result_minsize_removed)}
    if UI_get_result_minsize_removed <= LibVersion then
    begin
{$IF declared(_UI_get_result_minsize)}
      UI_get_result_minsize := _UI_get_result_minsize;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_result_minsize_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_minsize');
{$IFEND}
  end;

  UI_get_result_maxsize := LoadLibFunction(ADllHandle,
    UI_get_result_maxsize_procname);
  FuncLoadError := not assigned(UI_get_result_maxsize);
  if FuncLoadError then
  begin
{$IF not defined(UI_get_result_maxsize_allownil)}
    UI_get_result_maxsize := ERR_UI_get_result_maxsize;
{$IFEND}
{$IF declared(UI_get_result_maxsize_introduced)}
    if LibVersion < UI_get_result_maxsize_introduced then
    begin
{$IF declared(FC_UI_get_result_maxsize)}
      UI_get_result_maxsize := FC_UI_get_result_maxsize;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_get_result_maxsize_removed)}
    if UI_get_result_maxsize_removed <= LibVersion then
    begin
{$IF declared(_UI_get_result_maxsize)}
      UI_get_result_maxsize := _UI_get_result_maxsize;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_get_result_maxsize_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_maxsize');
{$IFEND}
  end;

  UI_set_result := LoadLibFunction(ADllHandle, UI_set_result_procname);
  FuncLoadError := not assigned(UI_set_result);
  if FuncLoadError then
  begin
{$IF not defined(UI_set_result_allownil)}
    UI_set_result := ERR_UI_set_result;
{$IFEND}
{$IF declared(UI_set_result_introduced)}
    if LibVersion < UI_set_result_introduced then
    begin
{$IF declared(FC_UI_set_result)}
      UI_set_result := FC_UI_set_result;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_set_result_removed)}
    if UI_set_result_removed <= LibVersion then
    begin
{$IF declared(_UI_set_result)}
      UI_set_result := _UI_set_result;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_set_result_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_result');
{$IFEND}
  end;

  UI_set_result_ex := LoadLibFunction(ADllHandle, UI_set_result_ex_procname);
  FuncLoadError := not assigned(UI_set_result_ex);
  if FuncLoadError then
  begin
{$IF not defined(UI_set_result_ex_allownil)}
    UI_set_result_ex := ERR_UI_set_result_ex;
{$IFEND}
{$IF declared(UI_set_result_ex_introduced)}
    if LibVersion < UI_set_result_ex_introduced then
    begin
{$IF declared(FC_UI_set_result_ex)}
      UI_set_result_ex := FC_UI_set_result_ex;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_set_result_ex_removed)}
    if UI_set_result_ex_removed <= LibVersion then
    begin
{$IF declared(_UI_set_result_ex)}
      UI_set_result_ex := _UI_set_result_ex;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_set_result_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_result_ex');
{$IFEND}
  end;

  UI_UTIL_read_pw_string := LoadLibFunction(ADllHandle,
    UI_UTIL_read_pw_string_procname);
  FuncLoadError := not assigned(UI_UTIL_read_pw_string);
  if FuncLoadError then
  begin
{$IF not defined(UI_UTIL_read_pw_string_allownil)}
    UI_UTIL_read_pw_string := ERR_UI_UTIL_read_pw_string;
{$IFEND}
{$IF declared(UI_UTIL_read_pw_string_introduced)}
    if LibVersion < UI_UTIL_read_pw_string_introduced then
    begin
{$IF declared(FC_UI_UTIL_read_pw_string)}
      UI_UTIL_read_pw_string := FC_UI_UTIL_read_pw_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_UTIL_read_pw_string_removed)}
    if UI_UTIL_read_pw_string_removed <= LibVersion then
    begin
{$IF declared(_UI_UTIL_read_pw_string)}
      UI_UTIL_read_pw_string := _UI_UTIL_read_pw_string;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_UTIL_read_pw_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_read_pw_string');
{$IFEND}
  end;

  UI_UTIL_read_pw := LoadLibFunction(ADllHandle, UI_UTIL_read_pw_procname);
  FuncLoadError := not assigned(UI_UTIL_read_pw);
  if FuncLoadError then
  begin
{$IF not defined(UI_UTIL_read_pw_allownil)}
    UI_UTIL_read_pw := ERR_UI_UTIL_read_pw;
{$IFEND}
{$IF declared(UI_UTIL_read_pw_introduced)}
    if LibVersion < UI_UTIL_read_pw_introduced then
    begin
{$IF declared(FC_UI_UTIL_read_pw)}
      UI_UTIL_read_pw := FC_UI_UTIL_read_pw;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_UTIL_read_pw_removed)}
    if UI_UTIL_read_pw_removed <= LibVersion then
    begin
{$IF declared(_UI_UTIL_read_pw)}
      UI_UTIL_read_pw := _UI_UTIL_read_pw;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_UTIL_read_pw_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_read_pw');
{$IFEND}
  end;

  UI_UTIL_wrap_read_pem_callback := LoadLibFunction(ADllHandle,
    UI_UTIL_wrap_read_pem_callback_procname);
  FuncLoadError := not assigned(UI_UTIL_wrap_read_pem_callback);
  if FuncLoadError then
  begin
{$IF not defined(UI_UTIL_wrap_read_pem_callback_allownil)}
    UI_UTIL_wrap_read_pem_callback := ERR_UI_UTIL_wrap_read_pem_callback;
{$IFEND}
{$IF declared(UI_UTIL_wrap_read_pem_callback_introduced)}
    if LibVersion < UI_UTIL_wrap_read_pem_callback_introduced then
    begin
{$IF declared(FC_UI_UTIL_wrap_read_pem_callback)}
      UI_UTIL_wrap_read_pem_callback := FC_UI_UTIL_wrap_read_pem_callback;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(UI_UTIL_wrap_read_pem_callback_removed)}
    if UI_UTIL_wrap_read_pem_callback_removed <= LibVersion then
    begin
{$IF declared(_UI_UTIL_wrap_read_pem_callback)}
      UI_UTIL_wrap_read_pem_callback := _UI_UTIL_wrap_read_pem_callback;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(UI_UTIL_wrap_read_pem_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_wrap_read_pem_callback');
{$IFEND}
  end;

end;

procedure Unload;
begin
  UI_new := nil;
  UI_new_method := nil;
  UI_free := nil;
  UI_add_input_string := nil;
  UI_dup_input_string := nil;
  UI_add_verify_string := nil;
  UI_dup_verify_string := nil;
  UI_add_input_boolean := nil;
  UI_dup_input_boolean := nil;
  UI_add_info_string := nil;
  UI_dup_info_string := nil;
  UI_add_error_string := nil;
  UI_dup_error_string := nil;
  UI_construct_prompt := nil;
  UI_add_user_data := nil;
  UI_dup_user_data := nil;
  UI_get0_user_data := nil;
  UI_get0_result := nil;
  UI_get_result_length := nil;
  UI_process := nil;
  UI_ctrl := nil;
  UI_set_ex_data := nil;
  UI_get_ex_data := nil;
  UI_set_default_method := nil;
  UI_get_default_method := nil;
  UI_get_method := nil;
  UI_set_method := nil;
  UI_TaurusTLS := nil;
  UI_null := nil;
  UI_create_method := nil;
  UI_destroy_method := nil;
  UI_method_set_opener := nil;
  UI_method_set_writer := nil;
  UI_method_set_flusher := nil;
  UI_method_set_reader := nil;
  UI_method_set_closer := nil;
  UI_method_set_data_duplicator := nil;
  UI_method_set_prompt_constructor := nil;
  UI_method_set_ex_data := nil;
  UI_method_get_opener := nil;
  UI_method_get_writer := nil;
  UI_method_get_flusher := nil;
  UI_method_get_reader := nil;
  UI_method_get_closer := nil;
  UI_method_get_prompt_constructor := nil;
  UI_method_get_data_duplicator := nil;
  UI_method_get_data_destructor := nil;
  UI_method_get_ex_data := nil;
  UI_get_string_type := nil;
  UI_get_input_flags := nil;
  UI_get0_output_string := nil;
  UI_get0_action_string := nil;
  UI_get0_result_string := nil;
  UI_get_result_string_length := nil;
  UI_get0_test_string := nil;
  UI_get_result_minsize := nil;
  UI_get_result_maxsize := nil;
  UI_set_result := nil;
  UI_set_result_ex := nil;
  UI_UTIL_read_pw_string := nil;
  UI_UTIL_read_pw := nil;
  UI_UTIL_wrap_read_pem_callback := nil;
end;
  {$I TaurusTLSUnusedParamOn.inc}
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization

Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
