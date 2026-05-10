{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2024 - 2025 TaurusTLS Developers, All Rights Reserved       *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}
{$I TaurusTLSCompilerDefines.inc}
/// <summary>
///   Class wrapperers on OpenSSL Random Generator functions.
/// </summary>
unit TaurusTLS_Random;
{$I TaurusTLSLinkDefines.inc}

interface

uses
  Classes,
  SysUtils,
  IdGlobal,
  IdCTypes,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_rand,
  TaurusTLSHeaders_randerr;

type
  ///  <summary>
  ///  The <c>TTaurusTLS_CustomOSSLRandomBytes</c> is generic class
  ///  decalred interface for calling random procedures
  ///  </summary>
  TTaurusTLS_CustomOSSLRandomBytes = class
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FCtx: POSSL_LIB_CTX;
    FStrength: TIdC_UINT;
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    ///  <summary>
    ///  The <c>DoRandom</c> is abstact method generates random
    ///  sequence of bytes.
    ///  </summary>
    ///  <param name="ctx">
    ///  Valid pointer to the <c>openssl</c> library context
    ///  or <c>nil</c> value for default library context
    ///  <remark>
    ///  This parameters takes effect with the <c>openssl 3.0</c> and higher
    ///  It ignores if application use <c>openssl 1.1.x</c>
    ///  </remark>
    ///  </param>
    ///  <param name="buf">
    ///  Untyped variable to be filled with random bytes
    ///  </param>
    ///  <param name="num">
    ///  Number of bytes to be filled to the <c>buf</c> /> parameter
    ///  </param>
    ///  <param name="strength">
    ///  Cryptography strength used for generating random bytes sequence
    ///  <c>openssl</c>currently supports strength level up to 256 (which is default)
    ///  <see cref="TaurusTLSHeaders_rand.RAND_DEFAULT_STRENGTH" />
    ///  <remark>
    ///  This parameters takes effect with the <c>openssl 3.0</c> and higher
    ///  It ignores if application use <c>openssl 1.1.x</c>
    ///  </remark>
    ///  </param>
    ///  <returns>
    ///  <c>1</c> on success, <c>-1</c> if not supported by the current method,
    ///   or <c>0</c> on other failure
    ///  </returns>
    ///  <remark>
    ///  Derived class must implement  this method.
    ///  </remark>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
    function DoRandom(ctx : POSSL_LIB_CTX; var buf; num: TIdC_SIZET;
      strength: TIdC_UINT): TIdC_INT; overload; virtual; abstract;
  public
    ///  <summary>
    ///  The <c>Random</c> is a public method to generate sequence of random bytes
    ///  </summary>
    ///  <param name="buf">
    ///  Untyped variable to be filled with random bytes
    ///  </param>
    ///  <param name="num">
    ///  Number of bytes to be filled to the <c>buf</c> /> parameter
    ///  </param>
    ///  <returns>
    ///  <c>1</c> on success, <c>-1</c> if not supported by the current method,
    ///  or <c>0</c> on other failure
    ///  </returns>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
    function Random(var buf; num: TIdC_SIZET): TIdC_INT;
      {$IFDEF DCC}{$IFDEF USE_INLINE}inline;{$ENDIF}{$ENDIF}
    ///  <summary>
    ///  The constructor <c>Create</c> create the instance
    ///  </summary>
    ///  <param name="ACtx">
    ///  Valid pointer to the <c>openssl</c> library context
    ///  or <c>nil</c> value for default library context
    ///  <remark>
    ///  This parameters takes effect with the <c>openssl 3.0</c> and higher
    ///  It ignores if application use <c>openssl 1.1.x</c>
    ///  </remark>
    ///  </param>
    ///  <param name="AStrength">
    ///  Cryptography strength used for generating random bytes sequence
    ///  <c>openssl</c>currently supports strength level up to 256 (which is default)
    ///  <see cref="TaurusTLSHeaders_rand.RAND_DEFAULT_STRENGTH" />
    ///  <remark>
    ///  This parameters takes effect with the <c>openssl 3.0</c> and higher
    ///  It ignores if application use <c>openssl 1.1.x</c>
    ///  </remark>
    ///  </param>
    constructor Create(ACtx: POSSL_LIB_CTX;
      AStrength: TIdC_UINT = RAND_DEFAULT_STRENGTH);
  end;

  ///  <summary>
  ///  The <c>TTaurusTLS_OSSLPrivateRandomBytes</c> class implements
  ///  <see cref="DoRandom" /> method use:
  ///  <list type="bullet">
  ///    <item>
  ///      <c>RAND_priv_bytes_ex</c> function with <c>openssl 3.0</c> and higher
  ///    </item>
  ///    <item>
  ///      <c>RAND_priv_bytes</c> with <c>openssl 1.1.x</c>
  ///    </item>
  ///  </list>
  ///  </summary>
  ///  <inheritdoc />
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_priv_bytes
    /// </seealso>
  TTaurusTLS_OSSLPrivateRandomBytes = class(TTaurusTLS_CustomOSSLRandomBytes)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    function DoRandom(ctx : POSSL_LIB_CTX; var buf; num: TIdC_SIZET;
      strength: TIdC_UINT): TIdC_INT; override;
  end;

  ///  <summary>
  ///  The <c>TTaurusTLS_OSSLPublicRandomBytes</c> class implements
  ///  <see cref="DoRandom" /> method use:
  ///  <list type="bullet">
  ///    <item>
  ///      <c>RAND_bytes_ex</c> function with <c>openssl 3.0</c> and higher
  ///    </item>
  ///    <item>
  ///      <c>RAND_bytes</c> with <c>openssl 1.1.x</c>
  ///    </item>
  ///  </list>
  ///  </summary>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
  TTaurusTLS_OSSLPublicRandomBytes = class(TTaurusTLS_CustomOSSLRandomBytes)
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    function DoRandom(ctx : POSSL_LIB_CTX; var buf; num: TIdC_SIZET;
      strength: TIdC_UINT): TIdC_INT; override;
  end;

  ///  <summary>
  ///  The <c>TTaurusTLS_OSSLRandom</c> class implements various methods
  ///  to fill variables with a random data.
  ///  </summary>
  /// <remarks>
  /// This class is designed for code which handles error via <c>openssl error stack</c>
  /// Every <c>Random</c> method returns <c>1</c> on success,
  /// <c>-1</c> if not supported by the current method, or <c>0</c> on other failure.
  ///
  /// User-code must validate returned code for success.
  /// </remarks>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
  TTaurusTLS_OSSLRandom = class
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FRandomBytes: TTaurusTLS_CustomOSSLRandomBytes;

{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private class var
    FPrivateRandom: TTaurusTLS_OSSLRandom;
    FPublicRandom: TTaurusTLS_OSSLRandom;

{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    function GetRandom(var buf; num: TIdC_SIZET): TIdC_INT;
      {$IFNDEF FPC}{$IFDEF USE_INLINE}inline;{$ENDIF}{$ENDIF}

    ///  <summary>
    ///  The <c>class constructor</c> initializes shared <c>private</c> and <c>public</c>
    ///  random generators avalable via <see cref="PrivateRandom" /> and <see cref="PublicRandom" />
    ///  <c>class properties</c>.
    ///  </summary>
{$IFDEF FPC}
  public
{$ENDIF}
    class constructor Create;
    class destructor Destroy;
    constructor Create(ARandomGen: TTaurusTLS_CustomOSSLRandomBytes); overload;

  public
    destructor Destroy; override;
    ///  <summary>
    ///  The instance of <c>TTaurusTLS_OSSLRandom</c> class must be created
    ///  using <see cref="NewRandom" /> <c>class method</c>.
    ///  Creating the class via <c>constructor Create</c> fails with EAssert exception.
    ///  </summary>
    constructor Create; reintroduce; overload;
    ///  <summary>
    ///  The <c>Random</c> is a method to generate sequence of random bytes
    ///  </summary>
    ///  <param name="ABuffer">
    ///  Untyped variable to be filled with random bytes
    ///  </param>
    ///  <param name="ASize">
    ///  Number of bytes to be filled to the <c>buf</c> /> parameter
    ///  </param>
    ///  <returns>
    ///  <c>1</c> on success, <c>-1</c> if not supported by the current method,
    ///  or <c>0</c> on other failure
    ///  </returns>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
    function Random(out ABuffer; ASize: TIdC_SIZET): TIdC_INT;
      overload; {$IFNDEF FPC}{$IFDEF USE_INLINE}inline;{$ENDIF}{$ENDIF}
    ///  <summary>
    ///  The <c>Random</c> is a method to create array of random bytes sequence
    ///  </summary>
    ///  <param name="ABytes">
    ///  Reference to variable of TBytes. The method creates
    ///  a new TBytes array and fill it with random bytes.
    ///  </param>
    ///  <param name="ASize">
    ///  The size of <param ref="ABytes" /> array to be create
    ///  </param>
    ///  <returns>
    ///  <c>1</c> on success, <c>-1</c> if not supported by the current method,
    ///  or <c>0</c> on other failure
    ///  </returns>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
    function Random(var ABytes: TBytes; ASize: TIdC_SIZET): TIdC_INT;
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
    function Random(var ABytes: TIdBytes; ASize: TIdC_SIZET): TIdC_INT;
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
    ///  <summary>
    ///  The <c>Random</c> is a method returns random floating number value
    ///  </summary>
    ///  <param name="AOut">
    ///  Reference to variable of <c>extended</c> type.
    ///  The method returns value filled with a <c>random</c> value(s).
    ///  </param>
    ///  <returns>
    ///  <c>1</c> on success, <c>-1</c> if not supported by the current method,
    ///  or <c>0</c> on other failure
    ///  </returns>
    ///  <remarks>
    ///  This method returns number in ranges <c>-1 >= x &lt; 0</c> and <c> 0 > x and &lt;=1 </c>
    ///  </remarks>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
    function Random(var AOut: extended): TIdC_INT; overload;
    /// <summary>
    ///   The <c>Random</c> is a method to create a <c>generic type</c>
    ///   <typeparamref name="T" /> filled with a <c>random</c> value(s);
    /// </summary>
    /// <param name="AOut">
    ///   Reference to variable of <c>generic type</c> <typeparamref name="T" />.
    ///   The method returns value filled with a <c>random</c> value(s).
    /// </param>
    /// <returns>
    ///   <c>1</c> on success, <c>-1</c> if not supported by the current method,
    ///   or <c>0</c> on other failure
    /// </returns>
    /// <remarks>
    ///   This method is <b>only</b> safe for any numerical types. It does not
    ///   check range for user-defined enumeration types and boolean types.
    /// </remarks>
    /// <seealso
    /// href="https://docs.openssl.org/3.3/man3/RAND_bytes/#return-values">
    ///   RAND_bytes
    /// </seealso>
    {$IFNDEF FPC}
    function Random<T: record>(out AOut: T): TIdC_INT;
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
    {$ELSE}
    function Random<T>(out AOut: T): TIdC_INT;
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
    {$ENDIF}
    { TODO 5 -o@AT -cimplementation : Define and implement Random methods for AnisString and WideString types }
//    function RandomString(ALength: TIdC_SIZET): AnsiString; overload;
//    function RandomString(ALength: TIdC_SIZET): UnicodeString; overload;

    ///  <summary>
    ///  The <c>NewRandom</c> <c>class method</c> creates a new instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  which uses <paramref ref="ARandomBytes" /> as a random bytes generator.
    ///  </summary>
    ///  <param name="ARandomBytes">
    ///  Instance of class inherited from <see cref="TTaurusTLS_CustomOSSLRandomBytes" />
    ///  </param>
    ///  <returns>
    ///  An instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  </returns>
    ///  <remarks>
    ///  The caller code owns returned instance and it's responsible for freeing
    ///  this instance up.
    ///  </remarks>
    class function NewRandom(ARandomBytes: TTaurusTLS_CustomOSSLRandomBytes): TTaurusTLS_OSSLRandom;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  The <c>PrivateRandom</c> <c>class property</c> reterns an instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  which uses <c>openssl private</c> random bytes generator.
    ///  </summary>
    ///  <remarks>
    ///  User code <b>must not</b> free the obtained instance.
    ///  </remarks>
    class property PrivateRandom: TTaurusTLS_OSSLRandom read FPrivateRandom;
    ///  <summary>
    ///  The <c>PrivateRandom</c> <c>class property</c> reterns an instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  which uses <c>openssl public</c> random bytes generator.
    ///  </summary>
    ///  <remarks>
    ///  User code <b>must not</b> free the obtained instance.
    ///  </remarks>
    class property PublicRandom: TTaurusTLS_OSSLRandom read FPublicRandom;
  end;

  ///  <summary>
  ///  The <c>TTaurusTLS_Random</c> class implements various methods
  ///  to fill variables with a random data.
  ///  </summary>
  /// <remarks>
  /// This class handles errors with regular <c>exceptions</c>.
  /// </remarks>
  TTaurusTLS_Random = class
{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private
    FRandomBytes: TTaurusTLS_CustomOSSLRandomBytes;

{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} private class var
    FPrivateRandom: TTaurusTLS_Random;
    FPublicRandom: TTaurusTLS_Random;

{$IFDEF USE_STRICT_PRIVATE_PROTECTED} strict{$ENDIF} protected
    procedure GetRandom(out buf; num: TIdC_SIZET);
      {$IFNDEF FPC}{$IFDEF USE_INLINE}inline;{$ENDIF}{$ENDIF}
    procedure CheckError(const AResult: TIdC_INT);
      {$IFDEF USE_INLINE}inline;{$ENDIF}
{$IFDEF FPC}
  public
{$ENDIF}
    ///  <summary>
    ///  The <c>class constructor</c> initializes shared <c>private</c> and <c>public</c>
    ///  random generators avalable via <see cref="PrivateRandom" /> and <see cref="PublicRandom" />
    ///  <c>class properties</c>.
    ///  </summary>
    class constructor Create;
    class destructor Destroy;
    constructor Create(ARandomGen: TTaurusTLS_CustomOSSLRandomBytes); overload;

  public
    destructor Destroy; override;
    ///  <summary>
    ///  The instance of <c>TTaurusTLS_Random</c> class must be created
    ///  using <see cref="NewRandom" /> <c>class method</c>.
    ///  Creating the class via <c>constructor Create</c> fails with EAssert exception.
    ///  </summary>
    constructor Create; reintroduce; overload;
    ///  <summary>
    ///  The <c>Random</c> is a method to generate sequence of random bytes
    ///  </summary>
    ///  <param name="ABuffer">
    ///  Untyped variable to be filled with random bytes
    ///  </param>
    ///  <param name="ASize">
    ///  Number of bytes to be filled to the <c>buf</c> /> parameter
    ///  </param>
    procedure Random(out ABuffer; ASize: TIdC_SIZET); overload;
      {$IFNDEF FPC}{$IFDEF USE_INLINE}inline;{$ENDIF}{$ENDIF}
    ///  <summary>
    ///  The <c>Random</c> is a method to create array of random bytes sequence
    ///  </summary>
    ///  <param name="ABytes">
    ///  Reference to variable of TBytes. The method creates
    ///  a new TBytes array and fill it with random bytes.
    ///  </param>
    ///  <param name="ASize">
    ///  The size of <param ref="ABytes" /> array to be create
    ///  </param>
    function Random(ASize: TIdC_SIZET): TBytes;
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
    ///  <summary>
    ///  The <c>Random</c> is a method returns random floating number value
    ///  </summary>
    ///  <returns>
    ///  The method returns a floating number random value of <c>extended</c> type.
    ///  </returns>
    ///  <remarks>
    ///  This method returns number in ranges <c>-1 >= x &lt; 0</c> and <c> 0 > x and &lt;=1 </c>
    ///  </remarks>
    function Random: extended; overload;
    ///  <summary>
    ///  The <c>Random</c> is a method to create a <c>generic type</c> <typeparamref name="T" />
    ///  filled with a <c>random</c> value(s);
    ///  </summary>
    ///  <returns>
    ///  The method returns value of <c>generic type</c> <typeparamref name="T" />
    ///  filled with a <c>random</c> value(s).
    ///  </returns>
    ///  <remarks>
    ///  This method is <b>only</b> safe for any numerical types. It does not
    ///  check range for user-defined enumeration types and boolean types.
    ///  </remarks>
{$IFNDEF FPC}
    function Random<T: record>: T;
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
{$ELSE}
    function Random<T>: T;
      overload; {$IFDEF USE_INLINE}inline;{$ENDIF}
{$ENDIF}

    { TODO 5 -o@AT -cimplementation : Define and implement Random methods for AnisString and WideString types }
//    function RandomString(ALength: TIdC_SIZET): AnsiString; overload;
//    function RandomString(ALength: TIdC_SIZET): UnicodeString; overload;

    ///  <summary>
    ///  The <c>NewRandom</c> <c>class method</c> creates a new instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  which uses <paramref ref="ARandomBytes" /> as a random bytes generator.
    ///  </summary>
    ///  <param name="ARandomBytes">
    ///  Instance of class inherited from <see cref="TTaurusTLS_CustomOSSLRandomBytes" />
    ///  </param>
    ///  <returns>
    ///  An instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  </returns>
    ///  <remarks>
    ///  The caller code owns returned instance and it's responsible for freeing
    ///  this instance up.
    ///  </remarks>
    class function NewRandom(ARandomBytes: TTaurusTLS_CustomOSSLRandomBytes): TTaurusTLS_Random;
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    ///  <summary>
    ///  The <c>PrivateRandom</c> <c>class property</c> reterns an instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  which uses <c>openssl private</c> random bytes generator.
    ///  </summary>
    ///  <remarks>
    ///  User code <b>must not</b> free the obtained instance.
    ///  </remarks>
    class property PrivateRandom: TTaurusTLS_Random read FPrivateRandom;
    ///  <summary>
    ///  The <c>PrivateRandom</c> <c>class property</c> reterns an instance of <see cref="TTaurusTLS_OSSLRandom" /> class
    ///  which uses <c>openssl public</c> random bytes generator.
    ///  </summary>
    ///  <remarks>
    ///  User code <b>must not</b> free the obtained instance.
    ///  </remarks>
    class property PublicRandom: TTaurusTLS_Random read FPublicRandom;
  end;

  ///  <summary>
  ///  This exception indicates error returned from <c>openssl</c> random function(s)
  ///  in the <see cref="TTaurusTLS_Random" /> class.
  ///  </summary>
  ETaurusTLSRandom = class(ETaurusTLSAPICryptoError);

implementation

uses
  TaurusTLSHeaders_err;

function RandomToExtend(ASeed: TIdC_UINT64): extended;
  {$IFDEF USE_INLINE}inline;{$ENDIF}
const
  cMultiplier: extended = ((1.0/$100000000) / $100000000);  // 2^-64

var
  lExt: extended;

begin
  lExt:=ASeed;
  Result:=lExt*cMultiplier;
  if not (ASeed <> 0) and (((1 shl (ASeed and $3F)) and ASeed) <> 0) then
    Result:=-1*Result; //random negative
end;

{ TTaurusTLS_CustomOSSLRandomBytes }

constructor TTaurusTLS_CustomOSSLRandomBytes.Create(ACtx: POSSL_LIB_CTX;
  AStrength: TIdC_UINT);
begin
  FCtx:=ACtx;
  FStrength:=AStrength;
end;

function TTaurusTLS_CustomOSSLRandomBytes.Random(var buf;
  num: TIdC_SIZET): TIdC_INT;
begin
  if num > 0 then
    Result:=DoRandom(FCtx, buf, num, FStrength)
  else
    Result:=1;
end;

{ TTaurusTLS_OSSLPrivateRandomBytes }

function TTaurusTLS_OSSLPrivateRandomBytes.DoRandom(
  ctx: POSSL_LIB_CTX; var buf; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT;
begin
  Result:=RAND_priv_bytes_ex(ctx, @buf, num, strength);
end;

{ TTaurusTLS_OSSLPublicRandomBytes }

function TTaurusTLS_OSSLPublicRandomBytes.DoRandom(
  ctx: POSSL_LIB_CTX; var buf; num: TIdC_SIZET; strength: TIdC_UINT): TIdC_INT;
begin
  Result:=RAND_bytes_ex(ctx, @buf, num, strength);
end;

{ TTaurusTLS_OSSLRandom }

class function TTaurusTLS_OSSLRandom.NewRandom(
  ARandomBytes: TTaurusTLS_CustomOSSLRandomBytes): TTaurusTLS_OSSLRandom;
begin
  Result:=Create(ARandomBytes);
end;

class constructor TTaurusTLS_OSSLRandom.Create;
begin
  FPrivateRandom:=NewRandom(
    TTaurusTLS_OSSLPrivateRandomBytes.Create(nil, RAND_DEFAULT_STRENGTH));
  FPublicRandom:=NewRandom(
    TTaurusTLS_OSSLPublicRandomBytes.Create(nil, RAND_DEFAULT_STRENGTH));
end;

class destructor TTaurusTLS_OSSLRandom.Destroy;
begin
  FreeAndNil(FPublicRandom);
  FreeAndNil(FPrivateRandom);
end;

constructor TTaurusTLS_OSSLRandom.Create;
begin
  inherited;
  Assert(False, ClassName+' can not be creates with this constructor.');
end;

destructor TTaurusTLS_OSSLRandom.Destroy;
begin
  FreeAndNil(FRandomBytes);
  inherited;
end;

constructor TTaurusTLS_OSSLRandom.Create(ARandomGen: TTaurusTLS_CustomOSSLRandomBytes);
begin
  Assert(Assigned(ARandomGen), 'ARandomGen must not be ''nil''.');
  FRandomBytes:=ARandomGen;
end;

function TTaurusTLS_OSSLRandom.GetRandom(var buf; num: TIdC_SIZET): TIdC_INT;
begin
  Result:=FRandomBytes.Random(buf, num);
end;
{$IFDEF FPC}
  {$PUSH}
  {$WARN 5058 OFF : Variable "$1" does not seem to be initialized}
{$ENDIF}

function TTaurusTLS_OSSLRandom.Random(out ABuffer;
  ASize: TIdC_SIZET): TIdC_INT;
begin
  Result:=GetRandom(ABuffer, ASize);
end;
{$IFDEF FPC}
  {$POP}
{$ENDIF}

function TTaurusTLS_OSSLRandom.Random(var ABytes: TBytes;
  ASize: TIdC_SIZET): TIdC_INT;
begin
  if ASize = 0 then
    Exit(1);
  try
    SetLength(ABytes, ASize);
  except
    //Push error function and error code to the OpenSSL errors stack.
    SSLErr(RAND_F_DRBG_BYTES, ERR_R_MALLOC_FAILURE);
  end;
  Result:=GetRandom(ABytes[0], ASize);
end;

function TTaurusTLS_OSSLRandom.Random(var ABytes: TIdBytes;
  ASize: TIdC_SIZET): TIdC_INT;
begin
  if ASize = 0 then
    Exit(1);
  try
    SetLength(ABytes, ASize);
  except
    //Push error function and error code to the OpenSSL errors stack.
    SSLErr(RAND_F_DRBG_BYTES, ERR_R_MALLOC_FAILURE);
  end;
  Result:=GetRandom(ABytes[0], ASize);
end;

function TTaurusTLS_OSSLRandom.Random(var AOut: extended): TIdC_INT;
var
  lTemp: TIdC_UINT64;
begin
  repeat
{$IFNDEF FPC}
    Result:=Random<TIdC_UINT64>(lTemp);
{$ELSE}
    // FPC generates error for code above:
    // TaurusTLS_Random.pas(567,19) Error: Operator is not overloaded: "TTaurusTLS_OSSLRandom.Random(out <Formal type>;QWord):LongInt;" < "QWord"
    // The simples workaround not to use Operator overriding,
    // but to fill lTemp variable with function "Random(out ABuffer; ASize: TIdC_SIZET): TIdC_INT"
    Result:=Random(lTemp, SizeOf(lTemp));
{$ENDIF}
    if Result <> 1 then
      Exit;
  until (lTemp <> 0);
  try
    AOut:=RandomToExtend(lTemp);
  except
    SSLErr(RAND_F_DRBG_BYTES, RAND_R_INTERNAL_ERROR);
  end;
end;

{$IFNDEF FPC}
function TTaurusTLS_OSSLRandom.Random<T>(out AOut: T): TIdC_INT;
begin
  Result:=GetRandom(AOut, SizeOf(T));
end;
{$ELSE}
  {$PUSH}
  {$WARN 5058 OFF : Variable "$1" does not seem to be initialized}
function TTaurusTLS_OSSLRandom.Random<T>(out AOut:
  T): TIdC_INT;
begin
  // FPC mict stricter Generic types substitution than the Delphi.
  // It fails to comile with errors:
  // TaurusTLS_Random.pas(574,32) Error: function header doesn't match any method of this class "Random$1(out T):LongInt;"
  // TaurusTLS_Random.pas(265,14) Error: Found declaration: Random$1(out TTaurusTLS_OSSLRandom.T):LongInt;
  Result:=GetRandom(AOut, SizeOf(T));
end;
  {$POP}
{$ENDIF}

{ TTaurusTLS_Random }

class function TTaurusTLS_Random.NewRandom(
  ARandomBytes: TTaurusTLS_CustomOSSLRandomBytes): TTaurusTLS_Random;
begin
  Result:=Create(ARandomBytes);
end;

class constructor TTaurusTLS_Random.Create;
begin
  FPrivateRandom:=NewRandom(
    TTaurusTLS_OSSLPrivateRandomBytes.Create(nil, RAND_DEFAULT_STRENGTH));
  FPublicRandom:=NewRandom(
    TTaurusTLS_OSSLPublicRandomBytes.Create(nil, RAND_DEFAULT_STRENGTH));
end;

class destructor TTaurusTLS_Random.Destroy;
begin
  FreeAndNil(FPublicRandom);
  FreeAndNil(FPrivateRandom);
end;

constructor TTaurusTLS_Random.Create;
begin
  inherited;
  Assert(False, ClassName+' can not be creates with this constructor.');
end;

destructor TTaurusTLS_Random.Destroy;
begin
  FreeAndNil(FRandomBytes);
  inherited;
end;

procedure TTaurusTLS_Random.CheckError(const AResult: TIdC_INT);
begin
  if AResult <> 1 then
  begin
    ETaurusTLSRandom.RaiseException;
  end;
end;

constructor TTaurusTLS_Random.Create(ARandomGen: TTaurusTLS_CustomOSSLRandomBytes);
begin
  Assert(Assigned(ARandomGen), 'ARandomGen must not be ''nil''.');
  FRandomBytes:=ARandomGen;
end;

{$IFDEF FPC}
  {$PUSH}
  {$WARN 5058 OFF : Variable "$1" does not seem to be initialized}
{$ENDIF}
procedure TTaurusTLS_Random.GetRandom(out buf; num: TIdC_SIZET);
begin
  CheckError(FRandomBytes.Random(buf, num));
end;
{$IFDEF FPC}
  {$POP}
{$ENDIF}

procedure TTaurusTLS_Random.Random(out ABuffer; ASize: TIdC_SIZET);
begin
  GetRandom(ABuffer, ASize);
end;

{$IFDEF FPC}
  {$PUSH}
  {$WARN 5093 off : Function result variable of a managed type does not seem to be initialized}
{$ENDIF}
function TTaurusTLS_Random.Random(ASize: TIdC_SIZET): TBytes;
begin
  if ASize <= 0 then
    Exit;
  SetLength(Result, ASize);
  GetRandom(Result[0], ASize);
end;
{$IFDEF FPC}
  {$POP}
{$ENDIF}

function TTaurusTLS_Random.Random<T>: T;
begin
  GetRandom(Result, SizeOf(T));
end;

function TTaurusTLS_Random.Random: extended;
var
  lTemp: TIdC_UINT64;

begin
  repeat
{$IFNDEF FPC}
    lTemp:=Random<TIdC_UINT64>;
{$ELSE}
    // FPC generates error for code above:
    // TaurusTLS_Random.pas(567,19) Error: Operator is not overloaded: "TTaurusTLS_OSSLRandom.Random(out <Formal type>;QWord):LongInt;" < "QWord"
    // The simples workaround not to use Operator overriding,
    // but to fill lTemp variable with function "Random(out ABuffer; ASize: TIdC_SIZET): TIdC_INT"
    Random(lTemp, SizeOf(lTemp));
{$ENDIF}
  until (lTemp <> 0);
  Result:=RandomToExtend(lTemp);
end;

end.
