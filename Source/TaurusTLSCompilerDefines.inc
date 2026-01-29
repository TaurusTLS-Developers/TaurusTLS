{$IFDEF CONDITIONALEXPRESSIONS}
  // Must be at the top...
  {$IF CompilerVersion >= 24.0}
    {$LEGACYIFEND ON}
  {$IFEND}
{$ENDIF}

// General

{$IFNDEF DEBUG}
  {$DEFINE USE_INLINE}
{$ENDIF}

// Make this $DEFINE to use the 16 color icons required by Borland
// or DEFINE to use the 256 color Indy versions
{.$DEFINE Borland}

// When generating C++Builder output files, certain workarounds to compiler
// problems need to be enabled! When invoking DCC on the command-line, use
// the -DBCB parameter. When invoking MSBUILD, include the DCC_Define="BCB"
// attribute in the /p parameter.
{$IFDEF BCB}
  {$DEFINE CBUILDER}
{$ELSE}
  {$DEFINE DELPHI}
{$ENDIF}

{$UNDEF STATICLOAD_OPENSSL}

// Make sure the following are $DEFINE'd only for Delphi/C++Builder 2009 onwards
// as specified further below.  The VCL is fully Unicode, where the 'String'
// type maps to System.UnicodeString, not System.AnsiString anymore
{$UNDEF STRING_IS_UNICODE}
{$UNDEF STRING_IS_ANSI}

// Make sure the following are $DEFINE'd only for suitable environments
// as specified further below.  Delphi/C++Builder Mobile/NextGen compilers
// do not support Ansi data types anymore, and is moving away from raw
// pointers as well.
//
// UPDATE: in Delphi/C++Builder 10.4, all Ansi types are supported again on
// all platforms, including the mobile compilers.
{$DEFINE HAS_PAnsiChar}
{$UNDEF NO_ANSI_TYPES}
{$UNDEF HAS_TInterlocked}

// Make sure the following are $DEFINE'd only for suitable environments
// as specified further below.  Delphi/C++Builder Mobile/NextGen compilers
// use ARC for TObject life time management.
//
// UPDATE: ARC for TObject lifetime management has been removed in
// Delphi/C++Builder 10.4 mobile compilers.  All platforms now use a single
// unified memory management model!
{$UNDEF USE_MARSHALLED_PTRS}
{$UNDEF USE_OBJECT_ARC}

//Define for Delphi cross-compiler targetting Posix
{$UNDEF USE_VCL_POSIX}

//Define for Delphi 10.1 strict private and strict protected usage
{$UNDEF USE_STRICT_PRIVATE_PROTECTED}

//Define for Delphi 10.3 inline variable declarion availability
{$UNDEF USE_INLINE_VAR}

// detect compiler versions

{$IFNDEF FPC}

  // TODO: to detect features in Delphi/C++Builder v6 and later, use CompilerVersion
  // and RTLVersion constants instead of VERXXX defines.  We still support v5, which
  // does not have such constants.

  // Delphi 4
  {$IFDEF VER120}
    {$DEFINE DCC}
    {$DEFINE VCL_40}
    {$DEFINE DELPHI_4}
  {$ENDIF}

  // C++Builder 4
  {$IFDEF VER125}
    {$DEFINE DCC}
    {$DEFINE VCL_40}
    {$DEFINE CBUILDER_4}
  {$ENDIF}

  // Delphi & C++Builder 5
  {$IFDEF VER130}
    {$DEFINE DCC}
    {$DEFINE VCL_50}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_5}
    {$ELSE}
      {$DEFINE DELPHI_5}
    {$ENDIF}
  {$ENDIF}

  //Delphi & C++Builder 6
  {$IFDEF VER140}
    {$DEFINE DCC}
    {$DEFINE VCL_60}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_6}
    {$ELSE}
      {$DEFINE DELPHI_6}
    {$ENDIF}
  {$ENDIF}

  //Delphi 7
  {$IFDEF VER150}
    {$DEFINE DCC}
    {$DEFINE VCL_70}
    {$DEFINE DELPHI_7} // there was no C++ Builder 7
  {$ENDIF}

  //Delphi 8
  {$IFDEF VER160}
    {$DEFINE DCC}
    {$DEFINE VCL_80}
    {$DEFINE DELPHI_8} // there was no C++ Builder 8
  {$ENDIF}

  //Delphi 2005
  {$IFDEF VER170}
    {$DEFINE DCC}
    {$DEFINE VCL_2005}
    {$DEFINE DELPHI_2005} // there was no C++Builder 2005
  {$ENDIF}

  // NOTE: CodeGear decided to make Highlander be a non-breaking release
  // (no interface changes, thus fully backwards compatible without any
  // end user code changes), so VER180 applies to both BDS 2006 and
  // Highlander prior to the release of RAD Studio 2007.  Use VER185 to
  // identify Highlanger specifically.

  //Delphi & C++Builder 2006
  //Delphi & C++Builder 2007 (Highlander)
  {$IFDEF VER180}
    {$DEFINE DCC}
    {$DEFINE VCL_2006}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_2006}
    {$ELSE}
      {$DEFINE DELPHI_2006}
    {$ENDIF}
  {$ENDIF}

  //Delphi & C++Builder 2007 (Highlander)
  {$IFDEF VER185}
    {$DEFINE DCC}
    {$UNDEF VCL_2006}
    {$DEFINE VCL_2007}
    {$IFDEF CBUILDER}
      {$UNDEF CBUILDER_2006}
      {$DEFINE CBUILDER_2007}
    {$ELSE}
      {$UNDEF DELPHI_2006}
      {$DEFINE DELPHI_2007}
    {$ENDIF}
  {$ENDIF}

  // BDS 2007 NET personality uses VER190 instead of 185.
  //Delphi .NET 2007
  {$IFDEF VER190}
    {$DEFINE DCC}
    {$IFDEF CIL}
      //Delphi 2007
      {$DEFINE VCL_2007}
      {$DEFINE DELPHI_2007}
    {$ENDIF}
  {$ENDIF}

  //Delphi & C++Builder 2009 (Tiburon)
  {$IFDEF VER200}
    {$DEFINE DCC}
    {$DEFINE VCL_2009}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_2009}
    {$ELSE}
      {$DEFINE DELPHI_2009}
    {$ENDIF}
  {$ENDIF}

  //Delphi & C++Builder 2010 (Weaver)
  {$IFDEF VER210}
    {$DEFINE DCC}
    {$DEFINE VCL_2010}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_2010}
    {$ELSE}
      {$DEFINE DELPHI_2010}
    {$ENDIF}
  {$ENDIF}

  //Delphi & C++Builder XE (Fulcrum)
  {$IFDEF VER220}
  //REMOVE DCC DEFINE after the next Fulcrum beta.
  //It will be defined there.
    {$IFNDEF DCC}
      {$DEFINE DCC}
    {$ENDIF}
    {$DEFINE VCL_XE}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE}
    {$ELSE}
      {$DEFINE DELPHI_XE}
    {$ENDIF}
  {$ENDIF}

  // DCC is now defined by the Delphi compiler starting in XE2

  //Delphi & CBuilder XE2 (Pulsar)
  {$IFDEF VER230}
    {$DEFINE VCL_XE2}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE2}
    {$ELSE}
      {$DEFINE DELPHI_XE2}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder XE3 (Waterdragon)
  //Delphi & CBuilder XE3.5 (Quintessence - early betas only)
  {$IFDEF VER240}
    {$DEFINE VCL_XE3}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE3}
    {$ELSE}
      {$DEFINE DELPHI_XE3}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder XE4 (Quintessence)
  {$IFDEF VER250}
    {$UNDEF VCL_XE3}
    {$DEFINE VCL_XE4}
    {$IFDEF CBUILDER}
      {$UNDEF CBUILDER_XE3}
      {$DEFINE CBUILDER_XE4}
    {$ELSE}
      {$UNDEF DELPHI_XE3}
      {$DEFINE DELPHI_XE4}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder XE5 (Zephyr)
  {$IFDEF VER260}
    {$DEFINE VCL_XE5}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE5}
    {$ELSE}
      {$DEFINE DELPHI_XE5}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder AppMethod
  //AppMethod is just XE5 for mobile only, VCL is removed
  {$IFDEF VER265}
    {$DEFINE VCL_XE5}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE5}
    {$ELSE}
      {$DEFINE DELPHI_XE5}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder XE6 (Proteus)
  {$IFDEF VER270}
    {$DEFINE VCL_XE6}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE6}
    {$ELSE}
      {$DEFINE DELPHI_XE6}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder XE7 (Carpathia)
  {$IFDEF VER280}
    {$DEFINE VCL_XE7}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE7}
    {$ELSE}
      {$DEFINE DELPHI_XE7}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder XE8 (Elbrus)
  {$IFDEF VER290}
    {$DEFINE VCL_XE8}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_XE8}
    {$ELSE}
      {$DEFINE DELPHI_XE8}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder 10.0 Seattle (Aitana)
  {$IFDEF VER300}
    {$DEFINE VCL_10_0}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_VCL_10_0}
    {$ELSE}
      {$DEFINE DELPHI_VCL_10_0}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder 10.1 Berlin (BigBen)
  {$IFDEF VER310}
    {$DEFINE VCL_10_1}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_10_1}
    {$ELSE}
      {$DEFINE DELPHI_10_1}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder 10.2 Tokyo (Godzilla)
  {$IFDEF VER320}
    {$DEFINE VCL_10_2}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_10_2}
    {$ELSE}
      {$DEFINE DELPHI_10_2}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder 10.3 Rio (Carnival)
  {$IFDEF VER330}
    {$DEFINE VCL_10_3}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_10_3}
    {$ELSE}
      {$DEFINE DELPHI_10_3}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder 10.4 Sydney (Denali)
  {$IFDEF VER340}
    {$DEFINE VCL_10_4}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_10_4}
    {$ELSE}
      {$DEFINE DELPHI_10_4}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder 11.0 Alexandria (Olympus)
  {$IFDEF VER350}
    {$DEFINE VCL_11}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_11}
    {$ELSE}
      {$DEFINE DELPHI_11}
    {$ENDIF}
  {$ENDIF}

  //Delphi & CBuilder 12.0 Athens (Yukon)
  {$IFDEF VER360}
    {$DEFINE VCL_12}
    {$IFDEF CBUILDER}
      {$DEFINE CBUILDER_12}
    {$ELSE}
      {$DEFINE DELPHI_12}
    {$ENDIF}
  {$ENDIF}

    //Delphi & CBuilder 13.0+
  {$IFDEF CONDITIONALEXPRESSIONS}
    {$IF CompilerVersion >= 37}
      {$DEFINE VCL_13}
      {$IFDEF CBUILDER}
        {$DEFINE CBUILDER_13}
      {$ELSE}
        {$DEFINE DELPHI_13}
      {$ENDIF}
    {$IFEND}
  {$ENDIF}

      //Delphi & CBuilder 14.0+ (?)
  {$IFDEF CONDITIONALEXPRESSIONS}
    {$IF CompilerVersion >= 38}
      {$MESSAGE WARN 'Unknown compiler version detected! Assuming >= 14.x '}
      {$DEFINE VCL_UNKNOWN_VERSION}
      {$DEFINE VCL_14}
      {$IFDEF CBUILDER}
        {$DEFINE CBUILDER_14}
      {$ELSE}
        {$DEFINE DELPHI_14}
      {$ENDIF}
    {$IFEND}
  {$ENDIF}

  // Kylix
  //
  //Important:  Don't use CompilerVersion here as IF's are evaluated before
  //IFDEF's and Kylix 1 does not have CompilerVersion defined at all.
  {$IFDEF LINUX}
    {$DEFINE UNIX}
    {$IFDEF CONDITIONALEXPRESSIONS}
      {$IF (RTLVersion >= 14.0) and (RTLVersion <= 14.5) }
        {$DEFINE KYLIX}
        {$IF RTLVersion = 14.5}
          {$DEFINE KYLIX_3}
        {$ELSEIF RTLVersion >= 14.2}
          {$DEFINE KYLIX_2}
        {$ELSE}
          {$DEFINE KYLIX_1}
        {$IFEND}
      {$IFEND}
    {$ENDIF}
  {$ENDIF}

{$ENDIF}

// Delphi.NET
// Covers D8+
{$IFDEF CIL}
  // Platform specific conditional. Used for platform specific code.
  {$DEFINE DOTNET}
  {$DEFINE STRING_IS_UNICODE}
{$ENDIF}

{$IFDEF KYLIX}
  {$DEFINE VCL_60}
  {$DEFINE CPUI386}
  {$UNDEF USE_BASEUNIX}

  {$IFDEF KYLIX_3}
    {$DEFINE KYLIX_3_OR_ABOVE}
  {$ENDIF}

  {$IFDEF KYLIX_3_OR_ABOVE}
    {$DEFINE KYLIX_2_OR_ABOVE}
  {$ELSE}
    {$IFDEF KYLIX_2}
      {$DEFINE KYLIX_2_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF KYLIX_2_OR_ABOVE}
    {$DEFINE KYLIX_1_OR_ABOVE}
  {$ELSE}
    {$IFDEF KYLIX_1}
      {$DEFINE KYLIX_1_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFNDEF KYLIX_3_OR_ABOVE}
    {$DEFINE KYLIXCOMPAT}
  {$ENDIF}
{$ENDIF}

// FPC (2+)

{$IFDEF FPC}
  // TODO: In FreePascal 4.2.0+, a Delphi-like UnicodeString type is supported.
  // However, String/(P)Char do not map to UnicodeString/(P)WideChar unless
  // either {$MODE DelphiUnicode} or {$MODESWITCH UnicodeStrings} is used.
  // We should consider enabling one of them so Indy uses the same Unicode logic
  // in Delphi 2009+ and FreePascal 4.2.0+ and reduces IFDEFs (in particular,
  // STRING_UNICODE_MISMATCH, see further below).  However, FreePascal's RTL
  // is largely not UnicodeString-enabled yet.  Maybe we should enable
  // {$MODE DelphiUnicode} anyway, and then deal with any RTL function issues
  // on an as-needed basis...
  {$mode delphi}
  {$IFDEF FPC_2_7_1_OR_ABOVE}
    {/$MODE DelphiUnicode}
    {/$MODESWITCH UnicodeStrings}
    {/$CODEPAGE UTF8} // needed for Unicode string literals to work properly
  {$ENDIF}
  //note that we may need further defines for widget types depending on
  //what we do and what platforms we support in FPC.
  //I'll let Marco think about that one.
  {$IFDEF UNIX}
    {$DEFINE USE_BASEUNIX}
    {$IFDEF LINUX}
      //In Linux for I386, you can choose between a Kylix-libc API or
      //the standard RTL Unix API.  Just pass -dKYLIXCOMPAT to the FPC compiler.
      //I will see what I can do about the Makefile.
      {$IFDEF KYLIXCOMPAT}
        {$IFDEF CPUI386}
          {$UNDEF USE_BASEUNIX}
        {$ENDIF}
      {$ENDIF}
    {$ENDIF}
    {$IFDEF USE_BASEUNIX}
      {$UNDEF KYLIXCOMPAT}
    {$ENDIF}
  {$ENDIF}

  // FPC_FULLVERSION was added in FPC 2.2.4
  // Have to use Defined() or else Delphi compiler chokes, since it
  // evaluates $IF statements before $IFDEF statements...

  {$MACRO ON} // must be on in order to use versioning macros
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 30301)}
    {$DEFINE FPC_3_3_1_OR_ABOVE}
    {$DEFINE HAS_TInterlocked}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 30101)}
    {$DEFINE FPC_3_1_1_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 30000)}
    {$DEFINE FPC_3_0_0_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20701)}
    {$DEFINE FPC_2_7_1_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20604)}
    {$DEFINE FPC_2_6_4_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20602)}
    {$DEFINE FPC_2_6_2_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20600)}
    {$DEFINE FPC_2_6_0_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20404)}
    {$DEFINE FPC_2_4_4_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20402)}
    {$DEFINE FPC_2_4_2_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20400)}
    {$DEFINE FPC_2_4_0_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20204)}
    {$DEFINE FPC_2_2_4_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20202)}
    {$DEFINE FPC_2_2_2_OR_ABOVE}
  {$IFEND}
  {$IF DEFINED(FPC_FULLVERSION) AND (FPC_FULLVERSION >= 20105)}
    {$DEFINE FPC_2_1_5_OR_ABOVE}
  {$IFEND}

  // just in case
  {$IFDEF FPC_3_1_1}
    {$DEFINE FPC_3_1_1_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_3_0_0}
    {$DEFINE FPC_3_0_0_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_7_1}
    {$DEFINE FPC_2_7_1_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_6_4}
    {$DEFINE FPC_2_6_4_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_6_2}
    {$DEFINE FPC_2_6_2_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_6_0}
    {$DEFINE FPC_2_6_0_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_4_4}
    {$DEFINE FPC_2_4_4_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_4_2}
    {$DEFINE FPC_2_4_2_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_4_0}
    {$DEFINE FPC_2_4_0_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_2_4}
    {$DEFINE FPC_2_2_4_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_2_2}
    {$DEFINE FPC_2_2_2_OR_ABOVE}
  {$ENDIF}
  {$IFDEF FPC_2_1_5}
    {$DEFINE FPC_2_1_5_OR_ABOVE}
  {$ENDIF}

  {$IFDEF FPC_3_1_1_OR_ABOVE}
    {$DEFINE FPC_3_0_0_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_3_0_0}
      {$DEFINE FPC_3_0_0_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_3_0_0_OR_ABOVE}
    {$DEFINE FPC_2_7_1_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_7_1}
      {$DEFINE FPC_2_7_1_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_7_1_OR_ABOVE}
    {$DEFINE FPC_2_6_4_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_6_4}
      {$DEFINE FPC_2_6_4_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_6_4_OR_ABOVE}
    {$DEFINE FPC_2_6_2_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_6_2}
      {$DEFINE FPC_2_6_2_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_6_2_OR_ABOVE}
    {$DEFINE FPC_2_6_0_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_6_0}
      {$DEFINE FPC_2_6_0_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_6_0_OR_ABOVE}
    {$DEFINE FPC_2_4_4_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_4_4}
      {$DEFINE FPC_2_4_4_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_4_4_OR_ABOVE}
    {$DEFINE FPC_2_4_2_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_4_2}
      {$DEFINE FPC_2_4_2_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_4_2_OR_ABOVE}
    {$DEFINE FPC_2_4_0_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_4_0}
      {$DEFINE FPC_2_4_0_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_4_0_OR_ABOVE}
    {$DEFINE FPC_2_2_4_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_2_4}
      {$DEFINE FPC_2_2_4_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_2_4_OR_ABOVE}
    {$DEFINE FPC_2_2_2_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_2_2}
      {$DEFINE FPC_2_2_2_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_2_2_OR_ABOVE}
    {$DEFINE FPC_2_2_0_OR_ABOVE}
  {$ELSE}
    {$IFDEF VER2_2}
      {$DEFINE FPC_2_2_0_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF FPC_2_2_0_OR_ABOVE}
    {$DEFINE FPC_2_1_5_OR_ABOVE}
  {$ELSE}
    {$IFDEF FPC_2_1_5}
      {$DEFINE FPC_2_1_5_OR_ABOVE}
    {$ENDIF}
  {$ENDIF}

  {.$IFDEF FPC_2_7_1_OR_ABOVE}
    // support for RawByteString and UnicodeString
    {.$DEFINE VCL_2009}
    {.$DEFINE DELPHI_2009}
  {.$ELSE}
    {$DEFINE VCL_70}
    {$DEFINE DELPHI_7}
  {.$ENDIF}
   {$DEFINE HAS_DIRECTIVE_PUSHPOP} // TODO: when was push/pop introduced?
   {$DEFINE USE_NORETURN} // TODO: when was noreturn introduced? Possibly after 2.6.x
   {$IFDEF FPC}
     {$IF FPC_FULLVERSION = 30301} // Known-bad: FPC 3.3.1 fpcupdeluxe (possibly other versions)
       // xjikka 2026-01-29:
       // Windows and Windows + cross-compile to Raspberry Pi: FPC 3.3.1 rejects "raise" inside
       // routines declared as "noreturn" (even if "noreturn" is added consistently
       // to both interface and implementation).
       // Error:
       //   "Raise in subroutines declared as noreturn is not allowed"
       {$UNDEF USE_NORETURN}
     {$IFEND}
   {$ENDIF}
{$ENDIF}

// end FPC
{$IFDEF VCL_14}
  {$DEFINE VCL_14_OR_ABOVE}
{$ENDIF}
{$IFDEF VCL_14_OR_ABOVE}
  {$DEFINE VCL_13_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_13}
    {$DEFINE VCL_13_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_13}
  {$DEFINE VCL_13_OR_ABOVE}
{$ENDIF}
{$IFDEF VCL_13_OR_ABOVE}
  {$DEFINE VCL_12_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_12}
    {$DEFINE VCL_12_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_12_OR_ABOVE}
  {$DEFINE VCL_11_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_11}
    {$DEFINE VCL_11_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_11_OR_ABOVE}
  {$DEFINE VCL_10_4_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_10_4}
    {$DEFINE VCL_10_4_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_10_4_OR_ABOVE}
  {$DEFINE VCL_10_3_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_10_3}
    {$DEFINE VCL_10_3_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_10_3_OR_ABOVE}
   {$DEFINE USE_INLINE_VAR}
  {$DEFINE VCL_10_2_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_10_2}
    {$DEFINE VCL_10_2_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_10_2_OR_ABOVE}
  {$DEFINE VCL_10_1_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_10_1}
    {$DEFINE VCL_10_1_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_10_1_OR_ABOVE}
  {$DEFINE USE_STRICT_PRIVATE_PROTECTED}
  {$DEFINE VCL_10_0_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_10_0}
    {$DEFINE VCL_10_0_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_10_0_OR_ABOVE}
  {$DEFINE VCL_XE8_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE8}
    {$DEFINE VCL_XE8_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE8_OR_ABOVE}
  {$DEFINE VCL_XE7_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE7}
    {$DEFINE VCL_XE7_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE7_OR_ABOVE}
  {$DEFINE VCL_XE6_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE6}
    {$DEFINE VCL_XE6_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE6_OR_ABOVE}
  {$DEFINE VCL_XE5_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE5}
    {$DEFINE VCL_XE5_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE5_OR_ABOVE}
  {$DEFINE VCL_XE4_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE4}
    {$DEFINE VCL_XE4_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE4_OR_ABOVE}
  {$DEFINE VCL_XE3_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE3}
    {$DEFINE VCL_XE3_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE3_OR_ABOVE}
  {$DEFINE VCL_XE2_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE2}
    {$DEFINE VCL_XE2_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE2_OR_ABOVE}
  {$DEFINE VCL_XE_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_XE}
    {$DEFINE VCL_XE_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE_OR_ABOVE}
  {$DEFINE VCL_2010_OR_ABOVE}
  {$IFNDEF DOTNET}
    {$DEFINE HAS_TInterlocked}
  {$ENDIF}
{$ELSE}
  {$IFDEF VCL_2010}
    {$DEFINE VCL_2010_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_2010_OR_ABOVE}
  {$DEFINE VCL_2009_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_2009}
    {$DEFINE VCL_2009_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_2009_OR_ABOVE}
  {$DEFINE VCL_2007_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_2007}
    {$DEFINE VCL_2007_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_2007_OR_ABOVE}
  {$DEFINE VCL_2006_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_2006}
    {$DEFINE VCL_2006_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_2006_OR_ABOVE}
  {$DEFINE VCL_2005_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_2005}
    {$DEFINE VCL_2005_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_2005_OR_ABOVE}
  {$DEFINE VCL_8_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_80}
    {$DEFINE VCL_8_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_8_OR_ABOVE}
  {$DEFINE VCL_7_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_70}
    {$DEFINE VCL_7_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_7_OR_ABOVE}
  {$DEFINE VCL_6_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_60}
    {$DEFINE VCL_6_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_6_OR_ABOVE}
  {$DEFINE VCL_5_OR_ABOVE}
   {$IFNDEF KYLIX}
      {$DEFINE HAS_DEPRECATED}
      {$DEFINE HAS_NO_RET_VAL}
      {$IFNDEF VCL_8_OR_ABOVE}
        // Delphi 6 and 7 have an annoying bug that if a class method is declared as
        // deprecated, the compiler will emit a "symbol is deprecated" warning
        // on the method's implementation!  So we will have to wrap implementations
        // of deprecated methods with {$WARN SYMBOL_DEPRECATED OFF} directives
        // to disable that warning.
        {$DEFINE DEPRECATED_IMPL_BUG}
      {$ENDIF}
   {$ENDIF}
{$ELSE}
  {$IFDEF VCL_50}
    {$DEFINE VCL_5_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_5_OR_ABOVE}
  {$DEFINE VCL_4_OR_ABOVE}
{$ELSE}
  {$IFDEF VCL_40}
    {$DEFINE VCL_4_OR_ABOVE}
  {$ENDIF}
{$ENDIF}

// Normalize Delphi compiler defines to match FPC for consistency:
//
// CPU32 - any 32-bit CPU
// CPU64 - any 64-bit CPU
// WINDOWS - any Windows platform (32-bit, 64-bit, CE)
// WIN32 - Windows 32-bit
// WIN64 - Windows 64-bit
// WINCE - Windows CE
//
// Consult the "Free Pascal Programmer's Guide", Appendix G for the complete
// list of defines that are used. Do not work on this unless you understand
// what the FreePascal developers are doing.  Not only do you have to
// descriminate with operating systems, but also with chip architectures
// are well.
//
// DCC Pulsar+ define the following values:
// ASSEMBLER
// DCC
// CONDITIONALEXPRESSIONS
// NATIVECODE
// UNICODE
// MACOS
// MACOS32
// MACOS64
// MSWINDOWS
// WIN32
// WIN64
// LINUX
// POSIX
// POSIX32
// CPU386
// CPUX86
// CPUX64
//
// Kylix defines the following values:
// LINUX
// (others??)
//

{$IFNDEF FPC}
  // TODO: We need to use ENDIAN_BIG for big endian chip architectures,
  // such as 680x0, PowerPC, Sparc, and MIPS, once DCC supports them,
  // provided it does not already define its own ENDIAN values by then...
  {$DEFINE ENDIAN_LITTLE}
  {$IFNDEF VCL_6_OR_ABOVE}
    {$DEFINE MSWINDOWS}
  {$ENDIF}
  {$IFDEF MSWINDOWS}
    {$DEFINE WINDOWS}
  {$ENDIF}
  // TODO: map Pulsar's non-Windows platform defines...
  {$IFDEF VCL_XE2_OR_ABOVE}
    {$IFDEF VCL_XE8_OR_ABOVE}
      {$IFDEF CPU32BITS}
        //any 32-bit CPU
        {$DEFINE CPU32}
      {$ENDIF}
      {$IFDEF CPU64BITS}
        {$DEFINE CPU64}
      {$ENDIF}
    {$ELSE}
      {$IFDEF CPU386}
        //any 32-bit CPU
        {$DEFINE CPU32}
        //Intel 386 compatible chip architecture
        {$DEFINE CPUI386}
      {$ENDIF}
      {$IFDEF CPUX86}
        {$DEFINE CPU32}
      {$ENDIF}
      {$IFDEF CPUX64}
        //any 64-bit CPU
        {$DEFINE CPU64}
        //AMD64 compatible chip architecture
        {$DEFINE CPUX86_64}  //historical name for AMD64
        {$DEFINE CPUAMD64}
      {$ENDIF}
    {$ENDIF}
  {$ELSE}
    {$IFNDEF DOTNET}
      {$IFNDEF KYLIX}
        {$DEFINE I386}
      {$ENDIF}
    {$ENDIF}
    {$DEFINE CPU32}
  {$ENDIF}
{$ENDIF}

{$IFDEF DOTNET}
  //differences in DotNET Framework versions.
  {$IFDEF VCL_2007_OR_ABOVE}
    {$DEFINE DOTNET_2}
    {$DEFINE DOTNET_2_OR_ABOVE}
  {$ELSE}
    {$DEFINE DOTNET_1_1}
  {$ENDIF}
  {$DEFINE DOTNET_1_1_OR_ABOVE}
  // Extra include used in D7 for testing. Remove later when all comps are
  // ported. Used to selectively exclude non ported parts. Allowed in places
  // IFDEFs are otherwise not permitted.
  {$DEFINE DOTNET_EXCLUDE}
{$ENDIF}

// Check for available features

{$IFDEF VCL_6_OR_ABOVE}
  {$DEFINE HAS_PPointer}
  {$IFNDEF FPC}
    {$DEFINE HAS_TSelectionEditor}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_2006_OR_ABOVE}
  {$DEFINE USE_INLINE}
{$ENDIF}

{$IFDEF VCL_2009_OR_ABOVE}
  {$IFNDEF DOTNET}
    {$DEFINE STRING_IS_UNICODE}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE3_OR_ABOVE}
  {$DEFINE HAS_DIRECTIVE_ZEROBASEDSTRINGS}
  {$IFDEF NEXTGEN}
    {$DEFINE DCC_NEXTGEN}
    {$DEFINE USE_MARSHALLED_PTRS}
    {$IFDEF AUTOREFCOUNT}
      {$DEFINE USE_OBJECT_ARC}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_XE5_UPDATE2_OR_ABOVE}
  {$DEFINE HAS_DIRECTIVE_HPPEMIT_LINKUNIT}
  {$DEFINE HAS_DIRECTIVE_HPPEMIT_NAMESPACE}
{$ENDIF}

{$IFDEF VCL_10_2_OR_ABOVE}
  {.$WARN IMPLICIT_INTEGER_CAST_LOSS OFF}
  {.$WARN IMPLICIT_CONVERSION_LOSS OFF}
  {.$WARN COMBINING_SIGNED_UNSIGNED64 OFF}
{$ENDIF}

{$IFDEF VCL_10_4_OR_ABOVE}
  // 0-based string indexing via '[]' is turned off by default in Delphi 10.4.
  // TStringHelper is always 0-indexed, flat RTL functions are always 1-indexed,
  // and now '[]' is 1-indexed again on all platforms - {$ZEROBASEDSTRINGS OFF}
  // is the default.
  {.$UNDEF HAS_DIRECTIVE_ZEROBASEDSTRINGS}
{$ENDIF}

// Delphi XE+ cross-compiling
{$IFNDEF FPC}
  {$IFDEF POSIX}
    {$IF RTLVersion >= 22.0}
      {$DEFINE UNIX}
      {$UNDEF USE_BASEUNIX}
      {$DEFINE VCL_CROSS_COMPILE}
      {$DEFINE USE_VCL_POSIX}
    {$IFEND}
  {$ENDIF}
  {$IFDEF LINUX}
    {$IFDEF CONDITIONALEXPRESSIONS}
      {$IF RTLVersion >= 22.0}
        {$DEFINE VCL_CROSS_COMPILE}
        {$DEFINE USE_VCL_POSIX}
      {$IFEND}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$IFDEF VCL_CROSS_COMPILE}
  {$UNDEF KYLIXCOMPAT}
{$ELSE}
  {$IFDEF KYLIXCOMPAT}
    {$linklib c}
  {$ENDIF}
{$ENDIF}

{$IFDEF FPC}
   //This needs to be disabled for FreePascal to work.
   //See https://github.com/JPeterMugaas/TaurusTLS/issues/79
  {$UNDEF USE_INLINE}
  {$IFDEF FPC_UNICODESTRINGS}
    {$DEFINE STRING_IS_UNICODE}
  {$ENDIF}
{$ENDIF}

// .NET and Delphi 2009+ support UNICODE strings natively!
//
// NOTE: Do not define UNICODE here.  The compiler defines
// the symbol automatically.
{$IFNDEF STRING_IS_UNICODE}
  {$DEFINE STRING_IS_ANSI}
{$ENDIF}

{$IFDEF DCC_NEXTGEN}
  {$DEFINE NO_ANSI_TYPES}
  {$IFDEF USE_OBJECT_ARC}
    // TODO: move these to an appropriate section. Not doing this yet because
    // it is a major interface change to switch to Generics and we should
    // maintain backwards compatibility with earlier compilers for the time
    // being. Defining them only here for now because the non-Generic versions
    // of these classes have become deprecated by ARC and so we need to start
    // taking advantage of the Generics versions...
    {$DEFINE HAS_UNIT_Generics_Collections}
    {$DEFINE HAS_GENERICS_TList}
    {$DEFINE HAS_GENERICS_TThreadList}
  {$ENDIF}
{$ENDIF}

// TODO: Ansi data types were disabled on mobile platforms in XE3, but
// UTF8String and RawByteString were re-enabled in 10.1 Berlin! What else,
// if anything, was re-enabled to facilitate that?
//
// UPDATE: In 10.4 Sydney, AnsiChar and AnsiString were re-enabled on
// mobile platforms!  NEXTGEN is no longer defined in the mobile compilers.
{$IFDEF NO_ANSI_TYPES}
  {$UNDEF HAS_PAnsiChar}
{$ENDIF}

{$IFDEF WIN32}
  {$DEFINE WIN32_OR_WIN64}
{$ENDIF}
{$IFDEF WIN64}
  {$DEFINE WIN32_OR_WIN64}
{$ENDIF}

{$UNDEF STATICLOAD_OPENSSL}
{$UNDEF OPENSSL_USE_SHARED_LIBRARY}

{$IFDEF WINDOWS}
  //Define these two if you wish to have TaurusTLS staticly load the OpenSSL
  //.DLL's instead of dynamically.
    {/$DEFINE STATICLOAD_OPENSSL}
    {/$DEFINE OPENSSL_USE_SHARED_LIBRARY}
{$ENDIF}
{$IFDEF IOS}
  // Support for 64-bit ARM iOS Simulator was added in Delphi 11.2
  // TODO: how to detect iOS Simulator in FPC? Does it support 64-bit ARM?
  {$IFDEF CPUARM}
    {$IFNDEF IOSSIMULATOR}
      // RLebeau: For iOS devices, OpenSSL cannot be used as an external library,
      // it must be statically linked into the app.  For the iOS simulator, this
      // is not true.  Users who want to use OpenSSL in iOS device apps will need
      // to add the static OpenSSL library to the project and then include the
      // IdSSLOpenSSLHeaders_static unit in their uses clause. It hooks up the
      // statically linked functions for the IdSSLOpenSSLHeaders unit to use...
      {$DEFINE STATICLOAD_OPENSSL}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$IFDEF ANDROID}
  {$DEFINE STATICLOAD_OPENSSL}
{$ENDIF}

{$UNDEF USE_INVALIDATE_MOD_CACHE}
//This must come after the iconv defines because this compiler targets a Unix-like
//operating system.  One key difference is that it does have a TEncoding class.
//If this comes before the ICONV defines, it creates problems.
//This also must go before the THandle size calculations.
{$IFDEF VCL_CROSS_COMPILE}
  {$IFDEF POSIX}
    {$IFNDEF LINUX}
      {$DEFINE BSD}
    {$ENDIF}
    {$DEFINE USE_INVALIDATE_MOD_CACHE}
  {$ENDIF}
{$ENDIF}

//IMPORTANT!!!!
//
//Do not remove this!!!  This is to work around a conflict.  In DCC, MACOS
//will mean OS X.  In FreePascal, the DEFINE MACOS means MacIntosh System OS Classic.
{$IFDEF DCC}
  // DCC defines MACOS for both iOS and OS X platforms, need to differentiate
  {$IFDEF MACOS}
    {$IFNDEF IOS}
      {$DEFINE OSX}
      {$DEFINE DARWIN}
      {$DEFINE STATICLOAD_OPENSSL}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
{$IFDEF FPC}
  // FPC defines DARWIN for both OSX and iOS, need to differentiate
  {$IFDEF DARWIN}
    {$IFNDEF IOS}
      {$DEFINE OSX}
    {$ENDIF}
  {$ENDIF}
  {$IFDEF MACOS}
    {$DEFINE MACOS_CLASSIC}
  {$ENDIF}
{$ENDIF}

{$IFDEF BSD}
  //I think BSD might handle FreeBSD, NetBSD, OpenBSD, and Darwin
  {$IFDEF IOS}
    {$IFDEF CPUARM64}
      {$DEFINE CPU64}
    {$ELSE}
      {$IFDEF CPUARM32}
        {$DEFINE CPU32}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
{$IFDEF LINUX}
  {$IFDEF LINUX64}
    {$DEFINE CPU64}
  {$ELSE}
    {$IFDEF LINUX32}
      {$DEFINE CPU32}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{end Unix OS specific stuff}

{$IFDEF DEBUG}
  {$UNDEF USE_INLINE}
{$ENDIF}

// RLebeau 9/5/2013: it would take a lot of work to re-write Indy to support
// both 0-based and 1-based string indexing, so we'll just turn off 0-based
// indexing for now...
{$IFDEF HAS_DIRECTIVE_ZEROBASEDSTRINGS}
  {$ZEROBASEDSTRINGS OFF}
{$ENDIF}

{$IFDEF UNIX}
  {$UNDEF OSX_OR_IOS}
  {$IFDEF OSX}
    {$DEFINE OSX_OR_IOS}
  {$ENDIF}
  {$IFDEF IOS}
    {$DEFINE OSX_OR_IOS}
  {$ENDIF}
{$ENDIF}

{$IFDEF MSWINDOWS}
{$DEFINE WINDOWS}
{$ENDIF}
