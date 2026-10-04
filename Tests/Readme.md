# Unit Tests README

## Welcome!

This README is your go-to guide for developing, setting up, and running unit tests for TaurusTLS using the robust DUnitX framework tailored for Delphi. We're excited to share that this project currently supports both Windows and Linux operating systems.

## Prerequisites

Before you dive in, make sure you have the following essentials ready:

- **Delphi**: Delphi 10 (Seattle) or newer
- **DUnitX framework**: [GitHub Repository](https://github.com/VSoftTechnologies/DUnitX).
The unit tests require **AutoNameTestCase ** test attribute support in the **DUnitX** framework. This support does not exist in earlier versions of *DUnitX**, including the **DUnitX** package delivered with **Delphi**. Please use the source files from the [DUnitX repository](https://github.com/VSoftTechnologies/DUnitX.git), which is included in the **TaurusTLS** repository as a submodule for your convenience.
- **FastMM5 unit**: [GitHub Repository](https://github.com/pleriche/FastMM5). This unit is __optional__, and it's used for potential memory leak checks.
- **Indy - Internet Direct library**: [GitHub Repository](https://github.com/IndySockets/Indy).
- **TaurusTLS library**: [GitHub Repository](https://github.com/JPeterMugaas/TaurusTLS). This repository.
- **OpenSSL binaries** for Windows or the OpenSSL package suitable for your Linux distribution.

## Contributing to Unit Tests

We warmly invite you to get involved! To build a strong foundation, be sure to explore the **DUnitX** repository along with the **Embarcadero DocWiki**. These resources provide valuable insights and essential information on the fundamentals of DUnitX.

The `TaurusTLS.UT.dpr` is the habitat of all unit tests for the **TaurusTLS**  project. You are welcome to add new unit tests there.

For a smooth start, consider inheriting a test class from the `TOsslBaseFixture` found in the `TaurusTLS.UT.TestClasses` unit. This class will automatically load the `OpenSSL` library during `Fixture Setup` and unload it during `Fixture Teardown`. If there's ever a hiccup loading the OpenSSL library, your tests derived from `TOsslBaseFixture` will gracefully fail with the `EOsslBaseFixture` exception, keeping your testing experience clear and informative.

To add your own fixture setup or teardown, declare `SetupFixture` or `TearDownFixture` in your fixture with the `[SetupFixture]` or `[TearDownFixture]` attribute, and call `inherited` to keep loading and unloading the OpenSSL library.

And remember, new fixtures must be registered explicitly in the DUnitX framework. Add the following code snippet to your unit initialization section:

```pascal
initialization
  TDUnitX.RegisterTestFixture(<your_fixture_class_name>);
end.
```
## Compiling unit test
Please set up your build environment to use the correct version of the DUnitX framework. The simplest way to do this is to add the path to the DUnitX repository source files to the Search Files path of this project (Project> Options> Delphi Compiler> Search Path).

The **MEMLEAK_CHECK** conditional symbol controls the memory leak check on every test execution. Please declare it in the IDE (Project>Options>Delphi Compiler>Conditional Defines), or add the command-line switch **/p:DCC_Define=MEMLEAK_CHECK** to the **msbuild** if you build it in a CI/CD pipeline.

## Running Your Unit Tests

Running your unit tests is straightforward! You can execute them directly from the Delphi IDE, or if you prefer, run the compiled program separately. By default, all registered unit tests will run automatically, but you can customize your execution as needed. You can also use standard **DUnitX** command-line switches to filter out tests to run, test output details, etc.

### command-line switches
The `TaurusTLS.UT` extends **DUnitX** command-line switches set with new ones:
- **--opensslpath:value or -osp:value** - allows to specify path to **OpenSSL** library folder.
- **--fastmmdebugdll:value or -fmd:value** - Path to FastMM_FullDebugMode.dll or FastMM_FullDebugMode64.dll. This library is required to build detailed Memory Leak report. Please refer to the **FastMM5** documentation.
- **--fme:value or -fastmmlogenable:value** - enables or disables detailed Memory Leak report generation.
- **--fastmmlogname:value or -fml:value** - detailed Memory Leak report file name (default - stdout).

Let's get testing with enthusiasm and positivity!

