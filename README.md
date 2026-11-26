# TaurusTLS

Copyright (c) 2026 TaurusTLS Developers
All Rights Reserved

## General Information

TaurusTLS provides 3.x and 4.x support for Indy - Internet Direct.  It includes headers plus four components for Delphi and C++Builder.  Those components are:

- TTaurusTLSIOHandlerSocket - Enables TLS in a TIdTCPClientCustom descendant.
- TTaurusTLSServerIOHandler - Enables TLS in a TIdCustomTCPServer descendant.
- TTaurusTLSUnicodeLog - Triggers events when data is sent and received and data is provided in Unicode form if supported.
- TTaurusTLSLoader - Platform-aware component over the shared OpenSSL singleton.

The components are available on the IDE palette page, “TaurusTLS”.

TaurusTLS supports the following operating systems:

- Android
- iOS
- Linux
- MacOS
- Windows

## Upgrading to TaurusTLS 1.1

TaurusTLS 1.1 supports OpenSSL 3.x and 4.x and requires OpenSSL to be
loaded or initialized before use. See the [migration guide](Migration_to_1_1.md)
for initialization options, provider configuration and changes to existing applications.

## License

TaurusTLS is dual licensed. You can review which license better suits your needs, and use that license.  You can even change your mind later if you have previously chosen one.

The TaurusTLS Modified BSD license is a very no nonsense license that allows you to do almost anything you want with TaurusTLS provided you provide proper attribution.  Details are available in the Modified_BSD_LICENSE.md file included in the with this source-code.

To make it easier and consistent for JEDI users, we also offer an MPL license v1.1.  Details are available in the LICENSE_MPL_1_1.txt file included with this source-code.

## RAD Studio Installation

TaurusTLS supports the following RAD Studio versions:

- Florence (Delphi 13) - packages in the TaurusTLS\Packages\d13 folder
- Athens (Delphi 12) - packages in the TaurusTLS\Packages\d12 folder
- Alexandria (Delphi 11) - package in the TaurusTLS\Packages\d11 folder
- Sydney (Delphi 10.4) - package in the TaurusTLS\Packages\dsydney folder
- Rio (Delphi 10.3) - package in the TaurusTLS\Packages\drio folder
- Tokyo (Delphi 10.2) - package in the TaurusTLS\Packages\dtokyo folder
- Berlin (Delphi 10.1) - package in the TaurusTLS\Packages\dberlin folder
- Seattle (Delphi 10) - package in the TaurusTLS\Packages\dseattle folder

You may make packages for older versions of RAD Studio.

### For Indy Included with Delphi

1. Open TaurusAll.groupproj in the TaurusTLS\Packages\d12 folder.
2. Compile TaurusTLS_RT.
3. Compile TaurusTLS_DT and install it in the IDE.

You may install TaurusTLS into the 64-bit Integrated Development Environment (IDE) using the same procedure.

If you have [TMS Smart Setup 2.0](https://doc.tmssoftware.com/smartsetup/) with **no credentials** required, go to the "TMS Smart Setup Console", and do the following to install TaurusTLS:

```
tms confi﻿g
tms install taurustls_developers.taurustls
```

### For Indy that was Upgraded from the Website

1. Set the INDY_PATH environment variable for your user account to the location where Indy is located.
2. Open TaurusForIndy290All.groupproj in the TaurusTLS\Packages\d12 folder.
3. Compile TaurusTLS_RTForIndy290.
4. Compile TaurusTLS_DTForIndy290 and install it in the IDE.

You may install TaurusTLS into the 64-bit Integrated Development Environment (IDE) using the same procedure.

### Making your own Packages

I suggest that you have 2 separate packages; a runtime only package and a design-time package.  

The run-time package should depend upon your Indy package files and include the following:

- Source\TaurusTLS.pas
- Source\TaurusTLSConsts.pas
- Source\TaurusTLSExceptionHandlers.pas
- Source\TaurusTLSHeaders_*.pas
- Source\TaurusTLSIdFIPS.pas
- Source\TaurusTLSIdNTLM.pas
- Source\TaurusTLSLoader.pas
- Source\TaurusTLS_Files.pas
- Source\TaurusTLS_ProviderFIPS.pas
- Source\TaurusTLS_ProviderLegacy.pas
- Source\TaurusTLS_ResourceStrings.pas
- Source\TaurusTLS_Unicode_Log.pas
- Source\TaurusTLS_Utils.pas
- Source\TaurusTLS_X509.pas

The design-time package should depend upon the run-time package and include the following files:

- Source\TaurusTLS_Dsn_AboutDlg.pas
- Source\TaurusTLS_Dsn_ComponentEditor.pas
- Source\TaurusTLS_Dsn_Const.pas
- Source\TaurusTLS_Dsn_Register.pas
- Source\TaurusTLS_Dsn_ResourceStrings.pas

## Lazarus Installation

1. Open taurustlsldsgn.lpk from the TaurusTLS/Packages/lazarus.
2. From "Required Packages", open "TaurusTLSRT" and compile it.
3. Then compile the main package itself and install it in the IDE.

## Deploying Your Applications

Deployment instructions are now on the TaurusTLS website's [Deploying Your TaurusTLS Applications](https://taurustls.org/deployapps.xhtml)

## Component Reference

TaurusTLS includes a component reference in "Compiled HTML Help file (.chm)" format in the Help\chm directory.

## Demo Programs

Demo applications are maintained in the
[taurustls_demos repository](https://github.com/TaurusTLS-Developers/taurustls_demos)
and included here as the `demos` Git submodule. Each TaurusTLS checkout records
an exact demo revision.

**To download the demos, clone with `--recursive` (or `--recurse-submodules`).**
A plain `git clone` does not populate the `demos` submodule.

```text
git clone --recursive https://github.com/TaurusTLS-Developers/TaurusTLS.git
```

For an existing checkout, initialize or update the recorded demo revision:

```text
git submodule update --init --recursive demos
```

Run this command after pulling TaurusTLS changes or switching releases to obtain
the demo revision recorded by that checkout. It does not select the latest demo
commit automatically. Preserve any local demo edits before changing revisions.

Source archives do not include submodule contents; obtain the demo repository
separately when working without Git. See the
[FireMonkey demo README](demos/Delphi/TaurusFMXDemo/README.md) for build,
configuration and deployment instructions. That demo illustrates HTTP/FTP
transfers, certificate details, optional IOHandler AutoLoad and OpenSSL lifetime.
The cross-platform FTP console sample is under `demos/Both/FTP_Console`.

DUnitX is an external test dependency, not a submodule. See the
[test guide](Tests/Readme.md) for configuring its source path; it is not required
to build applications using TaurusTLS.

### Maintaining the recorded demo revision

TaurusTLS maintainers update the demo revision deliberately, for example when
preparing a release or including a relevant demo fix. A commit in the separate
demo repository does not require an immediate TaurusTLS update.

From the TaurusTLS repository root, fetch and select the reviewed demo commit
(replace REVIEWED_DEMO_COMMIT with its commit ID):

```text
git -C demos fetch origin
git -C demos checkout --detach REVIEWED_DEMO_COMMIT
```

Check the demos against the intended TaurusTLS version, then record the selected
revision in a signed TaurusTLS commit:

```text
git add demos
git commit -S -m "Update demo revision for TaurusTLS"
```

Commit and push demo source changes in the demo repository first. The selected
commit must be available there before publishing the TaurusTLS revision that
references it. Keep the submodule's working tree clean when recording the update.

## Tools I Use

### Beyond Compare

Compares different versions of a file.
<https://www.scootersoftware.com/>

### Deleaker

Helps us find leaks.
<https://www.deleaker.com/>

### DocInsight

Converts XML Documentation comments into a .CHM file.
<https://devjetsoftware.com/products/documentation-insight/>

### Pascal Analyzer

Analyzes source-code to find various types of potential issues.

<https://peganza.com/products_pal.html>

### TMS FixInsight

Analyzes source-code to find various types of potential issues.

<https://www.tmssoftware.com/site/fixinsight.asp>

## Credits

### Chad Z. Hower (Kudzu) and the Indy Pit Crew

author of the original code that was modified to create TaurusTLS.

### Dave Nottage

for providing the code used for loading OpenSSL on MacOS, and for changes needed for static binding, and Android and iOS

### Tony Whyman

for providing the OpenSSL headers that TaurusTLS is based upon

## Third Party Notices

Portions of this software are Copyright (c) 1993 – 2018, Chad Z. Hower
(Kudzu) and the Indy Pit Crew – <https://www.indyproject.org/>

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

1. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation, about box and/or other materials provided with the distribution.

2. No personal names or organizations names associated with the Indy project may be used to endorse or promote products derived from this software without specific prior written permission of the specific individual or organization.

THIS SOFTWARE IS PROVIDED BY Chad Z. Hower (Kudzu) and the Indy Pit Crew "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
