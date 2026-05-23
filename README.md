# TaurusTLS

Copyright (c) 2026 TaurusTLS Developers
All Rights Reserved

## General Information

TaurusTLS provides 3.x and 4.x support for Indy - Internet Direct.  It includes headers plus two components for Delphi and C++Builder.  Those components are:

- TTaurusTLSIOHandlerSocket - Enables TLS in a TIdTCPClientCustom descendant.
- TTaurusTLSServerIOHandler - Enables TLS in a TIdCustomTCPServer descendant.
- TTaurusTLSUnicodeLog - Triggers events when data is sent and received and data is provided in Unicode form if supported.

Both components are in the TaurusTLS.pas unit and the components are available on the IDE palette page, “TaurusTLS”.

TaurusTLS supports the following operating systems:

- Android
- iOS
- Linux
- MacOS
- Windows

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
tms configure
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
- Source\TaurusTLS_Files.pas
- Source\TaurusTLS_NTLM.pas
- Source\TaurusTLS_ResourceStrings.pas
- Source\TaurusTLS_Utils.pas
- Source\TaurusTLS_X509.pas
- Source\TaurusTLSConsts.pas
- Source\TaurusTLSExceptionHandlers.pas
- Source\TaurusTLSFIPS.pas
- Source\TaurusTLS_Unicode_Log.pas
- Source\TaurusTLSHeaders_*.pas
- Source\TaurusTLSLoader.pas

The design-time package should depend upon the run-time package and include the following files:

- Source\TaurusTLS_Dsn_AboutDlg.pas
- Source\TaurusTLS_Dsn_ComponentEditor.pas
- Source\TaurusTLS_Dsn_Register.pas
- Source\TaurusTLS_Dsn_ResourceStrings.pas

## Lazarus Installation

1. Open taurustlsldsgn.lpk from the TaurusTLS/Packages/lazarus.
2. From "Required Packages", open "TaurusTLSRT" and compile it.
3. Then compile the main package itself and install it in the IDE.

## Deploying Your Applications

TaurusTLS relies on OpenSSL 3.x or 4.x. Depending on the target platform, OpenSSL is either linked dynamically (requiring DLLs) or statically (compiled into your executable).

You can download the correct binaries for all platforms here:
**[OpenSSL-Distribution Releases](https://github.com/TaurusTLS-Developers/OpenSSL-Distribution/releases)**

### Dynamic Linking
#### Linux

`TaurusTLS` uses **dynamic linking** for the `Linux64` platform. 
On Linux, OpenSSL is usually installed by default on the OS. We recommend explicitly documenting this dependency for your end-users. If you choose to deploy a specific version, you can download redistributable Linux package from the **[OpenSSL-Distribution Releases](https://github.com/TaurusTLS-Developers/OpenSSL-Distribution/releases)** and resistribute it with your application(s).

#### Windows

On Windows, TaurusTLS uses **Dynamic Linking**. You **must** redistribute the OpenSSL shared libraries (`.dll`) and the License file alongside your application executable.

*   **Download:** Look for the standard packages (e.g., `openssl-3.6.1-Windows-x86.zip`, `openssl-3.6.1-Windows-x64.zip`, `openssl-3.6.1-Windows-arm64ec.zip`).
*   **Redistribution:** You must ship the following files with your application:

| Platform | OpenSSL 3.x Required Files | OpenSSL 4.x Required Files |
| :--- | :--- | :--- |
| **Windows 32-bit** | `libcrypto-3.dll`, `libssl-3.dll`, `LICENSE.txt` | `libcrypto-4.dll`, `libssl-4.dll`, `LICENSE.txt` |
| **Windows 64-bit** | `libcrypto-3-x64.dll`, `libssl-3-x64.dll`, `LICENSE.txt` | `libcrypto-4-x64.dll`, `libssl-4-x64.dll`, `LICENSE.txt` |
| **Windows ARM64EC**| `libcrypto-3-arm64.dll`, `libssl-3-arm64.dll`, `LICENSE.txt` | `libcrypto-4-arm64.dll`, `libssl-4-arm64.dll`, `LICENSE.txt` |

> **Note:** We strongly recommend also redistributing the `openssl.exe` included in the package, as users may need it for certificate management tasks like:
- Generate keys
- Create Certificate Signing Requests
- Create self-signed Certificates
- Examine certificates
- convert Certificate
- etc.

There's a reference book called the *OpenSSL Cookbook* at <https://www.feistyduck.com/books/openssl-cookbook/>.

### Static Linking (Android, iOS, macOS)

On Mobile and macOS platforms, TaurusTLS uses **Static Linking**. The OpenSSL code is compiled directly into your application binary.

*   **Download:** Look for the standard packages (e.g., `openssl-3.6.1-Android-arm64.zip`, `openssl-3.6.1-iOS-arm64.zip`, `openssl-3.6.1-macOS-arm64.zip`).
*   **Development:** You need the static library files (`.a`) contained in the `lib\static` folder of these archives to compile your project.
*   **Redistribution:** You do **not** need to ship any separate OpenSSL files (`.dylib`, `.so`, or `.a`). You only need to distribute:
    1.  Your Application package
    2.  The `LICENSE.txt` file (to comply with the OpenSSL license).

## Component Reference

TaurusTLS includes a component reference in "Compiled HTML Help file (.chm)" format in the Help\chm directory.

## Demo Programs

Taurus TLS includes 3 demo programs.  

### TaurusTLS\src\demos\FTPServer\TaurusFTPServer.dproj  

This is a FTP Server with TLS enabled that runs in the Windows console.  This program has been tested with the following FTP clients:

- FileZilla - <https://filezilla-project.org/>
- SmartFTP - <https://www.smartftp.com/en-us/>
- WinSCP - <https://winscp.net/eng/index.php>
- WS_FTP Professional - <https://www.progress.com/resources/papers/ws-ftp-pro-data-sheet>

This program requires a certificate to run.  Instructions for creating a self-signed certificate are available at [https://technotes.shemyak.com/posts/min-openssl-cnf/](https://technotes.shemyak.com/posts/min-openssl-cnf/).  You then need to create a server.ini file in the executable directory that enables the certificate that has the following lines:

```text
[Certificate]
CertificateFile=[path to your public certificate file]
KeyFile=[path to your private SSL key]
Password=[password for your private SSL key]
RootCertFile=[path to your root certificate file if applicable]
```

You can also do the following:

1. Copy the OpenSSL .dll's and openssl.exe to the directory where the FTP server demo .exe is built.  Usually that is \\$\(platform\)\\Debug or \\$\(platform\)\\Release.
2. Run the makecert.bat to generate a self-signed certificate.  Just answer the prompts and the certificate is generated.
3. Run the FTP Server .exe and it will create a default server.ini file that points to the certificate files generated in Step 2.

### TaurusTLS\demos\TaurusFTPConsole\taurusftp.dpr and taurusftp.lpr

This is a fully functional cross-platform console FTP client that can be built with both Delphi and Lazaurus.  It has been tested with the following servers:

- CompleteFTP Server - <https://enterprisedt.com/products/completeftp/>
- FileZilla Server - <https://filezilla-project.org/>
- ProFTPD - <http://www.proftpd.org/>
- PureFTPD - <https://www.pureftpd.org/>
- vsftpd - <https://security.appspot.com/vsftpd.html>
- Xlight FTP Server - <https://www.xlightftpd.com/>

For help using the client, just use the "help" command.

### TaurusTLS\Demos\TaurusHTTPServer\taurusHTTPServer.dpr and taurusHTTPServer.lpr

This is a minimal HTTP Server that only replies with a 200 code and an empty page.  This program is used for testing the server component for cross-platform usage.  This program requires a certificate file (domain.crt) and a private key file (domain.key) that has to generated by the openssl.exe program.

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

THIS SOFTWARE IS PROVIDED BY Chad Z. Hower (Kudzu) and the Indy Pit Crew “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
