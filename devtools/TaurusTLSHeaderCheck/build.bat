@echo off
rem Build TaurusTLSHeaderCheck. Requires rsvars.bat from a Delphi installation
rem to be on the path, or run this from a "RAD Studio Command Prompt".

if "%BDS%"=="" (
  for %%D in (37.0 36.0 35.0 34.0 23.0 22.0 21.0) do (
    if exist "%ProgramFiles(x86)%\Embarcadero\Studio\%%D\bin\rsvars.bat" (
      call "%ProgramFiles(x86)%\Embarcadero\Studio\%%D\bin\rsvars.bat" >nul
      goto :build
    )
  )
  echo Could not find rsvars.bat - run this from a RAD Studio Command Prompt.
  exit /b 2
)

:build
dcc32 -B TaurusTLSHeaderCheck.dpr
if errorlevel 1 exit /b 1
echo.
echo Built TaurusTLSHeaderCheck.exe
echo Usage: TaurusTLSHeaderCheck.exe ..\..\TaurusTLS\Source
