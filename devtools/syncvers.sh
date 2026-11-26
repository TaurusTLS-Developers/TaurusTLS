#!/bin/bash
pushd ..
find Packages/ -name "*.dpk" -exec cp -p {} ../git/TaurusTLS/{} \;
find Packages/ -name "*.dproj" -exec cp -p {} ../git/TaurusTLS/{} \;
find Packages/ -name "*.pas" -exec cp -p {} ../git/TaurusTLS/{} \;
find Packages/ -name "*.lpk" -exec cp -p {} ../git/TaurusTLS/{} \;
find Packages/ -name "*.res" -exec cp -p {} ../git/TaurusTLS/{} \;

find Packages/ -name "*.dpk" -exec cp -p {} ../git/indy_extras/TaurusTLS/{} \;
find Packages/ -name "*.dproj" -exec cp -p {} ../git/indy_extras/TaurusTLS/{} \;
find Packages/ -name "*.pas" -exec cp -p {} ../git/indy_extras/TaurusTLS/{} \;
find Packages/ -name "*.lpk" -exec cp -p {} ../git/indy_extras/TaurusTLS/{} \;
find Packages/ -name "*.res" -exec cp -p {} ../git/indy_extras/TaurusTLS/{} \;

cp -p Source/TaurusTLS_Dsn_ResourceStrings.pas ../git/TaurusTLS/Source/
cp -p Source/TaurusTLS_Vers.inc ../git/TaurusTLS/Source/
cp -p tmsbuild.yaml ../git/TaurusTLS/
cp -p version.txt ../git/TaurusTLS/
cp -p TaurusTLS_Developers.TaurusTLS.dspec ../git/TaurusTLS/

cp -p Source/TaurusTLS_Dsn_ResourceStrings.pas ../git/TaurusTLS/Source/
cp -p Source/TaurusTLS_Vers.inc ../git/indy_extras/TaurusTLS//Source/
cp -p tmsbuild.yaml ../git/indy_extras/TaurusTLS/
cp -p version.txt ../git/indy_extras/TaurusTLS/
cp -p TaurusTLS_Developers.TaurusTLS.dspec ../git/indy_extras/TaurusTLS/

cp -p devtools/VersionManager/Win32/Debug/*.ini ../git/TaurusTLS/devtools/VersionManager/Win32/Debug
rm -rf ../git/TaurusTLS/devtools/VersionManager/templates/*
cp -rp devtools/VersionManager/templates/* ../git/TaurusTLS/devtools/VersionManager/templates/
find  ../git/TaurusTLS/devtools/VersionManager/templates/ -name "*.groupproj" -exec rm -rf {} \;
find  ../git/TaurusTLS/devtools/VersionManager/templates/ -name "*.bak" -exec rm -rf {} \;
find  ../git/TaurusTLS/devtools/VersionManager/templates/ -name "*.diproj" -exec rm -rf {} \;
find  ../git/TaurusTLS/devtools/VersionManager/templates/ -name "*.res" -exec rm -rf {} \;
find  ../git/TaurusTLS/devtools/VersionManager/templates/ -name "*.lpk" -exec rm -rf {} \;
cp -p devtools/VersionManager/Win32/Debug/*.ini ../git/indy_extras/TaurusTLS/devtools/VersionManager/Win32/Debug/
rm -rf ../git/indy_extras/TaurusTLS/devtools/VersionManager/templates/*
cp -rp devtools/VersionManager/templates/* ../git/indy_extras/TaurusTLS/devtools/VersionManager/templates/
find  ../git/indy_extras/TaurusTLS/devtools/VersionManager/templates/ -name "*.groupproj" -exec rm -rf {} \;
find  ../git/indy_extras/TaurusTLS/devtools/VersionManager/templates/ -name "*.bak" -exec rm -rf {} \;
find  ../git/indy_extras/TaurusTLS/devtools/VersionManager/templates/ -name "*.diproj" -exec rm -rf {} \;
find  ../git/indy_extras/TaurusTLS/devtools/VersionManager/templates/ -name "*.res" -exec rm -rf {} \;
find  ../git/indy_extras/TaurusTLS/devtools/VersionManager/templates/ -name "*.lpk" -exec rm -rf {} \;
popd
