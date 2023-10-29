SETLOCAL

CALL "%ProgramFiles(x86)%\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" x86

msbuild /t:Rebuild "%~dp0source\allinone\allinone.sln" /p:Platform="Win32" /p:Configuration="Release" /p:PlatformToolset="v120"

msbuild /t:Build "%~dp0source\allinone\allinone.sln" /p:Platform="Compact2013_SDK_86Duino_80B" /p:Configuration="Debug"
msbuild /t:Build "%~dp0source\allinone\allinone.sln" /p:Platform="Compact2013_SDK_86Duino_80B" /p:Configuration="Release"

msbuild /t:Build "%~dp0source\allinone\allinone.sln" /p:Platform="WEC2013 Beaglebone SDK" /p:Configuration="Debug"
msbuild /t:Build "%~dp0source\allinone\allinone.sln" /p:Platform="WEC2013 Beaglebone SDK" /p:Configuration="Release"

7z.exe a -mx9 wec2013.7z include bin\*\ lib\*\
