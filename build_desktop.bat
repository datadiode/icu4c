SETLOCAL

CALL "%ProgramFiles(x86)%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86 8.1

msbuild /t:Rebuild "%~dp0source\allinone\allinone.sln" /p:Platform="Win32" /p:Configuration="Debug"
msbuild /t:Rebuild "%~dp0source\allinone\allinone.sln" /p:Platform="Win32" /p:Configuration="Release"

7z.exe a -mx9 desktop.7z include bin\* lib\*
