C:/msys64/usr/bin/wget.exe -nv https://download.microsoft.com/download/B/C/4/BC4FA89D-4F7B-4022-A4C1-2B3B6E08D8BE/AppBuilderSetup_VS2012_v50806.zip
C:/msys64/usr/bin/wget.exe -nv https://github.com/datadiode/supplements/raw/main/Compact2013_SDK_86Duino_80B.msi
C:/msys64/usr/bin/wget.exe -nv https://github.com/datadiode/supplements/raw/main/WEC2013_Beaglebone_SDK_1_00.msi
7z.exe x -oAppBuilderSetup AppBuilderSetup_VS2012_v50806.zip
AppBuilderSetup\VSEmbedded_AppBuilder.exe /Quiet /NoRestart
msiexec /i Compact2013_SDK_86Duino_80B.msi /quiet /norestart
msiexec /i WEC2013_Beaglebone_SDK_1_00.msi /quiet /norestart
