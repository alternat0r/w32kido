@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
del C:\rework\test_dbg.exe 2>nul
cl /nologo /W3 /O2 /MT C:\rework\test_dbg.c /Fe:C:\rework\test_dbg.exe /Fo:C:\rework\
C:\rework\test_dbg.exe
