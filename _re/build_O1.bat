@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio7\BuildTools\VC\Auxiliary\Buildcvarsall.bat" x86
del C:ework	b.exe 2>nul
cl /nologo /W3 /O1 /MT C:ework	est_bn_mul.c /Fe:C:ework	b.exe /Fo:C:ework\r
C:ework	b.exe
