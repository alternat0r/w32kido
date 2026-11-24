@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
del C:\rework\test_bn_mul.exe 2>nul
del C:\rework\test_bn_mul.obj 2>nul
cl /nologo /W3 /O2 /MT C:\rework\test_bn_mul.c /Fe:C:\rework\test_bn_mul.exe /Fo:C:\rework\
C:\rework\test_bn_mul.exe
