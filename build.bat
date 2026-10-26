@echo off
rem Needs a 32-bit MinGW gcc (e.g. C:\MinGW\bin\gcc.exe, 6.3.0). The game is 32-bit.
C:\MinGW\bin\gcc -shared -O2 -o MyDoc.dll src\patch.c src\mydoc.def -Wl,--enable-stdcall-fixup
