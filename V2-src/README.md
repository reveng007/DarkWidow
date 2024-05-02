### Compile using compile.bat:
```
@ECHO OFF

del spoof_DarkWidow.exe
nasm.exe -f win64 test_nasm.asm -o test_nasm.o
gcc spoof_DarkWidow.c -masm=intel test_nasm.o -o spoof_DarkWidow.exe
del test_nasm.o
```

If unable to compile, download this version of gcc to compile the above binary:
- version of mingw gcc: `gcc.exe (x86_64-posix-seh-rev0) 8.1.0` ([Download Link](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/seh/x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z/download))
