@ECHO OFF

del spoof_DarkWidow.exe
nasm.exe -f win64 test_nasm.asm -o test_nasm.o
::gcc.exe spoof_DarkWidow.c -masm=intel test_nasm.o -o spoof_DarkWidow.exe -lntdll
gcc spoof_DarkWidow.c -masm=intel test_nasm.o -o spoof_DarkWidow.exe
del test_nasm.o

::gcc.exe spoof_DarkWidow.c test_nasm.o -o spoof_DarkWidow.exe -lntdll
::gcc triboulet.c -masm=intel -O1 -o triboulet.exe
