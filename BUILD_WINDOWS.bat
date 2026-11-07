@echo off
setlocal
if /I not "%VSCMD_ARG_TGT_ARCH%"=="x64" (
  echo ERROR: Open "x64 Native Tools Command Prompt for VS 2022".
  echo This project supports x64 only.
  pause
  exit /b 1
)
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 goto :fail
cmake --build build --config Release --parallel
if errorlevel 1 goto :fail
if not exist "build\Release\PC_Performance_Monitor_x64.exe" goto :fail
echo Build completed: build\Release\PC_Performance_Monitor_x64.exe
pause
exit /b 0
:fail
echo BUILD FAILED. Copy the complete compiler output for diagnosis.
pause
exit /b 1
