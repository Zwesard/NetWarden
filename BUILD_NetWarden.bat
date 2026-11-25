@echo off
setlocal
cd /d "%~dp0"
echo ===== NetWarden: building NetWarden.exe =====
if not exist NetWarden.cs (
  echo NetWarden.cs not found. Extract the whole ZIP archive first, then run this file again.
  pause
  exit /b 1
)
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo .NET Framework 4 compiler was not found. Enable .NET Framework 4.8 in Windows Features.
  pause
  exit /b 1
)
"%CSC%" /nologo /target:winexe /optimize+ /codepage:65001 /out:NetWarden.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll NetWarden.cs
if errorlevel 1 (
  echo.
  echo BUILD FAILED. Take a screenshot of the errors above and send it to me.
  pause
  exit /b 1
)
echo.
echo Done. NetWarden.exe is ready - starting it now.
start "" "%~dp0NetWarden.exe"
timeout /t 3 >nul
