@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Gemini.ps1" -OpenAdmin
if errorlevel 1 (
  echo.
  echo Could not start the server. See the message above.
  pause
  exit /b 1
)
