@echo off
title Threat Check Frontend
echo ========================================================
echo   Threat Check - Frontend Server
echo ========================================================
echo.
set "PY_CMD=python"
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
)

echo Opening browser at http://localhost:5500...
start "" "http://localhost:5500"
echo Starting HTTP server on port 5500 (Press Ctrl+C to stop)...
"%PY_CMD%" -m http.server 5500
pause
