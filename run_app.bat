@echo off
title Threat Check Launcher
echo ========================================================
echo   Threat Check - Full Stack Application Launcher
echo ========================================================
echo.
set "PY_CMD=python"
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
)

echo [1/3] Starting Backend API in separate window...
start "Threat Check - Backend API" cmd /k "cd /d "%~dp0backend" && "%PY_CMD%" -m pip install -r requirements.txt && "%PY_CMD%" -m uvicorn main:app --reload --port 8000"

echo [2/3] Waiting for backend initialization...
timeout /t 3 /nobreak >nul

echo [3/3] Opening Frontend in browser and starting HTTP server...
start "" "http://localhost:5500"
"%PY_CMD%" -m http.server 5500

