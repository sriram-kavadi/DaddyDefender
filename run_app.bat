@echo off
title Threat Check Launcher
echo ========================================================
echo   Threat Check - Full Stack Application Launcher
echo ========================================================
echo.
echo [1/3] Starting Backend API in separate window...
start "Threat Check - Backend API" cmd /k "cd /d "%~dp0backend" && python -m pip install -r requirements.txt && python -m uvicorn main:app --reload --port 8000"

echo [2/3] Waiting for backend initialization...
timeout /t 3 /nobreak >nul

echo [3/3] Opening Frontend in browser and starting HTTP server...
start "" "http://localhost:5500"
python -m http.server 5500
