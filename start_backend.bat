@echo off
title Threat Check Backend API
echo ========================================================
echo   Threat Check - Backend API Server
echo ========================================================
echo.
cd /d "%~dp0backend"
set "PY_CMD=python"
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
)

echo [1/2] Installing / verifying dependencies...
"%PY_CMD%" -m pip install -r requirements.txt
echo.
echo [2/2] Launching FastAPI backend on http://localhost:8000...
echo.
"%PY_CMD%" -m uvicorn main:app --reload --port 8000
pause
