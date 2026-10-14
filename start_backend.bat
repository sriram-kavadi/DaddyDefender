@echo off
title Threat Check Backend API
echo ========================================================
echo   Threat Check - Backend API Server
echo ========================================================
echo.
cd /d "%~dp0backend"
echo [1/2] Installing / verifying dependencies...
python -m pip install -r requirements.txt
echo.
echo [2/2] Launching FastAPI backend on http://localhost:8000...
echo.
python -m uvicorn main:app --reload --port 8000
pause
