@echo off
title Threat Check Frontend
echo ========================================================
echo   Threat Check - Frontend Server
echo ========================================================
echo.
echo Opening browser at http://localhost:5500...
start "" "http://localhost:5500"
echo Starting HTTP server on port 5500 (Press Ctrl+C to stop)...
python -m http.server 5500
pause
