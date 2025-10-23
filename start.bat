@echo off
:: ============================================================================
:: Adaptive Security Suite - Start Script
:: Starts both Backend (Flask) and Frontend (React/Vite) simultaneously
:: ============================================================================

title Adaptive Security Suite - Launcher

echo.
echo ========================================================================
echo    ADAPTIVE SECURITY SUITE - SYSTEM LAUNCHER
echo ========================================================================
echo.

:: Set colors
color 0A

:: Check if Python is installed
echo [1/4] Checking Python installation...
py --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python from https://www.python.org/
    pause
    exit /b 1
)
echo [OK] Python found

:: Check if Node.js is installed
echo.
echo [2/4] Checking Node.js installation...
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not in PATH!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)
echo [OK] Node.js found

:: Check if frontend dependencies are installed
echo.
echo [3/4] Checking frontend dependencies...
if not exist "frontend\node_modules" (
    echo [INFO] Installing frontend dependencies...
    cd frontend
    call npm install
    cd ..
    if errorlevel 1 (
        echo [ERROR] Failed to install frontend dependencies!
        pause
        exit /b 1
    )
    echo [OK] Frontend dependencies installed
) else (
    echo [OK] Frontend dependencies already installed
)

:: Start the services
echo.
echo [4/4] Starting services...
echo.
echo ========================================================================
echo  LAUNCHING BACKEND AND FRONTEND
echo ========================================================================
echo.
echo Backend (Flask API):  http://localhost:5001
echo Frontend (React App): http://localhost:3002
echo.
echo Press Ctrl+C to stop all services
echo ========================================================================
echo.

:: Start backend in a new window
start "Backend - Flask API (Port 5001)" cmd /k "cd /d %~dp0 && echo Starting Flask Backend... && py main.py"

:: Wait a bit for backend to initialize
timeout /t 3 /nobreak >nul

:: Start frontend in a new window
start "Frontend - React Dev Server (Port 3002)" cmd /k "cd /d %~dp0frontend && echo Starting React Frontend... && npm run dev"

:: Wait a bit for frontend to start
timeout /t 5 /nobreak >nul

:: Open browser
echo.
echo [INFO] Opening browser...
timeout /t 2 /nobreak >nul
start http://localhost:3002

echo.
echo ========================================================================
echo  SYSTEM STARTED SUCCESSFULLY!
echo ========================================================================
echo.
echo Backend and Frontend are running in separate windows.
echo.
echo To stop all services:
echo   1. Close this window, or
echo   2. Close the Backend and Frontend windows individually
echo.
echo Press any key to keep this launcher window open...
pause >nul
