@echo off
title Adaptive Security System - Full Stack Launcher
color 0A

echo ========================================
echo   ADAPTIVE SECURITY SYSTEM
echo   Full Stack Launch Script
echo ========================================
echo.

:: Check Python
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed!
    pause
    exit /b 1
)
echo [OK] Python found:
python --version
echo.

:: Check Node.js
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed!
    echo Please install from https://nodejs.org/
    pause
    exit /b 1
)
echo [OK] Node.js found:
node --version
echo.

:: Activate virtual environment if it exists
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
    echo [OK] Virtual environment activated
    echo.
) else (
    echo [WARNING] No virtual environment found at venv\
    echo [INFO] Using system Python
    echo.
)

:: Install frontend dependencies if needed
if not exist "frontend\node_modules\" (
    echo [INFO] Installing frontend dependencies...
    pushd frontend
    call npm install
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] npm install failed!
        popd
        pause
        exit /b 1
    )
    popd
    echo [OK] Frontend dependencies installed
    echo.
)

:: Build frontend assets if missing
if not exist "static\dist\index.html" (
    echo [INFO] Building frontend assets...
    pushd frontend
    call npm run build
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Frontend build failed!
        popd
        pause
        exit /b 1
    )
    popd
    echo [OK] Frontend assets built to static\dist
    echo.
) else (
    echo [INFO] Existing frontend build detected at static\dist
    echo.
)

:: Install Python dependencies if needed
echo [INFO] Checking Python dependencies...
pip install -q -r requirements.txt 2>nul
echo [OK] Python dependencies ready
echo.

:: Start backend in a new window
echo [INFO] Starting Flask backend server...
start "Adaptive Security Backend" cmd /k "python main.py"
timeout /t 5 /nobreak >nul
echo [OK] Backend started on http://localhost:5000
echo.

echo ========================================
echo   SYSTEM STARTED SUCCESSFULLY!
echo ========================================
echo.
echo Backend API:  http://localhost:5000
echo Dashboard:    http://localhost:5000/suite/status
echo Health Check: http://localhost:5000/health
echo.
echo Press any key to view this window...
echo Close this window to stop monitoring
echo (Backend will continue running in separate window)
echo.
pause

:: Keep window open
:loop
timeout /t 30 /nobreak >nul
goto loop
