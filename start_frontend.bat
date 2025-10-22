@echo off
echo ========================================
echo  Adaptive Security System - Frontend
echo ========================================
echo.

:: Check if Node.js is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo [OK] Node.js found
node --version
echo.

:: Navigate to frontend directory
cd frontend

:: Check if node_modules exists
if not exist "node_modules\" (
    echo [INFO] Installing dependencies...
    echo This may take a few minutes on first run...
    echo.
    call npm install
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] npm install failed!
        pause
        exit /b 1
    )
    echo.
    echo [OK] Dependencies installed successfully
    echo.
)

:: Start the development server
echo [INFO] Starting frontend development server...
echo.
echo Frontend will be available at:
echo   http://localhost:3002
echo.
echo Press Ctrl+C to stop the server
echo.

call npm run dev

pause
