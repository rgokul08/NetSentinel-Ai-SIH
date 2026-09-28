@echo off
TITLE ChainTrace AI - Network Attack Forecasting Platform (SIH 2026)
COLOR 0B

echo =========================================================================
echo    AI-BASED NETWORK ATTACK FORECASTING FROM NETWORK TRAFFIC DATA
echo                 Smart India Hackathon (SIH 2026)
echo =========================================================================
echo.

echo [1/3] Checking Directories...
cd /d "%~dp0"

echo [2/3] Launching FastAPI Backend Server on port 8000...
start "FastAPI Backend" cmd /k "cd backend && python -m pip install -r requirements.txt && python app/main.py"

echo [3/3] Launching React Vite Frontend on port 3000...
start "React Frontend" cmd /k "cd frontend && npm install && npm run dev"

echo.
echo =========================================================================
echo  Platform is starting!
echo  - Frontend URL:  http://localhost:3000
echo  - Backend Docs:  http://localhost:8000/docs
echo  - Admin Login:   admin@soc.guard / Admin@1234
echo =========================================================================
echo.
pause
