@echo off
TITLE CyberForecast AI - Network Attack Forecasting Platform (SIH 2026)
COLOR 0B

echo =========================================================================
echo    AI-BASED NETWORK ATTACK FORECASTING FROM NETWORK TRAFFIC DATA
echo                 Smart India Hackathon (SIH 2026)
echo =========================================================================
echo.

echo [1/3] Checking Directories...
cd /d "%~dp0"

echo [2/3] Launching FastAPI Backend Server on port 8000...
start "CyberForecast Backend" cmd /k "cd backend && python -m pip install -r requirements.txt && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

echo [3/3] Launching React Vite Frontend on port 3000...
start "CyberForecast Frontend" cmd /k "cd frontend && npm install && npm run dev"

echo.
echo =========================================================================
echo  Platform is starting!
echo  - Frontend URL :  http://localhost:3000
echo  - Backend API  :  http://localhost:8000/api
echo  - API Docs     :  http://localhost:8000/api/docs
echo.
echo  Demo logins (seeded on first boot):
echo    admin@cyberforecast.ai   / Admin@1234
echo    analyst@cyberforecast.ai / Analyst@1234
echo    viewer@cyberforecast.ai  / Viewer@1234
echo.
echo  Optional: integrity-contract tests ->  cd blockchain ^&^& npm run test:offline
echo =========================================================================
echo.
pause
