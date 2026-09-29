# CyberForecast AI - PowerShell launcher (Smart India Hackathon)
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "   AI-BASED NETWORK ATTACK FORECASTING FROM NETWORK TRAFFIC DATA" -ForegroundColor Green
Write-Host "                Smart India Hackathon (SIH 2026)" -ForegroundColor Yellow
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host ""

$rootDir = $PSScriptRoot

Write-Host "[1/2] Starting FastAPI Backend on port 8000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir\backend'; pip install -r requirements.txt; python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

Write-Host "[2/2] Starting React Vite Frontend on port 3000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir\frontend'; npm install; npm run dev"

Write-Host ""
Write-Host "Application launched successfully!" -ForegroundColor Green
Write-Host "Frontend        : http://localhost:3000" -ForegroundColor Yellow
Write-Host "Backend API     : http://localhost:8000/api" -ForegroundColor Yellow
Write-Host "API docs        : http://localhost:8000/api/docs" -ForegroundColor Yellow
Write-Host ""
Write-Host "Demo logins (seeded on first boot):" -ForegroundColor Cyan
Write-Host "  admin@cyberforecast.ai   / Admin@1234" -ForegroundColor White
Write-Host "  analyst@cyberforecast.ai / Analyst@1234" -ForegroundColor White
Write-Host "  viewer@cyberforecast.ai  / Viewer@1234" -ForegroundColor White
Write-Host ""
Write-Host "Optional integrity-chain tests:  cd blockchain; npm install; npm run test:offline" -ForegroundColor DarkGray
