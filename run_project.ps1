# ChainTrace AI - PowerShell Multi-Process Launcher (SIH 2026)
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "   AI-BASED NETWORK ATTACK FORECASTING FROM NETWORK TRAFFIC DATA" -ForegroundColor Green
Write-Host "                Smart India Hackathon (SIH 2026)" -ForegroundColor Yellow
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host ""

$rootDir = $PSScriptRoot

Write-Host "[1/2] Starting FastAPI Backend on port 8000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir\backend'; pip install -r requirements.txt; python app/main.py"

Write-Host "[2/2] Starting React Vite Frontend on port 3000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$rootDir\frontend'; npm install; npm run dev"

Write-Host ""
Write-Host "Application launched successfully!" -ForegroundColor Green
Write-Host "Frontend: http://localhost:3000" -ForegroundColor Yellow
Write-Host "Backend API Docs: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "Admin User: admin@soc.guard / Admin@1234" -ForegroundColor Cyan
