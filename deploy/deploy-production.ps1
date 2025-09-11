#!/usr/bin/env pwsh
# Deploy frontend to PRODUCTION environment of Static Web App

param(
    [Parameter(Mandatory=$true)]
    [string]$AppName
)

# Variables
$ResourceGroupName = "rg-$AppName"
$StaticWebAppName = "swa-$AppName-796"

Write-Host "Deploying to PRODUCTION environment of Static Web App..." -ForegroundColor Cyan

# Get deployment token
$deploymentToken = az staticwebapp secrets list --resource-group $ResourceGroupName --name $StaticWebAppName --query "properties.apiKey" --output tsv 2>$null

if ($deploymentToken -and $deploymentToken -ne "null") {
    Write-Host "✅ Got deployment token" -ForegroundColor Green
    
    # Change to frontend directory
    Set-Location ".\frontend"
    
    # Deploy to PRODUCTION environment (not preview)
    Write-Host "Deploying to PRODUCTION environment..." -ForegroundColor Yellow
    npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --env "production" --verbose
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Frontend deployed to PRODUCTION successfully!" -ForegroundColor Green
        Write-Host "Production URL: https://white-sea-01bf0d91e.2.azurestaticapps.net/" -ForegroundColor Green
    } else {
        Write-Host "❌ Production deployment failed. Trying without --env flag..." -ForegroundColor Yellow
        
        # Try without explicit environment (should default to production)
        npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --production --verbose
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Frontend deployed to PRODUCTION successfully!" -ForegroundColor Green
        } else {
            Write-Host "❌ Production deployment failed" -ForegroundColor Red
        }
    }
    
    Set-Location ..
} else {
    Write-Host "❌ Could not get deployment token" -ForegroundColor Red
}
