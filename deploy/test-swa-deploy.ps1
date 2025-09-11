#!/usr/bin/env pwsh
# Test script to deploy frontend to existing Static Web App

param(
    [Parameter(Mandatory=$true)]
    [string]$AppName
)

# Variables
$ResourceGroupName = "rg-$AppName"
$StaticWebAppName = "swa-$AppName-796"  # Use the existing SWA name

Write-Host "Testing Static Web App deployment..." -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "Static Web App: $StaticWebAppName" -ForegroundColor White

# Check if SWA exists
Write-Host "Checking if Static Web App exists..." -ForegroundColor Yellow
$swaExists = az staticwebapp show --resource-group $ResourceGroupName --name $StaticWebAppName 2>$null
if ($swaExists) {
    $swaInfo = $swaExists | ConvertFrom-Json
    $swaUrl = "https://$($swaInfo.properties.defaultHostname)"
    Write-Host "✅ Static Web App exists: $swaUrl" -ForegroundColor Green
} else {
    Write-Host "❌ Static Web App not found" -ForegroundColor Red
    exit 1
}

# Get deployment token
Write-Host "Getting deployment token..." -ForegroundColor Yellow
$deploymentToken = az staticwebapp secrets list --resource-group $ResourceGroupName --name $StaticWebAppName --query "properties.apiKey" --output tsv 2>$null

if ($deploymentToken -and $deploymentToken -ne "null" -and $deploymentToken.Trim() -ne "") {
    Write-Host "✅ Got deployment token" -ForegroundColor Green
    
    # Change to frontend directory
    Set-Location ".\frontend"
    
    # Check if dist folder exists
    if (Test-Path ".\dist") {
        Write-Host "✅ Dist folder found" -ForegroundColor Green
        
        # List contents of dist folder
        Write-Host "Contents of dist folder:" -ForegroundColor White
        Get-ChildItem ".\dist" -Recurse | Select-Object Name, FullName
        
        # Deploy using SWA CLI
        Write-Host "Deploying frontend to Static Web App using SWA CLI..." -ForegroundColor Yellow
        
        # Try npx first, then fall back to swa CLI
        Write-Host "Attempting deployment with npx @azure/static-web-apps-cli..." -ForegroundColor White
        npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --verbose
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Frontend deployed successfully!" -ForegroundColor Green
        } else {
            Write-Host "❌ Deployment failed with npx. Trying alternative method..." -ForegroundColor Red
            
            # Try swa CLI directly
            Write-Host "Attempting deployment with swa CLI..." -ForegroundColor White
            swa deploy --deployment-token $deploymentToken --app-location "dist" --verbose
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Frontend deployed successfully with swa CLI!" -ForegroundColor Green
            } else {
                Write-Host "❌ Deployment failed with both methods" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "❌ Dist folder not found. Building frontend first..." -ForegroundColor Red
        
        # Install dependencies and build
        Write-Host "Installing npm dependencies..." -ForegroundColor Yellow
        npm install
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Building frontend..." -ForegroundColor Yellow
            npm run build
            
            if ($LASTEXITCODE -eq 0 -and (Test-Path ".\dist")) {
                Write-Host "✅ Frontend built successfully" -ForegroundColor Green
                
                # Deploy again
                Write-Host "Deploying frontend to Static Web App..." -ForegroundColor Yellow
                npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --verbose
                
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "✅ Frontend deployed successfully!" -ForegroundColor Green
                } else {
                    Write-Host "❌ Deployment failed after build" -ForegroundColor Red
                }
            } else {
                Write-Host "❌ Frontend build failed" -ForegroundColor Red
            }
        } else {
            Write-Host "❌ npm install failed" -ForegroundColor Red
        }
    }
    
    # Return to original directory
    Set-Location ..
} else {
    Write-Host "❌ Could not get deployment token" -ForegroundColor Red
}

Write-Host "Test deployment script completed" -ForegroundColor Cyan
