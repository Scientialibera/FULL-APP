#!/usr/bin/env pwsh
param(
    [Parameter(Mandatory=$true)]
    [string]$AppName,
    
    [Parameter(Mandatory=$true)]
    [string]$Location = "westus2"
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Clean app name (remove spaces, special characters, convert to lowercase)
$cleanAppName = $AppName -replace '[^a-zA-Z0-9]', ''
$cleanAppName = $cleanAppName.ToLower()

# Generate unique suffixes
$uniqueSuffix = Get-Random -Minimum 100 -Maximum 999

# Define resource names
$ResourceGroupName = "rg-$cleanAppName-test"
$Location = $Location

Write-Host "🚀 Starting test deployment for '$AppName'" -ForegroundColor Green
Write-Host "📍 Location: $Location" -ForegroundColor Cyan
Write-Host "📦 Resource Group: $ResourceGroupName" -ForegroundColor Cyan

# Step 1: Create Resource Group
Write-Host "🏗️ Creating Resource Group..." -ForegroundColor Yellow
$rgExists = az group exists --name $ResourceGroupName
if ($rgExists -eq "false") {
    az group create --name $ResourceGroupName --location $Location --output none
    Write-Host "✅ Resource Group '$ResourceGroupName' created" -ForegroundColor Green
} else {
    Write-Host "✅ Resource Group '$ResourceGroupName' already exists" -ForegroundColor Green
}

# Step 2: Get tenant ID
Write-Host "🔍 Getting tenant information..." -ForegroundColor Yellow
$tenantInfo = az account show | ConvertFrom-Json
$tenantId = $tenantInfo.tenantId
Write-Host "✅ Tenant ID: $tenantId" -ForegroundColor Green

# Step 3: Create API App Registration (for backend)
Write-Host "🔧 Creating API App Registration..." -ForegroundColor Yellow
$apiAppName = "$cleanAppName-api"

# Check if app already exists
$existingApiApp = az ad app list --display-name $apiAppName | ConvertFrom-Json
if ($existingApiApp.Count -eq 0) {
    Write-Host "Creating new API app registration..." -ForegroundColor Cyan
    $apiApp = az ad app create --display-name $apiAppName --sign-in-audience "AzureADMyOrg" | ConvertFrom-Json
    $apiAppId = $apiApp.appId
    
    # Add API scope
    $scopeId = [System.Guid]::NewGuid().ToString()
    $apiManifest = @{
        api = @{
            oauth2PermissionScopes = @(
                @{
                    id = $scopeId
                    adminConsentDescription = "Access the $cleanAppName API"
                    adminConsentDisplayName = "Access API"
                    userConsentDescription = "Access the $cleanAppName API"
                    userConsentDisplayName = "Access API"
                    value = "access_api"
                    type = "User"
                    isEnabled = $true
                }
            )
        }
        identifierUris = @("api://$apiAppId")
    }
    
    $manifestJson = $apiManifest | ConvertTo-Json -Depth 10 -Compress
    $manifestJson | Out-File -FilePath "temp-api-manifest.json" -Encoding UTF8
    
    az ad app update --id $apiAppId --set "@temp-api-manifest.json" --output none
    Remove-Item "temp-api-manifest.json" -Force
    
    Write-Host "✅ API App Registration created with ID: $apiAppId" -ForegroundColor Green
} else {
    $apiAppId = $existingApiApp[0].appId
    Write-Host "✅ API App Registration already exists with ID: $apiAppId" -ForegroundColor Green
}

# Step 4: Create SPA App Registration (for frontend)
Write-Host "🔧 Creating SPA App Registration..." -ForegroundColor Yellow
$spaAppName = "$cleanAppName-spa"

# Check if app already exists
$existingSpaApp = az ad app list --display-name $spaAppName | ConvertFrom-Json
if ($existingSpaApp.Count -eq 0) {
    Write-Host "Creating new SPA app registration..." -ForegroundColor Cyan
    
    # Create the SPA app with basic settings first
    $spaApp = az ad app create --display-name $spaAppName --sign-in-audience "AzureADMyOrg" | ConvertFrom-Json
    $spaAppId = $spaApp.appId
    
    Write-Host "✅ SPA App Registration created with ID: $spaAppId" -ForegroundColor Green
    Write-Host "ℹ️  Note: SPA redirect URLs will be updated after Static Web App is deployed" -ForegroundColor Yellow
} else {
    $spaAppId = $existingSpaApp[0].appId
    Write-Host "✅ SPA App Registration already exists with ID: $spaAppId" -ForegroundColor Green
}

# Step 5: Grant API permissions to SPA
Write-Host "🔐 Configuring API permissions..." -ForegroundColor Yellow
try {
    # Add API permission to SPA
    az ad app permission add --id $spaAppId --api $apiAppId --api-permissions "$scopeId=Scope" --output none
    
    # Grant admin consent
    az ad app permission admin-consent --id $spaAppId --output none
    
    Write-Host "✅ API permissions configured successfully" -ForegroundColor Green
} catch {
    Write-Host "⚠️  API permissions configuration failed, will retry later: $_" -ForegroundColor Yellow
}

Write-Host "🎉 Test deployment completed successfully!" -ForegroundColor Green
Write-Host "📋 Summary:" -ForegroundColor Cyan
Write-Host "   Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "   Tenant ID: $tenantId" -ForegroundColor White
Write-Host "   API App ID: $apiAppId" -ForegroundColor White
Write-Host "   SPA App ID: $spaAppId" -ForegroundColor White
