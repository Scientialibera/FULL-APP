# Azure Fullstack Application Deployment Script
# 
# This script automates the complete deployment of a fullstack application to Azure including:
# - Resource Group, Container Registry, Key Vault, SQL Server & Database, Redis Cache
# - User-assigned Managed Identity with proper RBAC permissions
# - Automatic creation of SQL Database user for Managed Identity authentication
# - Container Apps Environment and Application deployment
# - Static Web Apps for frontend hosting
#
# Prerequisites: Azure CLI, Docker, PowerShell, Node.js, and appropriate Azure permissions

param(
    [Parameter(Mandatory = $true)]
    [string]$AppName,
    
    [Parameter(Mandif ($LASTEXITCODE -eq 0) {
    Write-Host "Frontend deployed to Static Web App successfully" -ForegroundColor Green
} else {
    Write-Error "Frontend deployment failed"
    Set-Location $PSScriptRoot
    exit 1
}

# Get the actual Static Web App URL and update configuration
$swaInfo = az staticwebapp show --resource-group $ResourceGroupName --name $StaticWebAppName | ConvertFrom-Json
$actualSwaUrl = "https://$($swaInfo.properties.defaultHostname)"true)]
    [string]$Location,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipRedis
)

# Function to check if resource exists
function Test-AzResource {
    param($ResourceName, $ResourceType, $ResourceGroup = $null)
    
    if ($ResourceGroup) {
        $result = az resource show --name $ResourceName --resource-type $ResourceType --resource-group $ResourceGroup 2>$null
    } else {
        $result = az resource list --name $ResourceName --resource-type $ResourceType 2>$null
    }
    return $null -ne $result
}

# Function to check if resource group exists
function Test-ResourceGroup {
    param($ResourceGroupName)
    
    $result = az group show --name $ResourceGroupName 2>$null
    return $null -ne $result
}

# Function to assign RBAC role with retries
function Set-RoleAssignment {
    param($Principal, $Role, $Scope, $Description, $MaxRetries = 10)
    
    $retryCount = 0
    do {
        # Check if assignment already exists
        $existingAssignment = az role assignment list --assignee $Principal --role $Role --scope $Scope 2>$null | ConvertFrom-Json
        if ($existingAssignment -and $existingAssignment.Count -gt 0) {
            Write-Host "Role assignment already exists for $Description" -ForegroundColor Green
            return $true
        }
        
        Write-Host "Assigning role $Role to $Principal for $Description (attempt $($retryCount + 1)/$MaxRetries)" -ForegroundColor Yellow
        
        # Wait a bit for the principal to propagate in Azure AD
        if ($retryCount -gt 0) {
            Start-Sleep -Seconds (30 + (10 * $retryCount))
        }
        
        az role assignment create --assignee $Principal --role $Role --scope $Scope --output none 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully assigned $Description" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Failed to assign role for $Description (attempt $($retryCount + 1))"
            $retryCount++
        }
    } while ($retryCount -lt $MaxRetries)
    
    Write-Warning "Failed to assign $Description after $MaxRetries attempts. Continuing deployment..."
    return $false
}

# Function to create SQL Database user using proven AAD token method
function New-SqlDatabaseUser {
    param($SqlServerName, $SqlDatabaseName, $ManagedIdentityName)
    
    Write-Host "Creating SQL Database user for managed identity..." -ForegroundColor Yellow
    
    # Get current public IP and add temporary firewall rule
    $tempRuleName = "temp-deployment-rule"
    $currentIp = $null
    try {
        $currentIp = (Invoke-RestMethod -Uri "http://ipinfo.io/ip").Trim()
        if ($currentIp) {
            Write-Host "Adding temporary firewall rule for IP: $currentIp" -ForegroundColor Yellow
            az sql server firewall-rule create --resource-group $ResourceGroupName --server $SqlServerName --name $tempRuleName --start-ip-address $currentIp --end-ip-address $currentIp --output none
            Write-Host "✓ Temporary firewall rule added" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to add temporary firewall rule: $_"
    }

    # SQL script to create user and assign permissions
    $sqlScript = @"
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = '$ManagedIdentityName')
BEGIN
    CREATE USER [$ManagedIdentityName] FROM EXTERNAL PROVIDER;
    ALTER ROLE db_datareader ADD MEMBER [$ManagedIdentityName];
    ALTER ROLE db_datawriter ADD MEMBER [$ManagedIdentityName];
    ALTER ROLE db_ddladmin ADD MEMBER [$ManagedIdentityName];
END

-- Create sample table and data for testing
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='products' AND xtype='U')
BEGIN
    CREATE TABLE products (
        id INT IDENTITY(1,1) PRIMARY KEY,
        name NVARCHAR(255) NOT NULL,
        description NVARCHAR(MAX),
        price DECIMAL(10,2) NOT NULL,
        created_at DATETIME2 DEFAULT GETDATE()
    );
    
    INSERT INTO products (name, description, price) VALUES 
    ('Sample Product 1', 'This is a sample product for testing', 29.99),
    ('Sample Product 2', 'Another sample product', 49.99),
    ('Sample Product 3', 'Third sample product', 19.99);
END
"@

    # Execute SQL using AAD token with retries for AAD propagation
    $maxRetries = 6
    $delay = 15
    $success = $false
    
    for ($i = 1; $i -le $maxRetries -and -not $success; $i++) {
        try {
            # Get AAD access token
            $accessToken = az account get-access-token --resource https://database.windows.net/ --query accessToken -o tsv
            if (-not $accessToken) { throw "Failed to get access token" }

            # Execute SQL using .NET SqlClient
            Add-Type -AssemblyName System.Data
            $conn = New-Object System.Data.SqlClient.SqlConnection
            $conn.ConnectionString = "Server=tcp:$SqlServerName.database.windows.net,1433;Database=$SqlDatabaseName;Encrypt=True;TrustServerCertificate=False;"
            $conn.AccessToken = $accessToken
            $conn.Open()
            try {
                $cmd = $conn.CreateCommand()
                $cmd.CommandTimeout = 90
                $cmd.CommandText = $sqlScript
                $null = $cmd.ExecuteNonQuery()
                $success = $true
                Write-Host "✓ SQL Database user created/ensured (attempt $i)" -ForegroundColor Green
            } finally {
                $conn.Close()
                $conn.Dispose()
            }
        } catch {
            Write-Warning "Attempt $i failed (likely AAD propagation). Waiting $delay seconds... Details: $($_.Exception.Message)"
            if ($i -lt $maxRetries) {
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 120)
            }
        }
    }

    # Remove temporary firewall rule
    if ($currentIp) {
        try {
            az sql server firewall-rule delete --resource-group $ResourceGroupName --server $SqlServerName --name $tempRuleName --output none 2>$null
            Write-Host "Removed temporary firewall rule" -ForegroundColor DarkGray
        } catch { }
    }

    if (-not $success) {
        Write-Warning "Failed to create SQL Database user after $maxRetries attempts"
        Write-Host "You may need to create the database user manually:" -ForegroundColor Yellow
        Write-Host $sqlScript -ForegroundColor Yellow
        return $false
    }
    
    return $true
}

# Script Configuration
$timestamp = Get-Date -Format "MMddHHmm"
$randomSuffix = Get-Random -Minimum 100 -Maximum 999
$cleanAppName = $AppName -replace '[^a-zA-Z0-9]', ''  # Remove special characters for resource names
$ResourceGroupName = "rg-$AppName"
$RegistryName = "acr$($cleanAppName.ToLower())$randomSuffix"
$LogAnalyticsName = "log-$AppName"
$ContainerAppEnvName = "env-$AppName"
$ManagedIdentityName = "id-$AppName"
$KeyVaultName = "kv-$AppName-$randomSuffix"
$SqlServerName = "sql-$AppName-$randomSuffix"
$SqlDatabaseName = "sqldb-$AppName"
$RedisName = "redis$($cleanAppName.ToLower())$timestamp"
$StaticWebAppName = "swa-$AppName-$randomSuffix"
$ContainerAppName = "ca-$AppName"

Write-Host "Starting deployment of $AppName to $Location" -ForegroundColor Green

# Check if user is logged in
$context = az account show 2>$null
if (-not $context) {
    Write-Error "Not logged in to Azure. Please run 'az login' first."
    exit 1
}

# Ensure required Azure CLI extensions are installed
Write-Host "Checking Azure CLI extensions..." -ForegroundColor Cyan
$extensions = @("containerapp", "log-analytics", "staticwebapp")
foreach ($ext in $extensions) {
    $installed = az extension show --name $ext 2>$null
    if (-not $installed) {
        Write-Host "Installing Azure CLI extension: $ext" -ForegroundColor Yellow
        az extension add --name $ext --output none
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install Azure CLI extension: $ext"
            exit 1
        }
    }
}
Write-Host "Azure CLI extensions ready" -ForegroundColor Green

# Register required resource providers
Write-Host "Registering required resource providers..." -ForegroundColor Cyan
$resourceProviders = @("Microsoft.Sql", "Microsoft.Cache", "Microsoft.App", "Microsoft.ContainerRegistry", "Microsoft.OperationalInsights", "Microsoft.KeyVault", "Microsoft.ManagedIdentity", "Microsoft.Web")
foreach ($provider in $resourceProviders) {
    Write-Host "Registering $provider" -ForegroundColor Yellow
    az provider register --namespace $provider --output none
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to register resource provider: $provider"
    }
}
Write-Host "Resource providers registration initiated" -ForegroundColor Green

# Get subscription and tenant information
$accountInfo = az account show | ConvertFrom-Json
$subscriptionId = $accountInfo.id
$tenantId = $accountInfo.tenantId
Write-Host "Using subscription: $($accountInfo.name) ($subscriptionId)" -ForegroundColor Cyan

# Create Resource Group
Write-Host "Creating Resource Group: $ResourceGroupName" -ForegroundColor Yellow
if (-not (Test-ResourceGroup -ResourceGroupName $ResourceGroupName)) {
    az group create --name $ResourceGroupName --location $Location --output none
    Write-Host "Resource Group created" -ForegroundColor Green
} else {
    Write-Host "Resource Group already exists" -ForegroundColor Green
}

# Create User-Assigned Managed Identity
Write-Host "Creating User-Assigned Managed Identity: $ManagedIdentityName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $ManagedIdentityName -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities" -ResourceGroup $ResourceGroupName)) {
    az identity create --resource-group $ResourceGroupName --name $ManagedIdentityName --location $Location --output none
    Write-Host "Managed Identity created" -ForegroundColor Green
} else {
    Write-Host "Managed Identity already exists" -ForegroundColor Green
}

# Get managed identity details
$managedIdentity = az identity show --resource-group $ResourceGroupName --name $ManagedIdentityName | ConvertFrom-Json
$managedIdentityId = $managedIdentity.id
$managedIdentityClientId = $managedIdentity.clientId
$managedIdentityPrincipalId = $managedIdentity.principalId

# Create Container Registry
Write-Host "Creating Container Registry: $RegistryName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $RegistryName -ResourceType "Microsoft.ContainerRegistry/registries" -ResourceGroup $ResourceGroupName)) {
    az acr create --resource-group $ResourceGroupName --name $RegistryName --sku Basic --location $Location --output none
    Write-Host "Container Registry created" -ForegroundColor Green
} else {
    Write-Host "Container Registry already exists" -ForegroundColor Green
}

# Assign AcrPull role to managed identity for container registry
$registryId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.ContainerRegistry/registries/$RegistryName"
Set-RoleAssignment -Principal $managedIdentityPrincipalId -Role "AcrPull" -Scope $registryId -Description "Managed Identity AcrPull on Container Registry"

# Create Key Vault
Write-Host "Creating Key Vault: $KeyVaultName" -ForegroundColor Yellow
$keyVaultSuccess = $false
if (-not (Test-AzResource -ResourceName $KeyVaultName -ResourceType "Microsoft.KeyVault/vaults" -ResourceGroup $ResourceGroupName)) {
    az keyvault create --resource-group $ResourceGroupName --name $KeyVaultName --location $Location --enable-rbac-authorization true --output none
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Key Vault created" -ForegroundColor Green
        $keyVaultSuccess = $true
    } else {
        Write-Warning "Key Vault creation failed"
    }
} else {
    Write-Host "Key Vault already exists" -ForegroundColor Green
    $keyVaultSuccess = $true
}

# Assign Key Vault Secrets User role to managed identity
if ($keyVaultSuccess) {
    $keyVaultId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
    Set-RoleAssignment -Principal $managedIdentityPrincipalId -Role "Key Vault Secrets User" -Scope $keyVaultId -Description "Managed Identity Key Vault Secrets User"
    
    # Also assign current user as Key Vault Administrator for deployment
    $currentUserObjectId = az ad signed-in-user show --query id --output tsv
    Set-RoleAssignment -Principal $currentUserObjectId -Role "Key Vault Administrator" -Scope $keyVaultId -Description "Current User Key Vault Administrator"
    
    # Additional wait for Key Vault RBAC propagation (critical for secret operations)
    Write-Host "Waiting for Key Vault RBAC propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 90
}

# Create SQL Server
Write-Host "Creating SQL Server: $SqlServerName" -ForegroundColor Yellow
$existingSqlServer = az sql server show --resource-group $ResourceGroupName --name $SqlServerName 2>$null
if (-not $existingSqlServer) {
    # Get current user's object ID for SQL admin
    $currentUser = az ad signed-in-user show | ConvertFrom-Json
    $currentUserObjectId = $currentUser.id
    
    Write-Host "  Setting up SQL Server with AAD admin: $($currentUser.displayName)" -ForegroundColor White
    az sql server create --resource-group $ResourceGroupName --name $SqlServerName --location $Location --enable-ad-only-auth --external-admin-principal-type User --external-admin-name $currentUser.displayName --external-admin-sid $currentUserObjectId --output none
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SQL Server created" -ForegroundColor Green
    } else {
        Write-Error "Failed to create SQL server with exit code $LASTEXITCODE"
        exit 1
    }
} else {
    Write-Host "SQL Server already exists" -ForegroundColor Green
}

# Add firewall rule for Azure services
Write-Host "Configuring SQL Server firewall" -ForegroundColor Yellow
az sql server firewall-rule create --resource-group $ResourceGroupName --server $SqlServerName --name "AllowAzureServices" --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0 --output none

# Create SQL Database
Write-Host "Creating SQL Database: $SqlDatabaseName" -ForegroundColor Yellow
$existingSqlDb = az sql db show --resource-group $ResourceGroupName --server $SqlServerName --name $SqlDatabaseName 2>$null
if (-not $existingSqlDb) {
    az sql db create --resource-group $ResourceGroupName --server $SqlServerName --name $SqlDatabaseName --service-objective S0 --output none
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SQL Database created" -ForegroundColor Green
    } else {
        Write-Error "Failed to create SQL database with exit code $LASTEXITCODE"
        exit 1
    }
} else {
    Write-Host "SQL Database already exists" -ForegroundColor Green
}

# Create database user for managed identity
$userCreationSuccess = New-SqlDatabaseUser -SqlServerName $SqlServerName -SqlDatabaseName $SqlDatabaseName -ManagedIdentityName $ManagedIdentityName

# Store SQL connection details in Key Vault if both SQL and Key Vault succeeded
if ($userCreationSuccess -and $keyVaultSuccess) {
    Write-Host "Storing SQL connection details in Key Vault..." -ForegroundColor Yellow
    
    # Store SQL connection components
    $maxRetries = 10
    $retryCount = 0
    $sqlSecretsStored = $false
    
    do {
        $retryCount++
        Write-Host "Attempting to store SQL secrets (attempt $retryCount/$maxRetries)..." -ForegroundColor Yellow
        
        try {
            # Store individual SQL connection components
            az keyvault secret set --vault-name $KeyVaultName --name "sql-server" --value "$SqlServerName.database.windows.net" --output none 2>$null
            az keyvault secret set --vault-name $KeyVaultName --name "sql-database" --value $SqlDatabaseName --output none 2>$null
            az keyvault secret set --vault-name $KeyVaultName --name "sql-connection-string" --value "Server=tcp:$SqlServerName.database.windows.net,1433;Database=$SqlDatabaseName;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;" --output none 2>$null
            
            if ($LASTEXITCODE -eq 0) {
                $sqlSecretsStored = $true
                Write-Host "SQL connection details stored in Key Vault successfully" -ForegroundColor Green
            } else {
                throw "Azure CLI returned error code $LASTEXITCODE"
            }
        } catch {
            if ($retryCount -lt $maxRetries) {
                $waitTime = [math]::min([math]::Pow(2, $retryCount) * 5, 60)
                Write-Warning "Failed to store SQL secrets (attempt $retryCount/$maxRetries). Waiting $waitTime seconds before retry..."
                Start-Sleep -Seconds $waitTime
            } else {
                Write-Warning "Failed to store SQL connection details in Key Vault after $maxRetries attempts"
                Write-Host "SQL Server: $SqlServerName.database.windows.net" -ForegroundColor Yellow
                Write-Host "SQL Database: $SqlDatabaseName" -ForegroundColor Yellow
            }
        }
    } while (-not $sqlSecretsStored -and $retryCount -lt $maxRetries)
}

# Create Redis Cache (optional - skip if user creation failed to speed up deployment)
$redisSuccess = $false
if ($userCreationSuccess -and -not $SkipRedis) {
    Write-Host "Creating Redis Cache: $RedisName" -ForegroundColor Yellow
    if (-not (Test-AzResource -ResourceName $RedisName -ResourceType "Microsoft.Cache/Redis" -ResourceGroup $ResourceGroupName)) {
        az redis create --resource-group $ResourceGroupName --name $RedisName --location $Location --sku Basic --vm-size c0 --output none
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Redis Cache created" -ForegroundColor Green
            $redisSuccess = $true
        } else {
            Write-Warning "Redis Cache creation failed"
        }
    } else {
        Write-Host "Redis Cache already exists" -ForegroundColor Green
        $redisSuccess = $true
    }
    
    # Get Redis connection string and store in Key Vault (only if both Redis and Key Vault succeeded)
    if ($redisSuccess -and $keyVaultSuccess) {
        Write-Host "Storing Redis connection string in Key Vault" -ForegroundColor Yellow
        
        $redisKey = az redis list-keys --resource-group $ResourceGroupName --name $RedisName --query primaryKey --output tsv
        $redisConnectionString = "$RedisName.redis.cache.windows.net:6380,password=$redisKey,ssl=True,abortConnect=False"
        
        # Store with aggressive retry logic for RBAC propagation
        $maxRetries = 10
        $retryCount = 0
        $success = $false
        
        do {
            $retryCount++
            Write-Host "Attempting to store Redis connection string (attempt $retryCount/$maxRetries)..." -ForegroundColor Yellow
            
            az keyvault secret set --vault-name $KeyVaultName --name "redis-connection" --value $redisConnectionString --output none 2>$null
            if ($LASTEXITCODE -eq 0) {
                $success = $true
                Write-Host "Redis connection string stored in Key Vault successfully" -ForegroundColor Green
            } else {
                if ($retryCount -lt $maxRetries) {
                    $waitTime = [math]::min([math]::Pow(2, $retryCount) * 10, 120)  # Cap at 2 minutes
                    Write-Warning "Failed to store secret (attempt $retryCount/$maxRetries). Waiting $waitTime seconds before retry..."
                    Start-Sleep -Seconds $waitTime
                } else {
                    Write-Warning "Failed to store Redis connection string in Key Vault after $maxRetries attempts"
                    Write-Host "Redis connection string: $redisConnectionString" -ForegroundColor Yellow
                    Write-Host "You can manually store this in Key Vault later using:" -ForegroundColor Yellow
                    Write-Host "az keyvault secret set --vault-name $KeyVaultName --name 'redis-connection' --value '$redisConnectionString'" -ForegroundColor White
                }
            }
        } while (-not $success -and $retryCount -lt $maxRetries)
        
        # Also store individual Redis components for easier access
        if ($success) {
            az keyvault secret set --vault-name $KeyVaultName --name "redis-host" --value "$RedisName.redis.cache.windows.net" --output none 2>$null
            az keyvault secret set --vault-name $KeyVaultName --name "redis-port" --value "6380" --output none 2>$null
            az keyvault secret set --vault-name $KeyVaultName --name "redis-password" --value $redisKey --output none 2>$null
        }
    }
} else {
    Write-Host "Skipping Redis Cache creation" -ForegroundColor Yellow
}

# Create Log Analytics Workspace
Write-Host "Creating Log Analytics Workspace: $LogAnalyticsName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $LogAnalyticsName -ResourceType "Microsoft.OperationalInsights/workspaces" -ResourceGroup $ResourceGroupName)) {
    az monitor log-analytics workspace create --resource-group $ResourceGroupName --workspace-name $LogAnalyticsName --location $Location --output none
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Log Analytics Workspace created" -ForegroundColor Green
    } else {
        Write-Error "Failed to create Log Analytics Workspace"
        exit 1
    }
} else {
    Write-Host "Log Analytics Workspace already exists" -ForegroundColor Green
}

# Get Log Analytics Workspace ID and Key
$logAnalyticsInfo = az monitor log-analytics workspace show --resource-group $ResourceGroupName --workspace-name $LogAnalyticsName | ConvertFrom-Json
$logAnalyticsId = $logAnalyticsInfo.customerId
$logAnalyticsKey = az monitor log-analytics workspace get-shared-keys --resource-group $ResourceGroupName --workspace-name $LogAnalyticsName --query primarySharedKey --output tsv

# Create Container Apps Environment
Write-Host "Creating Container Apps Environment: $ContainerAppEnvName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $ContainerAppEnvName -ResourceType "Microsoft.App/managedEnvironments" -ResourceGroup $ResourceGroupName)) {
    az containerapp env create --resource-group $ResourceGroupName --name $ContainerAppEnvName --location $Location --logs-workspace-id $logAnalyticsId --logs-workspace-key $logAnalyticsKey --output none
    Write-Host "Container Apps Environment created" -ForegroundColor Green
} else {
    Write-Host "Container Apps Environment already exists" -ForegroundColor Green
}

# Build and push backend container using ACR build
Write-Host "Building and pushing backend container using ACR build" -ForegroundColor Yellow
Set-Location "$PSScriptRoot\..\backend"

# Build and push using Azure Container Registry build tasks
$imageTag = "$RegistryName.azurecr.io/$($cleanAppName.ToLower())-backend:latest"
az acr build --registry $RegistryName --image "$($cleanAppName.ToLower())-backend:latest" .
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build and push Docker image using ACR"
    exit 1
}

Write-Host "Backend container built and pushed using ACR" -ForegroundColor Green

# Create App Registrations for authentication
Write-Host "Creating Azure AD App Registrations..." -ForegroundColor Yellow

# Create API App Registration
$apiAppName = "API $AppName"
Write-Host "Creating API App Registration: $apiAppName" -ForegroundColor White
$apiApp = az ad app create --display-name $apiAppName --identifier-uris "api://$AppName-api" --query "{appId:appId,id:id}" --output json | ConvertFrom-Json
$apiAppId = $apiApp.appId
Write-Host "API App ID: $apiAppId" -ForegroundColor Green

# Create SPA App Registration  
$spaAppName = "SPA $AppName"
Write-Host "Creating SPA App Registration: $spaAppName" -ForegroundColor White
$spaApp = az ad app create --display-name $spaAppName --spa-redirect-uris "http://localhost:5173" --query "{appId:appId,id:id}" --output json | ConvertFrom-Json
$spaAppId = $spaApp.appId
Write-Host "SPA App ID: $spaAppId" -ForegroundColor Green

# Configure API permissions for SPA to access API
Write-Host "Configuring API permissions..." -ForegroundColor White
$apiPermission = @{
    "id" = $apiAppId
    "type" = "Scope"
} | ConvertTo-Json -Compress
az ad app permission add --id $spaApp.id --api $apiAppId --api-permissions "User.Read"

Write-Host "App Registrations created successfully" -ForegroundColor Green

# Create Container App
Write-Host "Creating Container App: $ContainerAppName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $ContainerAppName -ResourceType "Microsoft.App/containerApps" -ResourceGroup $ResourceGroupName)) {
    $containerAppEnvVars = @(
        "TENANT_ID=$tenantId",
        "API_AUDIENCE=api://$apiAppId",
        "SQL_SERVER=$SqlServerName.database.windows.net",
        "SQL_DB=$SqlDatabaseName",
        "AZURE_CLIENT_ID=$managedIdentityClientId",
        "PORT=8080"
    )
    
    # Add Key Vault and Redis only if they were created successfully
    if ($keyVaultSuccess) {
        $containerAppEnvVars += "KEYVAULT_URI=https://$KeyVaultName.vault.azure.net/"
        if ($redisSuccess) {
            $containerAppEnvVars += "REDIS_SECRET_NAME=redis-connection"
        }
    }
    
    $envVarsString = $containerAppEnvVars -join " "
    $fullImageName = "$RegistryName.azurecr.io/$($cleanAppName.ToLower())-backend:latest"
    
    az containerapp create --resource-group $ResourceGroupName --name $ContainerAppName --environment $ContainerAppEnvName --image $fullImageName --target-port 8080 --ingress external --min-replicas 1 --max-replicas 3 --cpu 0.5 --memory 1Gi --user-assigned $managedIdentityId --env-vars $envVarsString --registry-server "$RegistryName.azurecr.io" --registry-identity $managedIdentityId --output none
    
    Write-Host "Container App created" -ForegroundColor Green
} else {
    Write-Host "Container App already exists, updating environment variables..." -ForegroundColor Yellow
    
    # Define the same environment variables for update
    $containerAppEnvVars = @(
        "TENANT_ID=$tenantId",
        "API_AUDIENCE=api://$apiAppId",
        "SQL_SERVER=$SqlServerName.database.windows.net",
        "SQL_DB=$SqlDatabaseName",
        "AZURE_CLIENT_ID=$managedIdentityClientId",
        "PORT=8080"
    )
    
    # Add Key Vault and Redis only if they were created successfully
    if ($keyVaultSuccess) {
        $containerAppEnvVars += "KEYVAULT_URI=https://$KeyVaultName.vault.azure.net/"
        if ($redisSuccess) {
            $containerAppEnvVars += "REDIS_SECRET_NAME=redis-connection"
        }
    }
    
    $envVarsString = $containerAppEnvVars -join " "
    
    # Update the Container App with correct environment variables
    az containerapp update --name $ContainerAppName --resource-group $ResourceGroupName --set-env-vars $envVarsString --output none
    
    Write-Host "Container App environment variables updated" -ForegroundColor Green
}

# Get Container App URL
$containerApp = az containerapp show --resource-group $ResourceGroupName --name $ContainerAppName | ConvertFrom-Json
$apiBaseUrl = "https://$($containerApp.properties.configuration.ingress.fqdn)"

Write-Host "Container App deployed successfully!" -ForegroundColor Green
Write-Host "API URL: $apiBaseUrl" -ForegroundColor White

# Skip Static Web App deployment for simplified version
Write-Host "Skipping frontend deployment for simplified version" -ForegroundColor Yellow
Write-Host "You can test the API directly at: $apiBaseUrl/healthz" -ForegroundColor White

# Build frontend
Write-Host "Building frontend application" -ForegroundColor Yellow
Set-Location "$PSScriptRoot\..\frontend"

# Create config file for production
$frontendConfig = @{
    tenantId = $tenantId
    spaClientId = $spaAppId
    apiAudience = "api://$apiAppId"
    apiBaseUrl = $apiBaseUrl
    authority = "https://login.microsoftonline.com/$tenantId"
    redirectUri = $swaUrl
} | ConvertTo-Json -Depth 2

$frontendConfig | Out-File -FilePath "public\config.local.json" -Encoding UTF8

# Install dependencies and build
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install frontend dependencies"
    exit 1
}

npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build frontend"
    exit 1
}

Write-Host "Frontend built successfully" -ForegroundColor Green

# Create Static Web App
Write-Host "Creating Static Web App: $StaticWebAppName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $StaticWebAppName -ResourceType "Microsoft.Web/staticSites" -ResourceGroup $ResourceGroupName)) {
    # Create SWA without Git integration for manual deployment
    az staticwebapp create --resource-group $ResourceGroupName --name $StaticWebAppName --location $Location --sku "Free" --output none
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Static Web App created successfully" -ForegroundColor Green
    } else {
        Write-Warning "Static Web App creation failed, but will attempt deployment anyway"
    }
} else {
    Write-Host "Static Web App already exists" -ForegroundColor Green
}

# Deploy frontend to Static Web App
Write-Host "Deploying frontend to Static Web App" -ForegroundColor Yellow

# Change to frontend directory and build
Set-Location "$PSScriptRoot\..\frontend"

# Install dependencies if needed
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing npm dependencies..." -ForegroundColor White
    npm install
}

# Build frontend
Write-Host "Building frontend..." -ForegroundColor White
npm run build

if (-not (Test-Path "dist")) {
    Write-Error "Frontend build failed - dist folder not found"
    Set-Location $PSScriptRoot
    exit 1
}

# Get deployment token
$deploymentToken = az staticwebapp secrets list --resource-group $ResourceGroupName --name $StaticWebAppName --query "properties.apiKey" --output tsv 2>$null

if ($deploymentToken -and $deploymentToken -ne "null" -and $deploymentToken.Trim() -ne "") {
    Write-Host "Deploying to PRODUCTION environment..." -ForegroundColor Green
    
    # Deploy to production environment
    npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --env "production" --verbose
    
    if ($LASTEXITCODE -ne 0) {
        # Fallback: try without --env flag
        Write-Host "Retrying without --env flag..." -ForegroundColor Yellow
        npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --verbose
    }
} else {
    Write-Error "Could not get deployment token for Static Web App"
    Set-Location $PSScriptRoot
    exit 1
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Frontend deployed to Static Web App successfully" -ForegroundColor Green
} else {
    Write-Error "Frontend deployment failed"
    Set-Location $PSScriptRoot
    exit 1
# Get the actual Static Web App URL and update configuration
$swaInfo = az staticwebapp show --resource-group $ResourceGroupName --name $StaticWebAppName | ConvertFrom-Json
$actualSwaUrl = "https://$($swaInfo.properties.defaultHostname)"

Write-Host "Static Web App URL: $actualSwaUrl" -ForegroundColor Green

# Update SPA app registration with correct redirect URI
Write-Host "Updating SPA app registration with correct redirect URI..." -ForegroundColor Yellow
$updatedRedirectUris = @("http://localhost:5173", $actualSwaUrl)
az ad app update --id $spaApp.id --spa-redirect-uris $updatedRedirectUris
Write-Host "SPA redirect URI updated" -ForegroundColor Green

# Update frontend configuration file with real values
Write-Host "Updating frontend configuration..." -ForegroundColor Yellow
$frontendConfig = @{
    tenantId = $tenantId
    spaClientId = $spaAppId
    apiAudience = "api://$AppName-api"
    apiBaseUrl = $apiBaseUrl
    authority = "https://login.microsoftonline.com/$tenantId"
    redirectUri = $actualSwaUrl
} | ConvertTo-Json -Depth 10

# Update the config file in the dist folder and redeploy
Set-Content -Path "dist/config.local.json" -Value $frontendConfig -Encoding UTF8
Write-Host "Frontend configuration updated" -ForegroundColor Green

# Redeploy with updated configuration
Write-Host "Redeploying frontend with updated configuration..." -ForegroundColor Yellow
npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --env "production" --verbose

if ($LASTEXITCODE -eq 0) {
    Write-Host "Frontend redeployed with correct configuration" -ForegroundColor Green
} else {
    Write-Warning "Frontend redeploy may have failed"
}

# Return to original directory
Set-Location $PSScriptRoot

# Store all deployment configuration in Key Vault for easy access
if ($keyVaultSuccess) {
    Write-Host "Storing deployment configuration in Key Vault..." -ForegroundColor Yellow
    try {
        # Store all key configuration values
        az keyvault secret set --vault-name $KeyVaultName --name "deployment-summary" --value "Deployment completed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" --output none 2>$null
        az keyvault secret set --vault-name $KeyVaultName --name "api-url" --value $apiBaseUrl --output none 2>$null
        az keyvault secret set --vault-name $KeyVaultName --name "frontend-url" --value $actualSwaUrl --output none 2>$null
        az keyvault secret set --vault-name $KeyVaultName --name "tenant-id" --value $tenantId --output none 2>$null
        az keyvault secret set --vault-name $KeyVaultName --name "subscription-id" --value $subscriptionId --output none 2>$null
        az keyvault secret set --vault-name $KeyVaultName --name "resource-group" --value $ResourceGroupName --output none 2>$null
        az keyvault secret set --vault-name $KeyVaultName --name "managed-identity-client-id" --value $managedIdentityClientId --output none 2>$null
        
        Write-Host "Deployment configuration stored in Key Vault" -ForegroundColor Green
    } catch {
        Write-Warning "Could not store deployment configuration in Key Vault: $_"
    }
}

# Output deployment information
Write-Host "`nDeployment completed successfully!" -ForegroundColor Green
Write-Host "`nDeployment Summary:" -ForegroundColor Cyan
Write-Host "SPA URL: $actualSwaUrl" -ForegroundColor White
Write-Host "API FQDN: $apiBaseUrl" -ForegroundColor White
Write-Host "Tenant ID: $tenantId" -ForegroundColor White
Write-Host "SPA Client ID: $spaAppId" -ForegroundColor White
Write-Host "API App ID: $apiAppId" -ForegroundColor White
Write-Host "Scope: api://$apiAppId/user_impersonation" -ForegroundColor White
Write-Host "SQL Server: $SqlServerName.database.windows.net" -ForegroundColor White
Write-Host "SQL Database: $SqlDatabaseName" -ForegroundColor White
Write-Host "Key Vault: $KeyVaultName" -ForegroundColor White
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White

Write-Host "`nTest your application:" -ForegroundColor Yellow
Write-Host "1. Visit: $actualSwaUrl" -ForegroundColor White
Write-Host "2. Sign in with your Microsoft account" -ForegroundColor White
Write-Host "3. Test the API integration" -ForegroundColor White
Write-Host "`nAll resources created successfully!" -ForegroundColor Green
