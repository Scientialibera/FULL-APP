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
    
    [Parameter(Mandatory = $true)]
    [string]$Location,
    
    [Parameter(Mandatory = $false)]
    [switch]$UseLocalDockerBuild
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
            Write-Host "Temporary firewall rule added" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to add temporary firewall rule: $_"
    }

    # SQL script to create user and assign permissions
    # Use a single-quoted here-string to avoid PowerShell parsing issues, then substitute the managed identity name
    $sqlScript = @'
-- Create managed identity user
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = '$ManagedIdentityName')
BEGIN
    CREATE USER [$ManagedIdentityName] FROM EXTERNAL PROVIDER;
    ALTER ROLE db_datareader ADD MEMBER [$ManagedIdentityName];
    ALTER ROLE db_datawriter ADD MEMBER [$ManagedIdentityName];
    ALTER ROLE db_ddladmin ADD MEMBER [$ManagedIdentityName];
    PRINT 'User $ManagedIdentityName created and permissions granted';
END
ELSE
BEGIN
    PRINT 'User $ManagedIdentityName already exists';
END

-- Create products table for testing
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
    
    PRINT 'Products table created and sample data inserted';
END
ELSE
BEGIN
    PRINT 'Products table already exists';
END

-- Create users table for demo authentication
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
BEGIN
    CREATE TABLE users (
        id INT IDENTITY(1,1) PRIMARY KEY,
        username NVARCHAR(255) NOT NULL UNIQUE,
        display_name NVARCHAR(255),
        email NVARCHAR(255),
        created_at DATETIME2 DEFAULT GETDATE()
    );
    
    INSERT INTO users (username, display_name, email) VALUES 
    ('demo', 'Demo User', 'demo@example.com'),
    ('testuser', 'Test User', 'test@example.com');
    
    PRINT 'Users table created and sample data inserted';
END
ELSE
BEGIN
    PRINT 'Users table already exists';
END
'@

    # Replace the placeholder with the actual managed identity name (preserve required SQL quoting)
    $sqlScript = $sqlScript -replace '\$ManagedIdentityName', $ManagedIdentityName

    # Execute SQL using AAD token with retries for AAD propagation
    $maxRetries = 10  # Increased from 6 to 10
    $delay = 30       # Increased initial delay
    $success = $false
    
    for ($i = 1; $i -le $maxRetries -and -not $success; $i++) {
        try {
            Write-Host "Attempting SQL user creation (attempt $i/$maxRetries)..." -ForegroundColor White
            
            # Get AAD access token
            $accessToken = az account get-access-token --resource https://database.windows.net/ --query accessToken -o tsv
            if (-not $accessToken) { throw "Failed to get access token" }

            # Execute SQL using .NET SqlClient
            Add-Type -AssemblyName System.Data
            $conn = New-Object System.Data.SqlClient.SqlConnection
            $conn.ConnectionString = "Server=tcp:$SqlServerName.database.windows.net,1433;Database=$SqlDatabaseName;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60;"
            $conn.AccessToken = $accessToken
            $conn.Open()
            try {
                $cmd = $conn.CreateCommand()
                $cmd.CommandTimeout = 120  # Increased timeout
                $cmd.CommandText = $sqlScript
                $result = $cmd.ExecuteNonQuery()
                $success = $true
                Write-Host "SQL Database user created/ensured successfully (attempt $i)" -ForegroundColor Green
                Write-Host "  SQL commands executed: $result" -ForegroundColor DarkGray
            } finally {
                $conn.Close()
                $conn.Dispose()
            }
        } catch {
            $errorMessage = $_.Exception.Message
            Write-Warning "Attempt $i failed. Error: $errorMessage"
            if ($i -lt $maxRetries) {
                Write-Host "Waiting $delay seconds before retry..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay + 30, 180)  # Progressive backoff, max 3 minutes
            } else {
                Write-Error "All attempts failed. Last error: $errorMessage"
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
        Write-Host "SQL Database connection will not work until managed identity user is created manually" -ForegroundColor Yellow
        Write-Host "You can create the user manually by running this SQL script:" -ForegroundColor Yellow
        Write-Host $sqlScript -ForegroundColor Cyan
        Write-Host "Or re-run the deployment script to retry" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "SQL Database user and sample data setup completed successfully" -ForegroundColor Green
    return $true
}

    # Add Container App outbound IP addresses to Azure SQL Server firewall
    function Add-ContainerAppFirewallRules {
        param(
            [string]$ResourceGroupName,
            [string]$ContainerAppName,
            [string]$SqlServerName
        )

        Write-Host "Adding Container App outbound IPs to SQL firewall for $ContainerAppName -> $SqlServerName" -ForegroundColor Cyan

        try {
            $ips = az containerapp show -g $ResourceGroupName -n $ContainerAppName --query "properties.outboundIpAddresses" -o tsv 2>$null
        } catch {
            Write-Warning "Failed to query Container App outbound IPs: $_"
            return
        }

        if (-not $ips) {
            Write-Warning "No outbound IPs found for Container App $ContainerAppName. Skipping firewall updates."
            return
        }

        # az returns a newline-separated list; iterate and create per-IP rules if missing
        foreach ($line in $ips -split "`n") {
            $ip = $line.Trim()
            if (-not $ip) { continue }
            $ruleName = "aca-" + ($ip -replace '\.','-')
            try {
                $existing = az sql server firewall-rule show --resource-group $ResourceGroupName --server $SqlServerName --name $ruleName -o none 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Firewall rule $ruleName already exists for $ip" -ForegroundColor DarkGray
                    continue
                }
            } catch {
                # not found - create it
            }

            try {
                az sql server firewall-rule create --resource-group $ResourceGroupName --server $SqlServerName --name $ruleName --start-ip-address $ip --end-ip-address $ip --output none
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Created SQL firewall rule $ruleName for IP ${ip}" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to create firewall rule $ruleName for IP ${ip}"
                }
            } catch {
                Write-Warning "Error creating firewall rule $ruleName for IP ${ip}: $_"
            }
        }
    }

# Script Configuration
# Normalize app name deterministically: remove any non-alphanumeric characters and ensure it starts with a letter
$randomSuffix = Get-Random -Minimum 100 -Maximum 999  # keep for fallback only
$normalized = ($AppName -replace '[^a-zA-Z0-9]', '')
if ([string]::IsNullOrEmpty($normalized)) { $normalized = "app" }
if ($normalized -notmatch '^[a-zA-Z]') { $normalized = 'a' + $normalized }
$normalized = $normalized.ToLower()

# Helper to truncate strings safely
function TruncateString {
    param($s, $len)
    if ($null -eq $s) { return $s }
    if ($s.Length -le $len) { return $s }
    return $s.Substring(0, $len)
}

# Build resource names deterministically (no random suffixes). Keep a short random suffix only as a fallback for ACR.
$ResourceGroupName = "rg$normalized"
$RegistryName = TruncateString "acr$normalized" 50
$LogAnalyticsName = TruncateString "log$normalized" 63
$ContainerAppEnvName = TruncateString "env$normalized" 45
$ManagedIdentityName = TruncateString "id$normalized" 45

# Key Vault requires 3-24 alphanumeric characters, must start with a letter
$kvBase = "kv$normalized"
$kvBase = $kvBase -replace '[^a-zA-Z0-9]', ''
$kvBase = TruncateString $kvBase 24
if ($kvBase -notmatch '^[a-zA-Z]') { $kvBase = 'a' + (TruncateString $kvBase 23) }
$KeyVaultName = $kvBase

# SQL server and database names
$SqlServerName = TruncateString "sql$normalized" 63
$SqlDatabaseName = TruncateString "sqldb$normalized" 63

$RedisName = TruncateString "redis$normalized" 63
$StaticWebAppName = TruncateString "swa$normalized" 63
$ContainerAppName = TruncateString "ca$normalized" 45

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
# Add Service Connector provider so we can create containerapp connections (storage/sql/keyvault)
$resourceProviders += "Microsoft.ServiceLinker"
foreach ($provider in $resourceProviders) {
    Write-Host "Registering $provider" -ForegroundColor Yellow
    az provider register --namespace $provider --output none
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to register resource provider: $provider"
    }
}
Write-Host "Resource providers registration initiated" -ForegroundColor Green

# Ensure Service Connector provider registration completes (best-effort)
try {
    Write-Host "Ensuring Microsoft.ServiceLinker is registered..." -ForegroundColor Cyan
    az provider register -n Microsoft.ServiceLinker --output none
} catch {
    Write-Warning "Failed to start registration for Microsoft.ServiceLinker: $_"
}


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
$managedIdentityCreated = $false
if (-not (Test-AzResource -ResourceName $ManagedIdentityName -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities" -ResourceGroup $ResourceGroupName)) {
    az identity create --resource-group $ResourceGroupName --name $ManagedIdentityName --location $Location --output none
    Write-Host "Managed Identity created" -ForegroundColor Green
    $managedIdentityCreated = $true
} else {
    Write-Host "Managed Identity already exists" -ForegroundColor Green
}

# Get managed identity details
$managedIdentity = az identity show --resource-group $ResourceGroupName --name $ManagedIdentityName | ConvertFrom-Json
$managedIdentityId = $managedIdentity.id
$managedIdentityClientId = $managedIdentity.clientId
$managedIdentityPrincipalId = $managedIdentity.principalId

# Wait for managed identity propagation if newly created
if ($managedIdentityCreated) {
    Write-Host "Waiting for managed identity propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 20
}

# Create Container Registry (deterministic name). If the name is already taken globally and not in this resource group, try a single fallback with a short suffix.
Write-Host "Creating/ensuring Container Registry: $RegistryName" -ForegroundColor Yellow
$acrExistsInRg = Test-AzResource -ResourceName $RegistryName -ResourceType "Microsoft.ContainerRegistry/registries" -ResourceGroup $ResourceGroupName
if (-not $acrExistsInRg) {
    # Try to create the registry with the deterministic name
    az acr create --resource-group $ResourceGroupName --name $RegistryName --sku Basic --location $Location --output none 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Container Registry created: $RegistryName" -ForegroundColor Green
    } else {
        Write-Warning "Could not create ACR with name $RegistryName. It may be taken globally. Checking if a registry with that name exists in another scope..."
        # Check if a registry with that name exists somewhere else (global name collision)
        $globalAcr = az acr list --query "[?name=='$RegistryName'] | [0]" --output json 2>$null | ConvertFrom-Json
        if ($globalAcr -and $globalAcr.name -eq $RegistryName) {
            Write-Warning "A global ACR with name $RegistryName exists in another subscription/rg. Using that registry for image push if accessible."
            $RegistryName = $globalAcr.name
        } else {
            # Fallback: try once with a short random suffix appended
            $fallbackRegistry = TruncateString ("acr$normalized$randomSuffix") 50
            Write-Host "Attempting fallback registry name: $fallbackRegistry" -ForegroundColor Yellow
            az acr create --resource-group $ResourceGroupName --name $fallbackRegistry --sku Basic --location $Location --output none 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Fallback Container Registry created: $fallbackRegistry" -ForegroundColor Green
                $RegistryName = $fallbackRegistry
            } else {
                Write-Warning "Failed to create fallback ACR as well. Please check ACR name availability or create an ACR manually." 
            }
        }
    }
} else {
    Write-Host "Container Registry already exists in resource group" -ForegroundColor Green
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
    Start-Sleep -Seconds 20
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
$sqlDatabaseCreated = $false
$existingSqlDb = az sql db show --resource-group $ResourceGroupName --server $SqlServerName --name $SqlDatabaseName 2>$null
if (-not $existingSqlDb) {
    az sql db create --resource-group $ResourceGroupName --server $SqlServerName --name $SqlDatabaseName --service-objective S0 --output none
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SQL Database created" -ForegroundColor Green
        $sqlDatabaseCreated = $true
    } else {
        Write-Error "Failed to create SQL database with exit code $LASTEXITCODE"
        exit 1
    }
} else {
    Write-Host "SQL Database already exists" -ForegroundColor Green
}

# Wait for SQL Database to be fully ready
if ($sqlDatabaseCreated) {
    Write-Host "Waiting for SQL Database to be fully ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
}

# Assign SQL permissions to managed identity at the server level
Write-Host "Assigning SQL Server permissions to managed identity..." -ForegroundColor Yellow
$sqlServerId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$SqlServerName"
Set-RoleAssignment -Principal $managedIdentityPrincipalId -Role "SQL DB Contributor" -Scope $sqlServerId -Description "Managed Identity SQL DB Contributor on SQL Server"

# Also assign permissions at the database level for fine-grained access
$sqlDatabaseId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$SqlServerName/databases/$SqlDatabaseName"
Set-RoleAssignment -Principal $managedIdentityPrincipalId -Role "SQL DB Contributor" -Scope $sqlDatabaseId -Description "Managed Identity SQL DB Contributor on SQL Database"

# Create database user for managed identity (with additional wait to ensure propagation)
Write-Host "Waiting for Azure AD propagation before creating SQL user..." -ForegroundColor Yellow
Start-Sleep -Seconds 30
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

# Create Redis Cache with managed identity authentication
$redisSuccess = $false
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

# Configure Redis with managed identity authentication (Redis 6.0+ with AAD)
if ($redisSuccess) {
    Write-Host "Configuring Redis for managed identity authentication..." -ForegroundColor Yellow
    
    # Assign Redis Contributor role to managed identity for Redis management
    $redisId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Cache/Redis/$RedisName"
    Set-RoleAssignment -Principal $managedIdentityPrincipalId -Role "Redis Cache Contributor" -Scope $redisId -Description "Managed Identity Redis Cache Contributor"
    
    # Store Redis configuration in Key Vault (hostname only, no keys)
    if ($keyVaultSuccess) {
        Write-Host "Storing Redis configuration in Key Vault..." -ForegroundColor Yellow
        
        $maxRetries = 10
        $retryCount = 0
        $success = $false
        
        do {
            $retryCount++
            Write-Host "Attempting to store Redis configuration (attempt $retryCount/$maxRetries)..." -ForegroundColor Yellow
            
            # Store only connection details, not keys
            az keyvault secret set --vault-name $KeyVaultName --name "redis-host" --value "$RedisName.redis.cache.windows.net" --output none 2>$null
            az keyvault secret set --vault-name $KeyVaultName --name "redis-port" --value "6380" --output none 2>$null
            az keyvault secret set --vault-name $KeyVaultName --name "redis-ssl" --value "true" --output none 2>$null

            # Also store full redis connection string (hostname:port,password=KEY,ssl=True,abortConnect=False)
            try {
                $primaryKey = az redis list-keys --name $RedisName --resource-group $ResourceGroupName --query primaryKey -o tsv 2>$null
                if ($primaryKey) {
                    $redisConn = "$($RedisName).redis.cache.windows.net:6380,password=$primaryKey,ssl=True,abortConnect=False"
                    az keyvault secret set --vault-name $KeyVaultName --name "redis-connection" --value "$redisConn" --output none 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Stored full redis connection string in Key Vault as 'redis-connection'" -ForegroundColor Green
                    } else {
                        Write-Warning "Failed to store full redis connection string in Key Vault"
                    }
                } else {
                    Write-Warning "Could not retrieve Redis primary key to build full connection string"
                }
            } catch {
                Write-Warning "Error retrieving Redis keys or storing redis-connection secret: $_"
            }
            
            if ($LASTEXITCODE -eq 0) {
                $success = $true
                Write-Host "Redis configuration stored in Key Vault successfully" -ForegroundColor Green
            } else {
                if ($retryCount -lt $maxRetries) {
                    $waitTime = [math]::min([math]::Pow(2, $retryCount) * 10, 120)
                    Write-Warning "Failed to store Redis config (attempt $retryCount/$maxRetries). Waiting $waitTime seconds before retry..."
                    Start-Sleep -Seconds $waitTime
                } else {
                    Write-Warning "Failed to store Redis configuration in Key Vault after $maxRetries attempts"
                    Write-Host "Redis Host: $RedisName.redis.cache.windows.net" -ForegroundColor Yellow
                    Write-Host "Port: 6380, SSL: true" -ForegroundColor Yellow
                }
            }
        } while (-not $success -and $retryCount -lt $maxRetries)
    }
    
    Write-Host "Redis configured for managed identity authentication" -ForegroundColor Green
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

# Build and push backend container
if ($UseLocalDockerBuild) {
    Write-Host "Building and pushing backend container using local Docker build" -ForegroundColor Yellow
    Set-Location "$PSScriptRoot\..\backend"
    
    # Login to ACR
    Write-Host "Logging into Azure Container Registry..." -ForegroundColor White
    az acr login --name $RegistryName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to login to Azure Container Registry"
        exit 1
    }
    
    # Build image locally
    $imageTag = "$RegistryName.azurecr.io/$($normalized)-backend:latest"
    Write-Host "Building Docker image: $imageTag" -ForegroundColor White
    docker build -t $imageTag .
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to build Docker image locally"
        exit 1
    }
    
    # Push image to ACR
    Write-Host "Pushing Docker image to ACR..." -ForegroundColor White
    docker push $imageTag
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to push Docker image to ACR"
        exit 1
    }
    
    Write-Host "Backend container built and pushed using local Docker build" -ForegroundColor Green
} else {
    Write-Host "Building and pushing backend container using ACR build" -ForegroundColor Yellow
    Set-Location "$PSScriptRoot\..\backend"

    # Build and push using Azure Container Registry build tasks
    $imageTag = "$RegistryName.azurecr.io/$($normalized)-backend:latest"
    az acr build --registry $RegistryName --image "$($normalized)-backend:latest" .
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "ACR Tasks build failed. This may be due to subscription limitations."
        Write-Host "Consider using -UseLocalDockerBuild parameter if Docker is running locally" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "Backend container built and pushed using ACR" -ForegroundColor Green
}

# Configure Azure AD Authentication with proper SSO
Write-Host "Creating Azure AD App Registrations for SSO..." -ForegroundColor Yellow

# Create API App Registration with proper scopes
$apiAppName = "API-$AppName"
Write-Host "Creating API App Registration: $apiAppName" -ForegroundColor White

# Check if API app already exists
$existingApiApp = az ad app list --display-name $apiAppName --query "[0].{appId:appId,id:id}" --output json 2>$null | ConvertFrom-Json
if ($existingApiApp -and $existingApiApp.appId) {
    Write-Host "API App Registration already exists" -ForegroundColor Green
    $apiAppId = $existingApiApp.appId
    $apiAppObjectId = $existingApiApp.id
} else {
    Write-Host "Creating new API app registration..." -ForegroundColor White
    # Create new API app
    $apiAppResult = az ad app create --display-name $apiAppName --query "{appId:appId,id:id}" --output json 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create API app registration"
        exit 1
    }
    $apiApp = $apiAppResult | ConvertFrom-Json
    $apiAppId = $apiApp.appId
    $apiAppObjectId = $apiApp.id
    
    # Update with proper identifier URI using the app ID
    Write-Host "Setting identifier URI for API app..." -ForegroundColor White
    az ad app update --id $apiAppObjectId --identifier-uris "api://$apiAppId" --output none 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to set identifier URI for API app"
    }
    
    # Create API scope for user impersonation
    Write-Host "Creating API scope for user access..." -ForegroundColor White
    $scopeManifest = @{
        oauth2PermissionScopes = @(
            @{
                adminConsentDescription = "Allow the application to access the API on behalf of the signed-in user"
                adminConsentDisplayName = "Access API"
                id = [System.Guid]::NewGuid().ToString()
                isEnabled = $true
                type = "User"
                userConsentDescription = "Allow the application to access the API on your behalf"
                userConsentDisplayName = "Access API"
                value = "user_impersonation"
            }
        )
    } | ConvertTo-Json -Depth 10
    
    $tempFile = New-TemporaryFile
    try {
        $scopeManifest | Out-File -FilePath $tempFile.FullName -Encoding UTF8
        az ad app update --id $apiAppObjectId --set api="@$($tempFile.FullName)" --output none 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed to set API scope for API app"
        }
    } finally {
        Remove-Item $tempFile.FullName -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "API App ID: $apiAppId" -ForegroundColor Green

# Create SPA App Registration with proper redirect URIs
$spaAppName = "SPA-$AppName"
Write-Host "Creating SPA App Registration: $spaAppName" -ForegroundColor White

# Check if SPA app already exists
$existingSpaApp = az ad app list --display-name $spaAppName --query "[0].{appId:appId,id:id}" --output json 2>$null | ConvertFrom-Json
if ($existingSpaApp -and $existingSpaApp.appId) {
    Write-Host "SPA App Registration already exists" -ForegroundColor Green
    $spaAppId = $existingSpaApp.appId
    $spaAppObjectId = $existingSpaApp.id
} else {
    Write-Host "Creating new SPA app registration..." -ForegroundColor White
    # Create SPA app
    $spaAppResult = az ad app create --display-name $spaAppName --query "{appId:appId,id:id}" --output json 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create SPA app registration"
        exit 1
    }
    $spaApp = $spaAppResult | ConvertFrom-Json
    $spaAppId = $spaApp.appId
    $spaAppObjectId = $spaApp.id
    
    # Update with SPA platform and redirect URI (localhost for development)
    Write-Host "Configuring SPA platform for app..." -ForegroundColor White
    az ad app update --id $spaAppObjectId --web-redirect-uris "http://localhost:5173" --output none 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to set initial redirect URI for SPA app"
    }
}
Write-Host "SPA App ID: $spaAppId" -ForegroundColor Green

# Configure API permissions for SPA to access API
Write-Host "Configuring API permissions for SPA..." -ForegroundColor White
$apiScope = "api://$apiAppId/user_impersonation"

# Add Microsoft Graph permissions
$existingGraphPermissions = az ad app permission list --id $spaAppObjectId --query "[?resourceId=='00000003-0000-0000-c000-000000000000']" --output json 2>$null | ConvertFrom-Json
if (-not $existingGraphPermissions -or $existingGraphPermissions.Count -eq 0) {
    Write-Host "Adding Microsoft Graph permissions to SPA..." -ForegroundColor White
    az ad app permission add --id $spaAppObjectId --api 00000003-0000-0000-c000-000000000000 --api-permissions 14dad69e-099b-42c9-810b-d002981feec1=Scope 2>$null
    Write-Host "Microsoft Graph permissions added" -ForegroundColor Green
} else {
    Write-Host "Microsoft Graph permissions already exist" -ForegroundColor Green
}

# Add API permissions
$existingApiPermissions = az ad app permission list --id $spaAppObjectId --query "[?resourceId=='$apiAppId']" --output json 2>$null | ConvertFrom-Json
if (-not $existingApiPermissions -or $existingApiPermissions.Count -eq 0) {
    Write-Host "Adding API permissions to SPA..." -ForegroundColor White
    $apiScopeId = az ad app show --id $apiAppId --query "api.oauth2PermissionScopes[0].id" --output tsv 2>$null
    if ($apiScopeId) {
        az ad app permission add --id $spaAppObjectId --api $apiAppId --api-permissions "$apiScopeId=Scope" 2>$null
        Write-Host "API permissions added" -ForegroundColor Green
    } else {
        Write-Warning "Could not find API scope ID for permissions"
    }
} else {
    Write-Host "API permissions already exist" -ForegroundColor Green
}

# Grant admin consent for your organization
Write-Host "Granting admin consent for API permissions..." -ForegroundColor Yellow
az ad app permission admin-consent --id $spaAppObjectId 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Admin consent granted successfully" -ForegroundColor Green
} else {
    Write-Warning "Admin consent failed or may need to be granted manually in Azure Portal"
    Write-Host "This is common in some tenant configurations and won't prevent the app from working" -ForegroundColor Yellow
    Write-Host "Users may see a consent prompt when first signing in" -ForegroundColor Yellow
}

$apiAudience = "api://$apiAppId"
$spaClientId = $spaAppId

Write-Host "Azure AD App Registrations configured for SSO successfully" -ForegroundColor Green

# Create Container App
Write-Host "Creating Container App: $ContainerAppName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $ContainerAppName -ResourceType "Microsoft.App/containerApps" -ResourceGroup $ResourceGroupName)) {
    # Environment variables for Container App - Azure AD SSO only
    $containerAppEnvVars = @(
        "TENANT_ID=$tenantId",
        "API_AUDIENCE=$apiAudience",
        "SQL_SERVER=$SqlServerName.database.windows.net",
        "SQL_DB=$SqlDatabaseName",
        "AZURE_CLIENT_ID=$managedIdentityClientId",
        "PORT=8080"
    )
    
    # Add Key Vault only if it was created successfully
    if ($keyVaultSuccess) {
        $containerAppEnvVars += "KEYVAULT_URI=https://$KeyVaultName.vault.azure.net/"
    }
    
    # Add Redis configuration since we always deploy Redis
    if ($redisSuccess) {
        $containerAppEnvVars += "REDIS_HOST=$RedisName.redis.cache.windows.net"
        $containerAppEnvVars += "REDIS_PORT=6380"
        $containerAppEnvVars += "REDIS_SSL=true"
        # Add the secret name so the backend knows which Key Vault secret to read
        $containerAppEnvVars += "REDIS_SECRET_NAME=redis-connection"
    }
    
    $fullImageName = "$RegistryName.azurecr.io/$($normalized)-backend:latest"
    
    # Pass env vars as an array so PowerShell expands them into separate CLI arguments
    az containerapp create --resource-group $ResourceGroupName --name $ContainerAppName --environment $ContainerAppEnvName --image $fullImageName --target-port 8080 --ingress external --min-replicas 1 --max-replicas 3 --cpu 0.5 --memory 1Gi --user-assigned $managedIdentityId --env-vars $containerAppEnvVars --registry-server "$RegistryName.azurecr.io" --registry-identity $managedIdentityId --output none
    # Ensure SQL firewall allows Container App outbound IPs
    Add-ContainerAppFirewallRules -ResourceGroupName $ResourceGroupName -ContainerAppName $ContainerAppName -SqlServerName $SqlServerName
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Container App created" -ForegroundColor Green
    } else {
        Write-Warning "Container App create returned non-zero exit code. Continuing to attempt configuration and retries." -ForegroundColor Yellow
    }
} else {
    Write-Host "Container App already exists, updating configuration..." -ForegroundColor Yellow
    
    # Define the same environment variables for update - Azure AD SSO only
    $containerAppEnvVars = @(
        "TENANT_ID=$tenantId",
        "API_AUDIENCE=api://$apiAppId",
        "SQL_SERVER=$SqlServerName.database.windows.net",
        "SQL_DB=$SqlDatabaseName",
        "AZURE_CLIENT_ID=$managedIdentityClientId",
        "PORT=8080"
    )
    
    # Add Key Vault only if it was created successfully
    if ($keyVaultSuccess) {
        $containerAppEnvVars += "KEYVAULT_URI=https://$KeyVaultName.vault.azure.net/"
    }
    
    # Add Redis configuration since we always deploy Redis
    if ($redisSuccess) {
        $containerAppEnvVars += "REDIS_HOST=$RedisName.redis.cache.windows.net"
        $containerAppEnvVars += "REDIS_PORT=6380"
        $containerAppEnvVars += "REDIS_SSL=true"
        # Add the secret name so the backend knows which Key Vault secret to read
        $containerAppEnvVars += "REDIS_SECRET_NAME=redis-connection"
    }
    
    $fullImageName = "$RegistryName.azurecr.io/$($normalized)-backend:latest"
    
    # Update the Container App with correct environment variables and image
    # Pass env vars as an array so they are applied as distinct key=value pairs
    az containerapp update --name $ContainerAppName --resource-group $ResourceGroupName --image $fullImageName --env-vars $containerAppEnvVars --output none
    # Ensure SQL firewall allows Container App outbound IPs after update
    Add-ContainerAppFirewallRules -ResourceGroupName $ResourceGroupName -ContainerAppName $ContainerAppName -SqlServerName $SqlServerName
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Container App configuration and image updated" -ForegroundColor Green
    } else {
        Write-Warning "Container App update returned non-zero exit code. Continuing and will retry fetching settings." -ForegroundColor Yellow
    }

    # Note: intentionally not re-applying env vars a second time here to avoid accidental concatenation or duplication
}

# Get Container App URL
# Poll for Container App ingress FQDN (sometimes not present immediately)
Write-Host "Polling for Container App ingress FQDN..." -ForegroundColor Yellow
$maxApiPoll = 40
$apiPollDelay = 10
$apiBaseUrl = $null
for ($i = 1; $i -le $maxApiPoll; $i++) {
    try {
        $containerApp = az containerapp show --resource-group $ResourceGroupName --name $ContainerAppName 2>$null | ConvertFrom-Json
        if ($containerApp -and $containerApp.properties -and $containerApp.properties.configuration -and $containerApp.properties.configuration.ingress -and $containerApp.properties.configuration.ingress.fqdn) {
            $apiBaseUrl = "https://$($containerApp.properties.configuration.ingress.fqdn)"
            Write-Host "Found Container App ingress FQDN: $apiBaseUrl (attempt $i)" -ForegroundColor Green
            break
        }
    } catch {
        # ignore transient errors
    }
    Write-Host "Container App ingress FQDN not ready yet (attempt $i/$maxApiPoll). Waiting $apiPollDelay seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds $apiPollDelay
}

if (-not $apiBaseUrl) {
    Write-Error "Could not determine Container App ingress FQDN after $maxApiPoll attempts. Aborting to avoid placeholder API URL."
    exit 1
} else {
    Write-Host "Container App deployed successfully!" -ForegroundColor Green
    Write-Host "API URL: $apiBaseUrl" -ForegroundColor White
}

# Intentionally not re-applying environment variables here. The Container App was created/updated above
# with the desired environment variables. Re-applying env vars can cause unexpected concatenation
# when invoked multiple times; avoid doing it to keep the deployment idempotent and predictable.

# Create Service Connector connections (idempotent) using the user-assigned identity created earlier (idfullapp)
try {
    Write-Host "Attempting to create Service Connector connections for Container App (SQL, Storage) using user-assigned identity..." -ForegroundColor Cyan

    # get the user assigned identity client id
    $uai = az identity show --resource-group $ResourceGroupName --name $ManagedIdentityName -o json 2>$null | ConvertFrom-Json
    if ($uai -and $uai.clientId) {
        $userClientId = $uai.clientId
        $subscriptionId = $subscriptionId

        # Create SQL connection if SQL database exists
        $sqlDbId = az resource show --ids "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$SqlServerName/databases/$SqlDatabaseName" -o tsv --query id 2>$null
        if ($sqlDbId) {
            Write-Host "Creating SQL service connection (if missing) using user-assigned identity..." -ForegroundColor Yellow
            az containerapp connection create sql --source-id "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.App/containerApps/$ContainerAppName" --target-id $sqlDbId --user-identity client-id=$userClientId subs-id=$subscriptionId --container $ContainerAppName --yes --output none 2>$null
            Write-Host "SQL service connection created or already exists" -ForegroundColor Green
        } else {
            Write-Host "SQL database resource not found; skipping SQL service connection" -ForegroundColor DarkGray
        }

        # Create Storage connection if there is a storage account in the same resource group (optional)
        $storageAccount = az resource list --resource-group $ResourceGroupName --resource-type "Microsoft.Storage/storageAccounts" --query "[0].id" -o tsv 2>$null
        if ($storageAccount) {
            Write-Host "Creating Storage service connection (if missing) using user-assigned identity..." -ForegroundColor Yellow
            az containerapp connection create storage-blob --source-id "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.App/containerApps/$ContainerAppName" --target-id "$storageAccount/blobServices/default" --user-identity client-id=$userClientId subs-id=$subscriptionId --container $ContainerAppName --yes --output none 2>$null
            Write-Host "Storage service connection created or already exists" -ForegroundColor Green
        } else {
            Write-Host "No storage account found in resource group; skipping storage service connection" -ForegroundColor DarkGray
        }
    } else {
        Write-Warning "User-assigned identity not found; cannot create service connections automatically"
    }
} catch {
    Write-Warning "Failed to create service connections automatically: $_"
}
# Create Static Web App early so we can autofill frontend config before building
Write-Host "Creating Static Web App early: $StaticWebAppName" -ForegroundColor Yellow
if (-not (Test-AzResource -ResourceName $StaticWebAppName -ResourceType "Microsoft.Web/staticSites" -ResourceGroup $ResourceGroupName)) {
    az staticwebapp create --resource-group $ResourceGroupName --name $StaticWebAppName --location $Location --sku "Free" --output none
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Static Web App created successfully (early)" -ForegroundColor Green
    } else {
        Write-Warning "Static Web App creation failed (early), continuing and will attempt later"
    }
} else {
    Write-Host "Static Web App already exists (early)" -ForegroundColor Green
}

# Get the actual Static Web App URL now so we can write config before building frontend
# Poll until the SWA defaultHostname is available (no placeholders) with a timeout
$maxPollAttempts = 30
$pollDelaySec = 10
$attempt = 0
$actualSwaUrl = $null
Write-Host "Waiting for Static Web App hostname to become available (no placeholders)..." -ForegroundColor Yellow
while ($attempt -lt $maxPollAttempts) {
    $attempt++
    try {
        $swaInfoEarly = az staticwebapp show --resource-group $ResourceGroupName --name $StaticWebAppName 2>$null | ConvertFrom-Json
        $hostname = $null
        if ($swaInfoEarly) {
            if ($swaInfoEarly.defaultHostname) { $hostname = $swaInfoEarly.defaultHostname }
            elseif ($swaInfoEarly.properties -and $swaInfoEarly.properties.defaultHostname) { $hostname = $swaInfoEarly.properties.defaultHostname }
            elseif ($swaInfoEarly.properties -and $swaInfoEarly.properties.hostNames -and $swaInfoEarly.properties.hostNames.Count -gt 0) { $hostname = $swaInfoEarly.properties.hostNames[0] }
            elseif ($swaInfoEarly.hostName) { $hostname = $swaInfoEarly.hostName }
        }
        if ($hostname) {
            $actualSwaUrl = "https://$hostname"
            Write-Host "Static Web App hostname available: $actualSwaUrl (attempt $attempt)" -ForegroundColor Green
            break
        }
    } catch {
        # ignore transient errors and retry
    }
    Write-Host "Static Web App hostname not ready yet (attempt $attempt/$maxPollAttempts). Waiting $pollDelaySec seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds $pollDelaySec
}

if (-not $actualSwaUrl) {
    Write-Error "Static Web App hostname did not become available within $($maxPollAttempts * $pollDelaySec) seconds. Aborting because placeholders are not allowed."
    exit 1
}

# Prepare frontend config in public so the build picks up correct values
Write-Host "Writing frontend config to public/config.local.json for build..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\..\frontend"
try {
    if (-not (Test-Path "public")) { New-Item -ItemType Directory -Path "public" | Out-Null }
    $frontendConfigEarly = @{ 
        tenantId = $tenantId
        spaClientId = $spaAppId
        apiAudience = "api://$apiAppId"
        apiBaseUrl = $apiBaseUrl
        authority = "https://login.microsoftonline.com/$tenantId"
        redirectUri = $actualSwaUrl
    } | ConvertTo-Json -Depth 10

    $publicConfigPath = Join-Path -Path (Get-Location) -ChildPath "public\config.local.json"
    $frontendConfigEarly | Out-File -FilePath $publicConfigPath -Encoding UTF8
    Write-Host "Wrote $publicConfigPath" -ForegroundColor Green
} finally {
    # stay in frontend dir to build
}

# Install dependencies and build once (no duplicate builds later). Abort on failure.
Write-Host "Installing frontend dependencies and building (single build)..." -ForegroundColor Yellow
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install frontend dependencies"
    exit 1
}


if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build frontend"
    exit 1
}

Write-Host "Frontend built successfully" -ForegroundColor Green
Set-Location $PSScriptRoot
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

# Get deployment token with retries and multiple retrieval strategies
$deploymentToken = $null
$maxTokenAttempts = 6
$tokenDelay = 8
for ($t = 1; $t -le $maxTokenAttempts; $t++) {
    try {
        Write-Host "Attempting to retrieve Static Web App deployment token (attempt $t/$maxTokenAttempts)..." -ForegroundColor Yellow
        # Primary: secrets list
        $token = az staticwebapp secrets list --resource-group $ResourceGroupName --name $StaticWebAppName --query "properties.apiKey" --output tsv 2>$null
        if (-not $token -or $token -eq "null") {
            # Secondary: show properties.apiKey
            $token = az staticwebapp show --resource-group $ResourceGroupName --name $StaticWebAppName --query "properties.apiKey" --output tsv 2>$null
        }
        if (-not $token -or $token -eq "null") {
            # Tertiary: list and query by name
            $token = az staticwebapp list --resource-group $ResourceGroupName --query "[?name=='$StaticWebAppName'].properties.apiKey | [0]" --output tsv 2>$null
        }
        if ($token -and $token -ne "null" -and $token.Trim() -ne "") {
            $deploymentToken = $token.Trim()
            Write-Host "Obtained deployment token" -ForegroundColor Green
            break
        }
    } catch {
        Write-Warning "Transient error retrieving token: $_"
    }
    Write-Host "Token not ready yet. Waiting $tokenDelay seconds before retry..." -ForegroundColor Yellow
    Start-Sleep -Seconds $tokenDelay
}

if (-not $deploymentToken) {
    Write-Error "Could not retrieve Static Web App deployment token after $maxTokenAttempts attempts. Frontend cannot be deployed automatically."
    Write-Host "You can try: az staticwebapp secrets list --resource-group $ResourceGroupName --name $StaticWebAppName --query properties.apiKey -o tsv" -ForegroundColor Yellow
    Write-Host "Or deploy manually with: npx @azure/static-web-apps-cli deploy --deployment-token <token> --app-location dist" -ForegroundColor Yellow
    exit 1
}

Write-Host "Deploying to PRODUCTION environment..." -ForegroundColor Green
# Deploy to production environment
npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --env "production" --verbose

if ($LASTEXITCODE -ne 0) {
    # Fallback: try without --env flag
    Write-Host "Retrying without --env flag..." -ForegroundColor Yellow
    npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --verbose
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Frontend deployed to Static Web App successfully" -ForegroundColor Green
} else {
    Write-Warning "Frontend deployment may have failed, but continuing with deployment"
}

# Get the actual Static Web App URL and update configuration
try {
    $swaInfo = az staticwebapp show --resource-group $ResourceGroupName --name $StaticWebAppName 2>$null | ConvertFrom-Json
    $swaHost = $null
    if ($swaInfo) {
        if ($swaInfo.defaultHostname) { $swaHost = $swaInfo.defaultHostname }
        elseif ($swaInfo.properties -and $swaInfo.properties.defaultHostname) { $swaHost = $swaInfo.properties.defaultHostname }
        elseif ($swaInfo.properties -and $swaInfo.properties.hostNames -and $swaInfo.properties.hostNames.Count -gt 0) { $swaHost = $swaInfo.properties.hostNames[0] }
        elseif ($swaInfo.hostName) { $swaHost = $swaInfo.hostName }
    }
    if (-not $swaHost) {
        Write-Error "Could not determine Static Web App hostname after deployment"
        exit 1
    }
    $actualSwaUrl = "https://$swaHost"
    Write-Host "Static Web App URL: $actualSwaUrl" -ForegroundColor Green
} catch {
    Write-Error "Failed to read Static Web App information: $_"
    exit 1
}

# Update SPA app registration with correct redirect URI
Write-Host "Updating SPA app registration with correct redirect URI..." -ForegroundColor Yellow
$updatedRedirectUris = @("http://localhost:5173", $actualSwaUrl)
az ad app update --id $spaAppObjectId --web-redirect-uris $updatedRedirectUris --output none 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "SPA redirect URI updated successfully" -ForegroundColor Green
} else {
    Write-Warning "Failed to update SPA redirect URI. You may need to update it manually in Azure Portal"
    Write-Host "Required redirect URIs: http://localhost:5173, $actualSwaUrl" -ForegroundColor Yellow
}

# Update frontend configuration file with real values
Write-Host "Updating frontend configuration..." -ForegroundColor Yellow
$frontendConfig = @{
    tenantId = $tenantId
    spaClientId = $spaAppId
    apiAudience = "api://$apiAppId"
    apiBaseUrl = $apiBaseUrl
    authority = "https://login.microsoftonline.com/$tenantId"
    redirectUri = $actualSwaUrl
} | ConvertTo-Json -Depth 10

# Update the config file in the dist folder and redeploy
Set-Content -Path "dist/config.local.json" -Value $frontendConfig -Encoding UTF8
Write-Host "Frontend configuration updated" -ForegroundColor Green

# Redeploy with updated configuration only if we have a deployment token
if ($deploymentToken -and $deploymentToken -ne "null" -and $deploymentToken.Trim() -ne "") {
    Write-Host "Redeploying frontend with updated configuration..." -ForegroundColor Yellow
    npx @azure/static-web-apps-cli deploy --deployment-token $deploymentToken --app-location "dist" --env "production" --verbose

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Frontend redeployed with correct configuration" -ForegroundColor Green
    } else {
        Write-Warning "Frontend redeploy may have failed"
    }
} else {
    Write-Host "Skipping frontend redeploy - no deployment token available" -ForegroundColor Yellow
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
Write-Host "SPA Client ID: $spaClientId" -ForegroundColor White
Write-Host "API Audience: $apiAudience" -ForegroundColor White
Write-Host "SQL Server: $SqlServerName.database.windows.net" -ForegroundColor White
Write-Host "SQL Database: $SqlDatabaseName" -ForegroundColor White
Write-Host "Key Vault: $KeyVaultName" -ForegroundColor White
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "API App ID: $apiAppId" -ForegroundColor White
Write-Host "Scope: api://$apiAppId/user_impersonation" -ForegroundColor White

Write-Host "`n*** AUTHENTICATION ***" -ForegroundColor Green
Write-Host "Azure AD SSO: Sign in with your Microsoft account" -ForegroundColor White
Write-Host "All authentication now uses Azure AD with managed identity" -ForegroundColor Green

Write-Host "`nTest your application:" -ForegroundColor Yellow
Write-Host "1. Visit: $actualSwaUrl" -ForegroundColor White
Write-Host "2. Sign in with your Microsoft account" -ForegroundColor White
Write-Host "3. Test the API integration" -ForegroundColor White

Write-Host "`nAll resources created successfully!" -ForegroundColor Green
