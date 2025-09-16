# Azure Fullstack Application

A modern, secure, and scalable fullstack application built with React (TypeScript) frontend and Python FastAPI backend, deployed on Azure with enterprise-grade security and architecture.

## Architecture

This application demonstrates modern Azure architecture patterns:

- **Frontend**: React SPA with TypeScript, Vite, and MSAL for Azure AD authentication
- **Backend**: Python FastAPI with JWT validation, Azure SQL, Redis caching, and Key Vault integration
- **Authentication**: Microsoft Entra ID (Azure AD) with app registrations for SPA and API
- **Database**: Azure SQL Database with AAD authentication (no SQL passwords)
- **Caching**: Azure Cache for Redis with connection string stored in Key Vault
- **Secrets Management**: Azure Key Vault with RBAC authentication
- **Hosting**: Azure Container Apps for API, Azure Static Web Apps for SPA
- **Identity**: User-Assigned Managed Identity for secure service-to-service authentication
- **Monitoring**: Log Analytics workspace integration

## Quick Start

### Prerequisites

- Azure account with appropriate permissions
- Azure CLI installed and configured
- PowerShell 5.1 or later
- Node.js 18+ and npm
- Docker (for local development)

### One-Command Deployment

```powershell
# Clone the repository
git clone https://github.com/Scientialibera/FULL-APP.git
cd FULL-APP

# Login to Azure
az login

# Deploy everything
.\deploy\deploy.ps1 -AppName "myapp" -Location "westus2"
```

### What Gets Created

The deployment script creates:

1. **Resource Group**: `rg{AppName}`
2. **Container Registry**: `acr{appname}{random}`
3. **Log Analytics Workspace**: `log-{AppName}`
4. **Container Apps Environment**: `env-{AppName}`
5. **User-Assigned Managed Identity**: `id-{AppName}`
6. **Key Vault**: `kv{AppName}{random}`
7. **SQL Server**: `sql-{AppName}-{random}` (AAD-only auth)
8. **SQL Database**: `sqldb-{AppName}`
9. **Redis Cache**: `redis-{AppName}-{random}`
10. **Static Web App**: `swa{AppName}{random}`
11. **Container App**: `ca{AppName}`
12. **Azure AD App Registrations**: `{AppName}-api` and `{AppName}-spa`

## Security Features

### Authentication & Authorization
- **Azure AD Integration**: Single sign-on with Microsoft accounts
- **JWT Validation**: All API endpoints validate Azure AD tokens
- **RBAC**: Role-based access control throughout Azure services
- **Managed Identity**: No passwords or connection strings in code

### Secrets Management
- **Key Vault**: All secrets stored in Azure Key Vault
- **Runtime Configuration**: Non-secret config in gitignored local file
- **MSI Authentication**: Managed identity for Key Vault access

### Network Security
- **HTTPS Only**: All endpoints use HTTPS
- **SQL Firewall**: Azure services firewall rule
- **Container Registry**: Private registry with managed identity pull

## Project Structure

```
azure-marketplace/
├── deploy/
│   └── deploy.ps1              # Single deployment script
├── frontend/                   # React TypeScript SPA
│   ├── src/
│   │   ├── components/
│   │   │   ├── ProductList.tsx
│   │   │   └── UserProfile.tsx
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   ├── config.ts
│   │   ├── apiService.ts
│   │   └── types.ts
│   ├── public/
│   │   └── config.template.json # Config template (replaced during deployment)
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
├── backend/                    # Python FastAPI API
│   ├── main.py                 # Main FastAPI application
│   ├── requirements.txt        # Python dependencies
│   └── Dockerfile              # Container configuration
├── .gitignore                  # Git ignore (includes config.local.json)
└── README.md
```

## Backend API

### Endpoints

- `GET /healthz` - Health check endpoint
- `GET /api/products` - Get all products (requires auth)
- `POST /api/products` - Create new product (requires auth)
- `GET /api/user` - Get current user info (requires auth)

### Configuration (Environment Variables)

- `TENANT_ID` - Azure AD tenant ID
- `API_AUDIENCE` - API app registration audience
- `SQL_SERVER` - Azure SQL server FQDN
- `SQL_DB` - Azure SQL database name
- `KEYVAULT_URI` - Key Vault URI
- `REDIS_SECRET_NAME` - Redis connection secret name in Key Vault
- `PORT` - Application port (default: 8080)

### Features

- **JWT Authentication**: Validates Azure AD access tokens
- **Azure SQL Integration**: Uses managed identity for database access
- **Redis Caching**: Cache-aside pattern for product listings
- **Key Vault Integration**: Secure secret retrieval
- **Health Checks**: Comprehensive service health monitoring
- **Error Handling**: Proper HTTP status codes and error messages

## Frontend SPA

### Features

- **React 18**: Modern React with hooks and function components
- **TypeScript**: Full type safety and IntelliSense
- **MSAL Integration**: Azure AD authentication with automatic token refresh
- **Responsive Design**: Mobile-first CSS with CSS Grid
- **Error Handling**: Graceful error states and loading indicators

### Configuration

The frontend reads runtime configuration from `/public/config.local.json` (generated during deployment):

```json
{
  "tenantId": "your-tenant-id",
  "spaClientId": "your-spa-client-id", 
  "apiAudience": "api://your-api-client-id",
  "apiBaseUrl": "https://your-api-url",
  "authority": "https://login.microsoftonline.com/your-tenant-id",
  "redirectUri": "https://your-app-url"
}
```

## Local Development

### Backend Development

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Set environment variables
$env:TENANT_ID="your-tenant-id"
$env:API_AUDIENCE="api://your-api-client-id"
# ... other environment variables

# Run the application
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Create local config (copy from deployed config.local.json or use development values)
cp public/config.template.json public/config.local.json
# Edit config.local.json with your values

# Start development server
npm run dev
```

## Deployment Process

The deployment script follows these steps:

1. **Validation**: Checks Azure login and permissions
2. **Resource Creation**: Creates all Azure resources idempotently
3. **RBAC Configuration**: Assigns necessary role permissions
4. **App Registrations**: Creates Azure AD apps with proper scopes
5. **Container Build**: Builds and pushes backend container to ACR
6. **Database Setup**: Creates SQL schema and managed identity user
7. **Configuration**: Generates frontend config from deployment outputs
8. **Application Deployment**: Deploys both frontend and backend

### Idempotent Deployment

The script is designed to be run multiple times safely:
- Checks for existing resources before creation
- Updates existing resources where appropriate
- Maintains configuration consistency

## Monitoring & Troubleshooting

## Service Connector (Microsoft.ServiceLinker) & Runtime Networking

This project now uses Azure Service Connector (preview) to wire Container Apps to Azure services (SQL, Storage, Key Vault) using a user-assigned managed identity created by the deployment script (`id<appname>`).

Key points:

- The deploy script registers the `Microsoft.ServiceLinker` provider (if not already registered) and creates idempotent container app connections for supported services.
- Service Connector provisions RBAC and injects configuration into the Container App so the app can use Managed Identity for authentication (no passwords in code).
- The script creates a service connection for Azure SQL using your existing user-assigned identity (recommended) rather than creating a system-assigned identity.
- The deployment also attempts to add the Container App outbound IP addresses to the Azure SQL server firewall so non‑VNet Container Apps can reach SQL. If you later move to a VNet-injected managed environment and Private Endpoints, update the script accordingly.

Provider registration
- Ensure `Microsoft.ServiceLinker` is registered in your subscription before creating connections (the deployment script will try to register it automatically):

```powershell
az provider register -n Microsoft.ServiceLinker
az provider show -n Microsoft.ServiceLinker --query registrationState -o tsv
```

Create a Service Connector connection (CLI examples)
- Using the user-assigned identity created by the deployment script (`id<appname>`). Replace placeholders as needed.

```powershell
# SQL (creates a Service Connector linking your container app to the SQL database using the user-assigned identity)
$sourceId = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.App/containerApps/<app>"
$targetSqlId = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Sql/servers/<sqlserver>/databases/<dbname>"
az containerapp connection create sql --source-id $sourceId --target-id $targetSqlId --user-identity client-id=<uai-client-id> subs-id=<sub> --container <containerName> --yes

# Storage (if you have a storage account)
$targetStorage = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<storage>/blobServices/default"
az containerapp connection create storage-blob --source-id $sourceId --target-id $targetStorage --user-identity client-id=<uai-client-id> subs-id=<sub> --container <containerName> --yes
```

Notes on network and NSG rules
- If your Container App managed environment is NOT VNet-injected (the default), NSGs on your subscription subnets will NOT filter ACA egress. Use Service Connector + SQL firewall rules or move to a VNet-injected environment for subnet-level control.
- If you do use a VNet-injected environment, you can use NSG service tags (`Storage`, `Sql`, `SqlManagement`, `KeyVault`, etc.) to permit outbound access to those Azure services while denying other egress. The deployment script contains example NSG commands in the documentation section.

Applying runtime env fixes without full redeploy
- If you need to correct `SQL_SERVER` / `SQL_DB` on an existing Container App without rebuilding/pushing images, update the Container App environment and restart the app. Two approaches:

- Simple CLI (preferred):

```powershell
az containerapp update --resource-group <rg> --name <app> --env-vars SQL_SERVER=<serverFqdn> SQL_DB=<dbname>
# then force a restart by scaling to 0 and back to 1
az containerapp update -g <rg> -n <app> --set template.scale.minReplicas=0 template.scale.maxReplicas=0
Start-Sleep -s 10
az containerapp update -g <rg> -n <app> --set template.scale.minReplicas=1 template.scale.maxReplicas=1
```

- Robust REST patch (works around CLI parsing issues):

```powershell
# 1) read the resource via az rest (include api-version)
$sub = az account show --query id -o tsv
$uri = "/subscriptions/$sub/resourceGroups/<rg>/providers/Microsoft.App/containerApps/<app>?api-version=2024-06-01"
$ca = az rest --method get --uri $uri -o json | ConvertFrom-Json

# 2) merge envs into $ca.properties.template.containers[0].env (preserve existing keys), then
$body = @{ properties = @{ template = @{ containers = $ca.properties.template.containers } } } | ConvertTo-Json -Depth 10

# 3) PATCH the resource
az rest --method patch --uri $uri --body $body --headers "Content-Type=application/json"

# 4) restart by scaling down/up (see above)
```

Verification commands

```powershell
# List service connections for a container app
az containerapp connection list --resource-group <rg> --name <app> --output table

# List SQL firewall rules
az sql server firewall-rule list -g <rg> -s <sqlserver> -o table

# Tail recent container app logs
az containerapp logs show --resource-group <rg> --name <app> --tail 200

# Check health endpoint
$fqdn = az containerapp show -g <rg> -n <app> --query "properties.configuration.ingress.fqdn" -o tsv
Invoke-WebRequest -Uri "https://$fqdn/health" -UseBasicParsing | Select-Object StatusCode, Content
```

Troubleshooting tips
- If `az` returns transient connection reset errors locally, try executing the same commands in Azure Cloud Shell (browser) which has a stable CLI environment and required extensions.
- If SQL connectivity still fails after env update and restart, verify the SQL server firewall includes the Container App outbound IPs (the deployment script attempts to add them using `Add-ContainerAppFirewallRules`) or consider enabling Private Endpoint and moving to a vNet-injected managed environment.


### Health Checks

- **API Health**: `GET /healthz` returns service status
- **Database Connection**: Health endpoint tests SQL connectivity
- **Redis Connection**: Health endpoint tests cache connectivity
- **Key Vault Access**: Health endpoint indicates Key Vault configuration

### Logs

- **Container Apps**: Logs available in Azure portal
- **Log Analytics**: Centralized logging for all services
- **Application Insights**: (Optional) Add for detailed telemetry

### Common Issues

1. **Authentication Failures**: Check app registration configuration
2. **Database Connection**: Verify managed identity permissions
3. **Key Vault Access**: Ensure RBAC permissions are correctly assigned
4. **Redis Connection**: Check connection string in Key Vault

## Security Best Practices

This application implements Azure security best practices:

1. **No Secrets in Code**: All secrets in Key Vault
2. **Managed Identity**: Service-to-service authentication without passwords
3. **HTTPS Everywhere**: All communication encrypted
4. **Least Privilege**: Minimal required permissions
5. **AAD-Only SQL**: No SQL authentication, only Azure AD
6. **Private Container Registry**: No anonymous pulls
7. **Input Validation**: Proper API input validation
8. **CORS Configuration**: Appropriate CORS settings

## Scaling Considerations

### Regional Deployment
- Current: Single-region deployment
- Future: Multi-region with Azure Front Door

### Database Scaling
- Current: Single SQL database
- Future: Read replicas, sharding, or Cosmos DB

### Container Scaling
- Current: 1-3 replica autoscaling
- Future: KEDA-based scaling, larger replica counts

### Caching
- Current: Single Redis instance
- Future: Redis cluster, CDN integration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Azure service health
3. Check application logs
4. Open an issue on GitHub

---

Built with Azure, React, and FastAPI
