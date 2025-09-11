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
.\deploy\deploy.ps1 -AppName "myapp" -Location "eastus"
```

### What Gets Created

The deployment script creates:

1. **Resource Group**: `rg-{AppName}`
2. **Container Registry**: `acr{appname}{random}`
3. **Log Analytics Workspace**: `log-{AppName}`
4. **Container Apps Environment**: `env-{AppName}`
5. **User-Assigned Managed Identity**: `id-{AppName}`
6. **Key Vault**: `kv-{AppName}-{random}`
7. **SQL Server**: `sql-{AppName}-{random}` (AAD-only auth)
8. **SQL Database**: `sqldb-{AppName}`
9. **Redis Cache**: `redis-{AppName}-{random}`
10. **Static Web App**: `swa-{AppName}-{random}`
11. **Container App**: `ca-{AppName}`
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
