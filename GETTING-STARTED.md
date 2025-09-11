# Getting Started Guide

## Quick Deployment

Follow these steps to deploy your Azure Fullstack Application:

### 1. Prerequisites Check

- **Azure Account**: Ensure you have an Azure account with appropriate permissions
- **Azure CLI**: Install and login to Azure CLI
- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+
- **Node.js**: Version 18 or later for frontend development
- **Git**: For cloning the repository

### 2. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/Scientialibera/FULL-APP.git
cd FULL-APP

# Login to Azure
az login
```

### 3. Deploy to Azure

```powershell
# Run the deployment script
.\deploy\deploy.ps1 -AppName "myapp" -Location "westus2"
```

**Note**: Replace `"myapp"` with your preferred application name (must be unique) and `"westus2"` with your preferred Azure region.

### 4. What Happens During Deployment

The script will:

1. **Validate** your Azure login and permissions
2. **Create** all required Azure resources
3. **Configure** security settings and managed identities
4. **Build** and deploy the backend container
5. **Build** and deploy the frontend application
6. **Generate** runtime configuration
7. **Verify** deployment success

### 5. Expected Output

After successful deployment, you'll see:

```
Deployment completed successfully!

Deployment Summary:
SPA URL: https://swa-myapp-1234.azurestaticapps.net
API FQDN: https://ca-myapp.kindwave-12345678.eastus.azurecontainerapps.io
Tenant ID: your-tenant-id
SPA Client ID: your-spa-client-id
API App ID: your-api-client-id
Scope: api://your-api-client-id/user_impersonation
SQL Server: sql-myapp-1234.database.windows.net
SQL Database: sqldb-myapp
Key Vault: kv-myapp-1234
Resource Group: rg-myapp
```

### 6. Test Your Application

1. **Visit the SPA URL** from the deployment output
2. **Sign in** with your Microsoft account
3. **Test the features**:
   - View your user profile
   - Add a new product
   - View the products list

### 7. Troubleshooting

If you encounter issues:

1. **Check Azure permissions**: Ensure your account has Contributor access
2. **Verify resource names**: Some Azure resource names must be globally unique
3. **Check logs**: Use Azure portal to view Container Apps logs
4. **Re-run deployment**: The script is idempotent and safe to re-run

### 8. Local Development (Optional)

For local development:

```powershell
# Setup development environment
.\deploy\setup-dev.ps1 -All

# Frontend development
cd frontend
npm run dev

# Backend development (in separate terminal)
cd backend
uvicorn main:app --reload
```

### 9. Clean Up (When Done)

To remove all resources:

```bash
# Delete the resource group (removes all resources)
az group delete --name "rg-myapp" --yes --no-wait
```

## Architecture Overview

Your deployed application includes:

- **Frontend**: React SPA hosted on Azure Static Web Apps
- **Backend**: Python FastAPI in Azure Container Apps
- **Database**: Azure SQL Database with managed identity authentication
- **Cache**: Azure Cache for Redis
- **Secrets**: Azure Key Vault for secure secret storage
- **Identity**: Azure AD app registrations for authentication
- **Monitoring**: Log Analytics workspace

## Next Steps

- Explore the codebase to understand the architecture
- Modify the application to fit your needs
- Add more features and endpoints
- Configure custom domains and SSL certificates
- Set up CI/CD pipelines for automated deployment

## Support

- Read the [README.md](README.md) for detailed documentation
- Report issues on GitHub
- Ask questions in discussions

---

Happy coding!
