import os
import logging
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import redis
import pyodbc
from sqlalchemy import create_engine, text
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from jose import JWTError, jwt
import httpx
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
TENANT_ID = os.getenv("TENANT_ID")
API_AUDIENCE = os.getenv("API_AUDIENCE")
SQL_SERVER = os.getenv("SQL_SERVER")
SQL_DB = os.getenv("SQL_DB")
SQL_USERNAME = os.getenv("SQL_USERNAME")  # Added for SQL auth
SQL_PASSWORD = os.getenv("SQL_PASSWORD")  # Added for SQL auth
KEYVAULT_URI = os.getenv("KEYVAULT_URI")
REDIS_SECRET_NAME = os.getenv("REDIS_SECRET_NAME", "redis-connection")
PORT = int(os.getenv("PORT", "8080"))

# Simple auth credentials for frontend (if configured)
SIMPLE_USERNAME = os.getenv("SIMPLE_USERNAME")
SIMPLE_PASSWORD = os.getenv("SIMPLE_PASSWORD")

# Log configuration at startup
logger.info(f"TENANT_ID: {TENANT_ID}")
logger.info(f"Simple tenant-only authentication configured")

# FastAPI app
app = FastAPI(title="Azure Fullstack API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global variables for connections
redis_client: Optional[redis.Redis] = None
sql_engine = None

# Pydantic models
class Product(BaseModel):
    id: Optional[int] = None
    name: str
    description: str
    price: float

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float

class HealthResponse(BaseModel):
    status: str
    services: dict

class SimpleLoginRequest(BaseModel):
    username: str
    password: str

class SimpleLoginResponse(BaseModel):
    token: str
    expiresIn: int

# Startup event
@app.on_event("startup")
async def startup_event():
    global redis_client, sql_engine
    
    logger.info("Starting up application...")
    
    # Initialize managed identity credential
    client_id = os.getenv("AZURE_CLIENT_ID")
    if client_id:
        credential = ManagedIdentityCredential(client_id=client_id)
        logger.info(f"Using user-assigned managed identity: {client_id}")
    else:
        credential = ManagedIdentityCredential()
        logger.info("Using system-assigned managed identity")
    
    # Initialize Key Vault client
    if KEYVAULT_URI:
        try:
            secret_client = SecretClient(vault_url=KEYVAULT_URI, credential=credential)
            logger.info(f"Key Vault client initialized for: {KEYVAULT_URI}")
            
            # Get Redis connection string from Key Vault
            try:
                redis_secret = secret_client.get_secret(REDIS_SECRET_NAME)
                redis_connection_string = redis_secret.value
                logger.info(f"Retrieved Redis connection string from Key Vault")
                
                # Parse Azure Cache for Redis connection string
                # Format: "hostname:port,password=xxx,ssl=True,abortConnect=False"
                parts = redis_connection_string.split(',')
                host_port = parts[0].split(':')
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else 6380
                
                # Extract password
                password = None
                ssl_enabled = True
                for part in parts[1:]:
                    if part.startswith('password='):
                        password = part.split('=', 1)[1]
                    elif part.startswith('ssl='):
                        ssl_enabled = part.split('=', 1)[1].lower() == 'true'
                
                # Create Redis connection with proper parameters
                redis_client = redis.Redis(
                    host=host,
                    port=port,
                    password=password,
                    ssl=ssl_enabled,
                    ssl_cert_reqs=None,
                    decode_responses=True
                )
                
                # Test the connection
                try:
                    redis_client.ping()
                    logger.info("Redis connection established successfully")
                except Exception as ping_error:
                    logger.error(f"Redis ping failed: {ping_error}")
                    redis_client = None
                
            except Exception as redis_error:
                logger.error(f"Failed to connect to Redis: {redis_error}")
                redis_client = None
                
        except Exception as kv_error:
            logger.error(f"Failed to connect to Key Vault: {kv_error}")
            logger.error(f"Key Vault URI: {KEYVAULT_URI}")
            logger.error(f"Client ID: {client_id}")
    else:
        logger.error("KEYVAULT_URI not configured")
    
    # Initialize SQL connection
    if SQL_SERVER and SQL_DB:
        try:
            logger.info("=== SQL DATABASE INITIALIZATION ===")
            logger.info(f"SQL_SERVER: {SQL_SERVER}")
            logger.info(f"SQL_DB: {SQL_DB}")
            
            # Get the client ID for user-assigned managed identity
            client_id = os.getenv("AZURE_CLIENT_ID")
            logger.info(f"AZURE_CLIENT_ID: {client_id}")
            
            connection_string = None
            
            # Try SQL Authentication first (more reliable)
            if SQL_USERNAME and SQL_PASSWORD:
                logger.info("🔐 Using SQL Authentication (username/password)")
                connection_string = (
                    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                    f"SERVER={SQL_SERVER};"
                    f"DATABASE={SQL_DB};"
                    f"UID={SQL_USERNAME};"
                    f"PWD={SQL_PASSWORD};"
                    f"Encrypt=yes;"
                    f"TrustServerCertificate=no;"
                    f"Connection Timeout=30;"
                )
                logger.info(f"Connection string (without password): DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={SQL_SERVER};DATABASE={SQL_DB};UID={SQL_USERNAME};PWD=***;...")
            
            # Fallback to Managed Identity if SQL auth not configured
            else:
                logger.info("🔒 SQL Authentication not configured, trying Managed Identity...")
                
                # Test if we can get a token first
                logger.info("Attempting to get SQL access token...")
                try:
                    token = credential.get_token("https://database.windows.net/.default")
                    access_token = token.token
                    logger.info("✅ Successfully obtained SQL access token")
                    logger.info(f"Token length: {len(access_token) if access_token else 0}")
                except Exception as token_error:
                    logger.error(f"❌ Failed to get SQL access token: {token_error}")
                    logger.error(f"Token error type: {type(token_error).__name__}")
                    raise token_error

                # Create connection string using Managed Identity authentication
                connection_string = (
                    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                    f"SERVER={SQL_SERVER};"
                    f"DATABASE={SQL_DB};"
                    f"Authentication=ActiveDirectoryMsi;"
                    f"Encrypt=yes;"
                    f"TrustServerCertificate=no;"
                    f"Connection Timeout=30;"
                )
                
                # Add Client Id if available for user-assigned managed identity
                if client_id:
                    connection_string += f"Client Id={client_id};"
                    logger.info("Using user-assigned managed identity with Client ID")
                else:
                    logger.info("Using system-assigned managed identity (no Client ID)")
                
                logger.info(f"Connection string (without sensitive data): DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={SQL_SERVER};DATABASE={SQL_DB};Authentication=ActiveDirectoryMsi;...")
            
            logger.info("Creating SQL engine...")
            sql_engine = create_engine(f"mssql+pyodbc:///?odbc_connect={connection_string}")
            logger.info("✅ SQL engine created successfully")
            
            # Test connection and create tables if they don't exist
            logger.info("Testing SQL connection...")
            try:
                with sql_engine.connect() as conn:
                    logger.info("✅ SQL connection opened successfully")
                    
                    # Verify connection works
                    logger.info("Executing test query...")
                    result = conn.execute(text("SELECT 1 as test_value"))
                    test_result = result.scalar()
                    logger.info(f"✅ Test query successful, result: {test_result}")
                    
                    # Check if products table exists
                    logger.info("Checking if products table exists...")
                    table_check = conn.execute(text("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'products'"))
                    table_exists = table_check.scalar() > 0
                    logger.info(f"Products table exists: {table_exists}")
                    
                    if not table_exists:
                        logger.info("Creating products table...")
                        conn.execute(text("""
                            CREATE TABLE products (
                                id INT IDENTITY(1,1) PRIMARY KEY,
                                name NVARCHAR(255) NOT NULL,
                                description NVARCHAR(MAX),
                                price DECIMAL(10,2) NOT NULL,
                                created_at DATETIME2 DEFAULT GETDATE()
                            )
                        """))
                        logger.info("✅ Products table created successfully")
                    
                    # Insert sample data if table is empty
                    logger.info("Checking for existing products...")
                    result = conn.execute(text("SELECT COUNT(*) as count FROM products"))
                    count = result.scalar()
                    logger.info(f"Current products count: {count}")
                    
                    if count == 0:
                        logger.info("Inserting sample products...")
                        conn.execute(text("""
                            INSERT INTO products (name, description, price) VALUES 
                            ('Sample Product 1', 'This is a sample product for testing', 29.99),
                            ('Sample Product 2', 'Another sample product', 49.99),
                            ('Sample Product 3', 'Third sample product', 19.99)
                        """))
                        logger.info("✅ Sample data inserted successfully")
                    
                    # Check if users table exists
                    logger.info("Checking if users table exists...")
                    users_table_check = conn.execute(text("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users'"))
                    users_table_exists = users_table_check.scalar() > 0
                    logger.info(f"Users table exists: {users_table_exists}")
                    
                    if not users_table_exists:
                        logger.info("Creating users table...")
                        conn.execute(text("""
                            CREATE TABLE users (
                                id INT IDENTITY(1,1) PRIMARY KEY,
                                username NVARCHAR(255) NOT NULL UNIQUE,
                                display_name NVARCHAR(255),
                                email NVARCHAR(255),
                                created_at DATETIME2 DEFAULT GETDATE()
                            )
                        """))
                        logger.info("✅ Users table created successfully")
                        
                        # Insert demo users
                        logger.info("Inserting demo users...")
                        conn.execute(text("""
                            INSERT INTO users (username, display_name, email) VALUES 
                            ('demo', 'Demo User', 'demo@example.com'),
                            ('testuser', 'Test User', 'test@example.com')
                        """))
                        logger.info("✅ Demo users inserted successfully")
                    
                    conn.commit()
                    logger.info("✅ All SQL operations committed successfully")
                    
            except Exception as conn_error:
                logger.error(f"❌ SQL connection/query error: {conn_error}")
                logger.error(f"Connection error type: {type(conn_error).__name__}")
                logger.error(f"Connection error details: {str(conn_error)}")
                raise conn_error
            
            logger.info("✅ SQL Database connection and setup completed successfully")
            
        except Exception as e:
            logger.error(f"❌ CRITICAL: Failed to connect to SQL Database")
            logger.error(f"Error: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error details: {str(e)}")
            logger.error(f"Connection details - Server: {SQL_SERVER}, DB: {SQL_DB}, Client ID: {client_id}")
            
            # Try to get more information about available ODBC drivers
            try:
                import subprocess
                result = subprocess.run(['odbcinst', '-q', '-d'], capture_output=True, text=True)
                logger.error(f"Available ODBC drivers: {result.stdout}")
            except Exception as driver_error:
                logger.error(f"Could not check ODBC drivers: {driver_error}")
            
            sql_engine = None
    else:
        logger.error("❌ SQL Database environment variables not configured")
        logger.error(f"SQL_SERVER: {SQL_SERVER}")
        logger.error(f"SQL_DB: {SQL_DB}")
        logger.error("Both SQL_SERVER and SQL_DB must be set")

# Authentication functions - Azure AD only
async def get_jwks():
    """Get JWKS from Microsoft identity platform"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys")
            return response.json()
    except Exception as e:
        logger.error(f"Failed to get JWKS: {e}")
        return None

async def verify_azure_ad_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Simple JWT token verification - only check tenant"""
    try:
        logger.info(f"=== Simple Token Verification ===")
        logger.info(f"Expected tenant: {TENANT_ID}")
        
        token = credentials.credentials
        logger.info(f"Token length: {len(token)}")
        
        # Decode token payload (without verification) to check tenant
        try:
            import base64
            import json
            payload_b64 = token.split('.')[1]
            # Add padding if needed
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            logger.info(f"Token tenant (tid): {payload.get('tid', 'N/A')}")
            logger.info(f"Token subject: {payload.get('sub', 'N/A')}")
            logger.info(f"Token upn: {payload.get('upn', 'N/A')}")
            
            # Check tenant match only
            token_tenant = payload.get('tid')
            if token_tenant != TENANT_ID:
                logger.error(f"TENANT MISMATCH - Token tenant: {token_tenant}, Expected: {TENANT_ID}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid tenant")
            else:
                logger.info(f"Tenant verified successfully")
                
            return payload
                
        except Exception as e:
            logger.error(f"Could not decode token payload: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")
        
    except Exception as e:
        logger.error(f"Unexpected error in token verification: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token verification error")

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify token - accept either demo tokens or real Azure AD JWT tokens"""
    token = credentials.credentials
    logger.info(f"Token verification - token length: {len(token)}")
    
    # Check if it's a demo token (short length, starts with 'demo-token-')
    if token.startswith('demo-token-') or len(token) < 100:
        logger.info("Demo token detected - allowing access")
        return {
            "name": "Demo User",
            "preferred_username": "demo@example.com", 
            "oid": "demo-user-id",
            "tid": TENANT_ID,
            "auth_mode": "demo"
        }
    
    # Otherwise verify as real Azure AD JWT token
    logger.info("Real JWT token detected - verifying with Azure AD")
    return await verify_azure_ad_token(credentials)

# Health check endpoint
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with detailed service status"""
    services = {
        "api": "healthy",
        "sql": "unknown",
        "redis": "unknown", 
        "keyvault": "unknown"
    }
    
    # Check SQL connection with detailed error info
    if sql_engine:
        try:
            with sql_engine.connect() as conn:
                result = conn.execute(text("SELECT COUNT(*) as count FROM products"))
                count = result.fetchone()[0]
                services["sql"] = f"healthy (products: {count})"
                logger.info(f"SQL health check passed: {count} products found")
        except Exception as e:
            services["sql"] = f"unhealthy: {str(e)[:100]}"
            logger.error(f"SQL health check failed: {e}")
    else:
        services["sql"] = "not_configured"
        logger.warning("SQL engine not initialized")
    
    # Check Redis connection with detailed error info
    if redis_client:
        try:
            redis_info = redis_client.ping()
            redis_client.set("health_check", "ok", ex=60)
            test_value = redis_client.get("health_check")
            if test_value:
                services["redis"] = "healthy (read/write: ok)"
                logger.info("Redis health check passed: read/write test successful")
            else:
                services["redis"] = "unhealthy: read test failed"
                logger.error("Redis read test failed")
        except Exception as e:
            services["redis"] = f"unhealthy: {str(e)[:100]}"
            logger.error(f"Redis health check failed: {e}")
    else:
        services["redis"] = "not_configured"
        logger.warning("Redis client not initialized")
    
    # Check Key Vault access with test secret read
    if KEYVAULT_URI:
        try:
            # Try to access the secret client and read a test secret
            client_id = os.getenv("AZURE_CLIENT_ID")
            if client_id:
                credential = ManagedIdentityCredential(client_id=client_id)
            else:
                credential = ManagedIdentityCredential()
            
            secret_client = SecretClient(vault_url=KEYVAULT_URI, credential=credential)
            test_secret = secret_client.get_secret(REDIS_SECRET_NAME)
            if test_secret and test_secret.value:
                services["keyvault"] = "healthy (secrets accessible)"
                logger.info("Key Vault health check passed: secrets accessible")
            else:
                services["keyvault"] = "unhealthy: secret not found"
                logger.error("Key Vault test secret not found")
        except Exception as e:
            services["keyvault"] = f"unhealthy: {str(e)[:100]}"
            logger.error(f"Key Vault health check failed: {e}")
    else:
        services["keyvault"] = "not_configured"
        logger.warning("Key Vault URI not configured")
    
    return HealthResponse(status="healthy", services=services)

# Simple login endpoint for frontend
@app.post("/api/login", response_model=SimpleLoginResponse)
async def simple_login(request: SimpleLoginRequest):
    """Simple login endpoint that validates credentials and returns an Azure AD token for the frontend"""
    if not SIMPLE_USERNAME or not SIMPLE_PASSWORD:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Simple auth not configured")
    
    # Validate simple credentials
    if request.username != SIMPLE_USERNAME or request.password != SIMPLE_PASSWORD:
        logger.warning(f"Failed simple login attempt for username: {request.username}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    try:
        # Get Azure AD token using managed identity for management scope
        client_id = os.getenv("AZURE_CLIENT_ID")
        if client_id:
            credential = ManagedIdentityCredential(client_id=client_id)
        else:
            credential = ManagedIdentityCredential()
            
        # Get token for standard Azure scope
        token_response = credential.get_token("https://management.azure.com/.default")
        access_token = token_response.token
        expires_in = int((token_response.expires_on - token_response.token_obtained_at).total_seconds())
        
        logger.info(f"Simple login successful for user: {request.username}")
        return SimpleLoginResponse(token=access_token, expiresIn=expires_in)
        
    except Exception as e:
        logger.error(f"Failed to get Azure AD token for simple login: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token generation failed")

# Simple auth endpoint for frontend
class SimpleAuthRequest(BaseModel):
    username: str
    password: str

class SimpleAuthResponse(BaseModel):
    access_token: str
    user: dict

@app.post("/api/auth/simple", response_model=SimpleAuthResponse)
async def simple_auth(auth_request: SimpleAuthRequest):
    """Simple authentication endpoint that returns an Azure AD service account token"""
    try:
        # Validate simple credentials
        if auth_request.username == "demo" and auth_request.password == "demo123":
            # Get a service account token using managed identity
            from azure.identity import ManagedIdentityCredential
            
            client_id = os.getenv("AZURE_CLIENT_ID")
            if client_id:
                credential = ManagedIdentityCredential(client_id=client_id)
            else:
                credential = ManagedIdentityCredential()
            
            # Get token for standard Azure scope
            token_response = credential.get_token("https://management.azure.com/.default")
            access_token = token_response.token
            
            user_info = {
                "name": "Demo User",
                "email": "demo@example.com",
                "username": auth_request.username,
                "auth_mode": "simple"
            }
            
            logger.info(f"Simple auth successful for user: {auth_request.username}")
            return SimpleAuthResponse(access_token=access_token, user=user_info)
        else:
            logger.error(f"Simple auth failed for user: {auth_request.username}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Simple auth error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication failed")

# Product endpoints
@app.get("/api/products", response_model=List[Product])
async def get_products(user: dict = Depends(verify_token)):
    """Get all products"""
    if not sql_engine:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database not available")
    
    # Try to get from Redis cache first
    cache_key = "products:all"
    if redis_client:
        try:
            cached_products = redis_client.get(cache_key)
            if cached_products:
                logger.info("Returning products from cache")
                return json.loads(cached_products)
        except Exception as e:
            logger.warning(f"Cache read failed: {e}")
    
    try:
        with sql_engine.connect() as conn:
            result = conn.execute(text("SELECT id, name, description, price FROM products ORDER BY created_at DESC"))
            products = []
            for row in result:
                products.append(Product(
                    id=row.id,
                    name=row.name,
                    description=row.description,
                    price=float(row.price)
                ))
            
            # Cache the results
            if redis_client:
                try:
                    redis_client.setex(cache_key, 300, json.dumps([p.dict() for p in products]))  # Cache for 5 minutes
                    logger.info("Products cached successfully")
                except Exception as e:
                    logger.warning(f"Cache write failed: {e}")
            
            return products
            
    except Exception as e:
        logger.error(f"Database query failed: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database query failed")

@app.post("/api/products", response_model=Product)
async def create_product(product: ProductCreate, user: dict = Depends(verify_token)):
    """Create a new product"""
    if not sql_engine:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database not available")
    
    try:
        with sql_engine.connect() as conn:
            result = conn.execute(
                text("INSERT INTO products (name, description, price) OUTPUT INSERTED.id VALUES (:name, :description, :price)"),
                {"name": product.name, "description": product.description, "price": product.price}
            )
            product_id = result.scalar()
            conn.commit()
            
            # Invalidate cache
            if redis_client:
                try:
                    redis_client.delete("products:all")
                    logger.info("Cache invalidated")
                except Exception as e:
                    logger.warning(f"Cache invalidation failed: {e}")
            
            return Product(
                id=product_id,
                name=product.name,
                description=product.description,
                price=product.price
            )
            
    except Exception as e:
        logger.error(f"Database insert failed: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database insert failed")

@app.get("/api/user")
async def get_user_info(user: dict = Depends(verify_token)):
    """Get current user information from token"""
    return {
        "name": user.get("name", "Unknown"),
        "email": user.get("preferred_username", "unknown@example.com"),
        "oid": user.get("oid"),
        "tid": user.get("tid")
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
