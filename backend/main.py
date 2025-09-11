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
KEYVAULT_URI = os.getenv("KEYVAULT_URI")
REDIS_SECRET_NAME = os.getenv("REDIS_SECRET_NAME", "redis-connection")
PORT = int(os.getenv("PORT", "8080"))

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
            # Get access token for SQL
            token = credential.get_token("https://database.windows.net/.default")
            access_token = token.token
            
            # Get the client ID for user-assigned managed identity
            client_id = os.getenv("AZURE_CLIENT_ID")

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
            
            logger.info(f"Connecting to SQL with MSI. Client ID: {client_id or 'user-assigned'}")
            logger.info(f"SQL Server: {SQL_SERVER}, Database: {SQL_DB}")
            
            sql_engine = create_engine(f"mssql+pyodbc:///?odbc_connect={connection_string}")
            
            # Test connection and create tables if they don't exist
            with sql_engine.connect() as conn:
                # Verify connection works
                conn.execute(text("SELECT 1"))
                logger.info("SQL Database connection successful")
                
                # Create products table if it doesn't exist
                conn.execute(text("""
                    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='products' AND xtype='U')
                    CREATE TABLE products (
                        id INT IDENTITY(1,1) PRIMARY KEY,
                        name NVARCHAR(255) NOT NULL,
                        description NVARCHAR(MAX),
                        price DECIMAL(10,2) NOT NULL,
                        created_at DATETIME2 DEFAULT GETDATE()
                    )
                """))
                
                # Insert sample data if table is empty
                result = conn.execute(text("SELECT COUNT(*) as count FROM products"))
                count = result.scalar()
                if count == 0:
                    conn.execute(text("""
                        INSERT INTO products (name, description, price) VALUES 
                        ('Sample Product 1', 'This is a sample product for testing', 29.99),
                        ('Sample Product 2', 'Another sample product', 49.99),
                        ('Sample Product 3', 'Third sample product', 19.99)
                    """))
                    logger.info("Inserted sample data into products table")
                
                conn.commit()
            
            logger.info("SQL Database connection established")
            
        except Exception as e:
            logger.error(f"Failed to connect to SQL Database: {e}")
            logger.error(f"Connection details - Server: {SQL_SERVER}, DB: {SQL_DB}, Client ID: {client_id}")
            sql_engine = None
    else:
        logger.error("SQL Database environment variables not configured")
        logger.error(f"SQL_SERVER: {SQL_SERVER}, SQL_DB: {SQL_DB}")

# JWT token validation
async def get_jwks():
    """Get JWKS from Microsoft identity platform"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys")
            return response.json()
    except Exception as e:
        logger.error(f"Failed to get JWKS: {e}")
        return None

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token from Azure AD"""
    try:
        token = credentials.credentials
        
        # Get JWKS
        jwks = await get_jwks()
        if not jwks:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not verify token")
        
        # Decode token header to get kid
        unverified_header = jwt.get_unverified_header(token)
        
        # Find the correct key
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                break
        
        if not rsa_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
        # Verify token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
        )
        
        return payload
        
    except JWTError as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not verify token")

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
