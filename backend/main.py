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
import urllib.parse
import time
import traceback
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from jose import JWTError, jwt
import httpx
import json
import asyncio
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables will be loaded at application startup.
# This ensures that environment variables applied/updated by the platform
# after the process started (for example via the Azure control plane) are
# observed correctly when the application initializes.
TENANT_ID = None
API_AUDIENCE = None
SQL_SERVER = None
SQL_DB = None
SQL_USERNAME = None
SQL_PASSWORD = None
KEYVAULT_URI = None
REDIS_SECRET_NAME = "redis-connection"
PORT = 8080

# Simple auth credentials for frontend (if configured)
SIMPLE_USERNAME = None
SIMPLE_PASSWORD = None


def load_envs():
    """Load environment variables into module globals. Call this at startup."""
    global TENANT_ID, API_AUDIENCE, SQL_SERVER, SQL_DB, SQL_USERNAME, SQL_PASSWORD
    global KEYVAULT_URI, REDIS_SECRET_NAME, PORT, SIMPLE_USERNAME, SIMPLE_PASSWORD

    TENANT_ID = os.getenv("TENANT_ID")
    API_AUDIENCE = os.getenv("API_AUDIENCE")
    SQL_SERVER = os.getenv("SQL_SERVER")
    SQL_DB = os.getenv("SQL_DB")
    SQL_USERNAME = os.getenv("SQL_USERNAME")  # Optional SQL auth
    SQL_PASSWORD = os.getenv("SQL_PASSWORD")  # Optional SQL auth
    KEYVAULT_URI = os.getenv("KEYVAULT_URI")
    REDIS_SECRET_NAME = os.getenv("REDIS_SECRET_NAME", "redis-connection")
    try:
        PORT = int(os.getenv("PORT", "8080"))
    except Exception:
        PORT = 8080

    SIMPLE_USERNAME = os.getenv("SIMPLE_USERNAME")
    SIMPLE_PASSWORD = os.getenv("SIMPLE_PASSWORD")

    # Log the loaded values (avoid printing secrets)
    logger.info(f"Loaded envs: TENANT_ID={TENANT_ID}, API_AUDIENCE={'SET' if API_AUDIENCE else 'NONE'}, SQL_SERVER={'SET' if SQL_SERVER else 'NONE'}, SQL_DB={'SET' if SQL_DB else 'NONE'}, KEYVAULT_URI={'SET' if KEYVAULT_URI else 'NONE'}, REDIS_SECRET_NAME={REDIS_SECRET_NAME}, PORT={PORT}")

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
    """Application startup: load environment variables but defer Redis/SQL connections.

    We intentionally avoid creating Redis and SQL connections at startup so that
    connection attempts can be made on-demand via explicit endpoints. This prevents
    long-blocking startup hangs and lets operators run targeted checks.
    """
    load_envs()
    logger.info("Starting up application (deferred Redis/SQL initialization)")
    # Do not attempt to connect to SQL/Redis at startup — connections are on-demand via endpoints below.


@app.get("/check/sql")
async def check_sql():
    """On-demand SQL connectivity check (no auth). Returns full error on failure."""
    load_envs()
    if not SQL_SERVER or not SQL_DB:
        return {"status": "not_configured", "error": "SQL_SERVER or SQL_DB not set"}
    loop = asyncio.get_event_loop()
    logger.info("Starting SQL connectivity check")
    # Log non-sensitive context for debugging
    logger.info(f"SQL check context: SQL_SERVER={SQL_SERVER}, SQL_DB={SQL_DB}, using_sql_auth={'yes' if (SQL_USERNAME and SQL_PASSWORD) else 'no'}, client_id_set={'yes' if os.getenv('AZURE_CLIENT_ID') else 'no'}")
    try:
        # Basic TCP reachability test to detect network/firewall issues quickly
        def _tcp_test():
            host = SQL_SERVER.split(',')[0]
            port = 1433
            try:
                # Allow host[:port] formats
                if ':' in host:
                    h, p = host.split(':', 1)
                    host = h
                    try:
                        port = int(p)
                    except ValueError:
                        port = 1433
                s = socket.create_connection((host, port), timeout=5)
                s.close()
                return True
            except Exception as se:
                logger.warning(f"TCP test to SQL server {host}:{port} failed: {type(se).__name__}: {se}")
                return False

        tcp_ok = await loop.run_in_executor(None, _tcp_test)
        if not tcp_ok:
            msg = (
                f"Network reachability test to SQL server failed (host={SQL_SERVER}, port=1433). "
                "This usually indicates a SQL Server firewall blocking the Container App outbound IPs. "
                "Ensure the SQL server allows connections from your Container App outbound IPs or set a temporary firewall rule."
            )
            logger.error(msg)
            return {"status": "unhealthy", "error": msg, "error_type": "NetworkUnreachable"}

        client_id = os.getenv("AZURE_CLIENT_ID")
        if client_id:
            credential = ManagedIdentityCredential(client_id=client_id)
        else:
            credential = ManagedIdentityCredential()

        # Prefer SQL auth if provided (run blocking DB calls in a thread)
        if SQL_USERNAME and SQL_PASSWORD:
            def _sync_sql_auth_check():
                conn_str = (
                    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                    f"SERVER={SQL_SERVER};"
                    f"DATABASE={SQL_DB};"
                    f"UID={SQL_USERNAME};"
                    f"PWD={SQL_PASSWORD};"
                    f"Encrypt=yes;TrustServerCertificate=no;Connection Timeout=15;"
                )
                engine = create_engine(f"mssql+pyodbc:///?odbc_connect={urllib.parse.quote_plus(conn_str)}")
                try:
                    with engine.connect() as conn:
                        result = conn.execute(text("SELECT 1"))
                        return result.scalar() is not None
                finally:
                    engine.dispose()

            logger.info("Running SQL auth check in thread (timeout=8s)")
            try:
                ok = await asyncio.wait_for(loop.run_in_executor(None, _sync_sql_auth_check), timeout=8)
            except asyncio.TimeoutError:
                logger.error("SQL auth check timed out")
                return {"status": "unhealthy", "error": "SQL auth check timed out", "error_type": "TimeoutError"}
            except Exception as e:
                logger.error(f"SQL auth check failed: {type(e).__name__}: {e}")
                raise
            logger.info(f"SQL auth check result: {ok}")
            return {"status": "healthy"} if ok else {"status": "unhealthy", "error": "query returned no rows"}

        # Otherwise use managed identity token (get token in thread to avoid blocking event loop)
        try:
            token = await loop.run_in_executor(None, credential.get_token, "https://database.windows.net/.default")
        except Exception as e:
            logger.error(f"Failed to acquire AAD token for SQL: {type(e).__name__}: {e}")
            raise

        access_token = token.token
        raw_conn = (
            f"DRIVER={{ODBC Driver 18 for SQL Server}};"
            f"SERVER={SQL_SERVER};"
            f"DATABASE={SQL_DB};"
            f"Encrypt=yes;TrustServerCertificate=no;Connection Timeout=15;"
        )
        if client_id:
            raw_conn += f"Client Id={client_id};"

        odbc_conn_str = urllib.parse.quote_plus(raw_conn)
        token_bytes = bytes(access_token, "utf-8") if access_token else None
        connect_args = {}
        if token_bytes:
            connect_args["attrs_before"] = {1256: token_bytes}

        def _sync_msi_sql_check():
            engine = create_engine(f"mssql+pyodbc:///?odbc_connect={odbc_conn_str}", connect_args=connect_args)
            try:
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT 1"))
                    return result.scalar() is not None
            finally:
                engine.dispose()
        logger.info("Running MSI SQL check in thread (timeout=8s)")
        try:
            ok = await asyncio.wait_for(loop.run_in_executor(None, _sync_msi_sql_check), timeout=8)
        except asyncio.TimeoutError:
            logger.error("MSI SQL check timed out")
            return {"status": "unhealthy", "error": "MSI SQL check timed out", "error_type": "TimeoutError"}
        except Exception as e:
            logger.error(f"MSI SQL check failed: {type(e).__name__}: {e}")
            raise
        logger.info(f"MSI SQL check result: {ok}")
        return {"status": "healthy"} if ok else {"status": "unhealthy", "error": "query returned no rows"}

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"SQL check failed: {type(e).__name__}: {e}\n{tb}")
        return {"status": "unhealthy", "error": str(e), "error_type": type(e).__name__, "trace": tb}


@app.get("/check/redis")
async def check_redis():
    """On-demand Redis connectivity check (no auth). Reads redis connection string from Key Vault and tests R/W."""
    load_envs()
    if not KEYVAULT_URI:
        return {"status": "not_configured", "error": "KEYVAULT_URI not set"}
    loop = asyncio.get_event_loop()
    client_id = os.getenv("AZURE_CLIENT_ID")
    if client_id:
        credential = ManagedIdentityCredential(client_id=client_id)
    else:
        credential = ManagedIdentityCredential()

    # Log Key Vault context (non-sensitive)
    logger.info(f"Redis check context: KEYVAULT_URI={'set' if KEYVAULT_URI else 'none'}, REDIS_SECRET_NAME={REDIS_SECRET_NAME}, client_id_set={'yes' if client_id else 'no'}")

    try:
        # Use SecretClient synchronously in thread to avoid blocking event loop
        secret_client = SecretClient(vault_url=KEYVAULT_URI, credential=credential)
        redis_secret = await loop.run_in_executor(None, secret_client.get_secret, REDIS_SECRET_NAME)
        redis_conn = redis_secret.value

        # Parse connection string: hostname:port,password=xxx,ssl=True,abortConnect=False
        parts = redis_conn.split(',')
        host_port = parts[0].split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 6380
        password = None
        ssl_enabled = True
        for part in parts[1:]:
            if part.startswith('password='):
                password = part.split('=', 1)[1]
            elif part.startswith('ssl='):
                ssl_enabled = part.split('=', 1)[1].lower() == 'true'

        # Log non-sensitive Redis context
        logger.info(f"Parsed Redis connection: host={host}, port={port}, ssl={ssl_enabled}, password_set={'yes' if password else 'no'}")

        # Create redis client with short connect/read timeouts
        r = redis.Redis(host=host, port=port, password=password, ssl=ssl_enabled, ssl_cert_reqs=None, decode_responses=True, socket_connect_timeout=5, socket_timeout=5)

        def _sync_redis_check():
            r.ping()
            r.set("health_check", "ok", ex=30)
            val = r.get("health_check")
            if val != "ok":
                raise Exception("Redis read/write test failed")
            return True

        ok = await loop.run_in_executor(None, _sync_redis_check)
        return {"status": "healthy"} if ok else {"status": "unhealthy", "error": "unknown"}

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"Redis check failed: {type(e).__name__}: {e}\n{tb}")
        return {"status": "unhealthy", "error": str(e), "error_type": type(e).__name__, "trace": tb}

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
