import asyncio

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from config import settings
from database.connection import close_mongo_connection, connect_to_mongo
from utils.rate_limit import InMemoryRateLimiter

from api.upload import router as upload_router
from api.analyze import router as analyze_router
from api.dashboard import router as dashboard_router
from api.reports import router as reports_router
from api.iocs import router as iocs_router
from api.auth import router as auth_router
from api.search import router as search_router
from api.auth import get_current_user

app = FastAPI(title=settings.APP_NAME, version=settings.VERSION)
app.middleware("http")(InMemoryRateLimiter())

allowed_origins = [origin.strip() for origin in settings.ALLOWED_ORIGINS.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

protected = [Depends(get_current_user)]

app.include_router(upload_router, prefix="/api/v1", dependencies=protected)
app.include_router(analyze_router, prefix="/api/v1", dependencies=protected)
app.include_router(dashboard_router, prefix="/api/v1", dependencies=protected)
app.include_router(reports_router, prefix="/api/v1", dependencies=protected)
app.include_router(iocs_router, prefix="/api/v1", dependencies=protected)
app.include_router(auth_router, prefix="/api/v1")
app.include_router(search_router, prefix="/api/v1", dependencies=protected)


@app.on_event("startup")
async def startup():
    logger.info(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    await connect_to_mongo()


@app.on_event("shutdown")
async def shutdown():
    logger.info("Shutting down...")
    await close_mongo_connection()


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "version": settings.VERSION}


@app.get("/api/v1/health/tools")
async def health_tools():
    tools = {"jadx": False, "apktool": False, "aapt": False}
    for tool in tools:
        try:
            proc = await asyncio.create_subprocess_exec(
                tool,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            tools[tool] = proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError):
            pass
        except Exception:
            pass
    return {"status": "ok", "tools": tools}
