from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.core.db import init_db
from src.router import fileTransfer ,audit_log_router
from src.router import authentication
from src.router import DepartmentRouter
from src.router import users
from src.router import user_me_info
# Global data storage
data = {}
drafts = []
courses = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Load JSON data
    init_db()
    
    
    print("✅ Data loaded successfully")
    yield
    # Shutdown: Add cleanup code here if needed
    print("👋 Shutting down...")

app = FastAPI(
    title="ClassManager Mock API",
    summary="Mock API for ClassManager application",
    openapi_url="/openapi.json",
    docs_url="/api/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(fileTransfer.router, prefix="/api", tags=["file"])
app.include_router(authentication.router, prefix="/api/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(user_me_info.router, prefix="/api/user/me/info", tags=["user/me/info"])
app.include_router(audit_log_router.router, prefix="/api", tags=["auditlog"])

app.include_router(DepartmentRouter.router, prefix="/api", tags=["dep"])
@app.get("/", tags=["Health"])
async def root():
    return {"status": "ok", "message": "ClassManager Mock API is running"}

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok"}