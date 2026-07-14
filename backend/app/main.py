from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CyberVault API",
    description="Cyber Security Platform",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ضع الراوترات هنا فقط
app.include_router(auth_router)
app.include_router(users_router)

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "operational",
        "version": "1.0.0",
        "platform": "CyberVault"
    }