from fastapi import FastAPI
from app.routers.health import router as health_router
from app.routers.auth import router as auth_router
from app.routers.assets import router as assets_router
from app.routers.scans import router as scans_router
from app.routers.soc import router as soc_router
from app.routers.admin_onboarding import router as admin_onboarding_router
from app.routers.invite_claim import router as invite_claim_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ThreatSense API")

# ✅ CORS: allow your Vercel frontend(s) to call this API
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    # ✅ Replace with your real Vercel domain(s):
    "https://threat-sense-2-0.vercel.app/",
    # If you add a custom domain later:
    # "https://yourdomain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app = FastAPI(title="Threat Sense API")

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(assets_router)
app.include_router(scans_router)
app.include_router(soc_router)
app.include_router(admin_onboarding_router)
app.include_router(invite_claim_router)
