from fastapi import FastAPI
from app.routers.health import router as health_router
from app.routers.auth import router as auth_router
from app.routers.assets import router as assets_router
from app.routers.scans import router as scans_router
from app.routers.soc import router as soc_router
from app.routers.admin_onboarding import router as admin_onboarding_router
from app.routers.invite_claim import router as invite_claim_router

app = FastAPI(title="Threat Sense API")

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(assets_router)
app.include_router(scans_router)
app.include_router(soc_router)
app.include_router(admin_onboarding_router)
app.include_router(invite_claim_router)
