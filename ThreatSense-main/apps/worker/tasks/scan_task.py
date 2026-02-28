import os, json
from datetime import datetime, timedelta
from celery import shared_task
from sqlmodel import Session, create_engine, select
from worker import celery_app
from plugins.nmap_stub import NmapStub
from plugins.nuclei_scan import NucleiScan
from plugins.soc_rules import SocRules

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

PLUGINS = {
    "nmap_stub": NmapStub(),
    "nuclei_scan": NucleiScan(),
    "soc_rules": SocRules(),
}

@shared_task(name="scan.run")
def run_scan(scan_id: str):
    from app_models import ScanRun, Asset, Finding  # loaded via local file below

    with Session(engine) as session:
        scan = session.exec(select(ScanRun).where(ScanRun.id == scan_id)).first()
        if not scan:
            return

        asset = session.exec(select(Asset).where(Asset.id == scan.asset_id)).first()
        if not asset:
            scan.status = "failed"
            scan.error_message = "Asset not found"
            session.add(scan)
            session.commit()
            return

        if scan.status not in ("queued", "running"):
            return

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        session.add(scan)
        session.commit()

        try:
            params = json.loads(scan.parameters_json or "{}")
            plugin = PLUGINS.get(scan.plugin)
            if not plugin:
                raise RuntimeError(f"Unknown plugin: {scan.plugin}")

            # If SOC scan, fetch events from DB for the time window + source
            if scan.plugin == "soc_rules":
                from app_models import Event  # mirror model above
                window_minutes = int(params.get("window_minutes") or 15)
                source = params.get("source") or asset.value  # asset.value is the log source
                cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)

                rows = session.exec(
                    select(Event).where(
                        Event.tenant_id == scan.tenant_id,
                        Event.source == source,
                        Event.ts >= cutoff
                    ).order_by(Event.ts.desc()).limit(5000)
                ).all()

                # Convert DB rows into normalized event dicts the plugin expects
                params["events"] = [{
                    "ts": r.ts.isoformat() + "Z",
                    "source": r.source,
                    "event_type": r.event_type,
                    "user": r.user,
                    "ip": r.ip,
                    "hostname": r.hostname,
                    "raw": json.loads(r.raw_json or "{}"),
                } for r in rows]

            result = plugin.run(asset.kind, asset.value, params)

            
            # write findings
            for f in result.findings:
                finding = Finding(
                    tenant_id=scan.tenant_id,
                    scan_run_id=scan.id,
                    asset_id=asset.id,
                    title=f["title"],
                    severity=f.get("severity", "low"),
                    category=f.get("category", "general"),
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                    cve=f.get("cve"),
                    cvss=f.get("cvss"),
                )
                session.add(finding)

            scan.status = "done"
            scan.finished_at = datetime.utcnow()
            scan.artifact_path = result.artifact_path
            session.add(scan)
            session.commit()

        except Exception as e:
            scan.status = "failed"
            scan.finished_at = datetime.utcnow()
            scan.error_message = str(e)
            session.add(scan)
            session.commit()

# ---- Minimal local “model mirror” to avoid circular import in this snippet ----
# In your real repo, you’ll make these shared (packages/common) or install api as a lib.
from sqlmodel import SQLModel, Field

class ScanRun(SQLModel, table=True):
    id: str = Field(primary_key=True)
    tenant_id: str
    asset_id: str
    scan_type: str
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    requested_by_user_id: str
    approved_by_user_id: str | None = None
    requires_approval: bool = False
    plugin: str
    parameters_json: str
    artifact_path: str | None = None
    error_message: str | None = None

class Asset(SQLModel, table=True):
    id: str = Field(primary_key=True)
    tenant_id: str
    kind: str
    value: str
    verified: bool

class Finding(SQLModel, table=True):
    id: str | None = Field(default=None, primary_key=True)
    tenant_id: str
    scan_run_id: str
    asset_id: str
    title: str
    severity: str
    category: str
    evidence: str
    remediation: str
    cve: str | None = None
    cvss: float | None = None

class Event(SQLModel, table=True):
    id: str = Field(primary_key=True)
    tenant_id: str
    ts: datetime
    source: str
    event_type: str
    user: str | None = None
    ip: str | None = None
    hostname: str | None = None
    raw_json: str

# Expose to the import above
app_models = type("app_models", (), {"ScanRun": ScanRun, "Asset": Asset, "Finding": Finding, "Event": Event})
