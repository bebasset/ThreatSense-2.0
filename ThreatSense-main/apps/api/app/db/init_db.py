from sqlmodel import SQLModel, Session, select
from app.db.session import engine
from app.models.tenant import Tenant
from app.models.user import User
from app.core.security import hash_password
from app.models.event import Event
from app.models.invite import Invite  # noqa: F401

def init():
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        # default tenant
        tenant = session.exec(select(Tenant).where(Tenant.name == "ThreatSense Demo")).first()
        if not tenant:
            tenant = Tenant(name="ThreatSense Demo")
            session.add(tenant)
            session.commit()
            session.refresh(tenant)

        # default owner
        email = "bassette.secure@gmail.com"
        user = session.exec(select(User).where(User.email == email)).first()
        if not user:
            user = User(
                tenant_id=tenant.id,
                email=email,
                password_hash=hash_password("Belbass2004$$$"),
                role="owner",
                is_active=True,
                is_platform_admin=True,  # NEW
             )
            session.add(user)
            session.commit()


if __name__ == "__main__":
    init()
