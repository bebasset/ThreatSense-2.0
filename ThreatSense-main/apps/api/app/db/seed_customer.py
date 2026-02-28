from sqlmodel import Session, select
from app.db.session import engine
from app.models.tenant import Tenant
from app.models.user import User
from app.core.security import hash_password

def seed_customer():
    with Session(engine) as session:
        tenant_name = "Acme Plumbing LLC"
        email = "owner@acme.local"
        password = "AcmePass123!"

        tenant = session.exec(select(Tenant).where(Tenant.name == tenant_name)).first()
        if not tenant:
            tenant = Tenant(name=tenant_name)
            session.add(tenant)
            session.commit()
            session.refresh(tenant)

        user = session.exec(select(User).where(User.email == email)).first()
        if not user:
            user = User(
                tenant_id=tenant.id,
                email=email,
                password_hash=hash_password(password),
                role="owner",
                is_active=True
            )
            session.add(user)
            session.commit()

        print("Seeded customer:")
        print(" tenant:", tenant.name, tenant.id)
        print(" user:", email)
        print(" pass:", password)

if __name__ == "__main__":
    seed_customer()
