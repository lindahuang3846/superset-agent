import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sessions.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from app.models import SessionRecord  # noqa: F401 — ensure model is registered
    Base.metadata.create_all(bind=engine)

    # Migrate existing database to add severity columns if they don't exist
    with engine.connect() as conn:
        try:
            # Check if severity_score column exists
            result = conn.execute(text("PRAGMA table_info(sessions)")).fetchall()
            columns = [row[1] for row in result]

            if "severity_score" not in columns:
                conn.execute(text("ALTER TABLE sessions ADD COLUMN severity_score INTEGER DEFAULT 0"))
                conn.commit()

            if "severity_label" not in columns:
                conn.execute(text("ALTER TABLE sessions ADD COLUMN severity_label TEXT DEFAULT 'Low'"))
                conn.commit()

            if "vulnerability_count" not in columns:
                conn.execute(text("ALTER TABLE sessions ADD COLUMN vulnerability_count INTEGER DEFAULT 1"))
                conn.commit()
        except Exception as e:
            print(f"Migration warning: {e}")
