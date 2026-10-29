"""
Database Session Management
SQLAlchemy engine, session factory, and FastAPI dependency.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import logging

from app.config import settings

logger = logging.getLogger("thelix.database")

# Handle SQLite vs PostgreSQL arguments
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
Base = declarative_base()


def reconcile_sqlite_schema(bind_engine):
    """
    Safely adds missing columns for local SQLite databases without requiring manual migrations.
    In production/staging, PostgreSQL migrations handle schema updates via 003_durable_scan_tasks.sql.
    """
    if bind_engine.dialect.name != "sqlite":
        return
    from sqlalchemy import text
    with bind_engine.connect() as conn:
        try:
            res = conn.execute(text("PRAGMA table_info(scan_tasks)")).fetchall()
            existing_cols = {r[1] for r in res}
            if existing_cols:
                if "lease_owner" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_tasks ADD COLUMN lease_owner VARCHAR(64)"))
                if "lease_expires_at" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_tasks ADD COLUMN lease_expires_at DATETIME"))
                if "attempt_count" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_tasks ADD COLUMN attempt_count INTEGER DEFAULT 0 NOT NULL"))
                if "max_attempts" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_tasks ADD COLUMN max_attempts INTEGER DEFAULT 3 NOT NULL"))
                if "payload_json" not in existing_cols:
                    conn.execute(text("ALTER TABLE scan_tasks ADD COLUMN payload_json JSON DEFAULT '{}' NOT NULL"))
                conn.commit()
        except Exception as e:
            logger.warning(f"SQLite schema reconciliation: {e}")


# Run initial table creation & SQLite column reconciliation
Base.metadata.create_all(bind=engine)
reconcile_sqlite_schema(engine)


def get_db():
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
