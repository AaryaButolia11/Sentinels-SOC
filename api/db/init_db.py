"""
db/init_db.py
=============
SQLAlchemy engine + session bootstrap. This module was referenced across
the API layer (main.py, routes/alerts.py, routes/feedback.py) but was
missing from the original drop -- without it the app could not start.

It exposes four things the rest of the code imports:

  - ``engine``        the SQLAlchemy engine (SQLite file by default)
  - ``SessionLocal``  a configured Session factory (used directly in
                      background tasks that manage their own lifecycle)
  - ``get_db``        a FastAPI dependency that yields a request-scoped
                      Session and always closes it
  - ``init_db``       create_all() for every table declared in models.py

The database URL is read from the ``SOC_DATABASE_URL`` environment
variable so the same code runs against SQLite locally and Postgres in a
container, with no code change. SQLite needs ``check_same_thread=False``
because the replay loop touches the DB from a background task thread.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base

# Default to a file-based SQLite DB living next to this package so the
# demo is zero-config. Override with SOC_DATABASE_URL for Postgres/MySQL.
DEFAULT_SQLITE_PATH = os.path.join(os.path.dirname(__file__), "soc.db")
DATABASE_URL = os.environ.get(
    "SOC_DATABASE_URL", f"sqlite:///{DEFAULT_SQLITE_PATH}"
)
# Render (and Heroku-style providers) hand out "postgres://" URLs, but
# SQLAlchemy 1.4+ only recognizes the "postgresql://" dialect prefix and
# raises NoSuchModuleError on the old form. Normalize it here so the same
# env var works whether it comes from Render, a manual Postgres, or SQLite.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQLite-specific connect args; harmless to compute, only applied when
# the URL is SQLite so Postgres/MySQL users aren't affected.
_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    future=True,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
)


def init_db() -> None:
    """Create all tables declared on ``Base.metadata`` if they don't
    already exist. Safe to call repeatedly (idempotent)."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency: yields a Session and guarantees it is closed,
    even if the request handler raises."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()