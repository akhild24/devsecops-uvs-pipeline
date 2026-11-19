import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Allow `import scoring`, `import models`, etc. from the backend/ package root
# when running pytest from either backend/ or the repo root.
BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture(autouse=True)
def _isolated_sqlite_db(monkeypatch, tmp_path):
    """Use a fresh SQLite file for each test to avoid history bleed between tests."""
    db_path = tmp_path / "test_devsecops.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import database
    import models

    database.engine.dispose()
    database.engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    database.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=database.engine)
    models.Base.metadata.create_all(bind=database.engine)

    yield

    database.engine.dispose()
