"""Local persistence and versioned migration entry point."""

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from aegis.config import ROOT, Settings


def create_database(settings: Settings, migrate: bool = True) -> tuple[Engine, sessionmaker[Session]]:
    folder = settings.data_dir
    if folder.is_symlink():
        raise ValueError("Data directory must not be a symbolic link")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (folder / "aegis.db").is_symlink():
        raise ValueError("Database must not be a symbolic link")
    os.chmod(folder, 0o700)
    is_sqlite = settings.database_url.startswith("sqlite")
    if is_sqlite:
        engine = create_engine(
            settings.database_url, connect_args={"check_same_thread": False, "timeout": 10}
        )

        @event.listens_for(engine, "connect")
        def setup(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=10000")
    else:
        engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=20)

    if migrate:
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(ROOT / "migrations"))
        config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        if is_sqlite:
            for path in folder.glob("aegis.db*"):
                if path.is_file():
                    os.chmod(path, 0o600)
    return engine, sessionmaker(engine, expire_on_commit=False)


def database_exists(folder: Path, database_url: str | None = None) -> bool:
    if database_url and not database_url.startswith("sqlite"):
        return True
    return (folder / "aegis.db").is_file()
