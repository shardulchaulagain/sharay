"""Explicit local-only runtime configuration."""

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    port: int = 8765
    session_seconds: int = 3600
    start_worker: bool = True

    @property
    def database_url(self) -> str:
        env_url = os.environ.get("SHARAY_DATABASE_URL", os.environ.get("DATABASE_URL"))
        if env_url:
            return env_url
        return f"sqlite:///{self.data_dir / 'aegis.db'}"

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @classmethod
    def from_env(cls) -> "Settings":
        folder = Path(
            os.environ.get("SHARAY_DATA_DIR", os.environ.get("AEGIS_DATA_DIR", str(ROOT / ".aegis")))
        )
        port = int(os.environ.get("SHARAY_PORT", os.environ.get("AEGIS_PORT", "8765")))
        if not 1024 <= port <= 65535:
            raise ValueError("SHARAY_PORT must be between 1024 and 65535")
        return cls(folder.absolute(), port)
