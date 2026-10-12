"""Temporary browser-QA environment, with a synthetic account and local target.

No production credentials or persistent operator database are used.
"""

import argparse
import tempfile
import threading
from pathlib import Path

import uvicorn

from aegis.api import create_app
from aegis.auth import provision_owner
from aegis.config import Settings
from fixtures.safe_targets.server import create_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8905)
    parser.add_argument("--target-port", type=int, default=8906)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aegis-ui-qa-") as folder:
        settings = Settings(Path(folder), args.port)
        app = create_app(settings)
        with app.state.sessions() as db:
            provision_owner(db, "qaoperator", "Synthetic-UI-test-only-791!")
            db.commit()
        fixture = create_server(args.target_port)
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        try:
            print(
                f"Synthetic QA UI: {settings.origin}; fixture: http://127.0.0.1:{fixture.server_port}/",
                flush=True,
            )
            uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False, log_level="warning")
        finally:
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=2)
            app.state.engine.dispose()


if __name__ == "__main__":
    main()
