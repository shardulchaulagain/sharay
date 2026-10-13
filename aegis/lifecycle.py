"""Cooperative POSIX child shutdown when its explicit owner pipe closes."""

import os
import select
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager


@contextmanager
def watch_parent_stdin(enabled: bool, request_stop: Callable[[], None]) -> Iterator[None]:
    if not enabled:
        yield
        return
    try:
        descriptor = os.dup(0)
    except OSError as exc:
        raise ValueError("Parent lifetime channel is unavailable") from exc
    try:
        if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
            raise ValueError("Parent lifetime channel must be a pipe")
        stopped = threading.Event()

        def watch():
            while not stopped.is_set():
                try:
                    if not select.select([descriptor], [], [], 0.1)[0]:
                        continue
                    # The owner never writes data. EOF, unexpected data or a
                    # broken channel all request shutdown, not tool actions.
                    os.read(descriptor, 1)
                except (OSError, ValueError):
                    pass
                request_stop()
                return

        thread = threading.Thread(target=watch, name="sharay-parent-lifetime", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join()
    finally:
        # Leave Python's stdin alone; the watcher owns only this duplicate.
        os.close(descriptor)
