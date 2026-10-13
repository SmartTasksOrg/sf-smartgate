"""Make a killed or refused action leave nothing half-done, where that is possible.

- ``atomic_write(path, data)``: write to a temporary file in the same folder, flush, fsync, then
  ``os.replace`` (atomic on POSIX and Windows for one file). Readers see the old file or the new one.
- ``staged_write(path)``: the same, as a context manager; the file is replaced only if the block ends
  without an exception (a kill raises Killed, so nothing is written).
- ``transaction(begin, commit, rollback)``: run a block inside a database transaction: commit at the
  end, roll back on any exception (including Killed).
- ``Compensations``: for external API calls, which cannot be rolled back, register an undo step after
  each call that succeeded; on failure they run in reverse order. This is best effort: an API that has
  already acted (a sent message, a payment) may not be undoable, and SmartGate cannot change that.
"""
from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager


def atomic_write(path: str, data, mode: str = 'w', encoding: str | None = 'utf-8') -> None:
    with staged_write(path, mode, encoding) as f:
        f.write(data)


@contextmanager
def staged_write(path: str, mode: str = 'w', encoding: str | None = 'utf-8'):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix='.smartgate-', suffix='.tmp', dir=d)
    ok = False
    try:
        with os.fdopen(fd, mode, encoding=None if 'b' in mode else encoding) as f:
            yield f
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        ok = True
    finally:
        if not ok:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


@contextmanager
def transaction(begin, commit, rollback):
    begin()
    try:
        yield
    except BaseException:
        rollback()
        raise
    else:
        commit()


class Compensations:
    def __init__(self):
        self._undo = []
        self.errors: list[Exception] = []

    def add(self, undo, *args, **kwargs):
        self._undo.append((undo, args, kwargs))

    def run(self):
        while self._undo:
            fn, a, k = self._undo.pop()
            try:
                fn(*a, **k)
            except Exception as e:  # keep undoing the rest
                self.errors.append(e)

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        if et is not None:
            self.run()
        else:
            self._undo.clear()
        return False
