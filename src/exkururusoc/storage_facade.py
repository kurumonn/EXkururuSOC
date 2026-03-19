from __future__ import annotations

from typing import Any

from .storage import SocStorage


class SocReadStorage:
    def __init__(self, storage: SocStorage) -> None:
        self._storage = storage

    def __getattr__(self, name: str) -> Any:
        return getattr(self._storage, name)


class SocWriteStorage(SocReadStorage):
    pass
