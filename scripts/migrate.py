#!/usr/bin/env python3
from __future__ import annotations

from exkururusoc.config import load_settings
from exkururusoc.storage import SocStorage


def main() -> None:
    settings = load_settings()
    storage = SocStorage(settings.db_path)
    print(f"ok: migrated -> {storage.db_path}")


if __name__ == "__main__":
    main()
