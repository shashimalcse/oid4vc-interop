"""vcit teardown hook for ThunderID: remove what setup.py created."""

from __future__ import annotations

import json
import sys

from thunder_admin import ThunderAdmin, log


def remove(admin: ThunderAdmin, cleanup: dict[str, list[str]]) -> None:
    steps = [
        ("definitions", admin.delete_presentation_definition),
        ("apps", admin.delete_app),
        ("users", admin.delete_user),
        ("configurations", admin.delete_credential_configuration),
    ]
    for kind, delete in steps:
        for resource_id in cleanup.get(kind, []):
            try:
                delete(resource_id)
                log(f"removed {kind[:-1]} {resource_id}")
            except Exception as e:  # keep going: one stuck resource must not strand the rest
                log(f"could not remove {kind[:-1]} {resource_id}: {e}")


def main() -> None:
    payload = json.load(sys.stdin)
    remove(ThunderAdmin(), payload.get("setup", {}).get("cleanup", {}))


if __name__ == "__main__":
    main()
