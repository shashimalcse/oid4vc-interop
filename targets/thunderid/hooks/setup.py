"""vcit setup hook for ThunderID: provision what the selected test profiles need.

Reads the vcit context (JSON) on stdin, prints the values target.yaml references as ${setup.*}.
Everything it creates is listed under `cleanup` for teardown.py.
"""

from __future__ import annotations

import json
import os
import sys

from thunder_admin import ThunderAdmin, log

USER_CLAIMS = {"given_name": "Ada", "family_name": "Lovelace", "email": "ada@example.org"}
TRUST_ANCHOR = "vcit"  # openid4vp.trusted_anchors entry in docker/deployment.yaml (the vcit test CA)
UNUSED = "not-provisioned"


def main() -> None:
    ctx = json.load(sys.stdin)
    profiles = set(ctx["profiles"])
    tag = f"vcit-{ctx['run_id'][-4:]}"
    admin = ThunderAdmin()
    cleanup: dict = {"apps": [], "configurations": [], "users": [], "definitions": [], "resource_servers": []}
    out: dict = {
        "credential_configuration_id": UNUSED,
        "clients": [{"client_id": UNUSED}, {"client_id": UNUSED}],
        "wallet_client": {"client_id": UNUSED},
        "user": {"username": UNUSED, "password": UNUSED},
        "presentation_definitions": {"suite": UNUSED, "wallet": UNUSED},
        "cleanup": cleanup,
    }
    try:
        if profiles & {"vci-base", "vci-haip", "wallet-interop"}:
            handle = f"{tag}-badge"
            vct = f"urn:vcit:{handle}"
            cfg = admin.create_credential_configuration(handle, vct, list(USER_CLAIMS))
            cleanup["configurations"].append(cfg["id"])
            out["credential_configuration_id"] = handle
            log(f"credential configuration {handle}")

            if os.environ.get("THUNDER_DEFAULT_RESOURCE_SERVER") == "1":
                # Opt-in workaround for the scope/resource gap (see baseline): bind tokens for
                # requests without an RFC 8707 resource to a per-run resource server, so the rest
                # of issuance can be tested. The previous setting is restored on teardown.
                cleanup["previous_default_resource_server"] = admin.get_default_resource_server()
                rs = admin.create_resource_server(f"{tag}-issuer", f"urn:vcit:{tag}:credential-issuer")
                cleanup["resource_servers"].append(rs)
                admin.set_default_resource_server({"resourceServerId": rs})
                log(f"defaultResourceServer -> {tag}-issuer (workaround)")

            username = f"{tag}-user"
            password = os.environ.get("TEST_USER_PASSWORD", "Vcit-Test-Pass-1")
            cleanup["users"].append(admin.create_user(username, password, USER_CLAIMS))
            out["user"] = {"username": username, "password": password}
            log(f"user {username}")

            callbacks = list(ctx["suite"]["callbacks"].values())
            if callbacks:
                for i, key in enumerate(ctx["clients"]):
                    client_id = f"{tag}-suite-client{i + 1}"
                    cleanup["apps"].append(admin.create_wallet_app(client_id, client_id, callbacks, key["public_jwk"], [handle]))
                    out["clients"][i] = {"client_id": client_id}
                    log(f"application {client_id}")

            if "wallet-interop" in profiles:
                client_id = f"{tag}-wallet"
                cleanup["apps"].append(admin.create_wallet_app(
                    client_id, client_id, [ctx["wallet"]["redirect_uri"]], ctx["wallet_client"]["public_jwk"], [handle]))
                out["wallet_client"] = {"client_id": client_id}
                # ThunderID trusts issuers by x5c chain only; its own credentials chain to its
                # signing certificate, which is not a configured anchor, so issuer trust is off here.
                cleanup["definitions"].append(admin.create_presentation_definition(
                    f"{tag}-wallet", vct, list(USER_CLAIMS), trust=None))
                out["presentation_definitions"]["wallet"] = f"{tag}-wallet"
                log(f"application and presentation definition {tag}-wallet")

        if profiles & {"vp-base", "vp-haip", "wallet-vp"}:
            pid = ctx["suite_credential"]
            cleanup["definitions"].append(admin.create_presentation_definition(
                f"{tag}-suite", pid["vct"], pid["claims"], trust=TRUST_ANCHOR))
            out["presentation_definitions"]["suite"] = f"{tag}-suite"
            log(f"presentation definition {tag}-suite (trusts the vcit test CA)")
    except Exception:
        from teardown import remove

        remove(admin, cleanup)
        raise

    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
