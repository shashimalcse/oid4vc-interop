"""vcit setup hook for WSO2 IS: provision what the selected test profiles need.

Reads the vcit context (JSON) on stdin, prints the values target.yaml references as
${setup.*} on stdout. Everything it creates is listed under `cleanup` for teardown.py.
"""

from __future__ import annotations

import json
import os
import sys

from wso2is_admin import ISAdmin, b64_pem, log

USER_CLAIMS = {"given_name": "Ada", "family_name": "Lovelace", "email": "ada@example.org"}
UNUSED = "not-provisioned"  # for values a test profile in this run does not need


def main() -> None:
    ctx = json.load(sys.stdin)
    profiles = set(ctx["profiles"])
    tag = f"vcit-{ctx['run_id'][-4:]}"
    admin = ISAdmin()
    cleanup: dict[str, list[str]] = {"apps": [], "templates": [], "users": [], "definitions": []}
    out: dict = {
        "credential_configuration_id": UNUSED,
        "clients": [{"client_id": UNUSED}, {"client_id": UNUSED}],
        "wallet_client": {"client_id": UNUSED},
        "public_client": {"client_id": UNUSED},
        "user": {"username": UNUSED, "password": UNUSED},
        "presentation_definitions": {"suite": UNUSED, "wallet": UNUSED},
        "credential_trust_anchor_pem": admin.signing_cert_pem(),
        "cleanup": cleanup,
    }
    public = os.environ["IS_PUBLIC_URL"].rstrip("/")

    try:
        if profiles & {"vci-base", "vci-haip", "wallet-interop"}:
            identifier = f"{tag}-EmployeeBadge"
            template = admin.create_vc_template(identifier, list(USER_CLAIMS))
            cleanup["templates"].append(template["id"])
            resource = admin.api_resource_id(identifier)
            out["credential_configuration_id"] = identifier
            log(f"VC template {identifier}")

            username = f"{tag}-user"
            password = os.environ.get("TEST_USER_PASSWORD", "Vcit-Test-Pass-1")
            cleanup["users"].append(admin.create_user(username, password, USER_CLAIMS))
            out["user"] = {"username": username, "password": password}
            log(f"user {username}")

            callbacks = list(ctx["suite"]["callbacks"].values())
            if callbacks:
                for i, key in enumerate(ctx["clients"]):
                    app = admin.create_app(f"{tag}-suite-client{i + 1}", callbacks, key["cert_pem"])
                    cleanup["apps"].append(app["id"])
                    admin.authorize_api(app["id"], resource, identifier)
                    out["clients"][i] = {"client_id": app["client_id"]}
                    log(f"application {tag}-suite-client{i + 1}")

            if "wallet-interop" in profiles:
                app = admin.create_app(f"{tag}-wallet", [ctx["wallet"]["redirect_uri"]], ctx["wallet_client"]["cert_pem"])
                cleanup["apps"].append(app["id"])
                admin.authorize_api(app["id"], resource, identifier)
                out["wallet_client"] = {"client_id": app["client_id"]}
                log(f"application {tag}-wallet")
                public = admin.create_public_app(f"{tag}-public-wallet", [ctx["wallet"]["redirect_uri"]])
                cleanup["apps"].append(public["id"])
                admin.authorize_api(public["id"], resource, identifier)
                out["public_client"] = {"client_id": public["client_id"]}
                log(f"application {tag}-public-wallet (public client)")

                # IS issues vct = template identifier, iss = the credential issuer URL, signed
                # with its primary key (no x5c), so it is trusted by certificate.
                pd = admin.create_presentation_definition(f"{tag}-wallet", identifier, list(USER_CLAIMS))
                cleanup["definitions"].append(pd["id"])
                admin.trust_issuer(pd["id"], {
                    "keySourceType": "pem",
                    "issuerUrl": f"{public}/oid4vci",
                    "keySource": b64_pem(out["credential_trust_anchor_pem"]),
                })
                out["presentation_definitions"]["wallet"] = f"{tag}-wallet"
                log(f"presentation definition {tag}-wallet")

        if profiles & {"vp-base", "vp-haip", "wallet-vp"}:
            pid = ctx["suite_credential"]
            pd = admin.create_presentation_definition(f"{tag}-suite", pid["vct"], pid["claims"])
            cleanup["definitions"].append(pd["id"])
            admin.trust_issuer(pd["id"], {"keySourceType": "x5c", "keySource": b64_pem(ctx["test_ca_pem"])})
            out["presentation_definitions"]["suite"] = f"{tag}-suite"
            log(f"presentation definition {tag}-suite")
    except Exception:
        # Leave nothing behind when setup fails half way; vcit only tears down a setup that succeeded.
        from teardown import remove

        remove(admin, cleanup)
        raise

    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
