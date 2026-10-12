"""Fixed values shared by the framework, the hooks contract and the docs."""

# Where Wallet2 is sent after authorization. Nothing listens there: the browser intercepts it.
WALLET_REDIRECT_URI = "https://wallet.vcit.invalid/cb"

# The conformance suite, acting as a wallet, presents an EUDI PID SD-JWT with these
# selectively disclosable claims. A verifier under test must request (at least) these.
PID_VCT = "urn:eudi:pid:1"
PID_CLAIMS = ["given_name", "family_name"]
PID_FORMAT = "dc+sd-jwt"

# The PID vcit itself issues to Wallet2 for wallet-vp (signed by the run's test CA, like the
# suite's). Values follow the EUDI PID sample data.
PID_SAMPLE = {"given_name": "Erika", "family_name": "Mustermann"}
PID_ISSUER = "https://pid-issuer.vcit.invalid"

# Issuer value of the wallet attestations the suite signs in the HAIP VCI plan.
ATTESTER_ISSUER = "https://attester.vcit.invalid"
