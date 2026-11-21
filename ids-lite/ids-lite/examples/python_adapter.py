"""
Minimal Python adapter (Django / Flask) for ids-lite.

The adapter is a thin client: it sends request metadata to the IDS service
(POST /ids/v1/adapter/evaluate, HMAC-signed) and enforces the returned decision.
Fail-open: if the service is unreachable, the request goes through.
Stdlib only.
"""
import hashlib
import hmac
import json
import os
import time
import urllib.request

IDS_URL = os.environ.get("IDS_URL", "http://127.0.0.1:3000/ids")
IDS_SECRET = os.environ.get("IDS_INGEST_SECRET", "dev-ingest-secret")
TIMEOUT = float(os.environ.get("IDS_TIMEOUT", "0.25"))  # seconds; keep it small


def evaluate(ip, method, path, query="", user_agent="", is_login_failure=False):
    body = json.dumps({
        "ip": ip, "method": method, "path": path, "query": query,
        "user_agent": user_agent, "is_login_failure": is_login_failure,
    })
    ts = str(int(time.time() * 1000))
    sig = "sha256=" + hmac.new(IDS_SECRET.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        IDS_URL + "/v1/adapter/evaluate", data=body.encode(), method="POST",
        headers={"Content-Type": "application/json", "X-IDS-Timestamp": ts, "X-IDS-Signature": sig},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())
    except Exception:
        return {"action": "none", "retry_after": None, "hits": []}  # fail-open


# ---------------- Django ----------------
class IDSMiddleware:
    """settings.MIDDLEWARE = ['path.to.IDSMiddleware', ...]  (put it near the top)"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.http import JsonResponse  # imported lazily so this file works without Django installed

        d = evaluate(
            request.META.get("REMOTE_ADDR", ""), request.method, request.path,
            request.META.get("QUERY_STRING", ""), request.META.get("HTTP_USER_AGENT", ""),
        )
        if d["action"] == "blocked":
            resp = JsonResponse({"error": {"code": "IDS_BLOCKED", "retry_after": d["retry_after"]}}, status=429)
            resp["Retry-After"] = str(d["retry_after"] or 900)
            return resp
        return self.get_response(request)


# ---------------- Flask ----------------
def init_flask(app):
    from flask import jsonify, request

    @app.before_request
    def _ids_guard():
        d = evaluate(request.remote_addr or "", request.method, request.path,
                     request.query_string.decode("utf-8", "ignore"), request.headers.get("User-Agent", ""))
        if d["action"] == "blocked":
            resp = jsonify(error={"code": "IDS_BLOCKED", "retry_after": d["retry_after"]})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(d["retry_after"] or 900)
            return resp
