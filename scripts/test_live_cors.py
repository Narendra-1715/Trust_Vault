import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
api_base = "https://trustvault-api-s6ba.onrender.com/api/v1"

# 1. Test OPTIONS Preflight
print("--- 1. Testing OPTIONS preflight request ---")
opt_req = urllib.request.Request(
    f"{api_base}/auth/login",
    headers={
        "Origin": "https://trustvault-ui.onrender.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,authorization",
        "User-Agent": "Mozilla/5.0"
    },
    method="OPTIONS"
)

try:
    with urllib.request.urlopen(opt_req, timeout=15, context=ctx) as res:
        print("OPTIONS Status:", res.status)
        for h, v in res.headers.items():
            if "access-control" in h.lower() or "cross-origin" in h.lower():
                print(f"  {h}: {v}")
except urllib.error.HTTPError as e:
    print("OPTIONS HTTPError:", e.code, e.headers)
except Exception as e:
    print("OPTIONS Exception:", e)

# 2. Test POST /auth/login
print("\n--- 2. Testing POST login request ---")
post_body = json.dumps({
    "email": "owner_b@trustvault.com",
    "password": "OwnerBPass123!"
}).encode("utf-8")

post_req = urllib.request.Request(
    f"{api_base}/auth/login",
    data=post_body,
    headers={
        "Origin": "https://trustvault-ui.onrender.com",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    },
    method="POST"
)

try:
    with urllib.request.urlopen(post_req, timeout=15, context=ctx) as res:
        print("POST Status:", res.status)
        for h, v in res.headers.items():
            if "access-control" in h.lower() or "cross-origin" in h.lower() or "cookie" in h.lower():
                print(f"  {h}: {v}")
        body = res.read().decode("utf-8")
        print("POST Response Body:", body)
except urllib.error.HTTPError as e:
    print("POST HTTPError:", e.code)
    for h, v in e.headers.items():
        if "access-control" in h.lower() or "cross-origin" in h.lower():
            print(f"  {h}: {v}")
    print("POST Error Body:", e.read().decode("utf-8"))
except Exception as e:
    print("POST Exception:", e)
