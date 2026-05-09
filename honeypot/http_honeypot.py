#!/usr/bin/env python3
"""
HTTP Honeypot using Flask.
Serves realistic fake admin/login pages and logs all HTTP requests to JSON lines.
"""

from datetime import datetime
import json
import logging
from pathlib import Path
from string import Template

from flask import Flask, make_response, request

# Flask app configuration
app = Flask(__name__)

# Runtime configuration
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
LOG_FILE = Path("logs/http_honeypot.json")

# Ensure logs directory exists
LOG_FILE.parent.mkdir(exist_ok=True)

# General logger for operational messages
logging.basicConfig(
    filename="logs/honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Realistic HTML templates for common attack targets
TEMPLATES = {
    "/admin": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Admin Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: Arial, sans-serif; background: #f4f6f9; margin: 0; }
    .card { max-width: 420px; margin: 80px auto; background: #fff; border-radius: 8px; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
    .card header { background: #1f2937; color: #fff; padding: 18px 24px; font-size: 18px; border-radius: 8px 8px 0 0; }
    .card form { padding: 24px; }
    label { display: block; margin-bottom: 6px; color: #4b5563; }
    input { width: 100%; padding: 10px 12px; margin-bottom: 14px; border: 1px solid #d1d5db; border-radius: 6px; }
    button { width: 100%; padding: 10px 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; cursor: pointer; }
    .help { font-size: 12px; color: #6b7280; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <header>Administrator Login</header>
    <form method="post">
      <label for="user">Username</label>
      <input id="user" name="username" type="text" autocomplete="username" />
      <label for="pass">Password</label>
      <input id="pass" name="password" type="password" autocomplete="current-password" />
      <button type="submit">Sign in</button>
    </form>
    <p class="help">Authorized personnel only.</p>
  </div>
</body>
</html>""",
    "/login": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Secure Portal</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: "Segoe UI", Arial, sans-serif; background: #e5e7eb; margin: 0; }
    .panel { max-width: 460px; margin: 70px auto; background: #fff; border-radius: 10px; padding: 26px; box-shadow: 0 8px 20px rgba(0,0,0,0.08); }
    h1 { margin: 0 0 12px; font-size: 22px; color: #111827; }
    label { display: block; margin: 12px 0 6px; color: #374151; }
    input { width: 100%; padding: 10px; border: 1px solid #cbd5f5; border-radius: 6px; }
    button { margin-top: 18px; width: 100%; padding: 10px; border: none; border-radius: 6px; background: #0f766e; color: #fff; }
    .foot { margin-top: 16px; font-size: 12px; color: #6b7280; text-align: center; }
  </style>
</head>
<body>
  <div class="panel">
    <h1>Member Login</h1>
    <form method="post">
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" autocomplete="username" />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" />
      <button type="submit">Log in</button>
    </form>
    <div class="foot">Session will expire after 10 minutes of inactivity.</div>
  </div>
</body>
</html>""",
    "/wp-admin": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>WordPress &rsaquo; Log In</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { background: #f1f1f1; font-family: Arial, sans-serif; }
    #login { width: 320px; padding: 8% 0 0; margin: auto; }
    form { background: #fff; padding: 26px; box-shadow: 0 1px 3px rgba(0,0,0,0.13); }
    label { display: block; margin-bottom: 6px; color: #555d66; }
    input { width: 100%; padding: 8px; margin-bottom: 14px; border: 1px solid #ccd0d4; }
    button { width: 100%; padding: 8px; background: #2271b1; color: #fff; border: none; }
  </style>
</head>
<body>
  <div id="login">
    <form method="post">
      <label for="user_login">Username or Email Address</label>
      <input type="text" name="log" id="user_login" />
      <label for="user_pass">Password</label>
      <input type="password" name="pwd" id="user_pass" />
      <button type="submit">Log In</button>
    </form>
  </div>
</body>
</html>""",
    "/phpmyadmin": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>phpMyAdmin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: Tahoma, sans-serif; background: #e9ecef; }
    .box { width: 380px; margin: 80px auto; background: #fff; padding: 24px; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    h1 { font-size: 20px; margin-bottom: 12px; }
    input { width: 100%; padding: 9px; margin-bottom: 12px; border: 1px solid #cbd3da; border-radius: 4px; }
    button { width: 100%; padding: 9px; background: #4e73df; color: #fff; border: none; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Welcome to phpMyAdmin</h1>
    <form method="post">
      <input name="pma_username" type="text" placeholder="Username" />
      <input name="pma_password" type="password" placeholder="Password" />
      <button type="submit">Go</button>
    </form>
  </div>
</body>
</html>""",
    "/config": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>System Configuration</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: Arial, sans-serif; background: #f8fafc; margin: 0; }
    .wrapper { max-width: 720px; margin: 40px auto; background: #fff; padding: 26px; border-radius: 8px; }
    h2 { margin-top: 0; }
    label { display: block; margin: 12px 0 6px; color: #4b5563; }
    input { width: 100%; padding: 8px; border: 1px solid #e5e7eb; border-radius: 4px; }
    .row { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
    .hint { font-size: 12px; color: #6b7280; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="wrapper">
    <h2>Configuration Manager</h2>
    <form method="post">
      <div class="row">
        <div>
          <label for="host">Database Host</label>
          <input id="host" name="db_host" value="db.internal.local" />
        </div>
        <div>
          <label for="port">Database Port</label>
          <input id="port" name="db_port" value="5432" />
        </div>
      </div>
      <label for="apikey">Service API Key</label>
      <input id="apikey" name="api_key" value="************" />
      <label for="timezone">Timezone</label>
      <input id="timezone" name="timezone" value="UTC" />
    </form>
    <div class="hint">Changes are audited and require admin approval.</div>
  </div>
</body>
</html>""",
    "/.env": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Environment Viewer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: "Courier New", monospace; background: #111827; color: #e5e7eb; }
    .panel { max-width: 640px; margin: 40px auto; background: #1f2937; padding: 20px; border-radius: 8px; }
    .line { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #374151; }
    .muted { color: #9ca3af; }
  </style>
</head>
<body>
  <div class="panel">
    <div class="line"><span>APP_ENV</span><span class="muted">production</span></div>
    <div class="line"><span>DB_HOST</span><span class="muted">db.internal.local</span></div>
    <div class="line"><span>DB_PASSWORD</span><span class="muted">********</span></div>
    <div class="line"><span>JWT_SECRET</span><span class="muted">********</span></div>
    <div class="line"><span>REDIS_URL</span><span class="muted">redis://cache:6379</span></div>
  </div>
</body>
</html>"""
}

# Generic fallback template for any other path
GENERIC_TEMPLATE = Template("""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Secure Service Gateway</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: Arial, sans-serif; background: #f3f4f6; margin: 0; }
    .shell { max-width: 720px; margin: 50px auto; background: #fff; padding: 24px; border-radius: 10px; }
    h1 { margin-top: 0; color: #111827; }
    p { color: #4b5563; line-height: 1.5; }
    .path { font-family: "Courier New", monospace; background: #f9fafb; padding: 6px 8px; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="shell">
    <h1>Service Portal</h1>
    <p>Welcome to the internal service gateway. Access is restricted to authorized users.</p>
    <p>Requested resource: <span class="path">$path</span></p>
  </div>
</body>
</html>""")


def _normalize_path(path_value):
    """
    Normalize request paths for template matching.
    """
    if path_value != "/" and path_value.endswith("/"):
        path_value = path_value[:-1]
    return path_value.lower()


def _get_client_ip():
    """
    Extract client IP with basic proxy header support.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _extract_form_data():
    """
    Collect any form, query, or JSON payload data for logging.
    """
    form_data = {}
    if request.form:
        form_data["form"] = request.form.to_dict(flat=False)
    if request.args:
        form_data["query"] = request.args.to_dict(flat=False)
    json_payload = request.get_json(silent=True)
    if json_payload is not None:
        form_data["json"] = json_payload
    return form_data


def _log_event(event):
    """
    Write an event as a JSON line to the honeypot log.
    """
    try:
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            handle.flush()
    except OSError as exc:
        logger.error("Failed to write http event: %s", exc)
    except (TypeError, ValueError) as exc:
        logger.error("Failed to serialize http event: %s", exc)


@app.before_request
def record_request():
    """
    Capture every request before it is handled by the route.
    """
    event = {
        "eventid": "http.request",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": _get_client_ip(),
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "form_data": _extract_form_data()
    }
    _log_event(event)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def catch_all(path):
    """
    Serve a fake page for any path and never return 404.
    """
    normalized = _normalize_path(request.path)
    html = TEMPLATES.get(normalized)
    if html is None:
        html = GENERIC_TEMPLATE.safe_substitute(path=request.path)
    response = make_response(html, 200)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response


if __name__ == "__main__":
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
