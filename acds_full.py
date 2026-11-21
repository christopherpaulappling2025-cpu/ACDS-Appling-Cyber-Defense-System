#!/usr/bin/env python3
"""
ACDS - Appling Cyber Defense System
Unified single-file platform (v7 prototype):
 - FastAPI backend + mobile-friendly HTML dashboard
 - IP geolocation (ipapi.co)
 - Rule-based anomaly scoring
 - Alerts: Email (SMTP), Slack, SMS (Twilio)
 - Local JSON event logging
 - Optional auto-commit to Git
 - Module placeholders for ZKP privacy, banking defense,
   Game of Life sim, solar system command view, choropleth maps

Security: Put all secrets into a .env file. NEVER commit .env.
"""

import os
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

load_dotenv()

# -----------------------
# Config from .env
# -----------------------
EVENTS_FILE = os.getenv("ACDS_EVENTS_FILE", "login_events.json")
GIT_REPO_PATH = os.getenv("ACDS_GIT_REPO_PATH", os.getcwd())
GIT_BRANCH = os.getenv("ACDS_GIT_BRANCH", "main")
GIT_COMMIT_MSG = os.getenv("ACDS_GIT_COMMIT_MSG", "ACDS auto-update commit")

EMAIL_SENDER = os.getenv("ACDS_EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("ACDS_EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("ACDS_EMAIL_RECEIVER")

SLACK_TOKEN = os.getenv("ACDS_SLACK_TOKEN")
SLACK_CHANNEL = os.getenv("ACDS_SLACK_CHANNEL")

TWILIO_ENABLED = os.getenv("ACDS_TWILIO_ENABLED", "false").lower() == "true"
TWILIO_ACCOUNT_SID = os.getenv("ACDS_TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("ACDS_TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("ACDS_TWILIO_PHONE_NUMBER")
ALERT_PHONE_NUMBER = os.getenv("ACDS_ALERT_PHONE_NUMBER")

GEO_SERVICE = os.getenv("ACDS_GEO_SERVICE", "ipapi.co")
THRESHOLD_SCORE_ALERT = int(os.getenv("ACDS_THRESH_ALERT", "5"))
PORT = int(os.getenv("PORT", "8000"))

# -----------------------
# Optional imports
# -----------------------
try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
except Exception:
    WebClient = None
    SlackApiError = Exception

try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

import smtplib
from email.mime.text import MIMEText

# -----------------------
# Helpers
# -----------------------
def load_events() -> list:
    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE, "r") as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []


def save_events(events: list):
    with open(EVENTS_FILE, "w") as f:
        json.dump(events, f, indent=2)


def safe_git_commit_push():
    try:
        if not os.path.exists(os.path.join(GIT_REPO_PATH, ".git")):
            return
        subprocess.run(["git", "add", EVENTS_FILE], cwd=GIT_REPO_PATH, check=False)
        subprocess.run(["git", "commit", "-m", GIT_COMMIT_MSG], cwd=GIT_REPO_PATH, check=False)
        subprocess.run(["git", "push", "origin", GIT_BRANCH], cwd=GIT_REPO_PATH, check=False)
    except Exception as e:
        print(f"[GIT ERROR] {e}")


def geolocate_ip(ip: str) -> Dict[str, str]:
    try:
        if GEO_SERVICE == "ipapi.co":
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6)
            if r.status_code == 200:
                j = r.json()
                return {
                    "ip": ip,
                    "country": j.get("country_name", "Unknown"),
                    "region": j.get("region", "Unknown"),
                    "city": j.get("city", "Unknown"),
                    "asn": j.get("org", "")
                }
    except Exception as e:
        print(f"[GEO ERROR] {e}")
    return {"ip": ip, "country": "Unknown", "region": "Unknown", "city": "Unknown", "asn": ""}


def compute_anomaly_score(record: dict, events: list) -> int:
    score = 0
    if record.get("country") and record["country"] not in ("United States", "US"):
        score += 5
    ip_count = sum(1 for e in events if e.get("ip") == record.get("ip"))
    if ip_count > 3:
        score += 2
    try:
        hour = datetime.fromisoformat(record["timestamp"]).hour
        if hour in (2, 3, 4, 5):
            score += 1
    except Exception:
        pass
    return score


def send_email_alert(subject: str, body: str):
    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
        server.ehlo()
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[{datetime.utcnow().isoformat()}] Email alert sent.")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def send_slack_alert(message: str):
    if not SLACK_TOKEN or not SLACK_CHANNEL or WebClient is None:
        return
    try:
        client = WebClient(token=SLACK_TOKEN)
        client.chat_postMessage(channel=SLACK_CHANNEL, text=message)
        print(f"[{datetime.utcnow().isoformat()}] Slack alert sent.")
    except Exception as e:
        print(f"[SLACK ERROR] {e}")


def send_sms_alert(message: str):
    if not TWILIO_ENABLED or not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER, ALERT_PHONE_NUMBER]) or TwilioClient is None:
        return
    try:
        client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(body=message, from_=TWILIO_PHONE_NUMBER, to=ALERT_PHONE_NUMBER)
        print(f"[{datetime.utcnow().isoformat()}] SMS alert sent.")
    except Exception as e:
        print(f"[SMS ERROR] {e}")


def retrain_model(events: list = None):
    print(f"[{datetime.utcnow().isoformat()}] retrain_model called (stub). Events: {len(events or [])}")


def get_channel_status() -> dict:
    return {
        "email": bool(EMAIL_SENDER and EMAIL_PASSWORD and EMAIL_RECEIVER),
        "slack": bool(SLACK_TOKEN and SLACK_CHANNEL),
        "sms": bool(TWILIO_ENABLED and TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER and ALERT_PHONE_NUMBER),
    }


# -----------------------
# FastAPI app
# -----------------------
app = FastAPI(title="Appling Cyber Defense System (ACDS)", version="7.0")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    events = load_events()
    channels = get_channel_status()
    anomaly_count = sum(1 for e in events if e.get("anomaly"))
    recent = list(reversed(events[-50:]))  # newest first, last 50

    rows = ""
    for e in recent:
        status_icon = "⚠️" if e.get("anomaly") else "✅"
        score = e.get("score", 0)
        rows += f"""
        <tr class="{'anomaly' if e.get('anomaly') else ''}">
          <td data-label="IP">{e.get('ip','')}</td>
          <td data-label="Location">{e.get('city','')} , {e.get('region','')} / {e.get('country','')}</td>
          <td data-label="Time">{e.get('timestamp','')[:19]}</td>
          <td data-label="Score">{score}</td>
          <td data-label="Status">{status_icon}</td>
        </tr>"""

    email_status = "🟢 Ready" if channels["email"] else "🔴 Not configured"
    slack_status = "🟢 Ready" if channels["slack"] else "🔴 Not configured"
    sms_status = "🟢 Ready" if channels["sms"] else "🔴 Not configured"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
  <title>ACDS — Appling Cyber Defense System</title>
  <style>
    :root {{
      --bg: #0b0f14;
      --card: #141a22;
      --border: #1e2a38;
      --text: #e6edf3;
      --muted: #8b9bb4;
      --accent: #3b82f6;
      --danger: #ef4444;
      --ok: #22c55e;
      --warn: #f59e0b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 12px;
      min-height: 100vh;
    }}
    .header {{
      text-align: center;
      padding: 16px 0 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }}
    .header h1 {{
      font-size: 1.4rem;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}
    .header .sub {{
      color: var(--muted);
      font-size: 0.85rem;
      margin-top: 4px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-bottom: 18px;
    }}
    .stat {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 8px;
      text-align: center;
    }}
    .stat .num {{
      font-size: 1.5rem;
      font-weight: 700;
    }}
    .stat .label {{
      font-size: 0.7rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .section {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 16px;
      overflow: hidden;
    }}
    .section-title {{
      padding: 12px 14px;
      font-size: 0.9rem;
      font-weight: 600;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .section-body {{ padding: 12px 14px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }}
    th {{
      text-align: left;
      color: var(--muted);
      font-weight: 500;
      padding: 6px 4px;
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 8px 4px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    tr.anomaly td {{ color: #fca5a5; }}
    .channels {{
      display: grid;
      gap: 8px;
    }}
    .channel {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 10px;
      background: #0f1520;
      border-radius: 8px;
      font-size: 0.85rem;
    }}
    .modules {{
      display: grid;
      gap: 8px;
    }}
    .module {{
      padding: 10px;
      background: #0f1520;
      border-radius: 8px;
      font-size: 0.8rem;
    }}
    .module strong {{ display: block; margin-bottom: 2px; }}
    .module span {{ color: var(--muted); font-size: 0.75rem; }}
    .badge {{
      font-size: 0.65rem;
      padding: 2px 6px;
      border-radius: 4px;
      background: #1e3a5f;
      color: #93c5fd;
    }}
    .badge.planned {{ background: #3f2e1e; color: #fbbf24; }}
    .api-list {{
      font-size: 0.8rem;
      color: var(--muted);
    }}
    .api-list code {{
      background: #0f1520;
      padding: 2px 6px;
      border-radius: 4px;
      color: #93c5fd;
      font-size: 0.75rem;
    }}
    .footer {{
      text-align: center;
      color: var(--muted);
      font-size: 0.7rem;
      padding: 16px 0 8px;
    }}
    /* Mobile card-style table */
    @media (max-width: 640px) {{
      table thead {{ display: none; }}
      table tr {{
        display: block;
        margin-bottom: 10px;
        background: #0f1520;
        border-radius: 8px;
        padding: 8px;
      }}
      table td {{
        display: flex;
        justify-content: space-between;
        border: none;
        padding: 4px 0;
      }}
      table td::before {{
        content: attr(data-label);
        color: var(--muted);
        font-size: 0.7rem;
        margin-right: 8px;
      }}
      .stats {{ grid-template-columns: repeat(3, 1fr); }}
    }}
  </style>
</head>
<body>
  <div class="header">
    <h1>ACDS</h1>
    <div class="sub">Appling Cyber Defense System · v7 Prototype</div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="num">{len(events)}</div>
      <div class="label">Events</div>
    </div>
    <div class="stat">
      <div class="num" style="color:var(--danger)">{anomaly_count}</div>
      <div class="label">Anomalies</div>
    </div>
    <div class="stat">
      <div class="num" style="color:var(--ok)">LIVE</div>
      <div class="label">Status</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">
      Recent Events
      <span class="badge">last 50</span>
    </div>
    <div class="section-body" style="padding:8px 10px; overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>Location</th>
            <th>Time (UTC)</th>
            <th>Score</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows if rows else '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px;">No events yet. POST to /login-event to start.</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Alert Channels</div>
    <div class="section-body">
      <div class="channels">
        <div class="channel"><span>Email (SMTP)</span><span>{email_status}</span></div>
        <div class="channel"><span>Slack</span><span>{slack_status}</span></div>
        <div class="channel"><span>SMS (Twilio)</span><span>{sms_status}</span></div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">
      System Modules
      <span class="badge planned">roadmap</span>
    </div>
    <div class="section-body">
      <div class="modules">
        <div class="module">
          <strong>Core Defense Engine</strong>
          <span>Login event intake · Geolocation · Anomaly scoring · Alerts</span>
        </div>
        <div class="module">
          <strong>ZKP Privacy Layer</strong>
          <span>Zero-knowledge proofs for private verification (planned)</span>
        </div>
        <div class="module">
          <strong>Banking / Transaction Defense</strong>
          <span>Secure transaction hooks + cyber-aware ledger (planned)</span>
        </div>
        <div class="module">
          <strong>Command Dashboard</strong>
          <span>Terra Concord / Helioscope command view (planned)</span>
        </div>
        <div class="module">
          <strong>Simulation Layer</strong>
          <span>Game of Life grid · Solar system sim · Choropleth maps (planned)</span>
        </div>
        <div class="module">
          <strong>HSM / Cold Enclave Recovery</strong>
          <span>Hardware security module recovery packets (planned)</span>
        </div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">API</div>
    <div class="section-body api-list">
      <p><code>POST /login-event</code> — body: {{"ip": "1.2.3.4"}}</p>
      <p style="margin-top:6px;"><code>GET /nightly-update</code> — retrain stub + optional git push</p>
      <p style="margin-top:6px;"><code>GET /status</code> — JSON system status</p>
      <p style="margin-top:6px;"><code>GET /events</code> — raw event list</p>
    </div>
  </div>

  <div class="footer">
    Appling Cyber Defense Technologies · Local prototype · Secrets stay in .env
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.post("/login-event")
async def login_event(payload: dict):
    ip = payload.get("ip") or payload.get("ip_address") or payload.get("ipAddress")
    if not ip:
        return JSONResponse({"error": "missing ip field (use {\"ip\":\"1.2.3.4\"})"}, status_code=400)

    events = load_events()
    geo = geolocate_ip(ip)
    record = {
        "ip": ip,
        "country": geo.get("country"),
        "region": geo.get("region"),
        "city": geo.get("city"),
        "asn": geo.get("asn"),
        "timestamp": datetime.utcnow().isoformat()
    }
    score = compute_anomaly_score(record, events)
    record["score"] = score
    record["anomaly"] = score >= THRESHOLD_SCORE_ALERT

    events.append(record)
    save_events(events)

    if record["anomaly"]:
        msg = (f"[ALERT] Suspicious login detected\nIP: {record['ip']}\nCountry: {record['country']}\n"
               f"Region: {record['region']}\nCity: {record['city']}\nTimestamp: {record['timestamp']}\nScore: {record['score']}")
        print(msg)
        try:
            send_email_alert("ACDS Suspicious Login", msg)
        except Exception:
            pass
        try:
            send_slack_alert(msg)
        except Exception:
            pass
        try:
            send_sms_alert(msg)
        except Exception:
            pass

    try:
        retrain_model(events)
    except Exception:
        pass

    try:
        safe_git_commit_push()
    except Exception:
        pass

    return {"record": record, "anomaly_detected": record["anomaly"]}


@app.get("/nightly-update")
def nightly_update_endpoint():
    events = load_events()
    retrain_model(events)
    safe_git_commit_push()
    return {"status": "nightly update run", "events_count": len(events)}


@app.get("/status")
def status():
    events = load_events()
    channels = get_channel_status()
    return {
        "system": "ACDS v7",
        "events": len(events),
        "anomalies": sum(1 for e in events if e.get("anomaly")),
        "channels": channels,
        "threshold": THRESHOLD_SCORE_ALERT,
        "time": datetime.utcnow().isoformat()
    }


@app.get("/events")
def list_events():
    return load_events()


if __name__ == "__main__":
    print("[ACDS] Starting server — open http://127.0.0.1:8000 in your browser")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
