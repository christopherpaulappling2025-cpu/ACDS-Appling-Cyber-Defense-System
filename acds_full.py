#!/usr/bin/env python3
"""
ACDS - Appling Cyber Defense System
Single-file runnable prototype:
 - FastAPI backend + simple HTML dashboard
 - IP geolocation lookup (ipapi.co)
 - Simple anomaly scoring
 - Alerts: Email (SMTP), Slack, SMS (Twilio)
 - Local JSON event logging
 - Optional auto-commit to Git (if repo configured)
 
Security: Put all secrets into a .env file and NEVER commit .env to GitHub.
"""

import os
import json
import subprocess
from datetime import datetime
from typing import Dict

import requests
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn

# Load environment variables from .env in working dir
load_dotenv()

# -----------------------
# Config from .env
# -----------------------
EVENTS_FILE = os.getenv("ACDS_EVENTS_FILE", "login_events.json")
GIT_REPO_PATH = os.getenv("ACDS_GIT_REPO_PATH", os.getcwd())
GIT_BRANCH = os.getenv("ACDS_GIT_BRANCH", "main")
GIT_COMMIT_MSG = os.getenv("ACDS_GIT_COMMIT_MSG", "ACDS auto-update commit")

# Email (SMTP) config
EMAIL_SENDER = os.getenv("ACDS_EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("ACDS_EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("ACDS_EMAIL_RECEIVER")

# Slack config
SLACK_TOKEN = os.getenv("ACDS_SLACK_TOKEN")
SLACK_CHANNEL = os.getenv("ACDS_SLACK_CHANNEL")

# Twilio config (SMS)
TWILIO_ENABLED = os.getenv("ACDS_TWILIO_ENABLED", "false").lower() == "true"
TWILIO_ACCOUNT_SID = os.getenv("ACDS_TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("ACDS_TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("ACDS_TWILIO_PHONE_NUMBER")
ALERT_PHONE_NUMBER = os.getenv("ACDS_ALERT_PHONE_NUMBER")

# Geolocation service (ipapi.co)
GEO_SERVICE = os.getenv("ACDS_GEO_SERVICE", "ipapi.co")

# Threshold settings (adjust as needed)
THRESHOLD_SCORE_ALERT = int(os.getenv("ACDS_THRESH_ALERT", "5"))

# -----------------------
# Dependencies check
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
# Helper functions
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
    """Commit and push EVENTS_FILE if repo is initialized and configured."""
    try:
        if not os.path.exists(os.path.join(GIT_REPO_PATH, ".git")):
            print("[GIT] No .git folder found; skipping commit/push.")
            return
        subprocess.run(["git", "add", EVENTS_FILE], cwd=GIT_REPO_PATH, check=False)
        subprocess.run(["git", "commit", "-m", GIT_COMMIT_MSG], cwd=GIT_REPO_PATH, check=False)
        subprocess.run(["git", "push", "origin", GIT_BRANCH], cwd=GIT_REPO_PATH, check=False)
        print(f"[{datetime.utcnow().isoformat()}] Git push attempted.")
    except Exception as e:
        print(f"[GIT ERROR] {e}")


# -----------------------
# Geolocation + detection
# -----------------------
def geolocate_ip(ip: str) -> Dict[str, str]:
    """Use ipapi.co to get country, region, city. Returns defaults on failure."""
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
    """Simple scoring rules. Extend with ML later."""
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


# -----------------------
# Alerts: Email, Slack, SMS
# -----------------------
def send_email_alert(subject: str, body: str):
    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        print("[EMAIL] Missing email configuration; skipping email alert.")
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
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
    if not SLACK_TOKEN or not SLACK_CHANNEL:
        print("[SLACK] Missing Slack configuration; skipping Slack alert.")
        return
    if WebClient is None:
        print("[SLACK] slack_sdk not installed; skipping Slack alert.")
        return
    try:
        client = WebClient(token=SLACK_TOKEN)
        client.chat_postMessage(channel=SLACK_CHANNEL, text=message)
        print(f"[{datetime.utcnow().isoformat()}] Slack alert sent.")
    except SlackApiError as e:
        print(f"[SLACK ERROR] {e RESPONSE['error']}")
    except Exception as e:
        print(f"[SLACK ERROR] {e}")


def send_sms_alert(message: str):
    if not TWILIO_ENABLED:
        print("[SMS] Twilio disabled; skipping SMS.")
        return
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_PHONE_NUMBER and ALERT_PHONE_NUMBER):
        print("[SMS] Missing Twilio config; skipping SMS.")
        return
    if TwilioClient is None:
        print("[SMS] twilio client not installed; skipping SMS.")
        return
    try:
        client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(body=message, from_=TWILIO_PHONE_NUMBER, to=ALERT_PHONE_NUMBER)
        print(f"[{datetime.utcnow().isoformat()}] SMS alert sent.")
    except Exception as e:
        print(f"[SMS ERROR] {e}")


# -----------------------
# AI retrain stub
# -----------------------
def retrain_model(events: list = None):
    print(f"[{datetime.utcnow().isoformat()}] retrain_model called (stub). Events count: {len(events or [])}")


# -----------------------
# FastAPI app
# -----------------------
app = FastAPI(title="Appling Cyber Defense System (ACDS)")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    events = load_events()
    rows = ""
    for e in events:
        rows += f"<tr><td>{e.get('ip','')} </td><td>{e.get('country','')} </td><td>{e.get('region','')} </td><td>{e.get('city','')} </td><td>{e.get('timestamp','')} </td><td>{'&#9888;' if e.get('anomaly') else '&#9989;'} </td></tr>"
    html = f"""
    <html>
      <head>
        <title>ACDS Dashboard</title>
        <style>
          body{{font-family: Arial; padding: 18px;}}
          table{{border-collapse: collapse; width:100%;}}
          th,td{{border:1px solid #ddd; padding:8px;}}
          th{{background:#f2f2f2;}}
        </style>
      </head>
      <body>
        <h1>Appling Cyber Defense Dashboard</h1>
        <p>Events stored locally: {len(events)}</p>
        <table><thead><tr><th>IP</th><th>Country</th><th>Region</th><th>City</th><th>Timestamp</th><th>Status</th></tr></thead><tbody>
        {rows}
        </tbody></table>
        <p>API endpoints:</p>
        <ul>
          <li>POST /login-event  — submit {{"ip"}} json</li>
          <li>GET  /nightly-update — retrain & push</li>
        </ul>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)


@app.post("/login-event")
async def login_event(payload: dict):
    ip = payload.get("ip") or payload.get("ip_address") or payload.get("ipAddress")
    if not ip:
        return {"error": "missing ip field (use {\"ip\":\"1.2.3.4\"})"}, 400

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
        except Exception as e:
            print(f"[ALERT ERROR EMAIL] {e}")
        try:
            send_slack_alert(msg)
        except Exception as e:
            print(f"[ALERT ERROR SLACK] {e}")
        try:
            send_sms_alert(msg)
        except Exception as e:
            print(f"[ALERT ERROR SMS] {e}")

    try:
        retrain_model(events)
    except Exception as e:
        print(f"[RETRAIN ERROR] {e}")

    try:
        safe_git_commit_push()
    except Exception as e:
        print(f"[GIT PUSH ERROR] {e}")

    return {"record": record, "anomaly_detected": record["anomaly"]}


@app.get("/nightly-update")
def nightly_update_endpoint():
    events = load_events()
    retrain_model(events)
    safe_git_commit_push()
    return {"status": "nightly update run", "events_count": len(events)}


if __name__ == "__main__":
    print("[ACDS] Starting server: visit http://127.0.0.1:8000/")
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
