# ACDS — Appling Cyber Defense System

**v7 Prototype · Unified Platform**

Single-file FastAPI application with a mobile-friendly dashboard for login event monitoring, anomaly detection, and multi-channel alerts.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/christopherpaulappling2025-cpu/ACDS-Appling-Cyber-Defense-System.git
cd ACDS-Appling-Cyber-Defense-System

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure secrets (copy example and edit)
cp .env.example .env
# Edit .env with your real keys (email, Slack, Twilio, etc.)

# 4. Run
python acds_full.py
```

Open in browser (phone or desktop):

**http://127.0.0.1:8000**

## What You See on the Dashboard

- Live event counter + anomaly count
- Recent login events (IP, location, score, status)
- Alert channel status (Email / Slack / SMS)
- System modules roadmap (ZKP, Banking Defense, Command View, Simulations, HSM)
- API reference

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard (HTML) |
| POST | `/login-event` | Submit `{ "ip": "1.2.3.4" }` |
| GET | `/status` | JSON system status |
| GET | `/events` | Raw event list |
| GET | `/nightly-update` | Retrain stub + optional git push |

## Security Notes

- All secrets live in `.env` only.
- Never commit `.env`.
- `.env.example` shows the required variable names.
- The system is a local prototype. Do not expose it to the public internet without additional hardening (auth, HTTPS, rate limits).

## Project Structure

```
acds_full.py          # Entire runnable platform
requirements.txt      # Dependencies
.env.example          # Secret template
SYSTEM_OVERVIEW.md    # High-level design
DEVELOPMENT_NOTES.md  # Notes
FUTURE_UPDATES.md     # Roadmap items
LICENSE
```

## License

See LICENSE file.
