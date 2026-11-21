# System Overview — ACDS v7

Appling Cyber Defense System is a local-first prototype for authentication event monitoring and anomaly response.

## Current Capabilities (Live)

1. **Event Intake** — POST login events with IP
2. **Geolocation** — Country / region / city via ipapi.co
3. **Anomaly Scoring** — Rule-based (foreign country, repeat IP, odd hours)
4. **Multi-channel Alerts** — Email (SMTP), Slack, SMS (Twilio)
5. **Local Persistence** — JSON event log
6. **Dashboard** — Mobile-friendly web UI at `/`
7. **Status API** — `/status` and `/events`

## Planned Modules (Roadmap)

- ZKP Privacy Layer — zero-knowledge verification of events without exposing raw data
- Banking / Transaction Defense — secure transaction hooks and cyber-aware ledger integration
- Command Dashboard — Terra Concord / Helioscope style operational view
- Simulation Layer — Conway Game of Life grid, solar system sim, interactive choropleth maps
- HSM / Cold Enclave Recovery — hardware-backed recovery packets

## Design Principles

- Single-file runnable prototype for easy inspection and iteration
- Secrets only in `.env` (never committed)
- Clear separation between detection, alerting, and future privacy/banking layers
- Local-first; cloud or multi-user features come later
