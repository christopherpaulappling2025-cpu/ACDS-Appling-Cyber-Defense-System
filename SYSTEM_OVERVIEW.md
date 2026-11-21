# System Overview

The ACDS prototype proposes a framework for:
1. Collecting and logging authentication events.
2. Identifying anomalous patterns such as impossible travel or multiple rapid logins.
3. Generating human-readable alerts.
4. Providing an extensible API for organizations to build on.

## Core Modules

- `monitor.py` – event intake and IP lookup
- `analyze.py` – rule-based + machine learning anomaly detection
- `alerts.py` – email, Slack, SMS
- `storage.py` – JSON/SQL logging
- `dashboard.py` – FastAPI web interface
