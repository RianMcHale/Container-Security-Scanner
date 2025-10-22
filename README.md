# Container-Security-Scanner
Simple container security scanner. Flask API runs Trivy on Docker images, saves results to SQLite, and exposes summaries + full JSON. Minimal Nginx UI (via /api) to start scans and browse history. Ships with Docker Compose and a persisted volume.
