# Container-Security-Scanner
This project implements a containerised security scanner platform. A small & easy platform that uses the open-source scanner Trivy to scan Docker images, store full JSON reports in a SQLite database and provide a simple web UI (via Nginx) for triggering scans, viewing summaries and examining detailed results. Built with Flask (Python) for the API and static HTML/JS for the UI.  
The goal of this personal project was to demonstrate how to apply the best containerisation practices, and implement DevSecOps workflows.

<img width="1285" height="757" alt="image" src="https://github.com/user-attachments/assets/bd08f3ec-5fb4-4998-876a-98a9bfe3d4c0" />

## Installation & Usage

**Prerequisites**
- Docker Engine (24+ recommended)
- Docker Compose v2+

**Start Guide**
```bash
git clone https://github.com/RianMcHale/ContainerSecurityScanner.git
cd ContainerSecurityScanner
docker compose build
docker compose up
```

Open your browser at http://localhost:8081, enter an image name (for example, node:8) and click Scan Image.  
Backend listens on http://localhost:5000 (API).

# Project Structure
```/
├─ scanner/  
│   ├─ app.py  
│   ├─ Dockerfile  
│   ├─ requirements.txt  
├─ ui/  
│   ├─ html/  
│   │   ├─ index.html  
│   │   ├─ script.js  
│   ├─ nginx.conf  
│   ├─ Dockerfile  
├─ docker-compose.yml  
```

# References
- **Ángel Maroco**: [_**Container vulnerability scanning with Trivy, Bluetab (2025)**_](https://www.bluetab.net/en/container-vulnerability-scanning-with-trivy)    
Why scanning during the build phase matters, what Trivy detects across OS and application dependencies, quick install options (script/Docker), and scanning local/remote images.

