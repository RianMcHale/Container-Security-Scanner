"""
scanner/app.py
-------------------
This small project implements a simple REST API for scanning Docker images using the open source Trivy security scanner.  The API accepts a container image name, invokes Trivy to analyse the image for known vulnerabilities, store the results in a local SQLite database and exposes endpoints to retrieve current and previous scan results.

The service is lightweight and easy to understand.
It demonstrates how to integrate a third‑party command line tool (Trivy)
within a Python Flask microservice and how to persist scan results in
SQLite.  Comments are kept concise to aid comprehension for a student
audience.
"""

import json
import os
import sqlite3
import subprocess
from datetime import datetime
from typing import Dict, Any

from flask import Flask, request, jsonify, g, abort

# Location of the SQLite database file inside the container
DB_PATH = os.getenv('SCANNER_DB_PATH', '/data/scans.db')

# Makes sure the data directory exists at startup
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    # 'g' stores the data for the CURRENT request only
    db = getattr(g, '_database', None)
    # connects to database file
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        # makes rows behave like dictionaries
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(_exception):
    """ Close the database when the request is complete """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """ Create the database table if it does not exist yet """
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image TEXT NOT NULL,
            created_at TEXT NOT NULL,
            report TEXT NOT NULL
        )
        """
    )
    db.commit()


def run_trivy_scan(image: str) -> Dict[str, Any]:
    """
    Runs the Trivy tool to scan a Docker image and return a JSON output
    """
    # Where Trivy stores it's downloaded data
    trivy_cache_dir = "/root/.cache/trivy"
    skip_flag = "--skip-db-update"

    # If Trivy has no database (db) yet, allow it to download one
    if not os.path.exists(os.path.join(trivy_cache_dir, "db")):
        skip_flag = ""

    # build the command to trun TRivy
    command = ["trivy", "image", "--quiet", skip_flag, "--format", "json", image] if skip_flag else [
        "trivy", "image", "--quiet", "--format", "json", image
    ]

    # run the command and capture output & errors
    completed = subprocess.run(command, capture_output=True, text=True)

    # if Trivy fails, print details and stop
    if completed.returncode != 0:
        print("Trivy failed:\n", completed.stderr)
        print("Trivy stdout:\n", completed.stdout)
        raise RuntimeError(completed.stderr or "Trivy returned non-zero exit code")

    # convert the JSON text into a Python dictionary
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse Trivy JSON output: {e}")


def summarise_vulnerabilities(report: Dict[str, Any]) -> Dict[str, int]:
    """
    Count how many vulnerabilities there are at each given severity level
    """
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'UNKNOWN': 0
    }
    # go through each section of the report
    for result in report.get('Results', []):
        # each section may list vulnerabiltiies
        for vuln in result.get('Vulnerabilities', []) or []:
            # get severity level (e.g High, Low, Critical)
            sev = vuln.get('Severity', 'UNKNOWN').upper()
            if sev not in severity_counts:
                severity_counts[sev] = 0
            severity_counts[sev] += 1
    return severity_counts


@app.route('/scan', methods=['POST'])
def scan_image():
    """
    POST /scan
    Takes a JSON body with the 'image' name, scans it and saves the
    results and then returns a short summary.
    """
    data = request.get_json(force=True)
    image = data.get('image')
    if not image:
        abort(400, description="Image name is required")
        
    # Run the scan using Trivy
    try:
        report = run_trivy_scan(image)
    except RuntimeError as e:
        print("Scan failed:", e)
        return jsonify({"error": str(e)}), 500
        
    # Save the full report to the db
    db = get_db()
    created_at = datetime.utcnow().isoformat()
    report_json = json.dumps(report)
    cursor = db.execute(
        "INSERT INTO scans (image, created_at, report) VALUES (?, ?, ?)",
        (image, created_at, report_json)
    )
    db.commit()
    
    # Get the ID of the saved scan
    scan_id = cursor.lastrowid
    
    # Make a short summary to return
    summary = summarise_vulnerabilities(report)
    response = {
        'id': scan_id,
        'image': image,
        'created_at': created_at,
        'summary': summary
    }
    return jsonify(response), 201


@app.route('/scans', methods=['GET'])
def list_scans():
    """
    GET /scans
    Return a list of all scans with summaries (no full reports)
    """
    db = get_db()
    rows = db.execute(
        "SELECT id, image, created_at, report FROM scans ORDER BY id DESC"
    ).fetchall()
    scans = []
    for row in rows:
        report = json.loads(row['report'])
        summary = summarise_vulnerabilities(report)
        scans.append({
            'id': row['id'],
            'image': row['image'],
            'created_at': row['created_at'],
            'summary': summary
        })
    return jsonify(scans)


@app.route('/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id: int):
    """
    GET /scans/<scan_id>
    REturn the full details (including the report) for a specific scan
    """
    db = get_db()
    row = db.execute(
        "SELECT id, image, created_at, report FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()
    if row is None:
        abort(404, description="Scan not found")
    report = json.loads(row['report'])
    summary = summarise_vulnerabilities(report)
    return jsonify({
        'id': row['id'],
        'image': row['image'],
        'created_at': row['created_at'],
        'summary': summary,
        'report': report
    })


@app.before_request
def setup():
    """ Make sure the db exists before handling any requests """
    init_db()


if __name__ == '__main__':
    # Start the Flask app if the file is ran correctly
    port = int(os.getenv('PORT', '5000'))
    app.run(host='0.0.0.0', port=port)
