import asyncio
from flask import Flask, request, jsonify, render_template, Response
import threading
from orchestrator import ScannerOrchestrator
import time
import csv
from io import StringIO

app = Flask(__name__)

# Very simple in-memory state for scans (in a real app, use Celery/Redis)
scan_status = {
    "status": "idle", # idle, scanning, completed, error
    "results": [],
    "target": "",
    "started_at": None,
}

def background_scan(target_url, timeout=15, max_concurrent=3):
    global scan_status
    scan_status["status"] = "scanning"
    scan_status["target"] = target_url
    scan_status["results"] = []
    scan_status["error_message"] = ""
    scan_status["started_at"] = time.time()
    
    try:
        orchestrator = ScannerOrchestrator(target_url=target_url, timeout=timeout, max_concurrent=max_concurrent)
        # Keep the demo UI from polling forever when a target stops responding.
        results = asyncio.run(asyncio.wait_for(orchestrator.run_scan(), timeout=600))
        
        # Convert findings to dicts for JSON
        results_json = []
        for r in results:
            evidence_data = None
            if r.evidence:
                evidence_data = {
                    "request": r.evidence.request,
                    "response": r.evidence.response
                }
            results_json.append({
                "name": r.name,
                "severity": r.severity.name,
                "endpoint": r.endpoint,
                "description": r.description,
                "evidence": evidence_data
            })
            
        scan_status["results"] = results_json
        scan_status["status"] = "completed"
    except Exception as e:
        scan_status["status"] = "error"
        scan_status["error_message"] = str(e)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    global scan_status
    data = request.json
    target_url = data.get('target_url')
    timeout = int(data.get('timeout', 15))
    max_concurrent = int(data.get('max_concurrent', 3))
    
    if not target_url:
        return jsonify({"error": "No target URL provided"}), 400
        
    if scan_status["status"] == "scanning":
        return jsonify({"error": "A scan is already in progress"}), 400
        
    thread = threading.Thread(target=background_scan, args=(target_url, timeout, max_concurrent), daemon=True)
    thread.start()
    
    return jsonify({"message": "Scan started"}), 200

@app.route('/api/scan/status', methods=['GET'])
def get_status():
    global scan_status
    return jsonify(scan_status)

@app.route('/api/scan/download/csv', methods=['GET'])
def download_csv():
    global scan_status
    if scan_status["status"] != "completed" or not scan_status["results"]:
        return "No results available", 400
        
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Severity', 'Vulnerability Name', 'Endpoint', 'Description'])
    for r in scan_status["results"]:
        cw.writerow([r['severity'], r['name'], r['endpoint'], r['description']])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=echo_scan_report.csv"}
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
