# Automated Attack Surface Analyzer

A modular, scalable Dynamic Application Security Testing (DAST) scanner written in Python. Designed to automatically discover endpoints and detect vulnerabilities in modern web applications, including Single Page Applications (SPAs) and RESTful APIs.

## Features

* **JavaScript Crawler**: Automatically parses HTML and `.js` files to discover hidden and dynamic API endpoints (e.g., `/rest/...`, `/api/...`).
* **Passive Scanning**: 
  * Detects missing Security Headers (`Strict-Transport-Security`, `Content-Security-Policy`, etc.).
  * Identifies Information Disclosure (technology leakage via HTTP headers).
* **Active Scanning**:
  * **Directory Discovery**: Brute-forces hidden files and directories (e.g., `.env`, `.git/config`) with intelligent "Soft 404" detection.
  * **SQL Injection (SQLi) Fuzzing**: Advanced error-based SQLi detection supporting:
    * GET Query Parameters (e.g., `?q=...`)
    * REST Path Parameters (e.g., `/rest/basket/${e}/coupon/${i}`)
    * POST JSON Body Fuzzing (automatically targets login, registration, and data submission endpoints).
* **Policy-Driven Engine**: Uses a JSON-based knowledge base (`knowledge_base/vulnerabilities.json`) to classify findings by severity and provide actionable remediation advice.
* **Automated Reporting**: Generates clean, readable `report.md` files detailing vulnerabilities, endpoints, and evidence.

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   The project relies on `requests` and `urllib3`.
   ```bash
   pip install requests urllib3
   ```

## Usage

1. Open `main.py` and modify the `base_url` variable to point to your target application:
   ```python
   def main():
       # Initialize basic components
       base_url = "http://localhost:3000" # <-- Change this to your target
       ...
   ```
   > ⚠️ **Warning:** Only scan applications you have explicit permission to test!

2. Run the scanner:
   ```bash
   python3 main.py
   ```

3. View the results in the terminal output and check the generated `report.md` for detailed findings.

## Architecture

* `core/`: Contains the foundational engine components:
  * `models.py`: Defines the `HttpClient` (wrapper for requests) and data models (`RawFinding`, `Evidence`, `Severity`).
  * `scanner.py`: The orchestration engine that coordinates passive, global, and endpoint-specific checks.
  * `crawler.py`: Handles regex-based endpoint discovery.
  * `policy.py`: Loads the vulnerability knowledge base and enriches raw findings.
* `checks/`: Contains the individual vulnerability detection modules (plugins). To add a new check, create a new file here and inherit from the appropriate base class.
* `knowledge_base/`: Stores `vulnerabilities.json`, defining the signature, severity, and remediation for each vulnerability type.
* `reports/`: Contains the `MarkdownReporter` used to output findings.

## Known Limitations & Future Work

* Currently, the SQLi Scanner focuses primarily on Error-Based SQLi. Time-based and Blind SQLi payloads can be added to `payloads` in the future.
* The crawler relies heavily on regex to find endpoints in JS files. While effective for many SPAs, complex dynamic routing might require AST parsing or headless browser integration (e.g., Playwright) for better coverage.
