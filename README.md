# VulnGuard AI

VulnGuard triages functions, analyzes high-risk code with Red and Blue agents,
and validates proposed patches with a Judge agent. Source discovery supports
Python, C, C++, Java, and JavaScript repositories.

## Prerequisites

- Python 3.11
- Node.js 20 or newer
- Docker Desktop for sandbox validation
- An API key for the configured LLM provider

## Setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set the API key and model-routing values in `.env`. The example is configured
for OpenAI.

Build the isolated multi-language sandbox image:

```powershell
docker build -t vulnguard-sandbox:latest -f vulnguard/sandbox/Dockerfile .
```

## Run the dashboard

Start the API from the project root:

```powershell
python -m vulnguard.main dashboard --backend fastapi --port 8000
```

Start the React UI in a second terminal:

```powershell
cd ui
npm install
npm run dev
```

Open `http://localhost:5173`, upload a supported source file or a ZIP repository, and
select a discovered function or scan all discovered functions as a batch.
Repository uploads enable cross-file context and project build/test validation.
Scans can be cancelled, recent history is shown in the dashboard, and results are retained in
`data/vulnguard.db`, and generated patch diffs can be downloaded from the live
agent feed.

Useful API endpoints:

- `GET /api/metrics`
- `GET /api/scan/status`
- `GET /api/results/{scan_id}`

## Run a CLI scan

```powershell
python -m vulnguard.main scan vulnerable_app.py --no-docker
```

Remove `--no-docker` when Docker Desktop is running and sandbox verification is
required.

## Run a repository benchmark

```powershell
python -m vulnguard.main benchmark . --max-files 100 --output-dir data/benchmarks
```

The command writes JSON and Markdown comparisons for VulnGuard triage and any
installed SAST tools. Precision and recall are reported only for labeled data.

## Test

```powershell
python -m pytest -q
cd ui
npm run lint
npm run build
```
