# Rudra’s Third Eye (AI)

A fast, agentic API security scanner with:
- ✅ Robust Postman parser (v2.x, vars, auth, GraphQL, legacy)
- ✅ Agentic Beast Mode (context-aware payloads & chaining)
- ✅ AI/ML verification with anti-false-positive & VRT P1–P3 scoring
- ✅ Live Socket.IO dashboard (Halodoc-style)
- ✅ PDF/HTML report generation

---

## ✨ Highlights

- **Postman integration**: deep parsing, variable resolution, colon `/:id` param filling, safe skipping of unresolved endpoints.
- **Recon**: OpenAPI discovery + seeded endpoints when specs are missing.
- **Agentic hunting**: pattern-driven payload crafting + response heuristics; reuses pooled HTTP session to avoid connection churn.
- **AI test generation**: comprehensive test ideas from collection analysis; executes a fast representative subset.
- **False-positive controls**: quick checks (auth redirects, CORS grading) + VRT priority mapping.
- **Dashboard**: progress, phases, activity log; stable Socket.IO (connect once, no flap).
- **Reports**: polished PDF (wkhtmltopdf/pdfkit) with auto-fallback to HTML.

---

## 🧱 Repository Layout

api-security-tool/
├── app.py # Flask + Socket.IO server (serves dashboard in prod)
├── scanner/
│ ├── adapter.py # Connection-pooled adapter (HTTP + native scanner aliasing)
│ └── core.py # Core scanner primitives
├── agents/
│ ├── beast_mode.py # Agentic hunter (concurrency + shared session)
│ └── hunter.py # Aux hunting logic
├── integrations/
│ └── postman.py # Enhanced Postman parser + integration
├── doc_parsers/
│ └── pdf_api_parser.py # (Optional) Build Postman from API PDF
├── report_generator.py # PDF/HTML report
├── ai_test_generator.py # AI analysis + test ideation
├── uploads/, reports/ # Runtime artifacts (ignored)
├── frontend/ # React + Vite + Tailwind dashboard
│ ├── index.html
│ ├── vite.config.js
│ ├── postcss.config.js
│ ├── tailwind.config.js
│ └── src/
│ ├── main.jsx
│ ├── index.css
│ ├── App.jsx
│ └── components/
│ ├── ScanDashboard.jsx
│ └── ScanProgress.jsx
├── .env.example
├── requirements.txt
└── .gitignore

---

## 🚦 Requirements

- **Python**: 3.10+ (3.11 recommended)
- **Node.js**: 18.18+ or 20+ (Vite v5 compatible)
- **wkhtmltopdf** (for PDF reports):
  - macOS (Homebrew): `brew install wkhtmltopdf`
  - Ubuntu/Debian: `sudo apt-get install -y wkhtmltopdf`
- **(Optional) SSH** access to GitHub for pushing

---

## 🔧 Backend Setup

```bash
# From repo root
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

# Create your environment file
cp .env.example .env
# Edit .env with your keys (OPENAI_API_KEY, GEMINI_API_KEY, etc.)
Start the backend:
python app.py
You should see:
🚀 Starting Rudra's Third Eye (AI)
📊 Dashboard (React): http://localhost:4000/dashboard
🔍 Health:             http://localhost:4000/health
The server is configured for stable Socket.IO (no dev reloader, tuned ping).
🎨 Frontend Setup (React + Vite + Tailwind)
cd frontend
npm install

# Tailwind PostCSS plugin (required by Tailwind v4+ notice)
npm i -D tailwindcss postcss autoprefixer @tailwindcss/postcss

# Socket.IO client & React plugin (if missing)
npm i socket.io-client
npm i -D @vitejs/plugin-react
Run in dev:
npm run dev
# → http://localhost:5173
The backend dev helper page is also at:
http://localhost:4000/dashboard
(When you build the frontend, Flask will serve the static dashboard from /frontend/dist.)
Build for production (served by Flask):

npm run build
# Restart backend to pick up frontend/dist
▶️ How to Use
Option A — Upload a Postman collection
Open the dashboard.
Choose a Postman collection JSON (.json).
(Optional) Provide a Postman environment/variables file.
Hit Start Scan.
Option B — Recon only (no collection)
Enter Target URL (e.g., https://api.example.com/).
The server will try OpenAPI discovery, else seed a minimal collection.
Start the scan.
Phases you’ll see:
Analysis → AI TestGen → Parsing → Agentic → AI Exec → Verify → Report
A PDF/HTML report is generated at the end. You’ll also see a download link.
⚙️ Environment Variables (.env)
Copy from .env.example and set as needed:
# Server
FLASK_ENV=production

# AI Providers (optional features)
OPENAI_API_KEY=sk-****************
GEMINI_API_KEY=************************

# Any custom config your modules read
# POSTMAN_API_KEY=
# HTTP_PROXY=
Secrets should not be committed. Use .env for local dev and GitHub Actions Secrets for CI/CD.
🧪 Troubleshooting
Tailwind error: “use @tailwindcss/postcss”
Install and set the plugin:
npm i -D @tailwindcss/postcss
postcss.config.js
export default {
  plugins: {
    '@tailwindcss/postcss': {},
    autoprefixer: {},
  },
}
Vite WS EPIPE / Socket flapping
Backend: socketio.run(..., debug=False, use_reloader=False)
Frontend: create Socket.IO once, use direct URL:
const socket = io("http://localhost:4000", { path: "/socket.io", transports: ["websocket"] });
Or proxy /socket.io in vite.config.js with ws: true.
urllib3.connectionpool: Connection pool is full
Fixed by pooled ScannerAdapter (pool_block=True, shared session).
Keep agent concurrency reasonable (8–12); reuse adapter session.
Report PDF fails: “No module named pdfkit”
pip install pdfkit (already in requirements.txt)
Install native wkhtmltopdf (see Requirements).
```
🛡️ Security Notes:

Logs do not emit sensitive headers/payloads.
Endpoints with unresolved placeholders are skipped to avoid noisy DNS/405 errors.
VRT mapping: P1..P4 with anti-FP checks (auth redirects, CORS grading).

📦 Production Hints
Consider running with eventlet for optimal WebSocket performance:
pip install eventlet
# app.py (no change needed; Flask-SocketIO auto-detects)
python app.py
Reverse-proxy via Nginx/Traefik; pass /socket.io as WebSocket upstream.

🧑‍💻 Contributing
Create a feature branch: git checkout -b feat/awesome
Commit changes: git commit -m "feat: awesome"
Push: git push -u origin feat/awesome
Open a PR
