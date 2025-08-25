# Rudra’s Third Eye — AI API Scanner

>API security dashboard with AI-assisted Postman collection fixing, quick URL scanning, and one-click Markdown report generation.

<img alt="Theme preview" src="docs/preview.png" width="880"/>

## ✨ Features

* **Paste or Upload Postman collection**: Automatically normalize and fix collections, with optional secret redaction.

* **AI/ML Scoring Engine**: A self-contained engine that highlights risky requests and URLs with a score (0-1) and a label (High, Medium, Low, Info).

* **Rule-based Findings**: Detects common security issues like HTTP without TLS, sensitive headers, GET requests with a body, missing Content-Type headers, and internal routes.

* **Quick URL Scan**: A lightweight probe using HEAD/GET requests to check for security headers.

* **One-click Markdown Report Generation**: Easily create detailed reports.

* **“HackerOne/Nuclei”-style Dark UI**: A clean, modern interface.

* **Clear Actions**: Convenient "Clear" buttons on each card and a "Clear All" button for a fresh start.

---

## 🧩 Architecture

This project is a full-stack application composed of a backend API and a frontend UI.

```
.
├── server/
│   ├── main.py                # FastAPI app with AI scoring, scanners, and report generation
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── src/
│   │   ├── App.tsx            # React UI for all scanning functionalities
│   │   ├── api.ts             # Frontend API client
│   │   └── index.css          # HackerOne/Nuclei-like theme
│   ├── package.json
│   └── vite.config.ts
├── .gitignore
└── README.md
```

**Backend**: Built with **FastAPI** and uses `uvicorn` and `httpx`.
**Frontend**: Developed with **React**, **TypeScript**, and **Vite`.

---

## 🚀 Getting Started

### Prerequisites

* **Python** 3.10+

* **Node.js** 18+ (or newer)

* **Git**

### 1. Backend Setup

```bash
cd server
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start the API server
uvicorn main:app --reload --port 8000
```

The API will be running at `http://127.0.0.1:8000`.

### 2. Frontend Setup

```bash
cd ../frontend
npm install
```

**Development:**

```bash
# Optional: Set the API base if needed (defaults to [http://127.0.0.1:8000](http://127.0.0.1:8000))
# echo "VITE_API_BASE=[http://127.0.0.1:8000](http://127.0.0.1:8000)" > .env

npm run dev
```

Open the local URL printed in your terminal (e.g., `http://127.0.0.1:5173`).

**Production Build:**

```bash
npm run build
npm run preview
```

---

## 🔌 API Endpoints

**Base URL**: `http://127.0.0.1:8000`

* `GET /health`

* `POST /ai/fix_postman`

* `POST /scan/postman`

* `POST /scan/report`

* `POST /scan/url`

* `GET /hackerone/inscope`

For detailed request and response bodies, refer to the source code.

### cURL Examples

**Fix Postman Collection:**

```bash
curl -sS [http://127.0.0.1:8000/ai/fix_postman](http://127.0.0.1:8000/ai/fix_postman) \
  -H 'Content-Type: application/json' \
  -d '{"collection": {"collection":{"item":[]}}, "provider":"none", "redact_secrets":true}'
```

**Scan Postman Collection:**

```bash
curl -sS [http://127.0.0.1:8000/scan/postman](http://127.0.0.1:8000/scan/postman) \
  -H 'Content-Type: application/json' \
  -d '{"collection": {"collection":{"item":[]}}}'
```

**Generate Report:**

```bash
curl -sS [http://172.0.0.1:8000/scan/report](http://172.0.0.1:8000/scan/report) \
  -H 'Content-Type: application/json' \
  -d '{"collection": {"collection":{"item":[]}}, "format":"markdown"}'
```

**Scan a URL:**

```bash
curl -sS [http://127.0.0.1:8000/scan/url](http://127.0.0.1:8000/scan/url) \
  -H 'Content-Type: application/json' \
  -d '{"url":"[https://example.com/health](https://example.com/health)"}'
```

---

## 🧠 AI/ML Scoring (Built-in)

The project includes a compact **logistic model** that runs on interpretable features such as transport protocol, sensitive headers, and internal routes. It emits a security score between 0 and 1, along with a corresponding label (High, Medium, Low, Info) that complements rule-based findings. No external models or GPUs are required.

---

## ⚙️ Configuration

### Frontend

| Variable | Description | Default Value | 
| :--- | :--- | :--- |
| `VITE_API_BASE` | The base URL for the backend API. | `http://127.0.0.1:8000` | 

### Backend

No required environment variables by default. The `httpx` library is optional; if it's not available, the URL probing feature will simply skip header checks.

---

## 🔒 Security Notes

* **Never commit real secrets**. The fixer redacts common secret headers (e.g., `Authorization`, `X-APP-TOKEN`) in-memory.

* Use **HTTPS** in production; HSTS is recommended.

* Avoid placing PII and sensitive tokens in query strings.

## 🗺️ Roadmap

* [ ] PDF/HTML export for reports
* [ ] Optional external model (sklearn/ONNX) loader
* [ ] Fine-grained rule toggles and custom signatures

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1.  Open an issue to discuss major changes before submitting a pull request.
2.  Keep pull requests small and focused on a single feature or fix.
3.  Use clear and helpful commit messages.

---

## 📄 License

This project is licensed under the MIT License.

