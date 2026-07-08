# Agentic SOC Triage Assistant 

An **Autonomous Security Operations Center (SOC) Triage System** powered by LangGraph, LLMs, and Python. This project is designed to automate the initial investigation and triage of security alerts and raw logs, reducing the false positive workload on human SOC analysts.

##  Key Features

*   **Multi-Agent State Machine (LangGraph):** The system relies on a strictly defined directed graph rather than an unconstrained LLM. It manages iterative reasoning (ReAct) efficiently.
*   **Deterministic Entity Extraction:** Pre-processes logs with Regex to extract IPs, domains, hashes, and endpoints *before* sending data to the LLM, saving tokens and improving accuracy.
*   **Automated Deterministic Pre-Analysis:** Analyzes incoming event types and deterministically runs Python detection tools to generate highly accurate "candidate evidence" before the LLM is even invoked.
*   **Robust Evidence Validation:** Validates all LLM-provided evidence against the original raw logs to reduce hallucinated evidence through strict `event_id` and substring quote validation.
*   **Deterministic Reporting:** Generates strictly deterministic reports for evidence, recommended actions, and MITRE mapping to prevent LLM hallucination in critical sections. The report generation layer is intentionally concise and evidence-first. It produces short SOC triage summaries focused on four questions: what happened, why it matters, what evidence supports the verdict, and what the analyst should do next.
*   **Action Recommendations & MITRE ATT&CK:** Maps specific incident types (e.g., `sql_injection`, `dns_tunneling`, `benign_web_traffic`) to actionable mitigation strategies and MITRE techniques.
*   **Infinite Loop Protection:** Enforces a strict iteration limit to prevent the agent from getting stuck in an endless tool-calling loop.
*   **FastAPI Integration:** Fully accessible via a REST API (`/analyze`, `/incident/{id}/report`).

##  Tech Stack

*   **Python 3.10+**
*   **LangGraph & LangChain:** For agent orchestration and tool binding.
*   **Groq API (Llama 3.3 70B):** High-speed, cost-effective LLM inference.
*   **FastAPI & Uvicorn:** For API endpoints and server deployment.
*   **Pydantic:** Strict schema validation for agent outputs.
*   **Pytest:** For deterministic logic testing.

## 📂 Project Structure

```text
SOC-Project/
├── main.py                # Main CLI entry point (Run here for terminal output)
├── server.py              # FastAPI server entry point (Run here for Web UI)
├── requirements.txt
├── README.md
├── data/
│   └── mock_logs.json     # 12 diverse incident scenarios (SQLi, Brute Force, False Positives etc.)
├── agent/                 # Core Autonomous Logic
│   ├── graph.py           # LangGraph workflow definition
│   ├── nodes.py           # Logic for pre-analysis, triage, validation, and reporting
│   ├── tools.py           # Deterministic Python detection functions
│   └── models.py          # Pydantic schemas (IncidentState, TriageResult)
└── tests/
    └── test_*.py          # Pytest suite for deterministic logic and reporter validation
```

## 🚀 How to Run

### 1. Terminal CLI (Rich UI)
We use the `rich` library to provide a beautiful, markdown-rendered terminal experience.
```bash
# Run a single incident test (INC-001)
python main.py

# Run all 12 incidents sequentially
# Linux/macOS:
RUN_ALL=true python main.py
# Windows PowerShell:
$env:RUN_ALL="true"; python main.py
```

### 2. FastAPI Web UI (Swagger)
For a visual interface, you can start the built-in REST API server.
```bash
python server.py
```
*   `nodes.py`: Workflow nodes such as entity extraction, automated detection, triage, validation, action recommendation and reporter.
*   `tools.py`: LLM-accessible tools and deterministic detection functions.
*   `models.py`: Pydantic models and LangGraph state schemas.
*   `mock_logs.json`: Mock SOC incident dataset.
*   `tests/`: Test suite for detection logic and graph execution.

##  System Definition

This project is not a full production SOC platform. It is a **LangGraph-based, deterministic detection-layered, and constrained LLM triage agent PoC** demonstrating evidence-based autonomous investigation. It is designed to speed up the triage process and significantly reduce the false positive workload on human analysts by providing highly validated contexts, rather than entirely replacing them.

##  License
MIT License
