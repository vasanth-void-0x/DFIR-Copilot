# DFIR Copilot

**Evidence-Grounded AI-Assisted Digital Forensics Workbench**

DFIR Copilot is a local-first Windows desktop application that preserves
evidence, verifies SHA-256 integrity, extracts forensic artifacts, reconstructs
an incident timeline, correlates suspicious activity, and produces defensible
reports. Its Copilot can run fully offline or optionally use Groq, but every
substantive answer must cite case artifact IDs.

> Portfolio/training software — not a replacement for validated forensic
> suites, organizational procedure, or expert examiner judgment.

## Why this project is different

- It is a real desktop workflow, not a static dashboard.
- Original evidence is never modified.
- A hash mismatch stops analysis.
- Findings are built from deterministic artifacts before AI is used.
- Cloud AI is disabled by default and never receives original evidence files.
- The included demo is realistic but contains no malware or live infrastructure.

## Features

### Evidence preservation

- Multi-case investigation management
- Case-scoped evidence storage
- SHA-256 before/after copy verification
- Atomic per-case JSON evidence manifest
- Re-verification on every analysis
- Chain-of-custody and application audit logs

### Forensic analysis

- File metadata extraction
- Windows EVTX parsing (`python-evtx`)
- JSON, JSONL, and CSV event imports
- Autopsy-style deleted-file record imports
- Official YARA-X scanning with MITRE ATT&CK metadata
- Explicitly labelled built-in fallback indicators if YARA-X is unavailable
- Download → PowerShell → network correlation
- Post-connection deletion / anti-forensic correlation

### Evidence-grounded Copilot

- Offline answers without an API key
- Optional Groq inference through `.env`
- Structured context only; no original file upload
- Artifact/finding citations are validated before an answer is accepted
- “Insufficient evidence” behavior when the case does not support a conclusion

### Reporting

- Multi-page PDF forensic report
- Portable interactive HTML report
- Machine-readable JSON case export
- Evidence inventory, findings, timeline, custody, and examiner warning

## Screenshots

| Evidence & Case Management | Timeline Reconstruction |
|---|---|
| ![Evidence view](screenshots/evidence.png) | ![Timeline view](screenshots/timeline.png) |

| Correlated Findings | Evidence-Grounded Copilot |
|---|---|
| ![Findings view](screenshots/findings.png) | ![Copilot view](screenshots/copilot.png) |

| Generated Report |
|---|
| ![Report output](screenshots/report.png) |

## Desktop workflow

```mermaid
flowchart LR
    A["Create case"] --> B["Import evidence"]
    B --> C["Verify SHA-256"]
    C --> D["Analyze artifacts"]
    D --> E["Review timeline"]
    E --> F["Ask Copilot"]
    F --> G["Export report"]
```

## Quick start on Windows

Requirements: Windows 10/11 and Python 3.10 or newer.

1. Extract this project.
2. Double-click `START_DFIR_COPILOT.bat` in the main folder.
3. Select **Load Safe Demo** in the app.
4. Review Evidence, Timeline, Findings, Copilot, and Reports.

Manual setup:

```powershell
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python main.py
```

The first setup downloads free Python dependencies. Normal case analysis works
locally after installation. The app uses VirusTotal's official `yara-x`
package, which provides a prebuilt Windows wheel and does not require Microsoft
C++ Build Tools.

## Optional Groq configuration

Copy `.env.example` to `.env` and add the key:

```env
GROQ_API_KEY=your_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

Groq mode remains opt-in inside the Copilot page. Without a key, the offline
grounded assistant and every forensic feature continue to work.

## Safe command-line verification

Run the complete demo analysis, grounded query, and report generation in an
isolated temporary directory:

```powershell
python main.py --self-check
```

Run automated tests:

```powershell
python -m unittest discover -s tests -v
```

## Build the Windows application

Double-click `BUILD_EXE.bat` in the main folder, or run:

```text
scripts\build_windows.bat
```

The output is:

```text
dist\DFIR-Copilot\DFIR-Copilot.exe
```

PyInstaller builds for the operating system on which it runs, so the Windows
`.exe` must be produced on Windows.

## Evidence formats

| Format | Handling |
|---|---|
| Any file | Preserve, hash, verify, record metadata |
| `.evtx` | Parse Windows event records when `python-evtx` is installed |
| `.json` / `.jsonl` | Import structured timestamped artifacts |
| `.csv` | Import generic or Autopsy-style records |
| Files scanned by YARA-X | Store rule, severity, description, and MITRE ID |
| `.img` / `.raw` / `.E01` | Preserve and hash; import Autopsy/FTK exports for deep analysis |

Deep disk-image extraction is intentionally delegated to Autopsy or FTK
Imager. This design remains reliable on an 8 GB student laptop while retaining
a realistic forensic workflow.

## Project structure

```text
DFIR-Copilot/
├── main.py
├── src/dfir_copilot/
│   ├── engine/       # Hashing, parsers, YARA-X, correlation
│   ├── services/     # Cases, Copilot, reports, demo
│   └── ui/           # PySide6 desktop workbench
├── resources/rules/  # Safe YARA-X-compatible rules
├── demo_evidence/    # Synthetic training case
├── tests/            # End-to-end integrity tests
├── docs/             # Architecture and demo guide
└── scripts/          # Windows run/build/verify helpers
```

## Tests cover

- SHA-256 change detection
- Complete demo ingestion and correlation
- Download → PowerShell → network finding
- Deleted-file / anti-forensic finding
- Evidence-cited offline Copilot answers
- Tamper detection that stops analysis
- PDF, HTML, and JSON report generation

## Portfolio description

> Built a local-first PySide6 digital forensics workbench that preserves and
> SHA-256-verifies evidence, parses Windows/Autopsy artifacts, applies YARA-X and
> MITRE-mapped correlations, reconstructs incident timelines, and produces
> evidence-cited AI assistance plus chain-of-custody reports.

See [Architecture](docs/ARCHITECTURE.md), [Demo Guide](docs/DEMO_GUIDE.md), and
[Security Model](SECURITY.md). A verified synthetic output is included as
[Sample PDF Report](samples/DFIR-Copilot-Sample-Report.pdf) and
[Sample HTML Report](samples/DFIR-Copilot-Sample-Report.html).

## License

MIT. Third-party tools and libraries retain their own licences.