# FindEvil

A multi-agent DFIR pipeline that ingests Windows memory dumps, disk images, registry hives, event logs, prefetch, and MFT/USN data; emits validated forensic claims; and builds a typed [Cognee](https://github.com/topoteretes/cognee) knowledge graph with full evidence provenance.

Built for the **SANS AI Hackathon**.

---

## Architecture

Three layers, never crossed:

| Layer | Where it lives | Who writes it |
|---|---|---|
| **Evidence** | Local directory — immutable raw files | external (you drop files in) |
| **Claims** | Markdown files with YAML frontmatter | domain agents |
| **Entities** | Cognee graph (typed nodes + edges, every one carrying `evidence_refs`) | orchestrator only — agents never touch Cognee |

```
                          ┌─────────────────┐
 evidence/new/   ────►   │   dispatcher    │   (orchestrator/main.py)
 (you drop here)         └────────┬────────┘
                                  │ filename heuristic
                ┌──────────┬──────┼──────┬──────────┬──────────┐
                ▼          ▼      ▼      ▼          ▼          ▼
            memory_agent  disk  registry evtx   prefetch    mft_agent
                │          │      │       │       │           │
                └──────────┴───── claims/todo/ ◄──┴───────────┘
                                  │
                                  ▼
                          ┌─────────────────┐
                          │  validator      │  self-correction loop
                          │  (verifies      │  (entity refs + property
                          │   evidence_refs)│   spot-checks)
                          └────────┬────────┘
                                   │
                          ┌────────┴────────┐
                          ▼                 ▼
                    claims/done/      claims/rejected/
                          │
                          ▼
                  extractor → Cognee graph
                          │
                          ▼
                  correlation_agent  (cross-domain pattern matching)
                          │
                          ▼
                   report_agent  →  reports/case_*.md
```

The orchestrator stays under 400 LOC by design — it dispatches, validates, and routes. All forensic logic lives in the per-domain agents. See [`SKILLS.md`](./SKILLS.md) for the full rules of the road.

---

## Installation

FindEvil is designed to run end-to-end on a stock **SANS SIFT Workstation** VM (Ubuntu 22.04, x86-64). SIFT ships with Volatility 3, EZ Tools, YARA, The Sleuth Kit, EWF tools, Plaso, and the .NET 6 runtime pre-installed at the paths FindEvil expects. On top of SIFT you install **Chisel**, this repo, the Python dependencies, and the YARA signature-base.

If you already have a working SIFT VM, skip to step 2.

### 1. Get SIFT Workstation

1. Request the SIFT VM download from <https://www.sans.org/tools/sift-workstation/> (free, requires a SANS account).
2. Import the supplied OVA into VMware Workstation/Fusion or VirtualBox. Recommended VM specs: **8 GB RAM, 4 CPU, 100+ GB disk** (E01 images are large).
3. Boot the VM. Default credentials: `sansforensics` / `forensics`. Open a terminal — your home is `/home/sansforensics`.
4. Verify the SIFT-bundled tools FindEvil depends on are present:

```bash
python3 /opt/volatility3-2.20.0/vol.py --help | head -1     # Volatility 3
/usr/local/bin/yara --version                                # YARA 4.x
fls -V && ewfmount -h | head -1                              # Sleuth Kit + EWF
dotnet --info | head -3                                      # .NET 6 runtime
log2timeline.py --version                                    # Plaso
ls /opt/zimmermantools/                                      # EZ Tools (RECmd, EvtxECmd, MFTECmd, …)
```

If any of these are missing, follow the [SIFT install guide](https://github.com/teamdfir/sift) before continuing. The exact paths FindEvil expects are listed in [Prerequisites reference](#prerequisites-reference) below.

### 2. Clone FindEvil and install Chisel

```bash
cd ~
git clone https://github.com/<you>/findevil.git
cd findevil

# Chisel — Rust-powered MCP server providing path-confined evidence reads.
# Grab the latest Linux x86_64 binary from the Chisel releases page:
#   https://github.com/ckanthony/Chisel/releases/latest
# Drop the binary into this repo's root and make it executable:
curl -L -o chisel \
  "$(curl -s https://api.github.com/repos/ckanthony/Chisel/releases/latest \
     | grep browser_download_url \
     | grep -E 'linux.*x86_64|linux-amd64' \
     | head -1 | cut -d\" -f4)"
chmod +x chisel
./chisel --help | head -3   # sanity check
```

To build Chisel from source instead: `git clone https://github.com/ckanthony/Chisel.git && cd Chisel && cargo build --release && cp target/release/chisel /path/to/findevil/`.

### 3. Python environment + dependencies

```bash
cd ~/findevil
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

This installs **[Cognee](https://github.com/topoteretes/cognee)** — the typed knowledge-graph backend the orchestrator extracts entities into — plus `python-dotenv`, `PyYAML`, `requests`, and the optional `anthropic` SDK (only used if you set `ANTHROPIC_API_KEY` later). Cognee runs entirely on-disk under `evidence/audit/<CASE_ID>/cognee_{system,data}` — no external service or API key required.

### 4. YARA signature-base

The YARA rule base is vendored separately (Detection Rule License 1.1 — kept out of this repo).

```bash
cd ~/findevil
git clone https://github.com/Neo23x0/signature-base rules/signature-base
yarac rules/signature-base/yara/*.yar rules/signature-base.compiled
```

### 5. Configure `.env`

```bash
cd ~/findevil
cp .env.example .env

# Generate and persist a fresh Chisel bearer-token secret
echo "CHISEL_SECRET=$(openssl rand -hex 24)" >> .env

# Optional: ANTHROPIC_API_KEY enables the LLM-polished CISO summary at the
# top of each case report. Without it the summary still renders with a
# deterministic prose template — genuinely optional.
# echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
```

If `CHISEL_SECRET` is unset when the orchestrator starts, agents fail fast with a `KeyError` at import time. This is intentional — a missing secret should never silently fall through to a default.

`.env.example` already includes the Cognee defaults that this pipeline depends on — leave them in place unless you know you need otherwise:

- `COGNEE_VECTOR_STORE=local` / `COGNEE_GRAPH_STORE=local` — pin Cognee to on-disk storage (no cloud).
- `ENABLE_BACKEND_ACCESS_CONTROL=false` — Cognee 1.0 defaults multi-user access control to on, which hides the orchestrator's ingested data from the unauthenticated web UI. Single-analyst workstation — keep this off so you can browse the case graph after a run.
- `SYSTEM_ROOT_DIRECTORY` / `DATA_ROOT_DIRECTORY` are **intentionally not in `.env`** — `orchestrator/main.py` sets them per-case at startup (one isolated graph + vector store per CASE_ID under `evidence/audit/`).

### 6. Smoke check

```bash
# Terminal A — start Chisel, confined to the evidence root
cd ~/findevil
./chisel --root "$PWD/evidence" --secret "$(grep ^CHISEL_SECRET .env | cut -d= -f2)"
```

**Watch the `--root` carefully** — it must resolve to `~/findevil/evidence`, not a doubled path like `~/findevil/findevil/evidence`. A wrong `--root` causes every forensic-tool call to fail with `security error: resolved path … is outside configured root`.

```bash
# Terminal B — sanity-import the orchestrator
cd ~/findevil
source .venv/bin/activate
python -c "import orchestrator.main; print('OK')"
```

You should see the orchestrator import without error and print a `CASE_ID=…` line. You're ready to run a case (see [Running a case](#running-a-case) below).

---

## Prerequisites reference

Tool paths FindEvil expects. All defaults match a stock SIFT Workstation install:

| Tool | Where FindEvil expects it | Notes |
|---|---|---|
| Python | 3.10+ | |
| Volatility 3 | `python3 /opt/volatility3-2.20.0/vol.py` | Memory analysis. NOT `/usr/local/bin/vol.py` (that's Vol2). |
| EWF tools | `ewfmount`, `ewfinfo` (system PATH) | Mount `.E01` images. |
| YARA | `/usr/local/bin/yara`, `yarac` (4.x) | Memory + file scanning. |
| The Sleuth Kit | `fls`, `icat`, `mmls`, `fsstat` (system PATH) | Disk image traversal. |
| EZ Tools (.NET 6 runtime) | `dotnet /opt/zimmermantools/<Tool>.dll` | RECmd, EvtxECmd, MFTECmd, RBCmd, AppCompatCacheParser, AmcacheParser. |
| Plaso | `log2timeline.py`, `psort.py` | Timeline cross-checks. |
| Chisel MCP | `./chisel` (this repo root), HTTP at `127.0.0.1:3000` | Path-confined evidence reads. |

### Forensic-tool execution audit log

Every forensic-tool invocation (`vol`, `dotnet EvtxECmd.dll`, `log2timeline.py`, `psort.py`, `ewfmount`, `fls`, `icat`, `mmls`, `fsstat`, `dotnet RECmd.dll`, `dotnet MFTECmd.dll`, `dotnet RBCmd.dll`, `dotnet AppCompatCacheParser.dll`, `dotnet AmcacheParser.dll`) is routed through Chisel's `shell_exec` allowlist and logged to `evidence/audit/chisel_exec_<YYYYMMDD>.jsonl` (one record per invocation: timestamp, agent, tool, args, exit_code, stdout_bytes, stderr_summary, elapsed_ms).

The audit log answers "what did this case actually run?" with one `cat`. The Chisel server's command allowlist is the source of truth for which tools agents are permitted to invoke (see `chisel-core/src/ops/shell.rs:WHITELIST`). Adding a new forensic tool requires both adding it to the allowlist AND adding the agent code that invokes it.

---

## Running a case

```bash
# 1. Drop evidence into evidence/new/. The dispatcher routes by filename:
cp /path/to/memdump.raw          evidence/new/
cp /path/to/disk.E01             evidence/new/
cp /path/to/SYSTEM               evidence/new/
cp /path/to/Security.evtx        evidence/new/
cp /path/to/PREFETCH.pf          evidence/new/
cp /path/to/'$MFT'               evidence/new/__mft__\$MFT
cp /path/to/'$J'                 evidence/new/__usnjrnl__\$J

# 2. Run the orchestrator (Terminal B; Chisel must be running in Terminal A)
python -m orchestrator.main

# 3. Read the report
ls -t reports/case_*.md | head -1
```

### Orchestrator CLI flags

| Flag | Effect |
|---|---|
| *(none)* | One-shot: process all pending evidence, settle (30 s of inactivity), generate report, exit. |
| `--watch` | Watch forever (legacy; no settle-detection, no report). |
| `--quiet-period N` | Seconds of inactivity required to declare the pipeline settled (default 30). |

### Filename routing

The dispatcher in `orchestrator/main.py:124-220` routes by filename heuristic:

| Pattern | Agent |
|---|---|
| `*baseline*` | registered to `evidence/baselines/` (used by memory_agent for diff) |
| `*.E01`, `*.Ex01` | disk_image_agent (mounts + extracts hives → re-queues into `evidence/new/`) |
| `*.evtx`, `__evtx_*` | evtx_agent |
| `__mft__*`, `*$MFT`, `__usnjrnl__*`, `*$J`, `__recycle__*` | mft_agent |
| `*.pf`, `__prefetch__*` | prefetch_agent |
| Registry hives (auto-detected by header) | registry_agent |
| anything else | memory_agent |

---

## Browse the case graph (Cognee web UI)

Every run produces two queryable artifacts: the Markdown report under `reports/` and a **typed knowledge graph** under `evidence/audit/<CASE_ID>/cognee_{system,data}` (one isolated graph per case, Kuzu-backed). The report is the executive view; the graph is the analyst's view — every node carries `evidence_refs` back to the raw artifact it was extracted from.

Open an archived case in the Cognee web UI:

```bash
# Stop Chisel first — Cognee's frontend also wants port 3000
# (in the Chisel terminal: Ctrl-C)

cd ~/findevil
source .venv/bin/activate
scripts/open_case_in_cognee.sh <CASE_ID>      # e.g. 20260606_191903
```

The script exports the per-case `SYSTEM_ROOT_DIRECTORY` / `DATA_ROOT_DIRECTORY`, launches Cognee's backend on `http://localhost:8000`, frontend on `http://localhost:3000`, and opens your browser. Ctrl-C tears down both. Running it with no arguments lists available CASE_IDs.

The graph is typed via `cognee_schema/schema.py` — Process, RegistryKey, Event, ProcessExecution, File, Service nodes with provenance-mandatory `evidence_refs`, connected by typed edges (`EXECUTED`, `WROTE_REGISTRY`, `LOADED_DLL`, etc., each carrying `confidence` and `derived_from`). The exact shape is the contract: agents emit claims, the orchestrator deterministically extracts entities, no LLM in the structured-data path.

---

## Project layout

```
.
├── orchestrator/           # Thin dispatcher + validator + extractor (<400 LOC)
│   ├── main.py             # CLI entrypoint
│   ├── watcher.py          # Watches evidence/new/ and claims/todo/
│   ├── validator.py        # Self-correction loop (evidence ref + property checks)
│   └── extractor.py        # Deterministic claim → Cognee entity extraction
├── agents/                 # One agent per forensic domain
│   ├── _chisel.py          # Shared MCP-over-HTTP client for Chisel
│   ├── memory_agent/       # Volatility 3: pslist, psscan, malfind, netscan, dlllist
│   ├── disk_image_agent/   # ewfmount + Sleuth Kit hive extraction
│   ├── registry_agent/     # RECmd / AppCompat / Amcache parsing
│   ├── evtx_agent/         # EvtxECmd: security events, logons, service creation
│   ├── prefetch_agent/     # pyscca: execution timeline + last run times
│   ├── mft_agent/          # MFTECmd + RBCmd: file activity + recycle bin
│   ├── correlation_agent/  # Cross-domain pattern matching (Tier A/B/C)
│   └── report_agent/       # Markdown report + MITRE ATT&CK + graph viz
├── cognee_schema/
│   └── schema.py           # Pydantic typed nodes + edges; provenance-required
├── rules/                  # YARA rules (clone signature-base separately — see Setup)
├── evidence/               # Per-case input (gitignored)
├── reports/                # Generated case reports (gitignored)
└── SKILLS.md               # Per-domain forensic skill loaded by the agents at runtime
```

---

## Output

Each run produces two artifacts:

**1. Markdown case report** — `reports/case_YYYYMMDD_HHMMSS.md`

- **CISO summary** (one-paragraph plain-English briefing + risk/confidence/next-steps for non-technical leadership; LLM-polished if `ANTHROPIC_API_KEY` is set, deterministic prose otherwise)
- Executive summary (Tier-A correlations: cross-domain, ≥0.95 confidence)
- Domain sections (Tier-B: high-confidence single-domain findings)
- Appendix (Tier-C: recurring / lower-confidence)
- MITRE ATT&CK technique mapping
- Graph visualization (`reports/case_graph_*.html`) — interactive, filterable, self-contained HTML

**2. Cognee knowledge graph** — `evidence/audit/<CASE_ID>/cognee_{system,data}/`

The full typed graph: every Process / RegistryKey / Event / ProcessExecution / File / Service node with provenance back to the raw artifact, plus typed edges with `confidence` + `derived_from`. Browse it in the Cognee web UI via [`scripts/open_case_in_cognee.sh`](#browse-the-case-graph-cognee-web-ui), or query it directly with Cognee's Python API.

---

## Architectural rules

Four guarantees the pipeline enforces (via Chisel, the orchestrator, and the validator — not via agent self-discipline):

- **Three-layer separation.** Agents never write to Cognee — they only emit Markdown claims. Orchestrator never runs forensic logic — it only dispatches, validates, and extracts.
- **Entity extraction is deterministic Python only.** No LLM in the structured-data path.
- **Every claim must self-validate** — every cited `evidence_ref` must exist on disk; every asserted entity property must match the source.
- **Orchestrator stays thin.** Target <400 LOC across `orchestrator/`.

The agents themselves load [`SKILLS.md`](./SKILLS.md) — a per-domain forensic playbook covering the tools each agent owns, the standard triage sweep, "when you see X, pivot to Y" signals, and the cross-source corroboration patterns that drive Tier A confidence. That's where the forensic *intelligence* of this pipeline lives.

---

## Credits

- **SANS AI Hackathon** — challenge framing + sample case data
- [`Neo23x0/signature-base`](https://github.com/Neo23x0/signature-base) — YARA rule base (Detection Rule License 1.1)
- [`Cognee`](https://github.com/topoteretes/cognee) — typed knowledge-graph backend
- [Volatility Foundation](https://www.volatilityfoundation.org/) — memory analysis
- [Eric Zimmerman tools](https://ericzimmerman.github.io/) — registry / EVTX / MFT parsers

---

## License

Released under the MIT License. See [`LICENSE`](./LICENSE).
