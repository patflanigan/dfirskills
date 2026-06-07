# dfirskills

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

The orchestrator dispatches, validates, and routes. All forensic logic lives in the per-domain agents. 

---

## Installation

dfirskills is designed to run end-to-end on a stock **SANS SIFT Workstation** VM (Ubuntu 22.04, x86-64). SIFT ships with Volatility 3, EZ Tools, YARA, The Sleuth Kit, EWF tools, Plaso, and the .NET 6 runtime pre-installed at the paths dfirskills expects. On top of SIFT you install Cognee, this repo, the Python dependencies, and the YARA signature-base.

If you already have a working SIFT VM, skip to step 2.

### 1. Get SIFT Workstation

1. Request the SIFT VM download from <https://www.sans.org/tools/sift-workstation/> 
2. Import the supplied OVA into VMware Workstation/Fusion or VirtualBox. Recommended VM specs: **8 GB RAM, 4 CPU, 100+ GB disk** (E01 images are large).
3. Boot the VM. Default credentials: `sansforensics` / `forensics`. Open a terminal — your home is `/home/sansforensics`.
4. Ensure protocol SIFT is installed
   `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`

If any of these are missing, follow the [SIFT install guide](https://github.com/teamdfir/sift) before continuing. 

### 2. Clone dfirskills 
```bash
git clone https://github.com/patflanigan/dfirskills.git
cd dfirskills

dfirskills includes a forked custom compiled version of Chisel — Rust-powered MCP server providing path-confined evidence reads.
 -> reference https://github.com/ckanthony/Chisel
/Chisel/chisel-core/src/ops/shell.rs creates command restrictions to the following tools

const WHITELIST: &[&str] = &[
    "grep", "sed", "awk", "find", "cat", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "diff",
    "file", "stat", "ls", "du",
    // ← Your DFIR tools go here
    "log2timeline.py",
	"psort.py",
	"pinfo.py",
	"image_export.py",
	"mactime",
	"fls",
	"ils",
	"icat",
	"istat",
	"ifind",
	"ffind",
	"fsstat",
	"blkcat",
	"blkls",
	"blkstat",
	"blkcalc",
	"mmls",
	"mmstat",
	"mmcat",
	"tsk_recover",
	"sorter",
	"sigfind",
	"jls",
	"jcat",
	"hfind",
	"ewfmount",
	"vshadowmount",
	"bdemount",
	"xmount",
	"imagemounter",
	"mount_ewf.py",
	"qemu-nbd",
	"partprobe",
	"mount",
	"umount",
	"losetup",
	"volatility",
	"vol.py",
	"vol",
	"rekall",
	"dotnet",
	"mftecmd",
	"evtxecmd",
	"recmd",
	"pecmd",
	"amcacheparser",
	"appcompatcacheparser",
	"jlecmd",
	"lecmd",
	"sqlecmd",
	"srumecmd",
	"vtecmd",
	"rbcmd",
	"bstrings",
	"rip.pl",
	"regripper",
	"bulk_extractor",
	"foremost",
	"photorec",
	"scalpel",
	"strings",
	"floss",
	"tshark",
	"tcpdump",
	"ngrep",
	"tcpxtract",
	"exiftool",
	"yara",
	"clamscan",
	"hayabusa",
	"md5sum",
	"sha1sum",
	"sha256sum",
	"sha512sum",
	"ssdeep",
	"md5deep",
	"echo",
	"printf",
	"ls",
	"cat",
	"grep",
	"rg",
	"find",
	"file",
	"stat",
	"hexdump",
	"xxd",
	"head",
	"tail",
	"less",
	"awk",
	"sed",
	"sort",
	"uniq",
	"wc",
        "yara",
        "yarac",
        "fusermount",
];

```

To build Chisel from source instead: `git clone https://github.com/ckanthony/Chisel.git 
add the above allow lists
&& cd Chisel && cargo build --release && cp target/release/chisel /path/to/dfirskills/`.

### 3. Python environment + dependencies

```bash
cd ~/dfirskills
sudo apt install python3.12-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt --break-system-packages
```

This installs **[Cognee](https://github.com/topoteretes/cognee)** — the typed knowledge-graph backend the orchestrator extracts entities into — plus `python-dotenv`, `PyYAML`, `requests`, and the optional `anthropic` SDK (only used if you set `ANTHROPIC_API_KEY` later). Cognee runs entirely on-disk under `evidence/audit/<CASE_ID>/cognee_{system,data}` — no external service or API key required.

### 4. YARA signature-base

The YARA rule base is vendored separately (Detection Rule License 1.1 — kept out of this repo).

```bash
cd ~/dfirskills
sudo apt install yara
git clone https://github.com/Neo23x0/signature-base rules/signature-base
yarac rules/signature-base/yara/*.yar rules/signature-base.compiled
```

### 5. Configure `.env`

```bash
cd ~/dfirskills
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
- `SYSTEM_ROOT_DIRECTORY` / `DATA_ROOT_DIRECTORY` are **intentionally not in `.env`** — `orchestrator/main.py` sets them per-case at startup (one isolated graph + vector store per CASE_ID under `evidence/audit/`).

### 6. Smoke check

```bash
# Terminal A — start Chisel, confined to the evidence root
cd ~/dfirskills
./chisel --root "$PWD/evidence" --secret "$(grep ^CHISEL_SECRET .env | cut -d= -f2)"
```

**Watch the `--root` carefully** — it must resolve to `~/dfirskills/evidence. A wrong `--root` causes every forensic-tool call to fail with `security error: resolved path … is outside configured root`.

```bash
# Terminal B — sanity-import the orchestrator
cd ~/dfirskills
source .venv/bin/activate
python -c "import orchestrator.main; print('OK')"
```

You should see the orchestrator import without error and print a `CASE_ID=…` line. You're ready to run a case (see [Running a case](#running-a-case) below).

---

### Forensic-tool execution audit log

Every forensic-tool invocation is routed through Chisel's `shell_exec` allowlist and logged to `evidence/audit/chisel_exec_<YYYYMMDD>.jsonl` (one record per invocation: timestamp, agent, tool, args, exit_code, stdout_bytes, stderr_summary, elapsed_ms).

The audit log answers "what did this case actually run?" with one `cat`. The Chisel server's command allowlist is the source of truth for which tools agents are permitted to invoke (see `chisel-core/src/ops/shell.rs:WHITELIST`). Adding a new forensic tool requires both adding it to the allowlist AND adding the agent code that invokes it.

---

## Running a case

```bash
# 1. Drop evidence into evidence/new/. The dispatcher routes by filename:
memdump.raw   ->       evidence/new/
disk.E01      ->       evidence/new/
SYSTEM        ->       evidence/new/
Security.evtx ->       evidence/new/
PREFETCH.pf   ->       evidence/new/
'$MFT'        ->       evidence/new/__mft__\$MFT
'$J'          ->       evidence/new/__usnjrnl__\$J

# 2. Run the orchestrator (Terminal B; Chisel must be running in Terminal A)
python -u -m orchestrator.main

# 3. Once the orchestration and agents are finished. Read the report under 
~/dfirskills2/reports
```

### Orchestrator CLI flags

| Flag | Effect |
|---|---|
| *(none)* | One-shot: process all pending evidence, settle (30 s of inactivity), generate report, exit. |
| `--watch` | Watch forever (legacy; no settle-detection, no report). |
| `--quiet-period N` | Seconds of inactivity required to declare the pipeline settled (default 30). |
| `--no-analyst` | Skip the LLM-driven forensic analyst deep-dive pass. Default: analyst runs after plaso. |

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

## Browse the case graph (Cognee html report)

Every run produces html graph under `reports/` and a **typed knowledge graph** under `evidence/audit/<CASE_ID>/cognee_{system,data}` (one isolated graph per case, Kuzu-backed). The report is the executive view; the graph is the analyst's view — every node carries `evidence_refs` back to the raw artifact it was extracted from.

```
The graph is typed via `cognee_schema/schema.py` — Process, RegistryKey, Event, ProcessExecution, File, Service nodes with provenance-mandatory `evidence_refs`, connected by typed edges (`EXECUTED`, `WROTE_REGISTRY`, `LOADED_DLL`, etc., each carrying `confidence` and `derived_from`). The exact shape is the contract: agents emit claims, the orchestrator deterministically extracts entities, no LLM in the structured-data path.
---

## Project layout
```
.
├── orchestrator/           # Thin dispatcher + validator + extractor  
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
├── evidence/               # Per-case evidence
├── reports/                # Generated case reports
└── SKILLS.md               # Per-domain forensic skill loaded by the agents at runtime
```

---

## Output

Each run produces two artifacts:

**1. Markdown case report** — `reports/case_YYYYMMDD_HHMMSS.md`

- **CISO summary** (one-paragraph plain-English briefing + risk/confidence/next-steps for non-technical leadership)
- Executive summary (Tier-A correlations: cross-domain, ≥0.95 confidence)
- Domain sections (Tier-B: high-confidence single-domain findings)
- Appendix (Tier-C: recurring / lower-confidence)
- MITRE ATT&CK technique mapping
- Graph visualization (`reports/case_graph_*.html`) — interactive, filterable, self-contained HTML

---

## Architectural rules

Four guarantees the pipeline enforces (via Chisel, the orchestrator, and the validator — not via agent self-discipline):

- **Three-layer separation.** Agents never write to Cognee — they only emit Markdown claims. Orchestrator never runs forensic logic — it only dispatches, validates, and extracts.
- **Entity extraction is deterministic Python only.** No LLM in the structured-data path.
- **Every claim must self-validate** — every cited `evidence_ref` must exist on disk; every asserted entity property must match the source.

The agents themselves load [`SKILLS.md`](./SKILLS.md) — a per-domain forensic playbook covering the tools each agent owns, the standard triage sweep, "when you see X, pivot to Y" signals, and the cross-source corroboration patterns that drive Tier A confidence. That's where the forensic *intelligence* of this pipeline lives.

---


## MIT License

Released under the MIT License. See [`LICENSE`](./LICENSE).
