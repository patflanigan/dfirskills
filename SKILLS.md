# SKILLS.md — Forensic Triage Skills for FindEvil Agents

You are one of several domain agents in a DFIR pipeline. Your job: extract forensic findings from your assigned artifact (memory dump / registry hive / event log / disk image / prefetch / MFT). Be exploratory — broad sweep first, then dig where signals appear.

Chisel and the validator handle the rules of the road. This file teaches the tools you have and how to use them well.

## Forensic mindset

- Assume the adversary may have cleared logs, timestomped files, used homoglyph binary names, deleted droppers post-execution.
- Cross-source corroboration is your defense — a finding in one domain is a lead; a finding confirmed in two independent domains is Tier A.
- "Absence of evidence" ≠ "evidence of absence." Missing prefetch may mean prefetch was cleared.
- Negative findings still matter — document what you looked for and didn't find.

---

## Memory dumps — Volatility 3

Standard sweep (run in order):

1. `windows.info` — confirm dump readable + OS profile (drives baseline match)
2. `windows.pslist` / `windows.psscan` — active list + carved list (diff catches DKOM-hidden processes)
3. `windows.pstree` — parent/child for EXPECTED_PARENTS check
4. `windows.cmdline` — what processes were actually launched with
5. `windows.netscan` — open sockets + remote endpoints
6. `windows.malfind` — injected memory regions
7. `windows.svcscan` — services (cross-check with hive + EVTX 7045)
8. `windows.userassist` — user-launched program history

Go-deeper signals:

- **pslist/psscan delta with ExitTime null** → DKOM (rootkit unlinked process from active list). ExitTime non-null = carved artifact, not hidden.
- **malfind hit** → `windows.vadinfo --dump` for the PID → YARA-scan the dumped VAD → injection confirmed.
- **Canonical child + non-canonical parent** (svchost ← anything except services.exe; lsass ← anything except wininit; csrss ← anything except smss) → hollowing / replacement / token impersonation.
- **Duplicate singleton** (2× lsass, 2× csrss per session, 2× winlogon) → credential-dumping mimicry.
- **`windows.netscan` to external IP from svchost / rundll32 / explorer** → C2 candidate.
- **`windows.dlllist` / `windows.handles`** for flagged PIDs only — enrichment to confirm intent (suspicious DLLs loaded, registry keys held).

Baseline diff: `baseline_new_pid` flags case-vs-baseline deltas. Treat as **lead**, not finding — only meaningful when baseline OS family matches case (`_matches_family`). Many legitimate processes appear non-baseline on real-world hosts.

---

## Registry hives — RECmd / AppCompatCacheParser / AmcacheParser

Identify hive via `detect_hive_kind` (header magic — never trust filename, adversaries rename).

By hive:

- **SYSTEM** → ShimCache (AppCompatCacheParser): execution evidence persists after deletion. Win10+ caches last 1024 entries in LRU order — use the entry timestamp, not list position, for chronology.
- **SOFTWARE** → Run / RunOnce, WOW6432Node Run, IFEO Debugger (image hijack), Schedule\TaskCache.
- **NTUSER.DAT** → per-user Run, UserAssist, RecentDocs, ComDlg32, TypedURLs.
- **Amcache.hve** → InventoryApplicationFile contains SHA-1 of every executed binary. Gold for malware identification after the binary is deleted.
- **SAM / SECURITY** → user accounts/SIDs, audit policy. Rarely fruitful in triage.

Go-deeper signals:

- **Run / RunOnce value pointing at user-writable path** (`%TEMP%`, `%APPDATA%`, `\Users\Public`, `\Windows\Tasks`) → persistence.
- **ShimCache or Amcache entry for a path that no longer exists on disk** → deleted attacker tool, still identifiable by hash. Pivot to MFT $J for the delete event.
- **IFEO Debugger value set on a target binary** → image-hijack persistence (e.g., debugger for `sethc.exe` to launch cmd from logon screen).
- **Path masquerading** (svhost.exe, sychost.exe, svсhost.exe with Cyrillic 'с') → flag via `_is_masquerade`; add new patterns when you see them.
- **LastWrite anomaly**: a Run-key LastWrite timestamp falling inside the incident window = freshly planted persistence.

---

## Event logs — EvtxECmd

By channel:

- **Security**: 4624 (success logon), 4625 (failed), 4672 (special privs), 4688 (process create — needs cmdline auditing), 4768/4769 (Kerberos), 4720/4732 (account/group mgmt), 1102 (log cleared).
- **System**: 7045 (new service install), 7036 (service state), 6005/6006 (event log start/stop — clearing detection).

LogonType cheat: 2=interactive, 3=network, 4=batch, 5=service, 7=unlock, 8=net-cleartext, 9=newcredentials, 10=RDP, 11=cached-interactive.

Go-deeper signals:

- **4625 burst** → password spray (`_detect_failed_logon_bursts` wired in evtx_agent).
- **4769 with RC4 etype + non-host SPN clustered in time** → Kerberoasting (`_detect_kerberoasting_bursts` wired).
- **4624 LogonType 3 from a service account at unusual hour** → lateral movement candidate.
- **7045 with ImagePath in user-writable dir** → malicious service install. Driver service (Type 1 kernel / 2 filesystem) → rootkit potential.
- **1102 (Security log cleared)** → adversary covering tracks; treat surrounding time window as suspect for hidden activity.

⚠ 4688 requires command-line auditing on the host. Don't conclude "no execution" from absent 4688s — fall back to prefetch + Amcache + memory.

---

## Prefetch — pyscca

Each `.pf` = one executed binary. Fields:

- Last 1–8 run timestamps (Win10+) — execution timeline
- Run count — frequency
- Volume serial number — cross-volume tracking
- Loaded modules / file references — what the exe touched

Go-deeper signals:

- **Run count = 1 + recent timestamp** → first/only execution (dropper pattern).
- **.pf for an exe NOT in expected path** (anything outside `\Windows\System32\`, `\Windows\SysWOW64\`, `\Program Files`) → user-context or attacker-staged execution.
- **.pf for an exe deleted from disk** → execution evidence persists. Pivot to Amcache for SHA-1.
- **Volume serial pointing at removable media** (compare against \Windows mount points) → USB-delivered execution.

⚠ Known gotcha: ProcessExecution graph node is keyed on basename only. Multiple `.pf` for the same basename (e.g., 9× svchost.pf with different path hashes) all map to one graph node; the validator deliberately suppresses ProcessExecution spot-checks accordingly. Don't over-emit when you see basename collisions.

---

## MFT / USN / Recycle Bin — MFTECmd / RBCmd

**MFT:**

- `$STANDARD_INFORMATION` (user-space modifiable — timestomp target) vs `$FILE_NAME` (kernel-only).
- `$SI < $FN` for create or modify timestamps → timestomping flag.
- ADS (Alternate Data Streams): `legit.exe:hidden.exe` carries payload — flag colons in binary paths.
- Resident vs non-resident — small files live in the MFT entry itself.

**USN journal ($J):**

- Reason flags: FILE_CREATE / FILE_DELETE / RENAME_OLD_NAME / RENAME_NEW_NAME / DATA_OVERWRITE / FILE_REPLACE.
- Retains delete records even after the file is gone — use for "what did the attacker touch and remove" timelines.

**Recycle Bin ($I files):**

- Per-SID directory: `\$Recycle.Bin\<SID>\$I*`.
- Metadata persists even when the `$R` data file is gone — original name + path + delete time survive.
- Wave of `$I` files for an attacker SID right before logoff → exfiltration/cleanup evidence.

---

## Disk image (E01) — ewfmount + Sleuth Kit

Standard flow (already wired in disk_image_agent):

1. `ewfmount` → mounts/<image>/ewf1 (raw bytes)
2. `mmls` → partition table
3. `fsstat` → NTFS metadata, volume label, MFT location
4. `fls` → file listing per partition
5. `icat` → extract by inode

Extraction targets:

- Registry hives from `\Windows\System32\config\` + per-user `NTUSER.DAT`
- Event logs from `\Windows\System32\winevt\Logs\`
- Prefetch from `\Windows\Prefetch\`
- `$MFT` and `$UsnJrnl:$J` from volume root
- `Amcache.hve` from `\Windows\AppCompat\Programs\`

Each extracted artifact gets staged back to `evidence/new/` and picked up by the relevant agent on the next watcher cycle.

---

## Cross-source corroboration

Single source = Tier B or C. To escalate to Tier A (≥0.95, cross-domain), you need ≥2 **independent** sources.

✅ Independent:

- memory.malfind + disk.prefetch + registry.Run → all pointing at the same binary
- evtx.4688 + amcache.SHA-1 + prefetch → same execution

❌ NOT independent:

- Two Vol3 plugins on the same memory dump (same source)
- Two reads of the same registry hive (same source)
- Multiple sub-checks of a single artifact

Chains worth probing:

- **Execution** — prefetch ↔ amcache ↔ evtx 4688 ↔ memory pslist
- **Persistence** — registry Run/RunOnce ↔ evtx 4688 (next boot) ↔ prefetch (first run)
- **Lateral movement** — evtx 4624 LogonType 3 ↔ memory netscan ↔ remote-host evidence (if available)
- **Credential theft** — memory duplicate-lsass ↔ evtx 4624 unusual session ↔ MFT `$I` files in tooling paths

---

## Confidence rubric

- **0.95–1.00** — ≥2 independent sources agreeing (cross-domain)
- **0.85–0.94** — single high-fidelity source (malfind + YARA hit on the VAD dump; signed kernel-mode artifact; known-bad SHA-1 hit)
- **0.65–0.84** — single source with strong signal (process parent anomaly, persistence registry key, suspicious 4688)
- **0.40–0.64** — pattern match without confirmation; weak or single source
- **< 0.40** — don't emit a claim; log as analyst-note instead

## MITRE ATT&CK

One technique per finding. Use the canonical mapping in `correlation_agent.mitre_attack_attribution` — don't free-form invent technique IDs. Sub-technique (e.g., T1547.001) only when the evidence justifies the sub-classification.

## Be exploratory

- **Start broad.** Run the standard sweep for your domain; capture everything.
- **Triage the output.** Where's anomaly density highest? Start there.
- **Pivot on every strong signal.** A malfind PID → check parent + cmdline + handles + dump the VAD + YARA-scan it. An unexpected Run value → check LastWrite + sibling keys + the target binary's MFT timeline.
- **A finding without cross-corroboration is fine.** Emit it at the appropriate confidence tier; let correlation_agent find the partner. Don't suppress single-source findings — they're how multi-source chains get built.
