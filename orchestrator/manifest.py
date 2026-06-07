# orchestrator/manifest.py
"""
Evidence integrity manifest — pre/post run SHA256 chain-of-custody.

Pre-run: walks evidence/new/ at orchestrator startup, hashes every file,
emits evidence_manifest_pre.json under the per-case audit dir.

Post-run: re-hashes each pre-manifest file (searching new/, processed/,
baselines/ since the orchestrator's directory state machine moves files
from new/ to processed/ on successful dispatch), emits
evidence_manifest_post.json with a status field per file.

Status values:
  UNCHANGED — pre/post SHA256s match
  MODIFIED  — file found but contents changed
  MISSING   — file from pre-manifest no longer exists anywhere
"""

import hashlib
import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Iterable

CHUNK = 1 << 20  # 1 MiB
MANIFEST_TOOL = "findevil-orchestrator/0.1"
ALGORITHM = "sha256"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def _iter_files(root: Path) -> Iterable[Path]:
    # Skip dotfiles and any nested dir — evidence/new/ should be flat top-level files.
    for p in sorted(root.iterdir()):
        if p.is_file() and not p.name.startswith("."):
            yield p


def _file_entry(path: Path, evidence_root: Path) -> dict:
    stat = path.stat()
    return {
        "original_path": str(path.relative_to(evidence_root.parent)),
        "size_bytes": stat.st_size,
        "sha256": _sha256(path),
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
    }


def write_initial_manifest(case_id: str, evidence_new_dir: Path, audit_dir: Path) -> tuple[Path, int]:
    """Hash every file in evidence/new/ and write evidence_manifest_pre.json.
    Returns (manifest_path, file_count). Always writes — even if no files."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    evidence_root = evidence_new_dir.parent
    files = [_file_entry(p, evidence_root) for p in _iter_files(evidence_new_dir)]
    manifest = {
        "case_id": case_id,
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "tool": MANIFEST_TOOL,
        "algorithm": ALGORITHM,
        "files": files,
    }
    out = audit_dir / "evidence_manifest_pre.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out, len(files)


def _locate(filename: str, evidence_root: Path) -> Path | None:
    # Search subdirs in the order files can travel through the pipeline.
    for sub in ("new", "processed", "baselines"):
        candidate = evidence_root / sub / filename
        if candidate.is_file():
            return candidate
    return None


def verify_and_write_final_manifest(case_id: str, audit_dir: Path, evidence_root: Path) -> dict:
    """Re-hash each file from the pre-manifest and write evidence_manifest_post.json.
    Returns a summary dict: {checked, unchanged, modified, missing, files: [...]}."""
    pre_path = audit_dir / "evidence_manifest_pre.json"
    if not pre_path.is_file():
        # Nothing to verify — pre-manifest never written (orchestrator started with no evidence).
        summary = {"checked": 0, "unchanged": 0, "modified": 0, "missing": 0, "files": []}
        (audit_dir / "evidence_manifest_post.json").write_text(
            json.dumps({"case_id": case_id, "summary": summary, "note": "no pre-manifest"}, indent=2),
            encoding="utf-8",
        )
        return summary

    pre = json.loads(pre_path.read_text(encoding="utf-8"))
    results = []
    counts = {"unchanged": 0, "modified": 0, "missing": 0}
    for entry in pre["files"]:
        filename = Path(entry["original_path"]).name
        found = _locate(filename, evidence_root)
        if found is None:
            status = "MISSING"
            verification = {"found_at": None, "size_bytes_now": None, "sha256_now": None, "status": status}
        else:
            sha = _sha256(found)
            size = found.stat().st_size
            status = "UNCHANGED" if sha == entry["sha256"] else "MODIFIED"
            verification = {
                "found_at": str(found.relative_to(evidence_root.parent)),
                "size_bytes_now": size,
                "sha256_now": sha,
                "status": status,
            }
        counts[status.lower()] += 1
        results.append({**entry, "verification": verification})

    summary = {
        "checked": len(results),
        "unchanged": counts["unchanged"],
        "modified": counts["modified"],
        "missing": counts["missing"],
    }
    post = {
        "case_id": case_id,
        "verified_at_utc": datetime.now(UTC).isoformat(),
        "tool": MANIFEST_TOOL,
        "algorithm": ALGORITHM,
        "summary": summary,
        "files": results,
    }
    (audit_dir / "evidence_manifest_post.json").write_text(json.dumps(post, indent=2), encoding="utf-8")
    return {**summary, "files": results}
