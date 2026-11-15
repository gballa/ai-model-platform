"""Vulnerability Intelligence MCP Server & Authorized Pentest Scope Guard.

Implements offline/mirror-first CVE, OSV, NVD, CISA KEV, FIRST EPSS, and CWE
correlation, polyglot SBOM/manifest parsing, confirmed-vs-weakness epistemic
classification, and fail-closed Rules-of-Engagement enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import threading
import tomllib
from typing import Any, Callable, Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .mcp_tools import CPGVulnerabilityFinding


class VulnFindingClassification(str, Enum):
    """Distinguishes verified vulnerabilities from potential weaknesses."""

    CONFIRMED_VULNERABILITY = "CONFIRMED_VULNERABILITY"
    POTENTIAL_WEAKNESS = "POTENTIAL_WEAKNESS"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class PackageDependency:
    """Normalized software dependency extracted from a manifest or lockfile."""

    ecosystem: str
    name: str
    version: str | None
    pinned: bool
    source_file: str


@dataclass(frozen=True)
class VulnerabilityIntelligenceRecord:
    """Correlated vulnerability intelligence entry with attribution & risk scoring."""

    vuln_id: str
    source: str
    package_name: str
    ecosystem: str
    installed_version: str | None
    classification: VulnFindingClassification
    severity: str
    cvss_score: float | None
    cwe_ids: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    kev_listed: bool
    epss_score: float | None
    epss_percentile: float | None
    confidence: float
    rationale: str
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "source": self.source,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "installed_version": self.installed_version,
            "classification": self.classification.value,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cwe_ids": list(self.cwe_ids),
            "fixed_versions": list(self.fixed_versions),
            "kev_listed": self.kev_listed,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "references": list(self.references),
        }


@dataclass(frozen=True)
class AuthorizationScope:
    """Fail-closed Rules-of-Engagement (RoE) scope for authorized security assessments."""

    engagement_id: str
    authorized_targets: tuple[str, ...]
    valid_from_utc: str
    valid_until_utc: str
    allowed_actions: frozenset[str] = frozenset(
        {"passive_scan", "static_audit", "dependency_audit", "local_poc_verify"}
    )
    operator_approval_id: str = ""
    notes: str = ""


_BUILTIN_CWES: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory", "Base",
     "Path traversal allows reading or writing files outside an intended root directory.",
     ("Canonicalize with resolve() and verify is_relative_to(root); reject symlinks.",)),
    ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command", "Base",
     "OS command injection via shell invocation on untrusted arguments.",
     ("Use subprocess.run([...], shell=False) with validated argument lists.",)),
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation", "Base",
     "Cross-site scripting (XSS) from unescaped untrusted output in HTML/DOM.",
     ("Apply context-aware HTML escaping and strict Content-Security-Policy.",)),
    ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command", "Base",
     "SQL injection via string interpolation/concatenation into SQL statements.",
     ("Use bound parameterized queries instead of string formatting.",)),
    ("CWE-94", "Improper Control of Generation of Code", "Base",
     "Dynamic code execution via eval/exec/compile on untrusted expressions.",
     ("Replace eval/exec with ast.literal_eval or typed JSON parsers.",)),
    ("CWE-120", "Buffer Copy without Checking Size of Input", "Base",
     "Classic buffer overflow from unbounded memory copies (strcpy/gets/sprintf).",
     ("Use bounds-checked copy primitives and explicit buffer length checks.",)),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "Class",
     "Use of MD5, SHA-1, RC4, or ECB mode for security-sensitive cryptography.",
     ("Use SHA-256/SHA-3, AES-GCM, ChaCha20-Poly1305, or Ed25519.",)),
    ("CWE-502", "Deserialization of Untrusted Data", "Base",
     "Insecure object deserialization via pickle, yaml.load, or marshal on untrusted bytes.",
     ("Use JSON, Safetensors, or yaml.safe_load with schema validation.",)),
    ("CWE-611", "Improper Restriction of XML External Entity Reference", "Base",
     "XXE vulnerability from default XML parsers resolving external entities.",
     ("Use defusedxml or disable DTD/external entity resolution.",)),
    ("CWE-798", "Use of Hard-coded Credentials", "Class",
     "Hardcoded API keys, tokens, or passwords embedded in source code.",
     ("Load secrets from environment variables, KMS, or secret managers.",)),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", "Base",
     "Outbound HTTP/socket requests built from unvalidated user URLs or hosts.",
     ("Allowlist schemes/hosts and block private, loopback, and link-local IP ranges.",)),
)

_CLEAN_FEED_URLS: dict[str, str] = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://api.first.org/data/v1/epss",
    "osv_query": "https://api.osv.dev/v1/query",
}

_MAX_FEED_BYTES = 16 * 1024 * 1024


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso_utc(raw: str) -> datetime:
    cleaned = raw.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_pkg_name(ecosystem: str, name: str) -> str:
    eco = ecosystem.strip().lower()
    cleaned = name.strip().lower()
    if eco in {"pypi", "python"}:
        return re.sub(r"[-_.]+", "-", cleaned)
    return cleaned


def _version_key(ver: str) -> tuple[tuple[int, int | str], ...]:
    cleaned = ver.strip().lstrip("vV")
    cleaned = cleaned.split("+", 1)[0]
    parts = re.split(r"[.\-_]", cleaned)
    tokens: list[tuple[int, int | str]] = []
    for part in parts:
        if not part:
            continue
        subparts = re.findall(r"\d+|[a-zA-Z]+", part)
        for sub in subparts:
            if sub.isdigit():
                tokens.append((1, int(sub)))
            else:
                # Pre-release tags rank lower than numeric release segments (0 < 1)
                tokens.append((0, sub.lower()))
    return tuple(tokens)


def _compare_versions(a: str, b: str) -> int:
    ka = _version_key(a)
    kb = _version_key(b)
    max_len = max(len(ka), len(kb))
    for i in range(max_len):
        ta = ka[i] if i < len(ka) else (1, 0)
        tb = kb[i] if i < len(kb) else (1, 0)
        if ta[0] != tb[0]:
            return -1 if ta[0] < tb[0] else 1
        if ta[1] != tb[1]:
            return -1 if str(ta[1]) < str(tb[1]) and not isinstance(ta[1], int) else (
                -1 if ta[1] < tb[1] else 1  # type: ignore[operator]
            )
    return 0


def _version_matches_range(version: str, range_spec: dict[str, Any]) -> bool | None:
    """Evaluate OSV/NVD style range `{introduced, fixed, last_affected}`.

    Returns True (definitely affected), False (definitely unaffected), or
    None (insufficient range metadata to decide deterministically).
    """
    if "events" in range_spec and isinstance(range_spec["events"], list):
        introduced: str | None = None
        fixed: str | None = None
        last_affected: str | None = None
        for evt in range_spec["events"]:
            if not isinstance(evt, dict):
                continue
            if "introduced" in evt:
                introduced = str(evt["introduced"])
            if "fixed" in evt:
                fixed = str(evt["fixed"])
            if "last_affected" in evt:
                last_affected = str(evt["last_affected"])
        range_spec = {
            "introduced": introduced,
            "fixed": fixed,
            "last_affected": last_affected,
        }

    introduced = range_spec.get("introduced")
    fixed = range_spec.get("fixed")
    last_affected = range_spec.get("last_affected")

    if introduced is None and fixed is None and last_affected is None:
        return None
    if introduced is not None and str(introduced) not in {"0", ""}:
        if _compare_versions(version, str(introduced)) < 0:
            return False
    if fixed is not None and _compare_versions(version, str(fixed)) >= 0:
        return False
    if last_affected is not None and _compare_versions(version, str(last_affected)) > 0:
        return False
    return True


class VulnIntelMCPServer:
    """Thread-safe SQLite-backed Vulnerability Intelligence & RoE Verification Server."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._lock = threading.RLock()
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._init_schema()
            self._seed_builtin_cwes()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                normalized_package TEXT NOT NULL,
                affected_ranges_json TEXT NOT NULL,
                fixed_versions_json TEXT NOT NULL,
                cvss_score REAL,
                severity TEXT NOT NULL,
                cwe_ids_json TEXT NOT NULL,
                summary TEXT NOT NULL,
                references_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vuln_pkg
                ON vulnerabilities (normalized_package, ecosystem);

            CREATE TABLE IF NOT EXISTS cisa_kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT NOT NULL,
                product TEXT NOT NULL,
                vulnerability_name TEXT NOT NULL,
                date_added TEXT NOT NULL,
                due_date TEXT NOT NULL,
                known_ransomware_campaign_use TEXT NOT NULL,
                required_action TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS epss_scores (
                cve_id TEXT PRIMARY KEY,
                epss REAL NOT NULL,
                percentile REAL NOT NULL,
                scored_date TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cwe_catalog (
                cwe_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                abstraction TEXT NOT NULL,
                description TEXT NOT NULL,
                mitigations_json TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def _seed_builtin_cwes(self) -> None:
        self.ingest_cwe_records(
            [
                {
                    "cwe_id": cid,
                    "name": name,
                    "abstraction": abstraction,
                    "description": desc,
                    "mitigations": list(mits),
                }
                for cid, name, abstraction, desc, mits in _BUILTIN_CWES
            ]
        )

    def close(self) -> None:
        with self._lock:
            conn = getattr(self, "_conn", None)
            if conn is not None:
                conn.close()
                self._conn = None  # type: ignore[assignment]

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def ingest_cwe_records(self, records: list[dict[str, Any]]) -> int:
        count = 0
        with self._lock:
            for rec in records:
                cid = str(rec["cwe_id"]).upper().strip()
                self._conn.execute(
                    """
                    INSERT INTO cwe_catalog (cwe_id, name, abstraction, description, mitigations_json)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(cwe_id) DO UPDATE SET
                        name=excluded.name,
                        abstraction=excluded.abstraction,
                        description=excluded.description,
                        mitigations_json=excluded.mitigations_json
                    """,
                    (
                        cid,
                        str(rec.get("name", cid)),
                        str(rec.get("abstraction", "Base")),
                        str(rec.get("description", "")),
                        json.dumps(list(rec.get("mitigations", []))),
                    ),
                )
                count += 1
            self._conn.commit()
        return count

    def get_cwe_info(self, cwe_id: str) -> dict[str, Any] | None:
        cid = cwe_id.upper().strip()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM cwe_catalog WHERE cwe_id = ?", (cid,)
            ).fetchone()
        if row is None:
            return None
        return {
            "cwe_id": row["cwe_id"],
            "name": row["name"],
            "abstraction": row["abstraction"],
            "description": row["description"],
            "mitigations": json.loads(row["mitigations_json"]),
        }

    def ingest_cisa_kev(self, catalog: dict[str, Any] | list[dict[str, Any]]) -> int:
        items = catalog.get("vulnerabilities", []) if isinstance(catalog, dict) else list(catalog)
        count = 0
        with self._lock:
            for item in items:
                if not isinstance(item, dict) or not item.get("cveID"):
                    continue
                self._conn.execute(
                    """
                    INSERT INTO cisa_kev (
                        cve_id, vendor_project, product, vulnerability_name,
                        date_added, due_date, known_ransomware_campaign_use, required_action
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        vendor_project=excluded.vendor_project,
                        product=excluded.product,
                        vulnerability_name=excluded.vulnerability_name,
                        due_date=excluded.due_date,
                        known_ransomware_campaign_use=excluded.known_ransomware_campaign_use,
                        required_action=excluded.required_action
                    """,
                    (
                        str(item["cveID"]).upper().strip(),
                        str(item.get("vendorProject", "")),
                        str(item.get("product", "")),
                        str(item.get("vulnerabilityName", "")),
                        str(item.get("dateAdded", "")),
                        str(item.get("dueDate", "")),
                        str(item.get("knownRansomwareCampaignUse", "Unknown")),
                        str(item.get("requiredAction", "")),
                    ),
                )
                count += 1
            self._conn.commit()
        return count

    def ingest_epss_scores(self, records: dict[str, Any] | list[dict[str, Any]]) -> int:
        items = records.get("data", []) if isinstance(records, dict) else list(records)
        count = 0
        with self._lock:
            for item in items:
                if not isinstance(item, dict) or not item.get("cve"):
                    continue
                self._conn.execute(
                    """
                    INSERT INTO epss_scores (cve_id, epss, percentile, scored_date)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        epss=excluded.epss,
                        percentile=excluded.percentile,
                        scored_date=excluded.scored_date
                    """,
                    (
                        str(item["cve"]).upper().strip(),
                        float(item["epss"]),
                        float(item.get("percentile", 0.0)),
                        str(item.get("date", "")),
                    ),
                )
                count += 1
            self._conn.commit()
        return count

    def ingest_osv_records(self, records: list[dict[str, Any]]) -> int:
        """Ingest OSV schema entries (supports aliases for CVE mapping and affected ranges)."""
        count = 0
        now = _utc_now_iso()
        with self._lock:
            for rec in records:
                if not isinstance(rec, dict) or not rec.get("id"):
                    continue
                raw_id = str(rec["id"]).strip()
                aliases = [str(a).upper().strip() for a in rec.get("aliases", [])]
                cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
                vuln_id = cve_alias or raw_id.upper()
                db_spec = rec.get("database_specific") or {}
                cwe_ids = [str(c).upper() for c in db_spec.get("cwe_ids", [])]
                severity_str = str(db_spec.get("severity", "UNKNOWN")).upper()
                cvss_score: float | None = None
                for sev in rec.get("severity", []):
                    if isinstance(sev, dict) and isinstance(sev.get("score"), (int, float)):
                        cvss_score = float(sev["score"])
                        break
                refs = [
                    str(r["url"])
                    for r in rec.get("references", [])
                    if isinstance(r, dict) and r.get("url")
                ]

                affected_list = rec.get("affected", []) or []
                for aff in affected_list:
                    pkg_info = aff.get("package") or {}
                    pkg_name = str(pkg_info.get("name", "")).strip()
                    eco = str(pkg_info.get("ecosystem", "unknown")).strip()
                    if not pkg_name:
                        continue
                    ranges = aff.get("ranges", []) or []
                    fixed_versions: list[str] = []
                    for r in ranges:
                        for evt in r.get("events", []) or []:
                            if isinstance(evt, dict) and evt.get("fixed"):
                                fixed_versions.append(str(evt["fixed"]))
                    self._conn.execute(
                        """
                        INSERT INTO vulnerabilities (
                            vuln_id, source, ecosystem, package_name, normalized_package,
                            affected_ranges_json, fixed_versions_json, cvss_score,
                            severity, cwe_ids_json, summary, references_json, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(vuln_id) DO UPDATE SET
                            source=excluded.source,
                            ecosystem=excluded.ecosystem,
                            package_name=excluded.package_name,
                            normalized_package=excluded.normalized_package,
                            affected_ranges_json=excluded.affected_ranges_json,
                            fixed_versions_json=excluded.fixed_versions_json,
                            cvss_score=COALESCE(excluded.cvss_score, vulnerabilities.cvss_score),
                            severity=excluded.severity,
                            cwe_ids_json=excluded.cwe_ids_json,
                            summary=excluded.summary,
                            references_json=excluded.references_json,
                            updated_at=excluded.updated_at
                        """,
                        (
                            vuln_id,
                            "OSV",
                            eco,
                            pkg_name,
                            _normalize_pkg_name(eco, pkg_name),
                            json.dumps(ranges),
                            json.dumps(sorted(set(fixed_versions))),
                            cvss_score,
                            severity_str,
                            json.dumps(cwe_ids),
                            str(rec.get("summary") or rec.get("details") or "")[:600],
                            json.dumps(refs[:10]),
                            now,
                        ),
                    )
                    count += 1
            self._conn.commit()
        return count

    def ingest_nvd_records(self, records: list[dict[str, Any]]) -> int:
        """Ingest simplified NVD CVE JSON records into the offline mirror."""
        count = 0
        now = _utc_now_iso()
        with self._lock:
            for rec in records:
                cve = rec.get("cve", rec)
                if not isinstance(cve, dict) or not cve.get("id"):
                    continue
                vuln_id = str(cve["id"]).upper().strip()
                pkg_name = str(rec.get("package_name") or cve.get("package_name") or "").strip()
                eco = str(rec.get("ecosystem") or cve.get("ecosystem") or "generic").strip()
                if not pkg_name:
                    continue
                ranges = list(rec.get("affected_ranges") or cve.get("affected_ranges") or [])
                fixed = [str(v) for v in (rec.get("fixed_versions") or [])]
                cvss_val = rec.get("cvss_score")
                cvss_score = float(cvss_val) if isinstance(cvss_val, (int, float)) else None
                severity = str(rec.get("severity") or ("CRITICAL" if (cvss_score or 0) >= 9.0 else "HIGH")).upper()
                cwe_ids = [str(c).upper() for c in rec.get("cwe_ids", [])]
                refs = [str(u) for u in rec.get("references", [])]
                summary = str(rec.get("summary") or cve.get("description") or "")[:600]
                self._conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                        vuln_id, source, ecosystem, package_name, normalized_package,
                        affected_ranges_json, fixed_versions_json, cvss_score,
                        severity, cwe_ids_json, summary, references_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(vuln_id) DO UPDATE SET
                        affected_ranges_json=excluded.affected_ranges_json,
                        fixed_versions_json=excluded.fixed_versions_json,
                        cvss_score=COALESCE(excluded.cvss_score, vulnerabilities.cvss_score),
                        severity=excluded.severity,
                        cwe_ids_json=excluded.cwe_ids_json,
                        summary=excluded.summary,
                        references_json=excluded.references_json,
                        updated_at=excluded.updated_at
                    """,
                    (
                        vuln_id,
                        "NVD",
                        eco,
                        pkg_name,
                        _normalize_pkg_name(eco, pkg_name),
                        json.dumps(ranges),
                        json.dumps(fixed),
                        cvss_score,
                        severity,
                        json.dumps(cwe_ids),
                        summary,
                        json.dumps(refs[:10]),
                        now,
                    ),
                )
                count += 1
            self._conn.commit()
        return count

    def sync_live_feeds(
        self,
        feeds: Iterable[str] = ("kev", "epss"),
        packages: tuple[tuple[str, str], ...] = (),
        session_tainted: bool = False,
        timeout_sec: float = 15.0,
        opener: Callable[[Request, float], bytes] | None = None,
    ) -> dict[str, Any]:
        """Clean-zone live sync of public KEV / EPSS / OSV feeds into SQLite mirror.

        Always raises `PermissionError` if `session_tainted=True` to uphold the
        `TAINTED_UNTRUSTED` invariant.
        """
        if session_tainted:
            raise PermissionError(
                "TAINTED_UNTRUSTED session blocked from live vulnerability feed sync."
            )

        def _default_fetch(req: Request, timeout: float) -> bytes:
            with urlopen(req, timeout=timeout) as resp:  # noqa: S310
                data = resp.read(_MAX_FEED_BYTES + 1)
                if len(data) > _MAX_FEED_BYTES:
                    raise ValueError(f"Feed response exceeded {_MAX_FEED_BYTES} bytes.")
                return data

        fetch = opener or _default_fetch
        synced: dict[str, int] = {}
        errors: list[str] = []

        for feed in feeds:
            key = feed.strip().lower()
            try:
                if key == "kev":
                    req = Request(_CLEAN_FEED_URLS["kev"], headers={"User-Agent": "platform-core/1.0"})
                    payload = json.loads(fetch(req, timeout_sec).decode("utf-8"))
                    synced["kev"] = self.ingest_cisa_kev(payload)
                elif key == "epss":
                    req = Request(_CLEAN_FEED_URLS["epss"], headers={"User-Agent": "platform-core/1.0"})
                    payload = json.loads(fetch(req, timeout_sec).decode("utf-8"))
                    synced["epss"] = self.ingest_epss_scores(payload)
                elif key == "osv":
                    osv_count = 0
                    for eco, pkg in packages:
                        body = json.dumps({"package": {"name": pkg, "ecosystem": eco}}).encode("utf-8")
                        req = Request(
                            _CLEAN_FEED_URLS["osv_query"],
                            data=body,
                            headers={"Content-Type": "application/json", "User-Agent": "platform-core/1.0"},
                            method="POST",
                        )
                        payload = json.loads(fetch(req, timeout_sec).decode("utf-8"))
                        osv_count += self.ingest_osv_records(list(payload.get("vulns", [])))
                    synced["osv"] = osv_count
            except Exception as exc:
                errors.append(f"{key}: {exc}")

        return {
            "synced_counts": synced,
            "errors": errors,
            "synced_at_utc": _utc_now_iso(),
        }

    def mirror_stats(self) -> dict[str, int]:
        with self._lock:
            vulns = int(self._conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0])
            kev = int(self._conn.execute("SELECT COUNT(*) FROM cisa_kev").fetchone()[0])
            epss = int(self._conn.execute("SELECT COUNT(*) FROM epss_scores").fetchone()[0])
            cwes = int(self._conn.execute("SELECT COUNT(*) FROM cwe_catalog").fetchone()[0])
        return {
            "vulnerabilities": vulns,
            "cisa_kev": kev,
            "epss_scores": epss,
            "cwe_catalog": cwes,
        }

    def parse_dependencies_from_directory(self, project_dir: str | Path) -> list[PackageDependency]:
        """Extract normalized dependencies from Python, Node, Go, and Rust manifests."""
        raw_root = Path(project_dir)
        if raw_root.is_symlink():
            raise PermissionError(f"Symlinked project_dir rejected: {raw_root}")
        root = raw_root.resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"Project directory not found: {project_dir}")

        deps: list[PackageDependency] = []

        def _safe_file(name: str) -> Path | None:
            candidate = root / name
            if candidate.is_symlink() or not candidate.is_file():
                return None
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                raise PermissionError(f"Manifest path escapes project_dir: {candidate}")
            return resolved

        req_file = _safe_file("requirements.txt")
        if req_file is not None:
            for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.split("#", 1)[0].strip()
                if not stripped or stripped.startswith("-"):
                    continue
                m_eq = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+-]+)", stripped)
                if m_eq:
                    deps.append(PackageDependency("PyPI", m_eq.group(1), m_eq.group(2), True, "requirements.txt"))
                    continue
                m_loose = re.match(r"^([A-Za-z0-9._-]+)", stripped)
                if m_loose:
                    deps.append(PackageDependency("PyPI", m_loose.group(1), None, False, "requirements.txt"))

        pyproject_file = _safe_file("pyproject.toml")
        if pyproject_file is not None:
            data = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
            raw_deps = list((data.get("project") or {}).get("dependencies", []) or [])
            for item in raw_deps:
                if not isinstance(item, str):
                    continue
                m_eq = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+-]+)", item.strip())
                if m_eq:
                    deps.append(PackageDependency("PyPI", m_eq.group(1), m_eq.group(2), True, "pyproject.toml"))
                else:
                    m_name = re.match(r"^([A-Za-z0-9._-]+)", item.strip())
                    if m_name:
                        deps.append(PackageDependency("PyPI", m_name.group(1), None, False, "pyproject.toml"))

        pkg_lock = _safe_file("package-lock.json")
        if pkg_lock is not None:
            lock_data = json.loads(pkg_lock.read_text(encoding="utf-8"))
            packages_map = lock_data.get("packages") or {}
            if isinstance(packages_map, dict) and packages_map:
                for key, meta in packages_map.items():
                    if not key or not isinstance(meta, dict):
                        continue
                    pkg_name = key.split("node_modules/")[-1]
                    ver = meta.get("version")
                    if pkg_name:
                        deps.append(
                            PackageDependency("npm", pkg_name, str(ver) if ver else None, bool(ver), "package-lock.json")
                        )
            else:
                for pkg_name, meta in (lock_data.get("dependencies") or {}).items():
                    if isinstance(meta, dict):
                        ver = meta.get("version")
                        deps.append(
                            PackageDependency("npm", str(pkg_name), str(ver) if ver else None, bool(ver), "package-lock.json")
                        )

        go_mod = _safe_file("go.mod")
        if go_mod is not None:
            for line in go_mod.read_text(encoding="utf-8", errors="replace").splitlines():
                cleaned = line.strip()
                if cleaned.startswith("require ") or (cleaned and " v" in cleaned and not cleaned.startswith("//")):
                    cleaned = cleaned.removeprefix("require ").strip()
                    parts = cleaned.split()
                    if len(parts) >= 2 and parts[1].startswith("v"):
                        deps.append(PackageDependency("Go", parts[0], parts[1], True, "go.mod"))

        cargo_lock = _safe_file("Cargo.lock")
        if cargo_lock is not None:
            cargo_data = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
            for pkg in cargo_data.get("package", []) or []:
                if isinstance(pkg, dict) and pkg.get("name"):
                    ver = pkg.get("version")
                    deps.append(
                        PackageDependency("crates.io", str(pkg["name"]), str(ver) if ver else None, bool(ver), "Cargo.lock")
                    )

        return deps

    def correlate_package(
        self,
        package: str,
        version: str | None = None,
        ecosystem: str | None = None,
    ) -> list[VulnerabilityIntelligenceRecord]:
        """Correlate a package (and optional installed version) against mirrored feeds."""
        norm_target = _normalize_pkg_name(ecosystem or "generic", package)
        with self._lock:
            if ecosystem:
                rows = self._conn.execute(
                    """
                    SELECT * FROM vulnerabilities
                    WHERE normalized_package = ? AND lower(ecosystem) = lower(?)
                    """,
                    (_normalize_pkg_name(ecosystem, package), ecosystem),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM vulnerabilities
                    WHERE normalized_package = ? OR lower(package_name) = lower(?)
                    """,
                    (norm_target, package.strip()),
                ).fetchall()

        results: list[VulnerabilityIntelligenceRecord] = []
        for row in rows:
            vuln_id = row["vuln_id"]
            ranges = json.loads(row["affected_ranges_json"])
            fixed = tuple(json.loads(row["fixed_versions_json"]))
            cwe_ids = tuple(json.loads(row["cwe_ids_json"]))
            refs = tuple(json.loads(row["references_json"]))

            with self._lock:
                kev_row = self._conn.execute(
                    "SELECT 1 FROM cisa_kev WHERE cve_id = ?", (vuln_id,)
                ).fetchone()
                epss_row = self._conn.execute(
                    "SELECT epss, percentile FROM epss_scores WHERE cve_id = ?", (vuln_id,)
                ).fetchone()

            kev_listed = kev_row is not None
            epss_score = float(epss_row["epss"]) if epss_row is not None else None
            epss_pct = float(epss_row["percentile"]) if epss_row is not None else None

            if version is not None and ranges:
                verdicts = [_version_matches_range(version, r) for r in ranges if isinstance(r, dict)]
                if any(v is True for v in verdicts):
                    classification = VulnFindingClassification.CONFIRMED_VULNERABILITY
                    confidence = 0.96 if kev_listed else 0.90
                    rationale = (
                        f"Pinned version {version} of {row['package_name']} matches affected "
                        f"range for {vuln_id} ({row['source']})."
                    )
                elif all(v is False for v in verdicts):
                    # Explicitly fixed in installed version; do not raise false positive
                    continue
                else:
                    classification = VulnFindingClassification.POTENTIAL_WEAKNESS
                    confidence = 0.55
                    rationale = (
                        f"Range metadata for {vuln_id} is incomplete for exact determination on version {version}."
                    )
            else:
                classification = VulnFindingClassification.POTENTIAL_WEAKNESS
                confidence = 0.62 if kev_listed else 0.50
                rationale = (
                    f"Dependency {row['package_name']} is unpinned or lacks version range bounds; "
                    f"requires version confirmation against {vuln_id}."
                )

            results.append(
                VulnerabilityIntelligenceRecord(
                    vuln_id=vuln_id,
                    source=row["source"],
                    package_name=row["package_name"],
                    ecosystem=row["ecosystem"],
                    installed_version=version,
                    classification=classification,
                    severity=row["severity"],
                    cvss_score=row["cvss_score"],
                    cwe_ids=cwe_ids,
                    fixed_versions=fixed,
                    kev_listed=kev_listed,
                    epss_score=epss_score,
                    epss_percentile=epss_pct,
                    confidence=confidence,
                    rationale=rationale,
                    references=refs,
                )
            )
        return results

    def classify_code_findings(
        self,
        findings: list[CPGVulnerabilityFinding],
        confirmed_taint_lines: set[int] | None = None,
    ) -> list[dict[str, Any]]:
        """Classify static code findings into CONFIRMED_VULNERABILITY vs POTENTIAL_WEAKNESS."""
        confirmed_lines = confirmed_taint_lines or set()
        classified: list[dict[str, Any]] = []
        for f in findings:
            is_dataflow_confirmed = (
                f.line_number in confirmed_lines
                or f.source_expr.startswith("ast_taint:")
            )
            cwe_meta = self.get_cwe_info(f.cwe_id)
            if is_dataflow_confirmed:
                cls_label = VulnFindingClassification.CONFIRMED_VULNERABILITY
                conf = 0.92
            elif f.severity in {"CRITICAL", "HIGH"}:
                cls_label = VulnFindingClassification.POTENTIAL_WEAKNESS
                conf = 0.68
            else:
                cls_label = VulnFindingClassification.INFORMATIONAL
                conf = 0.45
            classified.append(
                {
                    "cwe_id": f.cwe_id,
                    "cwe_name": cwe_meta["name"] if cwe_meta else f.cwe_id,
                    "severity": f.severity,
                    "line_number": f.line_number,
                    "source_expr": f.source_expr,
                    "sink_expr": f.sink_expr,
                    "classification": cls_label.value,
                    "confidence": conf,
                    "description": f.description,
                    "remediation_hint": f.remediation_hint,
                    "mitigations": cwe_meta["mitigations"] if cwe_meta else [],
                }
            )
        return classified

    def audit_project_dependencies(
        self,
        project_dir: str | Path,
        cpg_findings: list[CPGVulnerabilityFinding] | None = None,
    ) -> dict[str, Any]:
        """Audit an entire project directory for vulnerable dependencies + classified CWE findings."""
        deps = self.parse_dependencies_from_directory(project_dir)
        dep_findings: list[dict[str, Any]] = []
        for dep in deps:
            for match in self.correlate_package(
                package=dep.name, version=dep.version, ecosystem=dep.ecosystem
            ):
                entry = match.to_dict()
                entry["source_file"] = dep.source_file
                dep_findings.append(entry)

        code_findings = self.classify_code_findings(cpg_findings or [])
        confirmed_count = sum(
            1
            for item in [*dep_findings, *code_findings]
            if item["classification"] == VulnFindingClassification.CONFIRMED_VULNERABILITY.value
        )
        weakness_count = sum(
            1
            for item in [*dep_findings, *code_findings]
            if item["classification"] == VulnFindingClassification.POTENTIAL_WEAKNESS.value
        )

        return {
            "project_dir": str(Path(project_dir).resolve()),
            "dependencies_scanned": len(deps),
            "dependency_findings": dep_findings,
            "code_findings": code_findings,
            "summary": {
                "confirmed_vulnerabilities": confirmed_count,
                "potential_weaknesses": weakness_count,
                "kev_matches": sum(1 for item in dep_findings if item.get("kev_listed")),
            },
        }

    @staticmethod
    def verify_authorization(
        scope: AuthorizationScope,
        target: str,
        action: str,
        now_utc: str | None = None,
    ) -> dict[str, Any]:
        """Verify Rules-of-Engagement scope, time window, and allowed action before security testing."""
        now_dt = _parse_iso_utc(now_utc) if now_utc else datetime.now(timezone.utc)
        start_dt = _parse_iso_utc(scope.valid_from_utc)
        end_dt = _parse_iso_utc(scope.valid_until_utc)

        if not scope.operator_approval_id.strip():
            return {
                "authorized": False,
                "reason": "Missing signed operator_approval_id for security assessment.",
            }
        if not (start_dt <= now_dt <= end_dt):
            return {
                "authorized": False,
                "reason": (
                    f"Authorization window expired/not active ({scope.valid_from_utc} .. "
                    f"{scope.valid_until_utc}; checked at {now_dt.isoformat()})."
                ),
            }
        cleaned_action = action.strip().lower()
        if cleaned_action not in {a.lower() for a in scope.allowed_actions}:
            return {
                "authorized": False,
                "reason": f"Action '{action}' is outside RoE allowed_actions={sorted(scope.allowed_actions)}.",
            }

        target_host = target.strip()
        if "://" in target_host:
            target_host = (urlparse(target_host).hostname or "").strip()
        elif ":" in target_host and not target_host.startswith("["):
            target_host = target_host.split(":", 1)[0]
        target_lower = target_host.lower()
        if not target_lower:
            return {"authorized": False, "reason": f"Unparseable target: {target!r}"}

        matched = False
        try:
            target_ip = ipaddress.ip_address(target_lower)
        except ValueError:
            target_ip = None

        for allowed in scope.authorized_targets:
            entry = allowed.strip().lower()
            if not entry:
                continue
            if target_ip is not None and "/" in entry:
                try:
                    if target_ip in ipaddress.ip_network(entry, strict=False):
                        matched = True
                        break
                except ValueError:
                    continue
            elif entry.startswith("*."):
                suffix = entry[1:]  # '.example.com'
                if target_lower.endswith(suffix) and len(target_lower) > len(suffix):
                    matched = True
                    break
            elif target_lower == entry:
                matched = True
                break

        if not matched:
            return {
                "authorized": False,
                "reason": f"Target '{target}' is NOT in authorized_targets={list(scope.authorized_targets)}.",
            }
        return {
            "authorized": True,
            "engagement_id": scope.engagement_id,
            "target": target_lower,
            "action": cleaned_action,
            "checked_at_utc": now_dt.isoformat(),
        }
