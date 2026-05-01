#!/usr/bin/env python3
"""
Automated Network Scanner  v3.0
Author  : Shubham Sahu  (ssahu@planful.com)
Requires: nmap  (sudo apt install nmap)
          git   (option 4 only)

New in v3.0
───────────
• Option 11 – Smart Vuln Scan
    1. Phase-1 service detection with -sV --version-intensity 9
    2. Automatic NSE script selection keyed on discovered services
    3. XML output parsed to extract hosts / ports / versions / CPEs
    4. CVE IDs harvested from every vuln-script run
    5. Each CVE enriched in parallel via NVD API v2.0, OSV.dev,
       GitHub Advisory REST API, and Vulners API
    6. Consolidated JSON + CSV report written to the results folder

• Option 12 – Enrich CVEs from an existing nmap XML file
    Point it at any previous scan's .xml and get the full enrichment
    report without re-running the scan.

• Option 2  – now uses -sV --version-intensity 9 by default for
    accurate service fingerprinting (was plain -T4 -v previously).

API keys (optional but recommended)
────────────────────────────────────
Set these environment variables before running:
    NVD_API_KEY        – NIST NVD  (50 req/30 s vs 5 req/30 s)
    GITHUB_TOKEN       – GitHub Advisory API
    VULNERS_API_KEY    – Vulners.com enrichment

Run: sudo python3 network_scanner.py
"""

# ─── Imports ──────────────────────────────────────────────────────────────────
import os
import re
import sys
import csv
import json
import time
import socket
import logging
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─── API Key Config (read from environment) ───────────────────────────────────
NVD_API_KEY     = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN    = os.getenv("GITHUB_TOKEN", "")
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "")

# ─── ANSI Colour Helpers ──────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"

def banner(text: str) -> None:
    print(C.CYAN + "─" * 84 + C.RESET)
    print(C.BOLD + C.WHITE + f"  {text}" + C.RESET)
    print(C.CYAN + "─" * 84 + C.RESET)

def ok(msg: str)      -> None: print(C.GREEN   + f"  [✔] {msg}" + C.RESET)
def warn(msg: str)    -> None: print(C.YELLOW  + f"  [!] {msg}" + C.RESET)
def err(msg: str)     -> None: print(C.RED     + f"  [✘] {msg}" + C.RESET)
def info(msg: str)    -> None: print(C.CYAN    + f"  [i] {msg}" + C.RESET)
def detail(msg: str)  -> None: print(C.MAGENTA + f"      {msg}" + C.RESET)

# ─── Dataclasses ──────────────────────────────────────────────────────────────
@dataclass
class ServiceInfo:
    """One open port detected by nmap service detection."""
    host:     str
    port:     int
    protocol: str
    state:    str
    service:  str           # e.g. "http", "ssh", "ms-sql-s"
    product:  str = ""      # e.g. "nginx"
    version:  str = ""      # e.g. "1.18.0"
    cpe:      str = ""      # e.g. "cpe:/a:nginx:nginx:1.18.0"

@dataclass
class CVEFinding:
    """Aggregated vulnerability intelligence for one CVE ID."""
    cve_id:            str
    cvss_v3:           Optional[float]  = None
    cvss_v2:           Optional[float]  = None
    severity:          str              = "UNKNOWN"
    description:       str              = ""
    exploit_available: bool             = False
    references:        list             = field(default_factory=list)
    sources:           list             = field(default_factory=list)
    # which host:port triggered this CVE
    affected_services: list             = field(default_factory=list)

# ─── Global Setup ─────────────────────────────────────────────────────────────
SCOPE_FILE  = Path("scope.txt")
RESULTS_DIR = Path(f"scan_results_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}")
LOG_FILE    = RESULTS_DIR / "scanner.log"

def setup_environment() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout),
        ],
    )
    ok(f"Output directory: {RESULTS_DIR}/")

def check_root() -> None:
    if os.geteuid() != 0:
        err("Must run as root.  Try: sudo python3 network_scanner.py")
        sys.exit(1)
    ok("Running as root.")

def check_scope_file() -> None:
    if not SCOPE_FILE.exists():
        err(f"'{SCOPE_FILE}' not found. One target IP/CIDR per line.")
        sys.exit(1)
    if SCOPE_FILE.stat().st_size == 0:
        err(f"'{SCOPE_FILE}' is empty.")
        sys.exit(1)
    targets = [l for l in SCOPE_FILE.read_text().splitlines() if l.strip()]
    ok(f"Scope: {len(targets)} target(s)")

def out(name: str) -> str:
    return str(RESULTS_DIR / name)

# ─── Timed nmap Wrapper ───────────────────────────────────────────────────────
def run_nmap(label: str, args: list[str]) -> None:
    info(f"Starting: {label}")
    logging.info("CMD: %s", " ".join(args))
    t0 = datetime.now()
    try:
        subprocess.run(args, check=True)
        secs = (datetime.now() - t0).seconds
        ok(f"'{label}' done in {secs}s")
        logging.info("DONE [%ds]: %s", secs, label)
    except subprocess.CalledProcessError as e:
        err(f"'{label}' returned code {e.returncode}")
        logging.error("FAILED: %s (code %s)", label, e.returncode)
    except FileNotFoundError:
        err("nmap not found – sudo apt install nmap")
        logging.critical("nmap binary missing")

# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION A – nmap XML Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_nmap_xml(xml_path: str | Path) -> list[ServiceInfo]:
    """
    Parse an nmap XML file (produced with -oX or -oA) and return every
    open port as a ServiceInfo object.
    """
    services: list[ServiceInfo] = []
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, FileNotFoundError) as exc:
        err(f"Cannot parse XML '{xml_path}': {exc}")
        return services

    for host_el in tree.findall("host"):
        # Resolve host address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr", "unknown")

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc_el = port_el.find("service")
            svc_name = ""
            product  = ""
            version  = ""
            cpe      = ""
            if svc_el is not None:
                svc_name = svc_el.get("name",    "")
                product  = svc_el.get("product", "")
                version  = svc_el.get("version", "")
                cpe_el   = svc_el.find("cpe")
                if cpe_el is not None and cpe_el.text:
                    cpe = cpe_el.text.strip()

            services.append(ServiceInfo(
                host     = host_ip,
                port     = int(port_el.get("portid", 0)),
                protocol = port_el.get("protocol", "tcp"),
                state    = "open",
                service  = svc_name.lower(),
                product  = product,
                version  = version,
                cpe      = cpe,
            ))
    return services


def extract_cves_from_file(path: str | Path) -> set[str]:
    """
    Regex-scan any nmap text / XML output file and return every unique
    CVE ID found.  Works on .nmap, .xml, .gnmap, .txt files.
    """
    pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    try:
        text = Path(path).read_text(errors="replace")
    except FileNotFoundError:
        return set()
    return {m.upper() for m in pattern.findall(text)}


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION B – Service-to-NSE Script Mapping
# ═══════════════════════════════════════════════════════════════════════════════

# Canonical service name (nmap's -sV "name" field) → targeted NSE scripts.
# Scripts are run exactly as passed to --script so they can be individual
# script names or wildcard categories (nmap supports both).
SERVICE_SCRIPTS: dict[str, list[str]] = {
    "http": [
        "http-title", "http-headers", "http-methods", "http-auth-finder",
        "http-enum", "http-shellshock", "http-iis-webdav-vuln",
        "http-sql-injection", "http-stored-xss", "http-csrf",
        "http-open-redirect", "http-phpmyadmin-dir-traversal",
        "http-vuln-cve2010-0738", "http-vuln-cve2011-3192",
        "http-vuln-cve2014-3704", "http-vuln-cve2015-1635",
    ],
    "https": [
        "ssl-cert", "ssl-enum-ciphers", "ssl-dh-params",
        "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection",
        "ssl-date", "http-title", "http-methods", "http-auth-finder",
    ],
    "ssl": [
        "ssl-cert", "ssl-enum-ciphers", "ssl-dh-params",
        "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection",
    ],
    "ftp": [
        "ftp-anon", "ftp-bounce", "ftp-syst",
        "ftp-vuln-cve2010-4221", "ftp-proftpd-backdoor", "ftp-vsftpd-backdoor",
    ],
    "ssh": [
        "ssh-auth-methods", "ssh-hostkey", "ssh2-enum-algos", "sshv1",
    ],
    "smtp": [
        "smtp-commands", "smtp-enum-users", "smtp-open-relay",
        "smtp-ntlm-info", "smtp-vuln-cve2010-4344", "smtp-vuln-cve2011-1720",
    ],
    "pop3": [
        "pop3-capabilities", "pop3-ntlm-info",
    ],
    "imap": [
        "imap-capabilities", "imap-ntlm-info",
    ],
    "microsoft-ds": [           # SMB 445
        "smb-security-mode", "smb-vuln-ms17-010", "smb-vuln-cve2009-3103",
        "smb-vuln-ms08-067", "smb-vuln-ms10-054", "smb-vuln-ms10-061",
        "smb-vuln-cve-2017-7494", "smb2-security-mode",
        "smb-enum-shares", "smb-enum-users",
    ],
    "netbios-ssn": [            # SMB 139
        "smb-security-mode", "smb-enum-shares", "smb-enum-users",
    ],
    "msrpc": [
        "msrpc-enum",
    ],
    "rdp": [
        "rdp-vuln-ms12-020", "rdp-enum-encryption",
    ],
    "mysql": [
        "mysql-empty-password", "mysql-info",
        "mysql-vuln-cve2012-2122", "mysql-enum", "mysql-databases",
    ],
    "ms-sql-s": [
        "ms-sql-info", "ms-sql-empty-password", "ms-sql-dump-hashes",
        "ms-sql-config", "ms-sql-ntlm-info",
    ],
    "oracle-tns": [
        "oracle-tns-version", "oracle-brute", "oracle-sid-brute",
    ],
    "postgresql": [
        "pgsql-brute",
    ],
    "mongodb": [
        "mongodb-info", "mongodb-databases",
    ],
    "redis": [
        "redis-info", "redis-brute",
    ],
    "dns": [
        "dns-zone-transfer", "dns-recursion", "dns-cache-snoop",
        "dns-brute", "dns-nsec-enum",
    ],
    "snmp": [
        "snmp-info", "snmp-sysdescr", "snmp-interfaces",
        "snmp-processes", "snmp-brute",
    ],
    "ldap": [
        "ldap-rootdse", "ldap-search", "ldap-brute",
    ],
    "vnc": [
        "vnc-info", "vnc-brute", "vnc-title", "realvnc-auth-bypass",
    ],
    "telnet": [
        "telnet-ntlm-info", "telnet-encryption",
    ],
    "nfs": [
        "nfs-ls", "nfs-showmount", "nfs-statfs",
    ],
    "rpcbind": [
        "rpcinfo",
    ],
    "memcached": [
        "memcached-info",
    ],
    "elasticsearch": [
        "http-title", "http-methods",
    ],
    "docker": [
        "docker-version",
    ],
    "kubernetes": [
        "kubernetes-info",
    ],
}

# Always add vulners (needs -sV) and the generic vuln category
ALWAYS_INCLUDE = [
    "vulners",       # CPE-based CVE lookup via vulners.com script
    "vuln",          # generic vuln category (safe checks only)
]

def select_scripts_for_services(services: list[ServiceInfo]) -> list[str]:
    """
    Given a list of discovered ServiceInfo objects, return a deduplicated
    list of NSE scripts that are relevant to those services.
    """
    chosen: set[str] = set(ALWAYS_INCLUDE)
    for svc in services:
        key = svc.service.lower()
        # direct match
        if key in SERVICE_SCRIPTS:
            chosen.update(SERVICE_SCRIPTS[key])
        # partial-match fallback (e.g. "http-proxy" → http scripts)
        else:
            for svc_key, scripts in SERVICE_SCRIPTS.items():
                if svc_key in key or key in svc_key:
                    chosen.update(scripts)
                    break
    return sorted(chosen)


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION C – CVE Enrichment APIs
# ═══════════════════════════════════════════════════════════════════════════════

# ── Shared HTTP helper ────────────────────────────────────────────────────────
def _http_get(url: str, headers: dict | None = None,
              timeout: int = 12) -> dict | None:
    """
    Simple GET request returning parsed JSON or None on failure.
    No external libraries – uses urllib only.
    """
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        logging.debug("HTTP %s for %s: %s", e.code, url, e.reason)
    except urllib.error.URLError as e:
        logging.debug("URL error %s: %s", url, e.reason)
    except (json.JSONDecodeError, Exception) as e:
        logging.debug("Error fetching %s: %s", url, e)
    return None

# ── NVD API v2.0 rate limiter ─────────────────────────────────────────────────
_nvd_last_call: float = 0.0

def _nvd_wait() -> None:
    global _nvd_last_call
    # Without API key: 5 req / 30 s  →  sleep ≥6 s between calls
    # With    API key: 50 req / 30 s →  sleep ≥0.6 s between calls
    gap = 6.5 if not NVD_API_KEY else 0.7
    elapsed = time.monotonic() - _nvd_last_call
    if elapsed < gap:
        time.sleep(gap - elapsed)
    _nvd_last_call = time.monotonic()

# ── NVD API v2.0 ──────────────────────────────────────────────────────────────
def enrich_nvd(cve_id: str) -> dict:
    """
    Query NVD API v2.0 for a single CVE.
    Returns a partial CVEFinding-compatible dict.
    """
    _nvd_wait()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    hdrs = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    data = _http_get(url, headers=hdrs)
    result: dict = {"source": "NVD"}

    if not data:
        return result

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return result

    cve_data = vulns[0].get("cve", {})

    # Description (English preferred)
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            result["description"] = d.get("value", "")
            break

    # CVSS v3.1 → v3.0 → v2
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            result["cvss_v3"]  = m.get("baseScore")
            result["severity"] = m.get("baseSeverity", "UNKNOWN")
            break
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0].get("cvssData", {})
        result.setdefault("cvss_v2", m.get("baseScore"))

    # References
    result["references"] = [
        r.get("url") for r in cve_data.get("references", []) if r.get("url")
    ][:5]

    return result

# ── OSV.dev API ───────────────────────────────────────────────────────────────
def enrich_osv(cve_id: str) -> dict:
    """
    Query OSV.dev for a CVE ID using the REST endpoint.
    """
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    data = _http_get(url)
    result: dict = {"source": "OSV.dev"}

    if not data:
        return result

    result["description"] = data.get("summary", data.get("details", ""))[:300]

    # CVSS score from severity array
    for sev in data.get("severity", []):
        score_str = sev.get("score", "")
        # score_str e.g. "CVSS:3.1/AV:N/AC:L/..."  – extract base score
        m = re.search(r'/(\d+\.\d+)$', score_str)
        if m:
            try:
                result["cvss_v3"] = float(m.group(1))
            except ValueError:
                pass
            break

    result["references"] = [
        r.get("url") for r in data.get("references", []) if r.get("url")
    ][:5]

    return result

# ── GitHub Advisory REST API ──────────────────────────────────────────────────
def enrich_github(cve_id: str) -> dict:
    """
    Query GitHub Advisory Database via REST API.
    Requires GITHUB_TOKEN env var for authenticated requests
    (unauthenticated rate limit is very low).
    """
    result: dict = {"source": "GitHub Advisory"}

    if not GITHUB_TOKEN:
        logging.debug("GITHUB_TOKEN not set – skipping GitHub Advisory lookup")
        result["description"] = "GitHub Advisory skipped (GITHUB_TOKEN not set)"
        return result

    url = f"https://api.github.com/advisories?cve_id={cve_id}&per_page=1"
    hdrs = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = _http_get(url, headers=hdrs)

    if not data or not isinstance(data, list) or not data:
        return result

    adv = data[0]
    result["description"] = adv.get("summary", "")

    # GitHub uses text severities; map to approximate CVSS
    severity_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}
    sev_text = adv.get("severity", "").lower()
    if sev_text in severity_map:
        result["severity"] = sev_text.upper()
        result.setdefault("cvss_v3", severity_map[sev_text])

    # Prefer explicit CVSS scores if available
    cvss_obj = adv.get("cvss_severities", {})
    for key in ("cvss_v4", "cvss_v3"):
        if cvss_obj.get(key, {}).get("score"):
            result["cvss_v3"] = float(cvss_obj[key]["score"])
            break

    result["references"] = [
        ref.get("url") for ref in adv.get("references", []) if ref.get("url")
    ][:5]

    result["exploit_available"] = any(
        "exploit" in str(r).lower() for r in result.get("references", [])
    )

    return result

# ── Vulners API ───────────────────────────────────────────────────────────────
def enrich_vulners(cve_id: str) -> dict:
    """
    Query Vulners.com for a CVE.
    Requires VULNERS_API_KEY env var.
    """
    result: dict = {"source": "Vulners"}

    if not VULNERS_API_KEY:
        logging.debug("VULNERS_API_KEY not set – skipping Vulners lookup")
        result["description"] = "Vulners skipped (VULNERS_API_KEY not set)"
        return result

    url = (f"https://vulners.com/api/v3/search/id/"
           f"?id={urllib.parse.quote(cve_id)}&apiKey={VULNERS_API_KEY}")
    data = _http_get(url)

    if not data or data.get("result") != "OK":
        return result

    docs = data.get("data", {}).get("documents", {})
    doc  = docs.get(cve_id.upper(), {}).get("_source", {})
    if not doc:
        return result

    result["description"] = doc.get("description", "")[:300]

    cvss = doc.get("cvss", {})
    if cvss.get("score"):
        result["cvss_v3"] = float(cvss["score"])

    result["exploit_available"] = bool(doc.get("exploit"))

    result["references"] = [
        r if isinstance(r, str) else r.get("url", "")
        for r in doc.get("references", [])
    ][:5]

    return result


# ── CVE Enrichment Orchestrator ───────────────────────────────────────────────
def enrich_cve(cve_id: str) -> CVEFinding:
    """
    Enrich one CVE ID across all four sources concurrently, then merge
    the best available data into a single CVEFinding.
    """
    finding = CVEFinding(cve_id=cve_id)

    enrichers = {
        "NVD":             lambda: enrich_nvd(cve_id),
        "OSV.dev":         lambda: enrich_osv(cve_id),
        "GitHub Advisory": lambda: enrich_github(cve_id),
        "Vulners":         lambda: enrich_vulners(cve_id),
    }

    results: dict[str, dict] = {}
    # NVD must be rate-limited (serial); the rest can be parallel
    results["NVD"] = enrichers["NVD"]()

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(enrichers[k]): k
            for k in ("OSV.dev", "GitHub Advisory", "Vulners")
        }
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                results[key] = fut.result()
            except Exception as exc:
                logging.debug("Enricher %s failed: %s", key, exc)
                results[key] = {}

    # Merge: take the highest CVSS v3, first non-empty description, all refs
    all_refs: list[str] = []
    for source, r in results.items():
        if not r:
            continue
        finding.sources.append(source)

        score = r.get("cvss_v3")
        if score is not None:
            if finding.cvss_v3 is None or score > finding.cvss_v3:
                finding.cvss_v3 = score

        score2 = r.get("cvss_v2")
        if score2 is not None and finding.cvss_v2 is None:
            finding.cvss_v2 = score2

        if not finding.description and r.get("description"):
            finding.description = r["description"]

        if r.get("severity") and finding.severity == "UNKNOWN":
            finding.severity = r["severity"]

        if r.get("exploit_available"):
            finding.exploit_available = True

        all_refs.extend(r.get("references") or [])

    # Derive severity from CVSS v3 if API didn't supply it
    if finding.cvss_v3 is not None and finding.severity == "UNKNOWN":
        s = finding.cvss_v3
        finding.severity = (
            "CRITICAL" if s >= 9.0 else
            "HIGH"     if s >= 7.0 else
            "MEDIUM"   if s >= 4.0 else
            "LOW"
        )

    # Deduplicate references
    finding.references = list(dict.fromkeys(r for r in all_refs if r))[:8]

    return finding


def enrich_cves_bulk(
    cve_ids: set[str],
    affected_map: dict[str, list[str]] | None = None,
) -> list[CVEFinding]:
    """
    Enrich a collection of CVE IDs.  affected_map maps cve_id →
    list of "host:port" strings for traceability in the report.
    """
    if not cve_ids:
        return []

    info(f"Enriching {len(cve_ids)} CVEs across NVD / OSV.dev / GitHub Advisory / Vulners …")
    findings: list[CVEFinding] = []

    for i, cve_id in enumerate(sorted(cve_ids), 1):
        detail(f"  [{i}/{len(cve_ids)}] {cve_id}")
        finding = enrich_cve(cve_id)
        if affected_map and cve_id in affected_map:
            finding.affected_services = affected_map[cve_id]
        findings.append(finding)

    # Sort by CVSS descending (None / unknowns at bottom)
    findings.sort(key=lambda f: f.cvss_v3 if f.cvss_v3 is not None else -1, reverse=True)
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION D – Report Generation
# ═══════════════════════════════════════════════════════════════════════════════

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

def severity_colour(sev: str) -> str:
    return {
        "CRITICAL": C.RED + C.BOLD,
        "HIGH":     C.RED,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.GREEN,
    }.get(sev.upper(), C.WHITE)

def write_cve_report(findings: list[CVEFinding], services: list[ServiceInfo]) -> None:
    """Write JSON + CSV enrichment reports and print a terminal summary."""
    if not findings:
        warn("No CVEs to report.")
        return

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_path = out(f"cve_enrichment_{ts}.json")
    csv_path  = out(f"cve_enrichment_{ts}.csv")

    # ── JSON ────────────────────────────────────────────────────────────────
    report_data = {
        "generated": ts,
        "scope_file": str(SCOPE_FILE),
        "total_cves": len(findings),
        "services_scanned": len(services),
        "findings": [asdict(f) for f in findings],
    }
    with open(json_path, "w") as jf:
        json.dump(report_data, jf, indent=2, default=str)
    ok(f"JSON report: {Path(json_path).name}")

    # ── CSV ──────────────────────────────────────────────────────────────────
    csv_fields = [
        "cve_id", "severity", "cvss_v3", "cvss_v2",
        "exploit_available", "description",
        "affected_services", "sources", "references",
    ]
    with open(csv_path, "w", newline="") as cf:
        writer = csv.DictWriter(cf, fieldnames=csv_fields)
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "cve_id":            f.cve_id,
                "severity":          f.severity,
                "cvss_v3":           f.cvss_v3 if f.cvss_v3 is not None else "",
                "cvss_v2":           f.cvss_v2 if f.cvss_v2 is not None else "",
                "exploit_available": "YES" if f.exploit_available else "no",
                "description":       f.description[:150],
                "affected_services": " | ".join(f.affected_services),
                "sources":           " | ".join(f.sources),
                "references":        " | ".join(f.references[:3]),
            })
    ok(f"CSV report:  {Path(csv_path).name}")

    # ── Terminal Summary ─────────────────────────────────────────────────────
    banner("CVE Enrichment Summary")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        if counts.get(sev):
            sc = severity_colour(sev)
            print(f"    {sc}{sev:<10}{C.RESET}  {counts[sev]}")

    print()
    print(f"  {'CVE ID':<22} {'CVSS':>6}  {'SEV':<9}  {'EXPLOIT':>7}  "
          f"{'DESCRIPTION':<50}")
    print("  " + "─" * 100)

    for f in findings[:25]:   # cap terminal display at top 25
        sc   = severity_colour(f.severity)
        expl = C.RED + "YES" + C.RESET if f.exploit_available else "no"
        desc = (f.description or "—")[:50]
        cvss = f"{f.cvss_v3:.1f}" if f.cvss_v3 is not None else "n/a"
        print(f"  {f.cve_id:<22} {cvss:>6}  {sc}{f.severity:<9}{C.RESET}  "
              f"{expl:>7}  {desc}")

    if len(findings) > 25:
        info(f"… and {len(findings) - 25} more – see the CSV / JSON report.")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION E – Existing Menu Options (1–10)
# ═══════════════════════════════════════════════════════════════════════════════

def check_ip() -> None:
    banner("Check My IP Address")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        ok(f"Your IP address: {local_ip}")
    except OSError:
        warn("Could not determine IP. Check your network connection.")

def bnmap() -> None:
    banner("Basic Nmap Scan  (with service + version detection)")
    check_scope_file()
    # v3 improvement: version intensity 9 + XML output for downstream parsing
    run_nmap("Basic Scan", [
        "nmap", "-sV", "--version-intensity", "9",
        "-T4", "-v", "-oA", out("basic_scan"), "-iL", str(SCOPE_FILE),
    ])

def update_nmap() -> None:
    banner("Update Nmap Script Database")
    run_nmap("Script DB Update", ["nmap", "--script-updatedb"])

def nmaps_install() -> None:
    banner("Install Additional Nmap Scripts from GitHub")
    repos = [
        "https://github.com/vulnersCom/nmap-vulners.git",
        "https://github.com/scipag/vulscan.git",
    ]
    for repo in repos:
        name = repo.split("/")[-1].replace(".git", "")
        info(f"Cloning {name} …")
        try:
            subprocess.run(["git", "clone", repo], check=True)
            ok(f"Cloned {name}")
        except subprocess.CalledProcessError as e:
            err(f"Failed to clone {name} (code {e.returncode}) – already exists?")
        except FileNotFoundError:
            err("git not found – sudo apt install git")

def nmap_rall() -> None:
    banner("Run All Scan Types")
    check_scope_file()
    scans = [
        ("Port Discovery",   ["nmap", "-T4", "-v", "-p", "1-65535",
                               "-oN", out("port_discovery.txt"), "-iL", str(SCOPE_FILE)]),
        ("TCP Connect",      ["nmap", "-sT", "-T4", "-v",
                               "-oN", out("tcp_scan.txt"),        "-iL", str(SCOPE_FILE)]),
        ("ACK",              ["nmap", "-sA", "-T4",
                               "-oN", out("ack_scan.txt"),         "-iL", str(SCOPE_FILE)]),
        ("UDP",              ["nmap", "-sU", "-T4",
                               "-oN", out("udp_scan.txt"),         "-iL", str(SCOPE_FILE)]),
        ("FIN",              ["nmap", "-sF", "-T4",
                               "-oN", out("fin_scan.txt"),         "-iL", str(SCOPE_FILE)]),
        ("NULL",             ["nmap", "-sN", "-T4",
                               "-oN", out("null_scan.txt"),        "-iL", str(SCOPE_FILE)]),
        ("SYN Stealth",      ["nmap", "-sS", "-T4",
                               "-oN", out("syn_scan.txt"),         "-iL", str(SCOPE_FILE)]),
        ("Windows",          ["nmap", "-sW", "-T4",
                               "-oN", out("windows_scan.txt"),     "-iL", str(SCOPE_FILE)]),
        ("Xmas Tree",        ["nmap", "-sX", "-T4",
                               "-oN", out("xmas_scan.txt"),        "-iL", str(SCOPE_FILE)]),
        ("Aggressive",       ["nmap", "-A",  "-T4",
                               "-oN", out("aggressive_scan.txt"),  "-iL", str(SCOPE_FILE)]),
        ("IP Protocol",      ["nmap", "-sO", "-T4",
                               "-oN", out("ip_protocol_scan.txt"), "-iL", str(SCOPE_FILE)]),
        ("Fragment Packets", ["nmap", "-f",  "-T4",
                               "-oN", out("fragment_scan.txt"),    "-iL", str(SCOPE_FILE)]),
        ("OS Guess",         ["nmap", "-O", "--osscan-guess", "-T4",
                               "-oN", out("osguess_scan.txt"),     "-iL", str(SCOPE_FILE)]),
    ]
    for label, cmd in scans:
        run_nmap(label, cmd)
    print_scan_summary()

def nmap_all() -> None:
    banner("Run ALL Nmap Scripts")
    warn("Runs every script – takes a very long time.")
    check_scope_file()
    run_nmap("All Scripts", [
        "nmap", "-T4", "--script", "all",
        "-oN", out("all_scripts.txt"), "-iL", str(SCOPE_FILE),
    ])

def option7() -> None:
    banner("Nmap Vulnerability Scripts")
    check_scope_file()
    # vulners requires -sV to get CPE data for lookups
    run_nmap("vuln (built-in)", [
        "nmap", "-sV", "--version-intensity", "9", "-T4",
        "--script", "vuln",
        "-oA", out("vuln_builtin"), "-iL", str(SCOPE_FILE),
    ])
    run_nmap("vulscan", [
        "nmap", "-sV", "--version-intensity", "9", "-T4",
        "--script", "vulscan",
        "-oA", out("vulscan"), "-iL", str(SCOPE_FILE),
    ])
    run_nmap("nmap-vulners", [
        "nmap", "-sV", "--version-intensity", "9", "-T4",
        "--script", "nmap-vulners",
        "--script-args", "vulners.showall=true",
        "-oA", out("nmap_vulners"), "-iL", str(SCOPE_FILE),
    ])
    print_scan_summary()

def option8() -> None:
    banner("Nmap DoS Scripts")
    warn("DoS scripts can crash/degrade targets. Authorised targets only.")
    check_scope_file()
    run_nmap("DoS Scripts", [
        "nmap", "-T4", "--script", "dos",
        "-oN", out("dos_scripts.txt"), "-iL", str(SCOPE_FILE),
    ])

def option9() -> None:
    banner("Nmap Malware Scripts")
    check_scope_file()
    run_nmap("Malware Detection", [
        "nmap", "-T4", "--script", "malware",
        "-oN", out("malware_scripts.txt"), "-iL", str(SCOPE_FILE),
    ])

def option10() -> None:
    banner("Automated Essential Scan")
    check_scope_file()
    steps = [
        ("Service Version",  ["nmap", "-vv", "-T4", "-sV",
                               "--version-intensity", "9",
                               "-oA", out("service_version"),  "-iL", str(SCOPE_FILE)]),
        ("Aggressive",       ["nmap", "-T4", "-A", "-v",
                               "-oA", out("aggressive"),       "-iL", str(SCOPE_FILE)]),
        ("Discovery",        ["nmap", "-T4", "--script", "discovery",
                               "-oA", out("discovery"),        "-iL", str(SCOPE_FILE)]),
        ("Vulnerability",    ["nmap", "-sV", "--version-intensity", "9", "-T4",
                               "--script", "vuln",
                               "-oA", out("vulnerability"),    "-iL", str(SCOPE_FILE)]),
        ("Malware",          ["nmap", "-T4", "--script", "malware",
                               "-oA", out("malware"),          "-iL", str(SCOPE_FILE)]),
        ("All Scripts",      ["nmap", "-T4", "--script", "all",
                               "-oA", out("all_scripts"),      "-iL", str(SCOPE_FILE)]),
    ]
    for label, cmd in steps:
        run_nmap(label, cmd)
    print_scan_summary()


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION F – NEW Option 11: Smart Vulnerability Scan with CVE Enrichment
# ═══════════════════════════════════════════════════════════════════════════════

def option11() -> None:
    """
    4-phase smart vulnerability scan:

    Phase 1 – Deep service + version detection
        nmap -sV --version-intensity 9 -oX  (saves XML for parsing)

    Phase 2 – Targeted NSE script selection
        Parse the XML → identify services → select relevant scripts

    Phase 3 – Run selected scripts
        nmap --script <selected> -sV (vulners needs -sV / CPE data)

    Phase 4 – CVE Enrichment
        Extract CVE IDs from all output → enrich via NVD/OSV/GitHub/Vulners
        → write JSON + CSV report
    """
    banner("Smart Vulnerability Scan  (auto NSE + CVE Enrichment)")
    check_scope_file()

    # ── Phase 1: Deep service detection ──────────────────────────────────────
    info("Phase 1/4 – Service & version detection  (-sV --version-intensity 9)")
    svc_xml = out("phase1_services.xml")
    run_nmap("Phase 1: Service Detection", [
        "nmap", "-sV", "--version-intensity", "9",
        "-T4", "-v", "-oX", svc_xml, "-iL", str(SCOPE_FILE),
    ])

    services = parse_nmap_xml(svc_xml)
    if not services:
        warn("No open services found in phase 1. Continuing with generic scripts.")

    info(f"Phase 1 found {len(services)} open port(s) across all targets.")
    for svc in services:
        detail(f"{svc.host}:{svc.port}/{svc.protocol}  "
               f"{svc.service}  {svc.product} {svc.version}  {svc.cpe}")

    # ── Phase 2: Script selection ─────────────────────────────────────────────
    info("Phase 2/4 – Selecting NSE scripts for discovered services …")
    selected = select_scripts_for_services(services)
    info(f"Selected {len(selected)} script(s):")
    # Print in rows of 4
    for i in range(0, len(selected), 4):
        detail("  " + "  ".join(selected[i:i+4]))

    # ── Phase 3: Run targeted scripts ─────────────────────────────────────────
    info("Phase 3/4 – Running targeted vulnerability scripts …")
    script_str = ",".join(selected)
    targeted_base = out("phase3_targeted")
    run_nmap("Phase 3: Targeted Scripts", [
        "nmap", "-sV", "--version-intensity", "9", "-T4",
        "--script", script_str,
        "--script-args", "vulners.showall=true",
        "-oA", targeted_base, "-iL", str(SCOPE_FILE),
    ])

    # ── Phase 4: CVE enrichment ───────────────────────────────────────────────
    info("Phase 4/4 – Harvesting CVE IDs from all output files …")

    # Collect CVEs from every output file produced so far
    all_cves: set[str] = set()
    affected_map: dict[str, list[str]] = {}

    for f in RESULTS_DIR.iterdir():
        cvs = extract_cves_from_file(f)
        all_cves.update(cvs)

    # Best-effort: map each CVE to a host:port string from service info
    # (nmap doesn't always tie CVEs back to a specific port in text output)
    if services:
        for cve in all_cves:
            # Assign to every service as a conservative default
            affected_map[cve] = [f"{s.host}:{s.port}" for s in services]

    if not all_cves:
        warn("No CVE IDs found in scan output. "
             "Install nmap-vulners / vulscan (option 4) for better coverage.")
    else:
        ok(f"Found {len(all_cves)} unique CVE ID(s) to enrich.")
        findings = enrich_cves_bulk(all_cves, affected_map)
        write_cve_report(findings, services)

    print_scan_summary()


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION G – NEW Option 12: Enrich CVEs from an existing XML file
# ═══════════════════════════════════════════════════════════════════════════════

def option12() -> None:
    """
    Point at any previously generated nmap XML file and run the full
    CVE enrichment pipeline without re-scanning.
    """
    banner("Enrich CVEs from Existing Nmap XML")
    xml_input = input(C.BOLD + "  Path to nmap XML file: " + C.RESET).strip()

    xml_path = Path(xml_input)
    if not xml_path.exists():
        err(f"File not found: {xml_path}")
        return

    info("Parsing XML …")
    services = parse_nmap_xml(xml_path)
    ok(f"Parsed {len(services)} open port(s)")

    info("Extracting CVE IDs …")
    cve_ids = extract_cves_from_file(xml_path)

    # Also scan any .nmap text file with the same stem
    txt_path = xml_path.with_suffix(".nmap")
    if txt_path.exists():
        cve_ids.update(extract_cves_from_file(txt_path))

    if not cve_ids:
        warn("No CVE IDs found in that file.")
        warn("Tip: Re-run with nmap-vulners / vulscan scripts (option 4 → 7).")
        return

    ok(f"Found {len(cve_ids)} CVE ID(s)")
    findings = enrich_cves_bulk(cve_ids)
    write_cve_report(findings, services)
    print_scan_summary()


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION H – Summary, Menu, Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def print_scan_summary() -> None:
    files = sorted(RESULTS_DIR.iterdir())
    if not files:
        return
    banner("Output Files")
    for f in files:
        if f.suffix != ".log":
            ok(f.name)
    info(f"Folder : {RESULTS_DIR}/")
    info(f"Log    : {LOG_FILE}")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION I – NEW Option 13: Plugin-Based Checks + Risk Scoring
# ═══════════════════════════════════════════════════════════════════════════════

def option13() -> None:
    """
    Runs the 15 built-in plugin checks against every nmap output file
    in the current results directory, then scores every finding with the
    VPR risk engine and saves a ranked JSON report.
    """
    banner("Plugin-Based Checks  (15 checks + VPR Risk Engine)")
    try:
        from scanner_plugins import CheckRegistry, RiskEngine, save_findings
    except ImportError:
        err("scanner_plugins.py not found. Place it in the same directory.")
        return

    xml_files = sorted(RESULTS_DIR.glob("*.xml"))
    txt_files = sorted(RESULTS_DIR.glob("*.nmap"))

    if not xml_files and not txt_files:
        warn("No nmap output files in results directory yet. Run a scan first (options 2–11).")
        return

    info(f"Scanning {len(xml_files)} XML + {len(txt_files)} text file(s) …")

    # Parse XML for the service list (used by service-aware checks)
    from scanner_plugins import Check as _Check
    services = _Check.parse_xml_services(xml_files)
    info(f"Found {len(services)} open service(s) from XML")

    registry = CheckRegistry()
    findings = registry.run_all(xml_files, txt_files, services)

    if not findings:
        warn("No plugin findings. The checks may need nmap-vulners / ssl-* output to trigger.")
        warn("Run option 7 or option 11 first for richer script output.")
        return

    # Score with risk engine
    engine = RiskEngine()
    scored = engine.score_all(findings)

    # Terminal summary
    banner("Plugin Check Results")
    from collections import Counter
    sev_counts = Counter(f.severity for f in scored)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev_counts[sev]:
            info(f"  {sev:<10} {sev_counts[sev]}")

    print()
    print(f"  {'CHECK ID':<14} {'SEV':<10} {'VPR':>5}  {'HOST:PORT':<22}  NAME")
    print("  " + "─" * 90)
    for f in scored[:20]:
        print(f"  {f.check_id:<14} {f.severity:<10} {f.vpr_score:>5.1f}  "
              f"{f.host}:{f.port:<16}  {f.name[:45]}")
    if len(scored) > 20:
        info(f"  … and {len(scored) - 20} more. See the JSON report.")

    path = save_findings(scored, RESULTS_DIR)
    ok(f"Findings saved: {path.name}")
    print_scan_summary()


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION J – NEW Option 14: Generate Reports (HTML + Word)
# ═══════════════════════════════════════════════════════════════════════════════

def option14() -> None:
    """
    Reads all JSON output files in the results directory and generates:
      • A self-contained HTML executive dashboard
      • A professional Word (.docx) technical report
    """
    banner("Generate Reports  (HTML Executive + Word Technical)")
    try:
        from report_engine import HTMLReport, WordReport
    except ImportError:
        err("report_engine.py not found. Place it in the same directory.")
        return

    # HTML report
    info("Generating HTML executive report …")
    html_path = HTMLReport(RESULTS_DIR).generate()
    if html_path:
        ok(f"HTML report: {html_path.name}")
    else:
        err("HTML report generation failed.")

    # Word report
    info("Generating Word technical report via Node.js …")
    word_path = WordReport(RESULTS_DIR).generate()
    if word_path:
        ok(f"Word report: {word_path.name}")
    else:
        warn("Word report skipped (Node.js or generate_report.js not available).")

    print_scan_summary()


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION K – NEW Option 15: Web Application Scan
# ═══════════════════════════════════════════════════════════════════════════════

def option15() -> None:
    """
    Runs the web application scanner against all HTTP/HTTPS services
    discovered in previous scans.

    If Nikto is installed it is run first; then 7 custom checks run regardless:
      admin panel finder (80 paths), CORS, cookie flags, server banners,
      directory listing, information leakage, live TLS version check.
    """
    banner("Web Application Scan  (Nikto + 7 custom HTTP checks)")
    try:
        from web_scanner import WebScanner
    except ImportError:
        err("web_scanner.py not found. Place it in the same directory.")
        return

    check_scope_file()

    # Load services from any XML in the results folder
    from scanner_plugins import Check as _Check
    xml_files = sorted(RESULTS_DIR.glob("*.xml"))
    services  = _Check.parse_xml_services(xml_files)

    if not services:
        warn("No service data found. Run option 2 or 11 first to detect services.")
        warn("Falling back to scope.txt – will attempt HTTP/HTTPS on ports 80/443.")
        # Build a minimal service list from scope.txt
        targets = [l.strip() for l in SCOPE_FILE.read_text().splitlines() if l.strip()]
        services = [
            {"host": t, "port": 80,  "protocol": "tcp", "service": "http",  "product": "", "version": "", "cpe": ""}
            for t in targets
        ] + [
            {"host": t, "port": 443, "protocol": "tcp", "service": "https", "product": "", "version": "", "cpe": ""}
            for t in targets
        ]

    ws       = WebScanner(RESULTS_DIR)
    findings = ws.scan(services)

    if not findings:
        warn("No web findings. Targets may not have HTTP services or they were unreachable.")
        return

    path = ws.save(findings)
    ok(f"Web findings saved: {path.name}")

    # Terminal summary
    banner("Web Scan Results")
    from collections import Counter
    sev_counts = Counter(f.severity for f in findings)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev_counts[sev]:
            info(f"  {sev:<10} {sev_counts[sev]}")

    print()
    for f in findings[:15]:
        sev = f.severity
        print(f"  [{sev:<8}]  {f.host}:{f.port:<6}  {f.name[:60]}")
    if len(findings) > 15:
        info(f"  … and {len(findings) - 15} more. See web_findings JSON report.")

    print_scan_summary()


# ─── Update Menu and Dispatch ─────────────────────────────────────────────────

MENU = """
{cyan}{bold}  ╔════════════════════════════════════════════════════════════════════╗
  ║            Automated Network Scanner  v4.0                         ║
  ╚════════════════════════════════════════════════════════════════════╝{reset}

    {white} 1{reset}  Check My IP Address
    {white} 2{reset}  Basic Nmap Scan  (service version detection, intensity 9)
    {white} 3{reset}  Update Nmap Script Database
    {white} 4{reset}  Install Additional Scripts  (nmap-vulners / vulscan)
    {white} 5{reset}  Run All Scan Types
    {white} 6{reset}  Run All Nmap Scripts at Once
    {white} 7{reset}  Vulnerability Scripts  (vuln / vulscan / nmap-vulners + -sV)
    {white} 8{reset}  DoS Scripts            {yellow}⚠  authorised targets only{reset}
    {white} 9{reset}  Malware Detection Scripts
    {white}10{reset}  Automated Essential Scan
    {cyan}──────────────────────── v3.0  ─────────────────────────────────────{reset}
    {white}11{reset}  {bold}Smart Vuln Scan{reset}   – service detect → auto NSE → CVE enrich
    {white}12{reset}  {bold}Enrich CVEs{reset}       – from an existing nmap XML file
    {cyan}──────────────────────── v4.0  ─────────────────────────────────────{reset}
    {white}13{reset}  {bold}Plugin Checks{reset}     – 15 built-in checks + VPR risk engine
    {white}14{reset}  {bold}Generate Reports{reset}  – HTML executive + Word technical report
    {white}15{reset}  {bold}Web App Scan{reset}      – Nikto + 7 custom HTTP checks
    {white}99{reset}  Quit

  {yellow}API keys (optional):{reset}
    export NVD_API_KEY=...   export GITHUB_TOKEN=...   export VULNERS_API_KEY=...

  {yellow}Asset criticality (optional):{reset}  asset_criticality.json  {{"192.168.1.1": 1.0}}
"""

def print_menu() -> None:
    print(MENU.format(
        cyan=C.CYAN, bold=C.BOLD, reset=C.RESET,
        white=C.WHITE, yellow=C.YELLOW,
    ))

DISPATCH = {
    1:  check_ip,
    2:  bnmap,
    3:  update_nmap,
    4:  nmaps_install,
    5:  nmap_rall,
    6:  nmap_all,
    7:  option7,
    8:  option8,
    9:  option9,
    10: option10,
    11: option11,
    12: option12,
    13: option13,
    14: option14,
    15: option15,
}

def main_menu() -> None:
    while True:
        print_menu()
        try:
            choice = int(input(C.BOLD + "  Select option: " + C.RESET))
        except ValueError:
            warn("Please enter a number.")
            continue
        except (KeyboardInterrupt, EOFError):
            choice = 99

        if choice == 99:
            os.system("cls||clear")
            info("Goodbye.")
            sys.exit(0)
        elif choice in DISPATCH:
            DISPATCH[choice]()
        else:
            warn(f"'{choice}' is not a valid option.")

if __name__ == "__main__":
    os.system("cls||clear")
    check_root()
    setup_environment()
    main_menu()
