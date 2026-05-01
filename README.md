# Automated Network Scanner

> A menu-driven, multi-phase network and vulnerability scanner that wraps nmap with intelligent NSE script selection and multi-source CVE enrichment from NVD, OSV.dev, GitHub Advisory Database, and Vulners.

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Nmap](https://img.shields.io/badge/nmap-required-success.svg)](https://nmap.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20kali-orange.svg)]()
[![Version](https://img.shields.io/badge/version-3.0-informational.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## ⚠️ Legal & Ethical Use

**This tool performs active network scanning, vulnerability detection, and (optionally) denial-of-service testing. Run it ONLY against systems you own or have explicit written authorization to test.**

Unauthorized scanning is illegal in most jurisdictions (Computer Fraud and Abuse Act in the US, Computer Misuse Act 1990 in the UK, Section 43 of the IT Act 2000 in India, etc.) and may also violate your ISP's acceptable use policy. **The author and contributors disclaim all liability for misuse.**

If you're conducting a paid engagement, get the scope and authorization in writing first. Option 8 (DoS scripts) is particularly destructive — read the warning before running it.

---

## ✨ Features

### Core scanning (options 1–10)
- 13 nmap scan techniques (TCP connect, SYN stealth, ACK, UDP, FIN, NULL, Xmas, IP protocol, fragment, OS guess, etc.)
- Service & version detection at maximum intensity (`-sV --version-intensity 9`)
- Bulk script execution — `vuln`, `dos`, `malware`, and the full `--script all` set
- Auto-installation of `nmap-vulners` and `vulscan` from GitHub
- Automated essential scan (option 10) chains six common scan profiles

### Smart vulnerability scanning (option 11)
A 4-phase intelligent scan:
1. **Phase 1** — Deep service detection writes XML for downstream parsing
2. **Phase 2** — Auto-selects NSE scripts based on discovered services (29 service types mapped to ~150 targeted scripts)
3. **Phase 3** — Runs only the relevant scripts (faster + more accurate than `--script all`)
4. **Phase 4** — Harvests CVE IDs from output and enriches each across 4 sources concurrently

### CVE enrichment (option 12)
Point at any previously-generated nmap XML and get full enrichment without re-scanning. Useful when you already have scan output from a third-party engagement and just want intelligence on the CVEs it reported.

### CVE intelligence sources
| Source | Purpose | Auth |
|---|---|---|
| **NVD API v2.0** | Canonical CVE data, CVSS v3.1 scores | Optional API key (raises rate limit 10×) |
| **OSV.dev** | Ecosystem coverage, machine-readable affected ranges | None |
| **GitHub Advisory Database** | Curated ecosystem advisories | `GITHUB_TOKEN` required |
| **Vulners** | Severity context, exploit availability | `VULNERS_API_KEY` required |

NVD calls are rate-limited and serialized; OSV.dev / GitHub / Vulners run in parallel via a thread pool. Results from each source are merged: highest CVSS v3 wins, descriptions and references are deduplicated, and severity is derived from CVSS if no source supplies it.

---

## 📋 Requirements

| Component | Version | Required for |
|---|---|---|
| Python | 3.10+ | All options (uses `dict[str, ...]` and `\|` union type syntax) |
| nmap | 7.x or newer | All options 2–12 |
| git | any | Option 4 only (cloning vulners/vulscan repos) |
| Root / sudo | — | All options (raw socket scans, low ports) |

**Python standard library only — no `pip install` required.** The scanner uses `urllib`, `xml.etree.ElementTree`, `concurrent.futures`, and `dataclasses` from the stdlib.

---

## 📦 Installation

### 1. Install system dependencies

**Kali / Debian / Ubuntu:**
```bash
sudo apt update
sudo apt install -y nmap git python3
```

**RHEL / Fedora / Rocky:**
```bash
sudo dnf install -y nmap git python3
```

**Arch:**
```bash
sudo pacman -S nmap git python
```

### 2. Clone the repository

```bash
git clone https://github.com/<your-username>/automated-network-scanner.git
cd automated-network-scanner
```

### 3. Install additional nmap scripts (recommended)

You can do this from inside the tool (option 4) or manually. The smart vuln scan (option 11) works fine without them, but **CVE coverage is much better with `nmap-vulners` and `vulscan` installed**:

```bash
sudo git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/nmap-vulners
sudo git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan
sudo nmap --script-updatedb
```

### 4. Verify installation

```bash
nmap --version
python3 --version       # must be 3.10+
sudo python3 network_scanner.py
```

---

## ⚙️ Configuration

### `scope.txt` — required

Place one target per line. Supports IPs, CIDR ranges, hostnames, and IP ranges:

```
192.168.1.1
192.168.1.0/24
10.0.0.1-50
example.internal
2001:db8::/64
```

The file must exist and be non-empty before running any scan option (1–12). The scanner exits with an error otherwise.

### API keys — optional but recommended

Set as environment variables before running. Without them:
- **NVD** is rate-limited to 5 requests per 30 seconds (about 6 seconds per CVE)
- **GitHub Advisory** lookup is skipped entirely
- **Vulners** lookup is skipped entirely

```bash
export NVD_API_KEY="your-nvd-key-here"
export GITHUB_TOKEN="ghp_your-github-pat-here"
export VULNERS_API_KEY="your-vulners-key-here"
```

To make them persistent, append to `~/.bashrc` or `~/.zshrc`:

```bash
echo 'export NVD_API_KEY="..."' >> ~/.bashrc
echo 'export GITHUB_TOKEN="..."' >> ~/.bashrc
echo 'export VULNERS_API_KEY="..."' >> ~/.bashrc
source ~/.bashrc
```

**How to get the keys:**
- **NVD API key** → https://nvd.nist.gov/developers/request-an-api-key (free, instant — raises rate limit to 50 requests per 30 seconds)
- **GitHub PAT** → https://github.com/settings/tokens — only needs `public_repo` read; classic PAT or fine-grained both work
- **Vulners API key** → https://vulners.com/api/ (free tier available)

> ⚠️ **Don't commit API keys to the repo.** The `.gitignore` example below excludes a `.env` file you can use locally.

---

## 🚀 Usage

### Quick start

```bash
sudo python3 network_scanner.py
```

You'll see the menu:

```
  ╔════════════════════════════════════════════════════════════════════╗
  ║            Automated Network Scanner  v3.0                         ║
  ╚════════════════════════════════════════════════════════════════════╝

     1  Check My IP Address
     2  Basic Nmap Scan  (service version detection, intensity 9)
     3  Update Nmap Script Database
     4  Install Additional Scripts  (nmap-vulners / vulscan)
     5  Run All Scan Types
     6  Run All Nmap Scripts at Once
     7  Vulnerability Scripts  (vuln / vulscan / nmap-vulners + -sV)
     8  DoS Scripts            ⚠  authorised targets only
     9  Malware Detection Scripts
    10  Automated Essential Scan
    ──────────────────────────── v3.0 additions ───────────────────────
    11  Smart Vuln Scan  – service detect → auto NSE → CVE enrich
    12  Enrich CVEs      – from an existing nmap XML file
    99  Quit

  Select option:
```

### Recommended first-run workflow

For a thorough one-shot assessment of a target:

```bash
# 1. Edit scope.txt with your authorized targets
echo "192.168.1.0/24" > scope.txt

# 2. (Optional) Set API keys for richer CVE enrichment
export NVD_API_KEY="..."
export GITHUB_TOKEN="..."
export VULNERS_API_KEY="..."

# 3. Run the scanner
sudo -E python3 network_scanner.py
#  -E preserves your environment variables under sudo

# In the menu:
#   4  → install nmap-vulners + vulscan (one time only)
#  11  → smart vuln scan with CVE enrichment  ← the main event
#  99  → quit
```

Every run creates a timestamped output directory: `scan_results_YYYY-MM-DD_HH-MM-SS/`.

### Reusing previous scan output

If you already have an nmap XML from a previous run (or a third-party engagement) and just want CVE enrichment on it:

```bash
sudo -E python3 network_scanner.py
# Select option 12
# Enter the path: /path/to/previous_scan.xml
```

The scanner will parse the XML, extract every CVE ID it finds, and produce a fresh JSON + CSV enrichment report — without re-scanning the network.

---

## 📚 Menu reference

| # | Option | What it runs | Output |
|---|---|---|---|
| 1 | Check My IP | Local source-IP detection (no nmap) | terminal only |
| 2 | Basic nmap | `-sV --version-intensity 9 -T4 -v -oA` | `basic_scan.{nmap,xml,gnmap}` |
| 3 | Update script DB | `nmap --script-updatedb` | — |
| 4 | Install scripts | Clones `nmap-vulners` + `vulscan` from GitHub | `nmap-vulners/`, `vulscan/` (in CWD) |
| 5 | All scan types | 13 nmap techniques sequentially | 13 `.txt` files |
| 6 | All scripts | `--script all` (slow!) | `all_scripts.txt` |
| 7 | Vulnerability scripts | `vuln`, `vulscan`, `nmap-vulners` with `-sV` | three sets of `.{nmap,xml,gnmap}` |
| 8 | DoS scripts | `--script dos` ⚠️ destructive | `dos_scripts.txt` |
| 9 | Malware scripts | `--script malware` | `malware_scripts.txt` |
| 10 | Essential scan | Service version + aggressive + discovery + vuln + malware + all | 6 sets of `.{nmap,xml,gnmap}` |
| 11 | **Smart Vuln Scan** | 4-phase: detect → auto-NSE → run → enrich | XML + targeted output + `cve_enrichment_*.{json,csv}` |
| 12 | **Enrich CVEs** | Re-enrich an existing nmap XML | `cve_enrichment_*.{json,csv}` |
| 99 | Quit | — | — |

---

## 📂 Output structure

```
scan_results_2026-04-30_14-30-22/
├── scanner.log                        # Full session log (every nmap command + exit code)
├── basic_scan.{nmap,xml,gnmap}        # Option 2 output
├── phase1_services.xml                # Option 11 phase 1
├── phase3_targeted.{nmap,xml,gnmap}   # Option 11 phase 3
├── cve_enrichment_*.json              # Enrichment report (machine-readable)
└── cve_enrichment_*.csv               # Enrichment report (Excel-friendly)
```

### CVE enrichment JSON example

```json
{
  "generated": "2026-04-30_14-30-22",
  "scope_file": "scope.txt",
  "total_cves": 47,
  "services_scanned": 12,
  "findings": [
    {
      "cve_id": "CVE-2021-44228",
      "cvss_v3": 10.0,
      "cvss_v2": null,
      "severity": "CRITICAL",
      "description": "Apache Log4j2 JNDI features...",
      "exploit_available": true,
      "references": ["https://nvd.nist.gov/...", "..."],
      "sources": ["NVD", "OSV.dev", "GitHub Advisory", "Vulners"],
      "affected_services": ["192.168.1.10:8080", "192.168.1.10:8443"]
    }
  ]
}
```

### CSV columns

`cve_id, severity, cvss_v3, cvss_v2, exploit_available, description, affected_services, sources, references`

Drop straight into Excel for triage — rows are pre-sorted by CVSS descending, so Critical and High findings sit at the top.

---

## 🧠 How the smart scan works (option 11 deep-dive)

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: Service Detection                                     │
│  nmap -sV --version-intensity 9 -oX phase1_services.xml         │
│  → Discovers 12 open ports across 5 hosts                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: Script Selection                                      │
│  parse_nmap_xml() identifies: http, ssh, mysql, smb             │
│  select_scripts_for_services() picks ~40 relevant NSE scripts   │
│  → http-vuln-cve*, ssh-auth-methods, mysql-vuln-cve2012-2122,   │
│    smb-vuln-ms17-010, vulners, vuln, ...                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: Targeted Script Execution                             │
│  nmap -sV --script <selected> -oA phase3_targeted               │
│  → Output mentions CVE-2017-0144, CVE-2021-44228, ...           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: Multi-Source CVE Enrichment                           │
│  extract_cves_from_file() → set of unique CVE IDs               │
│  enrich_cve(cve) →                                              │
│       NVD (serial, rate-limited)  ┐                             │
│       OSV.dev    (parallel)       ├─→ Merged CVEFinding         │
│       GitHub Adv (parallel)       │                             │
│       Vulners    (parallel)       ┘                             │
│  → cve_enrichment_*.{json,csv}                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Why this is faster than `--script vuln` alone:** by selecting only the scripts relevant to discovered services (instead of running every vuln script against every host), phase 3 typically runs in 30–50% of the time `--script vuln` would take, while catching more service-specific issues.

---

## 🔧 Service → NSE script mapping

The scanner maps 29 service types to targeted NSE scripts. Highlights:

| Service | Sample scripts |
|---|---|
| http / https | `http-vuln-cve2014-3704`, `http-shellshock`, `http-sql-injection`, `http-csrf`, `ssl-heartbleed`, `ssl-poodle` |
| ssh | `ssh-auth-methods`, `ssh-hostkey`, `ssh2-enum-algos`, `sshv1` |
| smb (microsoft-ds, netbios-ssn) | `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-enum-shares`, `smb-enum-users` |
| mysql | `mysql-empty-password`, `mysql-vuln-cve2012-2122`, `mysql-databases` |
| ms-sql-s | `ms-sql-info`, `ms-sql-empty-password`, `ms-sql-dump-hashes` |
| oracle-tns | `oracle-tns-version`, `oracle-sid-brute` |
| snmp | `snmp-info`, `snmp-brute`, `snmp-processes` |
| dns | `dns-zone-transfer`, `dns-recursion`, `dns-brute` |
| ldap | `ldap-rootdse`, `ldap-search`, `ldap-brute` |
| rdp | `rdp-vuln-ms12-020`, `rdp-enum-encryption` |

Full coverage also includes: ftp, smtp, pop3, imap, msrpc, postgresql, mongodb, redis, vnc, telnet, nfs, rpcbind, memcached, elasticsearch, docker, kubernetes.

Plus `vulners` and `vuln` are always included for catch-all CPE-based CVE lookup.

Full mapping is in `SERVICE_SCRIPTS` at the top of `network_scanner.py` — extend it freely.

---

## 🔍 Troubleshooting

**`Must run as root`**
The scanner needs raw sockets and low-port access. Always launch with `sudo`. Use `sudo -E` to preserve your environment variables (API keys).

**`nmap not found`**
Install nmap (see Requirements). On minimal containers, also install `libpcap` and `libssl`.

**API keys not picked up under sudo**
By default, `sudo` strips environment variables. Use `sudo -E python3 network_scanner.py` to preserve them, or run as root directly with `su -`.

**`No CVE IDs found in scan output`**
Run option 4 first to install `nmap-vulners` and `vulscan`. Without them, only built-in `vuln` scripts contribute CVE IDs — coverage will be sparse.

**NVD enrichment is very slow**
Set `NVD_API_KEY` (free, instant) — raises rate limit from 5/30s to 50/30s. Without the key, 100 CVEs take roughly 10 minutes to enrich.

**Output files appear empty**
Check `scanner.log` in the results directory — every nmap command and exit code is logged.

**Targets aren't responding**
Add `-Pn` manually if hosts block ICMP. Modify the relevant `run_nmap()` call in the source — there's no menu flag for it currently.

**`scope.txt` errors**
The file must exist and contain at least one non-empty line. Comments aren't supported — use `#` lines only outside this file.

---

## 🛡️ Security notes for using this tool

- **Authorization in writing.** Email confirmation isn't enough for legal cover in most jurisdictions. Use a signed scope document.
- **Throttle in production-adjacent networks.** The default `-T4` timing is aggressive; consider patching to `-T3` or `-T2` if scanning live customer-facing infrastructure.
- **Coordinate with NOC / SOC.** Active scans look identical to attacks in IDS/SIEM logs. Notify defensive teams beforehand to prevent incident response false alarms.
- **Don't run option 8 on production.** DoS scripts can crash services. Only on dedicated test environments.
- **Keep findings confidential.** The output directories contain your customer's vulnerability state. Encrypt at rest, transport over TLS, retain per your engagement contract.
- **CVE results are point-in-time.** A clean report today doesn't mean a clean system tomorrow — re-scan regularly.
- **Keep the script DB updated.** Run option 3 (`nmap --script-updatedb`) periodically; new vulnerability scripts ship with nmap releases.

---

## 📝 Suggested `.gitignore`

If you push a fork to GitHub, add this to keep scan results and local secrets out of the repo:

```
# Scan results (contain customer vulnerability data)
scan_results_*/

# Local config
scope.txt
.env

# Cloned NSE scripts (option 4 puts them in CWD)
nmap-vulners/
vulscan/

# OS / editor
.DS_Store
.idea/
.vscode/
__pycache__/
*.pyc
```

---

## 🤝 Contributing

Issues and PRs welcome. Particularly useful:

- New service mappings in `SERVICE_SCRIPTS` (look at recent CVEs for inspiration — IoT services, container orchestrators, message queues, etc.)
- Additional CVE enrichment sources (e.g., CISA KEV catalog, EPSS scoring, ExploitDB)
- Output exporters (SARIF, DefectDojo, Jira, Slack webhook)
- Tighter mapping of CVEs to specific host:port pairs (currently option 11 maps each CVE to all detected services as a conservative default)

Please keep changes Python 3.10+ compatible and avoid adding hard pip dependencies — the stdlib-only constraint is a feature.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

---

## 👤 Author

**Shubham Sahu** — `ssahu@planful.com`

Built at Planful. Not an official Planful product — provided as-is for the security community.

---

## 🙏 Acknowledgments

- [Nmap](https://nmap.org/) — the foundation everything here is built on
- [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners) — CPE-based CVE lookup script
- [scipag/vulscan](https://github.com/scipag/vulscan) — offline CVE database scanner
- [NVD](https://nvd.nist.gov/) — National Vulnerability Database
- [OSV.dev](https://osv.dev/) — Open Source Vulnerability database
- [GitHub Advisory Database](https://github.com/advisories) — curated ecosystem advisories
- [Vulners](https://vulners.com/) — vulnerability intelligence platform

---

## ⚠️ Final disclaimer

This tool is for **authorized security testing and education only**. Running it against systems without explicit written permission from the owner is illegal and unethical. The author and any contributors disclaim liability for misuse, damages, service disruptions, or legal consequences arising from use of this software. **You are responsible for your own actions.**
