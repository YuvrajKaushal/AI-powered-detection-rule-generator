# Detection Rule Generator

An interactive AI-powered CLI agent that generates production-ready security detection rules from plain-English queries.

Supports **5 rule formats** simultaneously:

| Format | Platform | Use Case |
|---|---|---|
| **Sigma** | Any SIEM (platform-agnostic YAML) | Universal rule sharing, sigma2splunk/sigma2kql conversion |
| **KQL** | Microsoft Sentinel, Defender XDR | Azure/M365 environment threat hunting and alerting |
| **SPL** | Splunk SIEM | Saved searches, correlation rules, alerts |
| **SentinelOne** | SentinelOne EDR | Deep Visibility hunting + STAR automated response |
| **YARA** | File/memory scanners | Malware detection, IR triage, AV rules |

KQL queries are modelled after real-world patterns from the [SlimKQL/Detections.AI](https://github.com/SlimKQL/Detections.AI/tree/main/KQL) community detection library.

---

## Prerequisites

- Python 3.10 or higher
- An Anthropic API key ([get one here](https://console.anthropic.com))

---

## Installation

**1. Clone or download the project**

```
Automated script/
├── detection_agent.py
├── requirements.txt
├── README.md
└── rules/              ← auto-created on first run
    ├── threat_intel/
    ├── behavioral/
    ├── lateral_movement/
    ├── privilege_escalation/
    ├── persistence/
    ├── exfiltration/
    └── compliance/
```

**2. Install the dependency**

```powershell
pip install -r requirements.txt
```

**3. Set your Anthropic API key**

PowerShell (current session only):
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-YOUR_KEY_HERE"
```

PowerShell (persist across sessions — add to your profile):
```powershell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-YOUR_KEY_HERE", "User")
```

---

## Running the Agent

```powershell
python detection_agent.py
```

On startup you will see the **format selector dropdown**. Choose which rule formats to generate:

```
========================================================================
  SELECT RULE FORMATS
========================================================================

    [1]  [ ]  Sigma           Generic SIEM YAML rule (platform-agnostic)
    [2]  [ ]  KQL             Microsoft Sentinel / Defender 365
    [3]  [+]  SPL             Splunk Search Processing Language
    [4]  [+]  SentinelOne     Deep Visibility query + STAR automated rule
    [5]  [ ]  YARA            Malware / file content scanning

  Active : SPL, SentinelOne
  Enter numbers to select (e.g. 1 3 4)  |  'all'  |  Enter = confirm
  >
```

- Type **numbers** to select formats: `1 3 4` selects Sigma + SPL + SentinelOne
- Type **`all`** to select every format
- Press **Enter** to confirm and keep the current selection
- The `[+]` marker shows which formats are currently active

---

## Commands

Once inside the agent prompt (`detection>`):

| Command | Action |
|---|---|
| `<any query>` | Generate detection rules for the query |
| `format` | Re-open the format selector to change active formats |
| `list` | Browse all saved rules by category |
| `help` | Show help and example queries |
| `quit` | Exit |

---

## Writing Queries

Type any natural-language threat description. Be as specific or as broad as you like:

```
detection> detect ransomware encrypting files across network shares
detection> detect LSASS credential dumping via Mimikatz
detection> detect lateral movement via PsExec
detection> detect PowerShell encoded command execution
detection> detect DNS tunneling for data exfiltration
detection> detect Pass-the-Hash attack using stolen NTLM hashes
detection> detect new scheduled task created for persistence
detection> detect suspicious OAuth application consent
detection> detect mass email deletion in Exchange Online
detection> detect brute force login attempts against Active Directory
detection> detect living-off-the-land binaries (LOLBins) abuse
detection> CVE-2026-26119 Windows Admin Center privilege escalation
```

The agent automatically:
- Classifies the rule into the correct threat category
- Maps to MITRE ATT&CK technique IDs
- Assigns severity level
- Generates rules for every selected format

---

## Format Details

### Sigma
Platform-agnostic YAML detection rule. Can be converted to Splunk, Elasticsearch, Sentinel, and others using [sigma-cli](https://github.com/SigmaHQ/sigma-cli).

```yaml
title: Ransomware File Encryption Activity
status: experimental
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.encrypted'
      - '.locky'
  condition: selection
level: high
```

### KQL
Queries for **Microsoft Sentinel** (Log Analytics) and **Microsoft Defender XDR** (Advanced Hunting). Follows SlimKQL community conventions:

- `let LookBack = 1h;` time window variables
- `dynamic([...])` arrays for multi-value matching with `has_any()`
- Cross-table `let` + `join`/`union` for correlated detections
- `invoke FileProfile()` for rare/low-prevalence file detection
- `externaldata()` for importing external IOC CSV lists

Two queries are generated:
- **Hunting query** — for manual threat hunting in the advanced hunting console
- **Scheduled alert** — ready to deploy as a Sentinel Analytics Rule with frequency, period, and trigger settings

### SPL
Splunk Search Processing Language saved search. Includes:
- Full search string with proper `sourcetype` and `EventCode` references
- Cron schedule for automated alerting
- Alert threshold and comparator
- Time range (separate from the SPL string — paste into Splunk's time picker)

### SentinelOne
Two artifacts generated:
- **Deep Visibility query** — PowerQuery syntax for the SentinelOne Deep Visibility hunting console
- **STAR Rule** — Storyline Active Response rule for automated real-time detection, with severity, action, and `treatAsThreat` classification

### YARA
Complete YARA rule for file and memory scanning. Useful for:
- VirusTotal Livehunt / Retrohunt
- ClamAV custom signatures
- YARA-X / yaraScan in IR toolkits
- Malware sandbox detonation enrichment

Includes `meta`, `strings` (plaintext + hex + regex), and a `condition` block.

---

## Saved Rules

Rules are saved as JSON files under `rules/<category>/`:

```
rules/
├── threat_intel/          ← IOC-based detections (hashes, IPs, domains)
├── behavioral/            ← Anomaly and pattern-based detections
├── lateral_movement/      ← PsExec, WMI, RDP, Pass-the-Hash
├── privilege_escalation/  ← UAC bypass, token abuse, LSASS
├── persistence/           ← Scheduled tasks, registry, services
├── exfiltration/          ← DNS tunneling, large transfers
└── compliance/            ← Audit, policy, access control
```

Each JSON file contains the rule metadata and all generated format blocks:

```json
{
  "title": "Suspicious PowerShell Encoded Command",
  "category": "behavioral",
  "severity": "high",
  "mitre_attack": ["T1059.001", "T1027"],
  "tags": ["powershell", "windows", "lolbas"],
  "splunk": { "search": "...", "cron_schedule": "..." },
  "sentinelone": { "deep_visibility_query": "...", "star_rule": { ... } },
  "sigma": { "rule": "..." },
  "kql": { "hunting_query": "...", "scheduled_alert": { ... } },
  "yara": { "rule": "..." }
}
```

Use `detection> list` to browse all saved rules grouped by category.

---

## KQL Reference — SlimKQL Patterns

This agent's KQL generation is informed by real-world detection queries from the [SlimKQL/Detections.AI](https://github.com/SlimKQL/Detections.AI/tree/main/KQL) community library. Patterns used include:

| Pattern | Example Use |
|---|---|
| `let LookBack = 1h;` + `ago(LookBack)` | Consistent time window across all table filters |
| `let List = dynamic([...])` + `has_any(List)` | Efficient multi-value matching for process/domain lists |
| `let SubSet = Table \| where ... \| distinct Field;` then filter with `has_any(SubSet)` | Cross-table correlated detection |
| `invoke FileProfile("SHA1", 1000)` | Rare-binary detection via GlobalPrevalence < threshold |
| `externaldata(Col:type)[h'url']` | Import live IOC CSV feeds |
| `matches regex @"pattern"` with `tolower()` | Case-insensitive complex string matching |
| Multi-table `\| union` | Combine ProcessEvents + FileEvents + NetworkEvents |

---

## Troubleshooting

**`ANTHROPIC_API_KEY` not set**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

**Empty or malformed JSON output**
The model generates large outputs for all-5-format queries. If you hit a parse error, try selecting fewer formats or retry — the adaptive thinking model occasionally wraps JSON in markdown fences which the parser handles automatically.

**Rules directory not created**
The `rules/` folder and all category subdirectories are created automatically on first run. No manual setup needed.

---

## Model

Powered by **Claude Opus 4.8** (`claude-opus-4-8`) with adaptive extended thinking enabled. This model reasons through the threat scenario before generating rules, producing higher-quality, context-aware detections compared to non-thinking models.
