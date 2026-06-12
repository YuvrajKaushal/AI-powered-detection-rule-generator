#!/usr/bin/env python3
"""Detection Rule Generator — Sigma, KQL, SPL, SentinelOne, YARA | Powered by Claude"""

import anthropic
import json
import os
import re
from datetime import datetime
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────

CATEGORIES = [
    "threat_intel", "behavioral", "lateral_movement",
    "privilege_escalation", "persistence", "exfiltration", "compliance",
]

RULES_DIR = Path(__file__).parent / "rules"

# (key, display name, description)
FORMATS = [
    ("sigma",       "Sigma",       "Generic SIEM YAML rule (platform-agnostic)"),
    ("kql",         "KQL",         "Microsoft Sentinel / Defender 365"),
    ("spl",         "SPL",         "Splunk Search Processing Language"),
    ("sentinelone", "SentinelOne", "Deep Visibility query + STAR automated rule"),
    ("yara",        "YARA",        "Malware / file content scanning"),
]

W = 72
SEP = "=" * W
SUB = "-" * W

# ── System prompt (modular per format) ──────────────────────────────────────

_PROMPT_BASE = """You are an expert cybersecurity detection engineer. Generate high-quality, production-ready detection rules based on user queries.

## MANDATORY Output Format

Respond with ONLY a JSON object — no preamble, no explanation, no markdown fences. Start with `{` and end with `}`.

Always include these base fields plus only the format-specific keys requested:
{
  "title": "Short descriptive rule title",
  "description": "What this rule detects and why it matters",
  "category": "<threat_intel|behavioral|lateral_movement|privilege_escalation|persistence|exfiltration|compliance>",
  "severity": "<critical|high|medium|low>",
  "mitre_attack": ["T1234", "T1234.001"],
  "tags": ["example", "windows"]
}

## Category Selection
- threat_intel: IOC-based — known-bad hashes, IPs, domains, file names, signatures
- behavioral: anomalous patterns — unusual timing, frequency, volume, deviation from baseline
- lateral_movement: PsExec, WMI, SMB, RDP, Pass-the-Hash, Pass-the-Ticket, DCOM
- privilege_escalation: UAC bypass, token impersonation, LSASS dump, sudo/su abuse, kernel exploits
- persistence: registry Run keys, scheduled tasks, services, startup folder, WMI subscriptions, cron
- exfiltration: large transfers, DNS tunneling, cloud uploads, unusual outbound protocols
- compliance: failed logins, account lockouts, USB usage, admin account activity, audit gaps
"""

_PROMPT_SIGMA = """
## Sigma Format  (key: "sigma")

"sigma": {
  "rule": "<complete Sigma YAML as a single JSON string with \\n for newlines>",
  "description": "human-readable explanation of detection logic"
}

Sigma YAML structure:
  title: Rule Title
  id: <UUID v4>
  status: experimental
  description: What this detects
  references: []
  author: detection-agent
  date: YYYY/MM/DD
  tags:
    - attack.tXXXX
  logsource:
    category: <process_creation|file_event|registry_event|network_connection|dns_query|webserver>
    product: <windows|linux|macos>
  detection:
    selection:
      FieldName|modifier: value
    condition: selection
  falsepositives:
    - Unknown
  level: <informational|low|medium|high|critical>

Field modifiers: contains, endswith, startswith, re, all, base64, windash
Use pipe-separated list for OR within a field.
"""

_PROMPT_KQL = """
## KQL Format  (key: "kql")

"kql": {
  "hunting_query": "<KQL for Threat Hunting in Log Analytics / Advanced Hunting>",
  "scheduled_alert": {
    "query": "<KQL for Sentinel Scheduled Analytics Rule>",
    "query_frequency": "PT1H",
    "query_period": "PT24H",
    "trigger_operator": "GreaterThan",
    "trigger_threshold": 0,
    "severity": "High"
  },
  "description": "human-readable explanation of detection logic"
}

KQL tables and key fields:
- SecurityEvent: EventID, Account, Computer, CommandLine, NewProcessName, LogonType, IpAddress, SubjectUserName
- DeviceProcessEvents: DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessIntegrityLevel, SHA256, Timestamp
- DeviceNetworkEvents: DeviceName, RemoteIP, RemotePort, RemoteUrl, RemoteIPType, InitiatingProcessFileName, ActionType, Timestamp
- DeviceFileEvents: DeviceName, FileName, FolderPath, SHA256, ActionType, InitiatingProcessAccountName, Timestamp
- DeviceRegistryEvents: DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
- DeviceLogonEvents: DeviceName, AccountName, LogonType, RemoteIP, ActionType
- DeviceInfo: DeviceName, LoggedOnUsers, OSPlatform, PublicIP
- IdentityLogonEvents: AccountUpn, DeviceName, IPAddress, LogonType
- IdentityInfo: AccountUpn, OnPremSid, Department, JobTitle
- EmailEvents: NetworkMessageId, RecipientEmailAddress, SenderFromAddress, DeliveryAction, EmailDirection, Timestamp
- EmailAttachmentInfo: NetworkMessageId, FileName, FileExtension, FileType, SHA256
- EmailUrlInfo: NetworkMessageId, Url, UrlChain
- UrlClickEvents: AccountUpn, Url, UrlChain, ActionType, Timestamp
- CloudAppEvents: ActionType, AccountId, RawEventData, Application, Timestamp
- AuditLogs, SigninLogs: ResultType, AppId, UserPrincipalName, IPAddress, ConditionalAccessStatus
- AlertInfo, AlertEvidence: AlertId, Title, Severity, Category, ServiceSource

KQL style guidelines (based on SlimKQL/Detections.AI community patterns):
- Always open with a let LookBack = Xh/d/m; variable, then filter with | where Timestamp > ago(LookBack)
- Use let + dynamic([...]) for allowlists/denylist arrays: let BrowserList = dynamic(["chrome.exe","msedge.exe"]);
- Use has_any(ListVar) for efficient multi-value string matching — faster than OR chains
- Use matches regex @"pattern" for complex string patterns; use tolower() before regex for case-insensitive
- For correlated multi-table detections, build intermediate let tables then join/union:
    let SuspiciousUsers = EmailEvents | where ... | distinct RecipientEmailAddress;
    CloudAppEvents | where ... | where AccountId has_any(SuspiciousUsers)
- Use invoke FileProfile("SHA1", 1000) in DeviceFileEvents to get GlobalPrevalence for rare file detection
- Use externaldata(Col:type)[h'https://raw.githubusercontent.com/.../IOC.csv'] with (format='csv', ignoreFirstRecord=true) to import IOC lists
- Parse JSON fields with: tostring(parse_json(tostring(RawEventData.Field)).SubField)
- Use | union to merge results from multiple tables
- Cross-entity correlation pattern: build a distinct set from table A, join as filter into table B
- Use | extend to create derived fields before filtering on them
- End hunting queries with | project Timestamp, DeviceName, AccountName, <key fields> | sort by Timestamp desc
- For scheduled alerts use simplified queries with | summarize count() and threshold-based triggers
- Use RemoteIPType == "Public" to filter out internal traffic in network detections
"""

_PROMPT_SPL = """
## SPL Format  (key: "splunk")

"splunk": {
  "search": "<full SPL search string — do NOT include time range here>",
  "earliest_time": "-24h",
  "latest_time": "now",
  "cron_schedule": "0 * * * *",
  "alert_threshold": 1,
  "alert_comparator": "greater than",
  "description": "human-readable explanation of detection logic"
}

SPL guidelines:
- sourcetypes: WinEventLog:Security, WinEventLog:System, XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- EventCodes: 4624/4625 (logon), 4688 (process), 4698/4702 (scheduled task), 4720 (account), 7045 (service), Sysmon 1/3/7/11
- Use stats, eval, where, rex, transaction, lookup, join appropriately
- End with | table field1 field2 field3 for key investigative fields
- Add count-based thresholds where relevant (| where count > N)
- Earliest/latest go in their own JSON fields only
"""

_PROMPT_S1 = """
## SentinelOne Format  (key: "sentinelone")

"sentinelone": {
  "deep_visibility_query": "<PowerQuery for Deep Visibility threat hunting>",
  "star_rule": {
    "name": "STAR rule display name",
    "description": "what the STAR rule detects",
    "query": "<PowerQuery for STAR automated detection>",
    "severity": "HIGH",
    "action": "alert",
    "treatAsThreat": "SUSPICIOUS"
  },
  "description": "human-readable explanation of detection logic"
}

SentinelOne PowerQuery guidelines:
- Event types: ProcessCreation, FileCreation, FileModification, FileDeletion, RegistryKeyModification, RegistryValueModification, NetworkConnection, DnsQuery, CommandScriptExecution, Login, Logout, ModuleLoad, ScheduledTask
- Fields: SrcProcName, SrcProcCmdLine, TgtFilePath, TgtFileExtension, DstIP, DstPort, DnsRequest, SHA256, SrcProcUser, SrcProcParentName, RegistryKeyPath, RegistryValue
- Operators: =, !=, contains, in, startswith, endswith, matches (regex)
- Chain with AND / OR, group with parentheses
- treatAsThreat: "MALICIOUS" or "SUSPICIOUS"
- severity: "CRITICAL", "HIGH", "MEDIUM", "LOW"
"""

_PROMPT_YARA = """
## YARA Format  (key: "yara")

"yara": {
  "rule": "<complete YARA rule as a single JSON string with \\n for newlines>",
  "scan_targets": ["<memory|files|both>"],
  "description": "human-readable explanation of detection logic"
}

YARA rule structure:
  rule RuleName {
      meta:
          description = "..."
          author = "detection-agent"
          date = "YYYY-MM-DD"
          mitre_attack = "TXXXX"
      strings:
          $s1 = "plaintext string" nocase
          $s2 = { 4D 5A ?? ?? 00 00 }  // hex
          $re1 = /regex_pattern/i
      condition:
          any of them
  }

Modifiers: nocase, wide, ascii, fullword, base64
Use uint16(0) == 0x5A4D to check for PE files.
Use filesize for file size constraints.
Use all of ($s*) or N of them for precision.
Minimize false positives with specific string combinations.
"""


def _build_system_prompt(selected: set[str]) -> str:
    parts = [_PROMPT_BASE]
    order = [("sigma", _PROMPT_SIGMA), ("kql", _PROMPT_KQL), ("spl", _PROMPT_SPL),
             ("sentinelone", _PROMPT_S1), ("yara", _PROMPT_YARA)]
    for key, prompt in order:
        if key in selected:
            parts.append(prompt)
    parts.append("\nGenerate complete, functional rules that can be used without modification.")
    return "".join(parts)


# ── Format dropdown ──────────────────────────────────────────────────────────

def show_format_dropdown(current: set[str]) -> set[str]:
    selected = set(current)

    while True:
        print()
        print(SEP)
        print("  SELECT RULE FORMATS")
        print(SEP)
        print()
        for i, (key, name, desc) in enumerate(FORMATS, 1):
            mark = "+" if key in selected else " "
            print(f"    [{i}]  [{mark}]  {name:<14}  {desc}")
        print()
        active_names = [name for key, name, _ in FORMATS if key in selected]
        if active_names:
            print(f"  Active : {', '.join(active_names)}")
        else:
            print("  Active : (none selected)")
        print()
        print("  Enter numbers to select (e.g. 1 3 4)  |  'all'  |  Enter = confirm")
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            return selected if selected else {FORMATS[2][0]}  # default to SPL

        if raw == "":
            if selected:
                return selected
            print("  Please select at least one format.")
            continue

        if raw.lower() == "all":
            return {key for key, _, _ in FORMATS}

        nums = re.findall(r"\d+", raw)
        new_sel: set[str] = set()
        bad = False
        for n in nums:
            idx = int(n) - 1
            if 0 <= idx < len(FORMATS):
                new_sel.add(FORMATS[idx][0])
            else:
                print(f"  Invalid option: {n}  (choose 1–{len(FORMATS)})")
                bad = True
                break
        if not bad and new_sel:
            selected = new_sel


# ── Save / load rules ────────────────────────────────────────────────────────

def _init_dirs():
    for cat in CATEGORIES:
        (RULES_DIR / cat).mkdir(parents=True, exist_ok=True)


def save_rule(rule: dict) -> Path:
    category = rule.get("category", "behavioral")
    if category not in CATEGORIES:
        category = "behavioral"
    cat_dir = RULES_DIR / category
    cat_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "_", rule.get("title", "rule").lower()).strip("_")
    path = cat_dir / f"{ts}_{slug}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rule, f, indent=2)
    return path


# ── Display helpers ──────────────────────────────────────────────────────────

def _wrap(text: str, indent: int = 2, width: int = 68) -> str:
    prefix = " " * indent
    words, buf, lines = text.split(), [], []
    for w in words:
        if sum(len(x) + 1 for x in buf) + len(w) > width:
            lines.append(prefix + " ".join(buf))
            buf = [w]
        else:
            buf.append(w)
    if buf:
        lines.append(prefix + " ".join(buf))
    return "\n".join(lines)


def _print_multiline(text: str, indent: str = "    "):
    for line in text.splitlines():
        print(f"{indent}{line}")


def _display_sigma(data: dict):
    print()
    print(SUB)
    print("  SIGMA  (Generic SIEM YAML — platform-agnostic)")
    print(SUB)
    desc = data.get("description", "")
    if desc:
        print(f"  {desc}")
    rule_text = data.get("rule", "")
    if rule_text:
        print()
        print("  Rule YAML:")
        _print_multiline(rule_text)


def _display_kql(data: dict):
    print()
    print(SUB)
    print("  KQL  (Microsoft Sentinel / Defender 365)")
    print(SUB)
    desc = data.get("description", "")
    if desc:
        print(f"  {desc}")
    hq = data.get("hunting_query", "")
    if hq:
        print()
        print("  Threat Hunting Query:")
        for line in hq.splitlines():
            print(f"    {line}")
    sa = data.get("scheduled_alert", {})
    if sa:
        print()
        print("  Scheduled Analytics Rule:")
        q = sa.get("query", "")
        if q:
            for line in q.splitlines():
                print(f"    {line}")
        print()
        print(f"    Frequency : {sa.get('query_frequency', 'PT1H')}")
        print(f"    Period    : {sa.get('query_period', 'PT24H')}")
        print(f"    Trigger   : {sa.get('trigger_operator', 'GreaterThan')} {sa.get('trigger_threshold', 0)}")
        print(f"    Severity  : {sa.get('severity', 'High')}")


def _display_spl(data: dict):
    print()
    print(SUB)
    print("  SPL  (Splunk Saved Search / Alert)")
    print(SUB)
    desc = data.get("description", "")
    if desc:
        print(f"  {desc}")
    spl = data.get("search", "")
    if spl:
        print()
        print("  Search Query:")
        parts = spl.split(" | ")
        print(f"    {parts[0]}")
        for p in parts[1:]:
            print(f"    | {p}")
    print()
    print(f"  Time Range  : {data.get('earliest_time', '-24h')}  →  {data.get('latest_time', 'now')}")
    print(f"  Schedule    : {data.get('cron_schedule', '0 * * * *')}")
    print(f"  Alert When  : results {data.get('alert_comparator', 'greater than')} {data.get('alert_threshold', 1)}")


def _display_sentinelone(data: dict):
    print()
    print(SUB)
    print("  SENTINELONE  (Deep Visibility + STAR Rule)")
    print(SUB)
    desc = data.get("description", "")
    if desc:
        print(f"  {desc}")
    dv = data.get("deep_visibility_query", "")
    if dv:
        print()
        print("  Deep Visibility Query (Threat Hunting):")
        parts = re.split(r"\s+(AND|OR)\s+", dv)
        if len(parts) > 1:
            print(f"    {parts[0]}")
            i = 1
            while i < len(parts) - 1:
                print(f"    {parts[i]} {parts[i+1]}")
                i += 2
        else:
            print(f"    {dv}")
    star = data.get("star_rule", {})
    if star:
        print()
        print("  STAR Rule (Automated Detection + Response):")
        print(f"    Name      : {star.get('name', 'N/A')}")
        print(f"    Severity  : {star.get('severity', 'N/A')}")
        print(f"    Action    : {star.get('action', 'N/A')}")
        print(f"    Treat As  : {star.get('treatAsThreat', 'N/A')}")
        print(f"    Query     : {star.get('query', 'N/A')}")


def _display_yara(data: dict):
    print()
    print(SUB)
    print("  YARA  (Malware / File Content Scanning)")
    print(SUB)
    desc = data.get("description", "")
    if desc:
        print(f"  {desc}")
    targets = data.get("scan_targets", [])
    if targets:
        print(f"  Scan Targets: {', '.join(targets)}")
    rule_text = data.get("rule", "")
    if rule_text:
        print()
        print("  Rule:")
        _print_multiline(rule_text)


_FORMAT_DISPLAY = {
    "sigma":       _display_sigma,
    "kql":         _display_kql,
    "spl":         _display_spl,
    "sentinelone": _display_sentinelone,
    "yara":        _display_yara,
}


def display_rule(rule: dict, saved_path: Path, selected: set[str]):
    def lbl(label, val):
        print(f"  {label:<12}{val}")

    print()
    print(SEP)
    print("  DETECTION RULE GENERATED")
    print(SEP)
    lbl("Title:",    rule.get("title", "N/A"))
    lbl("Category:", rule.get("category", "N/A").replace("_", " ").upper())
    lbl("Severity:", rule.get("severity", "N/A").upper())
    mitre = rule.get("mitre_attack", [])
    if mitre:
        lbl("MITRE:", ", ".join(mitre))
    tags = rule.get("tags", [])
    if tags:
        lbl("Tags:", ", ".join(tags))
    formats_present = [name for key, name, _ in FORMATS if key in rule and key in selected]
    if formats_present:
        lbl("Formats:", ", ".join(formats_present))
    lbl("Saved:", str(saved_path))
    desc = rule.get("description", "")
    if desc:
        print()
        print(_wrap(desc))

    for key, _, _ in FORMATS:
        if key in selected and key in rule:
            _FORMAT_DISPLAY[key](rule[key])

    print()
    print(SEP)
    print()


# ── Rule generation ──────────────────────────────────────────────────────────

def generate_rule(query: str, selected: set[str]) -> dict | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("\n  ERROR: ANTHROPIC_API_KEY environment variable not set.")
        print("  Set it with:  $env:ANTHROPIC_API_KEY = 'sk-ant-...'")
        return None

    client = anthropic.Anthropic(api_key=api_key)
    format_names = [name for key, name, _ in FORMATS if key in selected]

    print(f"\n  Query   : {query}")
    print(f"  Formats : {', '.join(format_names)}")
    print("  Generating", end="", flush=True)

    full_text = ""
    system_prompt = _build_system_prompt(selected)

    kql_note = (
        " For KQL, follow the SlimKQL/Detections.AI community style:"
        " use let LookBack variables, dynamic() arrays, has_any(), cross-table let+join correlation,"
        " invoke FileProfile() for rare-file detection, and externaldata() for IOC imports where relevant."
        if "kql" in selected else ""
    )
    user_msg = (
        f"Generate detection rules for: {query}\n\n"
        f"Include ONLY these rule format keys in the JSON: {', '.join(k for k, _, _ in FORMATS if k in selected)}\n"
        f"{kql_note}\n"
        "Return ONLY the JSON object. No markdown, no explanation."
    )

    with client.messages.stream(
        model="claude-opus-4-8",
        max_tokens=8192,
        thinking={"type": "adaptive"},
        system=system_prompt,
        messages=[{"role": "user", "content": user_msg}],
    ) as stream:
        for event in stream:
            t = getattr(event, "type", None)
            if t == "content_block_delta":
                delta = getattr(event, "delta", None)
                if delta and getattr(delta, "type", None) == "text_delta":
                    full_text += delta.text
                    print(".", end="", flush=True)
            elif t == "content_block_start":
                block = getattr(event, "content_block", None)
                if block and getattr(block, "type", None) == "thinking":
                    print(".", end="", flush=True)

    print(" Done!\n")

    # Extract JSON
    stripped = full_text.strip()
    json_str = None
    if stripped.startswith("{"):
        json_str = stripped
    else:
        m = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", stripped)
        if m:
            json_str = m.group(1)
        else:
            m = re.search(r"\{[\s\S]*\}", stripped)
            if m:
                json_str = m.group(0)

    if not json_str:
        print("  ERROR: No JSON found in response.")
        print("  Raw (first 400 chars):", full_text[:400])
        return None

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"  ERROR: JSON parse failed — {e}")
        print("  Raw JSON (first 600 chars):", json_str[:600])
        return None


# ── List rules ───────────────────────────────────────────────────────────────

def list_rules():
    print()
    print(SEP)
    print("  SAVED DETECTION RULES")
    print(SEP)
    total = 0
    for cat in CATEGORIES:
        cat_path = RULES_DIR / cat
        if not cat_path.exists():
            continue
        files = sorted(cat_path.glob("*.json"))
        if not files:
            continue
        label = cat.upper().replace("_", " ")
        print(f"\n  [{label}]  ({len(files)} rule{'s' if len(files) != 1 else ''})")
        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                sev = data.get("severity", "?").upper()
                title = data.get("title", f.stem)
                mitre = ", ".join(data.get("mitre_attack", []))
                m_str = f"  [{mitre}]" if mitre else ""
                fmts = [name for key, name, _ in FORMATS if key in data]
                f_str = f"  ({', '.join(fmts)})" if fmts else ""
                print(f"    • [{sev}] {title}{m_str}{f_str}")
            except Exception:
                print(f"    • {f.stem}")
            total += 1
    if total == 0:
        print("\n  No rules saved yet — run a query to generate some!")
    else:
        print(f"\n  Total: {total} rule{'s' if total != 1 else ''}")
    print(SEP)
    print()


# ── Help ─────────────────────────────────────────────────────────────────────

def show_help(selected: set[str]):
    active = [name for key, name, _ in FORMATS if key in selected]
    print(f"""
  COMMANDS
  {SUB}
  <query>   Generate detection rules.  Examples:
              detect ransomware encryption activity
              detect lateral movement via PsExec
              detect LSASS credential dumping
              detect DNS tunneling exfiltration
              detect PowerShell encoded command execution
              detect Pass-the-Hash attack
              detect new scheduled task for persistence
              detect brute force failed logins

  format    Open format selector (currently: {', '.join(active)})
  list      List all saved rules
  help      Show this help
  quit      Exit
  {SUB}
""")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print()
    print(SEP)
    print("  DETECTION RULE GENERATOR")
    print("  Sigma  |  KQL  |  SPL  |  SentinelOne  |  YARA")
    print("  Powered by Claude Opus  |  Type 'help' for commands")
    print(SEP)

    _init_dirs()

    # Format selection at startup
    selected = show_format_dropdown({"spl", "sentinelone"})
    active = [name for key, name, _ in FORMATS if key in selected]
    print(f"\n  Formats locked in: {', '.join(active)}")
    print("  Type your query to generate rules, or 'help' for all commands.\n")

    while True:
        try:
            raw = input("  detection> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting...\n")
            break

        if not raw:
            continue

        cmd = raw.lower()

        if cmd in ("quit", "exit", "q", "bye"):
            print("\n  Goodbye!\n")
            break

        if cmd in ("format", "formats", "mode"):
            selected = show_format_dropdown(selected)
            active = [name for key, name, _ in FORMATS if key in selected]
            print(f"\n  Formats updated: {', '.join(active)}\n")
            continue

        if cmd == "list":
            list_rules()
            continue

        if cmd in ("help", "?", "h"):
            show_help(selected)
            continue

        rule = generate_rule(raw, selected)
        if rule:
            path = save_rule(rule)
            display_rule(rule, path, selected)
        else:
            print("  Failed to generate rule. Please try again.\n")


if __name__ == "__main__":
    main()
