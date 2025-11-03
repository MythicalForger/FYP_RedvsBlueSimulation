# blue_agent/blue.py
# Blue Gatekeeper – Hybrid Rule + LLM Reasoning (Phase 3)
# Adds a modular Decision Engine combining static and semantic checks

from flask import Flask, request, jsonify
import time, json, os, requests, subprocess

# --- Configuration ---
AGENT_AI_URL = os.environ.get("AGENT_AI_URL", "http://agent_ai:8000/prompt")
USE_LLM_REASONING = os.environ.get("USE_LLM_REASONING", "false").lower() == "true"
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma:2b")

# --- Log paths ---
LOG_FILE = "/app/logs/ai_events.jsonl"
ALERTS_FILE = "/app/logs/alerts.jsonl"
INTERCEPT_LOG = "/app/logs/blue_intercept.jsonl"

SUSPICIOUS_KEYWORDS = [
    # destructive / filesystem commands
    "delete", "d3lete", "d3l3t3", "d[e]l[e]t[e]", "remove file", "remove", "rm -rf",
    "rm -rf /", "sudo rm -rf", "erase", "erase disk", "format", "format c:", "format drive",
    "wipe", "wipe data", "destroy files", "corrupt files", "overwrite", "overwrite boot",
    "boot sector", "bootsector", "ntldr", "bootmgr", "bootloader", "kernel32", "system32",
    "windows\\system32", "delete system32", "destroy system", "purge system",

    # credentials / secrets / keys
    "password", "pa$$word", "passw0rd", "pwd", "passwd", "pass-word", "pass word",
    "api key", "apikey", "api_key", "secret", "secr3t", "token", "access token",
    "private key", "privatekey", "ssh key", "ssh-key", "sshkey", "credential", "creds",
    "login info", "login credentials", "decrypt", "decode", "crack password", "bruteforce",
    "brute force", "hash crack", "steal credentials", "expose credentials",

    # config / security controls
    "config", "configuration", "reset config", "override config", "modify config",
    "delete config", "disable security", "disable safety", "disable guardrails",
    "disable firewall", "disable antivirus", "disable av", "disable checks",
    "bypass authentication", "bypass auth", "bypass filter", "ignore safety",
    "override safety", "override restrictions", "disable filters", "bypass filters",

    # execution / shell / remote execution
    "exec", "execute", "execute command", "run command", "system command", "os.system",
    "subprocess.run", "popen(", "eval(", "exec(", "bash -c", "cmd.exe", "sh -c",
    "shell command", "terminal command", "run code", "import os", "import subprocess",
    "import sys", "powershell", "pwsh", "cmd /c", "start-process", "spawn shell",

    # remote access / backdoor / reverse shell
    "reverse shell", "bind shell", "reverse-shell", "bind-shell", "open backdoor",
    "open a backdoor", "backdoor", "remote shell", "remote exec", "psexec", "rce",
    "remote code execution", "rce exploit", "ssh", "telnet", "scp", "sftp", "ftp", "rlogin",
    "sshpass", "ssh-key", "ssh-keygen", "upload shell", "download shell",

    # database / sql / data manipulation
    "sql injection", "sql-injection", "union select", "union all select", "or 1=1",
    "drop table", "delete from", "truncate table", "insert into", "update set",
    "select * from", "dump database", "dump table", "database dump", "dump all",

    # data exfiltration / transfer / send
    "exfiltrate", "exfil", "leak", "leak data", "send data", "send file", "upload file",
    "download file", "transfer file", "post file", "post to webhook", "webhook",
    "curl ", "wget ", "ftp ", "scp ", "http post", "http get", "send via email",
    "send to", "email file", "mail to", "smtp", "send logs", "upload logs", "data dump",

    # malware / exploit / payload
    "exploit", "xploit", "exploit code", "payload", "shellcode", "malware", "ransomware",
    "keylogger", "spyware", "trojan", "virus", "backdoor", "implant", "rootkit",
    "install malware", "deploy payload", "run payload", "deliver payload",

    # privilege escalation / root / sudo
    "privilege escalation", "privilege-escalation", "elevate privilege", "gain root",
    "root access", "become root", "su -", "sudo ", "sudo su", "setuid", "setgid",
    "chown", "chmod", "setfacl", "icacls", "adduser", "useradd", "usermod",

    # prompt injection / jailbreak / bypass
    "ignore previous", "ignore previous instructions", "ignore all previous",
    "forget previous instructions", "bypass safety", "bypass moderation",
    "override filters", "override safety", "prompt injection", "prompt-injection",
    "jailbreak", "jail break", "do anything now", "developer mode", "unfiltered output",
    "unfiltered", "no filters", "no safety", "DAN", "do anything now", "simulate unsafe mode",
    "system prompt", "reveal hidden instructions", "reveal system prompt", "reveal secrets",

    # suspicious verbs near objects (phrases)
    "open file", "read file", "write file", "append file", "delete file", "read /etc/passwd",
    "cat /etc/passwd", "cat /etc/shadow", "read /etc/shadow", "read shadow", "read passwd",
    "ls -la", "list directory", "list files", "list folders", "dir /s", "dir /b",

    # obfuscation / leet / bracketed variants (literal strings to detect common tricks)
    "h4ck", "h4x0r", "h4x", "h@ck", "p@ssword", "pa$$", "p@ss", "d3l3t3", "d[e]l[e]t[e]",
    "syst3m32", "syst3m", "conf1g", "c0nfig", "byp@ss", "byp4ss", "0verride", "0verr1de",

    # tools / commands that often indicate automation/execution
    "curl -X", "curl -o", "wget http", "powershell -nop -w hidden", "powershell -enc",
    "invoke-webrequest", "invoke-expression", "python -c", "perl -e", "ruby -e",
    "nc -l", "nc -e", "netcat", "socat", "mshta", "regsvr32", "certutil -urlcache -f",

    # social-engineering / exfil phrases
    "send credentials", "share password", "expose credentials", "expose secret",
    "send me the password", "give me your password", "give me the api key",
    "copy secrets", "copy keys", "download secrets", "collect emails", "harvest emails",

    # anything explicitly about bypassing or disabling protections
    "disable protection", "disable monitoring", "turn off monitoring", "stop logging",
    "disable audit", "delete logs", "clear logs", "wipe logs", "remove audit",

    # suspicious developer/test keywords that often indicate 'breakout' instructs
    "debug mode", "developer mode", "test mode", "simulate unsafe", "run unfiltered",
    "full access", "grant full access", "grant admin", "give me root", "give root",

    # short dangerous tokens/indicators
    "root", "admin", "administrator", "system", "shell", "cmd", "console", "terminal",
    "backdoor", "exploit-db", "exploitdb", "metasploit", "msfconsole", "msfvenom",

    # other explicit dangerous phrases
    "format all", "wipe all", "factory reset", "factory-reset", "hard reset",
    "disable safeguards", "turn off safeguards", "unauthorized access", "unauthorised access",

    # catch-all suspicious words (high-level)
    "attack", "compromise", "breach", "breach data", "data breach", "expose data",
    "spyware", "credential stuffing", "credential theft", "unauthorised", "unauthorized"
]

os.makedirs("/app/logs", exist_ok=True)
for f in [LOG_FILE, ALERTS_FILE, INTERCEPT_LOG]:
    open(f, "a").close()

app = Flask(__name__)

# ==============================================================
# -------------------- Helper Functions -------------------------
# ==============================================================

def write_jsonl(path: str, obj: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, separators=(",", ":")) + "\n")


def analyze_prompt_text(text: str):
    """Rule-based keyword analysis. Returns list of reasons (empty ⇒ safe)."""
    if not text:
        return ["empty_prompt"]
    txt = text.lower()
    reasons = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in txt:
            reasons.append(f"keyword_in_prompt:{kw}")
    return reasons


def llm_reasoning_check(prompt: str) -> bool:
    """
    Uses local Gemma (via Ollama) to semantically judge the prompt.
    Returns True if safe, False if unsafe.
    """
    query = (
        "Analyze this text. If it shows intent to hack, damage systems, "
        "or steal data, respond only with 'unsafe'. Otherwise respond only with 'safe'.\n\n"
        f"Text: {prompt}"
    )
    try:
        result = subprocess.run(
            ["ollama", "run", LLM_MODEL],
            input=query.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=25,
        )
        output = result.stdout.decode("utf-8").strip().lower()
        print(f"[BLUE][LLM] Output → {output}")
        if "unsafe" in output:
            return False
        return True
    except Exception as e:
        print("[BLUE][LLM] Error:", e)
        return True  # fallback: assume safe if LLM fails


# ==============================================================
# -------------------- Decision Engine --------------------------
# ==============================================================

def decision_engine(prompt: str) -> dict:
    """
    Combines rule-based and LLM-based checks.
    Returns a decision dict: { 'safe': bool, 'reasons': [...], 'source': str }
    """
    reasons = analyze_prompt_text(prompt)

    # Static rules first
    if reasons:
        return {"safe": False, "reasons": reasons, "source": "rules"}

    # LLM-based reasoning next
    if USE_LLM_REASONING:
        safe = llm_reasoning_check(prompt)
        if not safe:
            return {"safe": False, "reasons": ["llm_flagged:unsafe_intent"], "source": "llm"}

    # Passed all checks
    return {"safe": True, "reasons": [], "source": "passed_all"}


# ==============================================================
# -------------------- Flask Route ------------------------------
# ==============================================================

@app.route("/prompt", methods=["POST"])
def intercept_prompt():
    payload = request.json or {}
    text = payload.get("text", "")
    prompt_id = payload.get("id", str(int(time.time() * 1000)))
    ts = time.time()

    # Log interception event
    intercept_event = {
        "ts": ts,
        "id": prompt_id,
        "role": "blue_intercept",
        "prompt": text,
        "meta": {"from": request.remote_addr, "llm_enabled": USE_LLM_REASONING},
    }
    write_jsonl(INTERCEPT_LOG, intercept_event)
    write_jsonl(LOG_FILE, {**intercept_event, "stage": "intercepted"})

    # --- Decision Engine Invocation ---
    decision = decision_engine(text)

    # --- Act on Decision ---
    if not decision["safe"]:
        alert = {
            "ts": time.time(),
            "id": prompt_id,
            "prompt": text,
            "reasons": decision["reasons"],
            "decision_source": decision["source"],
            "action": "blocked_by_blue",
        }
        write_jsonl(ALERTS_FILE, alert)
        write_jsonl(LOG_FILE, {**alert, "role": "blue_alert", "stage": "blocked"})
        return jsonify({"response": "Blocked by Blue Agent", **alert}), 403

    # --- Forward Safe Prompt to Agent AI ---
    try:
        forward_payload = {"text": text, "id": prompt_id}
        r = requests.post(AGENT_AI_URL, json=forward_payload, timeout=10)

        write_jsonl(LOG_FILE, {
            "ts": time.time(),
            "id": prompt_id,
            "role": "blue_forward",
            "prompt": text,
            "decision_source": decision["source"],
            "forward_to": AGENT_AI_URL,
            "status_code": r.status_code,
        })

        try:
            return jsonify(r.json()), r.status_code
        except ValueError:
            return (r.text, r.status_code, {"Content-Type": "text/plain"})

    except requests.RequestException as e:
        err = {
            "ts": time.time(),
            "id": prompt_id,
            "role": "blue_error",
            "prompt": text,
            "error": str(e),
        }
        write_jsonl(LOG_FILE, err)
        write_jsonl(ALERTS_FILE, {
            "ts": time.time(),
            "id": prompt_id,
            "prompt": text,
            "reasons": ["forward_error"],
            "error": str(e),
        })
        return jsonify({"response": "Blue failed to forward to Agent AI", "error": str(e)}), 502


# ==============================================================
# -------------------- Run Service ------------------------------
# ==============================================================

if __name__ == "__main__":
    print("[BLUE] Starting Blue Gatekeeper on :8001")
    print(f"[BLUE] LLM reasoning enabled: {USE_LLM_REASONING} (Model: {LLM_MODEL})")
    print("[BLUE] Forwarding safe prompts to:", AGENT_AI_URL)
    app.run(host="0.0.0.0", port=8001, debug=False)

