import os
import socket
import json
import subprocess
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, request, session, url_for, redirect, Response, abort
import requests
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import pyotp

load_dotenv()


VT_API_KEY = os.getenv("VT_API_KEY")
# optionally set path to httpx binary
HTTPX_BIN = os.getenv("HTTPX_BIN", "httpx")
SUBFINDER_BIN = os.getenv("SUBFINDER_BIN", "subfinder")
NUCLEI_BIN = os.getenv("NUCLEI_BIN", "nuclei")
PD_SCAN_MODE = os.getenv("PD_SCAN_MODE", "normal")
SECRET_KEY = os.getenv("SECRET_KEY", "change_this_in_production")
AI_PROVIDER = (os.getenv("AI_PROVIDER", "heuristic") or "heuristic").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
try:
    from openai import OpenAI
except Exception:
    OpenAI = None

app = Flask(__name__)
app.secret_key = SECRET_KEY

# OAuth configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# MongoDB configuration
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB", "fyp_app")

# Admin credentials (set in .env)
# Use either ADMIN_PASSWORD_HASH (preferred) or ADMIN_PASSWORD
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

def get_db():
    try:
        if not MONGO_URI:
            return None
        if not hasattr(app, "mongo_client") or app.mongo_client is None:
            app.mongo_client = MongoClient(MONGO_URI)
        db = app.mongo_client[MONGO_DB]
        try:
            db.scans.create_index([("user_id", 1), ("created_at", -1)])
        except Exception:
            pass
        return db
    except Exception:
        return None


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    if db is None:
        return None
    try:
        return db.users.find_one({"_id": ObjectId(uid)})
    except Exception:
        return None

# Safe helper to convert a string ID to ObjectId when possible
# Returns the original value if it’s not a valid ObjectId string
def ensure_object_id(uid):
    try:
        return ObjectId(uid)
    except Exception:
        return uid


def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None






def extract_virustotal_data(data):
    if not data or "error" in data or "data" not in data:
        return None
    attributes = data["data"]["attributes"]
    return {
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "reputation": attributes.get("reputation"),
        "whois": attributes.get("whois"),
        "last_modification_date": attributes.get("last_modification_date")
    }


# Helper to retrieve header value case-insensitively
def _get_header(headers, key):
    try:
        if isinstance(headers, dict):
            for k, v in headers.items():
                if str(k).lower() == key.lower():
                    return v
        elif isinstance(headers, list):
            for h in headers:
                name = h.get('name') or h.get('key')
                if name and name.lower() == key.lower():
                    return h.get('value') or h.get('val')
    except Exception:
        pass
    return None


def run_httpx(target):
    """
    Runs httpx CLI to probe the target. httpx emits JSON lines when -json is used.
    Returns a dict with status and parsed results (list).
    """
    try:
        # Call httpx with TLS and response headers included for richer JSON
        proc = subprocess.run(
            [HTTPX_BIN, "-json", "-silent", "-tls-grab", "-include-response-header", "-u", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15
        )
        if proc.returncode != 0 and not proc.stdout:
            return {"status": "error", "message": proc.stderr.strip()}

        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        parsed = []
        for ln in lines:
            try:
                parsed.append(json.loads(ln))
            except json.JSONDecodeError:
                continue

        summary = []
        for item in parsed:
            url_val = item.get("url") or item.get("host") or item.get("input") or target
            server_val = item.get("server") or item.get("webserver")
            content_type_val = item.get("content_type") or item.get("content-type")
            tls_val = item.get("tls_version") or item.get("tls-version") or item.get("tls")
            tls_version_val = None
            if isinstance(tls_val, dict):
                tls_version_val = tls_val.get("tls_version") or tls_val.get("version") or tls_val.get("tls")
            else:
                tls_version_val = tls_val
            ip_val = item.get("ip")

            # Try to populate from included response headers if missing
            resp = item.get("response") or {}
            headers = resp.get("headers") if isinstance(resp, dict) else None
            if not server_val and headers:
                server_val = _get_header(headers, "Server")
            if not content_type_val and headers:
                content_type_val = _get_header(headers, "Content-Type")

            if not ip_val and url_val:
                try:
                    host_part = url_val.split("://", 1)[-1].split("/", 1)[0]
                    ip_val = resolve_domain_to_ip(host_part)
                except Exception:
                    ip_val = None

            s = {
                "url": url_val,
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "server": server_val,
                "content_type": content_type_val,
                "tls_version": tls_version_val,
                "ip": ip_val,
                "tool": "httpx",
                "severity": None,
                "details": item,
            }

            # Lightweight enrichment if critical fields still missing
            if (not s.get("server") or not s.get("content_type") or not s.get("title")) and url_val:
                simple = probe_http_simple(url_val)
                if simple:
                    s["title"] = s["title"] or simple.get("title")
                    s["server"] = s["server"] or simple.get("server")
                    s["content_type"] = s["content_type"] or simple.get("content_type")
                    s["ip"] = s.get("ip") or simple.get("ip")

            summary.append(s)

        return {"status": "success", "raw": parsed, "summary": summary}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "httpx timed out"}
    except FileNotFoundError:
        return {"status": "error", "message": f"httpx binary not found: '{HTTPX_BIN}'. Ensure httpx is installed and in PATH"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def probe_http_simple(target):
    """
    Lightweight HTTP probe fallback when httpx isn't available.
    Tries https:// and http://, returns a single summary dict or None.
    """
    try:
        import requests, re
        # Build candidate URLs
        if target.startswith("http://") or target.startswith("https://"):
            candidates = [target]
            host_part = target.split("://", 1)[1].split("/", 1)[0]
        else:
            candidates = [f"https://{target}", f"http://{target}"]
            host_part = target
        ip = resolve_domain_to_ip(host_part)
        for url in candidates:
            try:
                resp = requests.get(url, timeout=10, allow_redirects=True)
                text = resp.text or ""
                m = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.I | re.S)
                title = m.group(1).strip() if m else None
                return {
                    "url": resp.url,
                    "status_code": resp.status_code,
                    "title": title,
                    "server": resp.headers.get("Server"),
                    "content_type": resp.headers.get("Content-Type"),
                    "tls_version": None,
                    "ip": ip,
                }
            except Exception:
                continue
        return None
    except Exception:
        return None


def run_subfinder(target, scan_mode=None):
    # Determine mode: prefer per-request form value, fallback to env
    mode = (scan_mode or os.getenv("PD_SCAN_MODE", "fast")).lower()
    # Skip heavy execution in fast mode
    if mode == "fast":
        return {
            "status": "skipped",
            "message": "Subfinder skipped in fast mode",
            "summary": None,
            "data": None,
        }
    try:
        # Ensure target looks like a domain
        if all(ch.isdigit() or ch == '.' for ch in target):
            return {"status": "error", "message": "Subfinder requires a domain, not an IP"}

        proc = subprocess.run(
            [SUBFINDER_BIN, "-d", target, "-silent", "-json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20
        )
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        raw = []
        summary = []
        for ln in lines:
            try:
                obj = json.loads(ln)
                host = obj.get("host") or obj.get("domain") or obj.get("input")
                if host:
                    raw.append(obj)
                    summary.append({
                        "url": host,
                        "status_code": None,
                        "title": "Subdomain",
                        "server": None,
                        "content_type": None,
                        "tls_version": None,
                        "ip": resolve_domain_to_ip(host),
                        "tool": "subfinder",
                        "severity": None,
                        "details": obj,
                    })
            except json.JSONDecodeError:
                host = ln.strip()
                if host:
                    raw.append({"host": host})
                    summary.append({
                        "url": host,
                        "status_code": None,
                        "title": "Subdomain",
                        "server": None,
                        "content_type": None,
                        "tls_version": None,
                        "ip": resolve_domain_to_ip(host),
                        "tool": "subfinder",
                        "severity": None,
                        "details": {"host": host},
                    })
        if not raw and proc.returncode != 0:
            return {"status": "error", "message": proc.stderr.strip() or "subfinder produced no output"}
        return {"status": "success", "raw": raw, "summary": summary}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "subfinder timed out"}
    except FileNotFoundError:
        return {"status": "error", "message": f"subfinder binary not found: '{SUBFINDER_BIN}'"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_nuclei(target, urls=None, scan_mode=None):
    mode = (scan_mode or os.getenv("PD_SCAN_MODE", "fast")).lower()
    if mode == "fast":
        return {
            "status": "skipped",
            "message": "Nuclei skipped in fast mode",
            "summary": None,
            "data": None,
        }
    try:
        candidates = []
        if urls:
            candidates = [u for u in urls if isinstance(u, str) and u]
        else:
            if target.startswith("http://") or target.startswith("https://"):
                candidates = [target]
            else:
                candidates = [f"https://{target}"]

        # Limit to the first candidate to reduce runtime
        candidates = candidates[:1]
        raw = []
        summary = []
        for u in candidates:
            proc = subprocess.run(
                [NUCLEI_BIN, "-u", u, "-silent", "-json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=12
            )
            lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
            for ln in lines:
                try:
                    obj = json.loads(ln)
                    raw.append(obj)
                    info = obj.get("info", {})
                    name = info.get("name") or obj.get("template-id") or obj.get("id")
                    severity = info.get("severity") or obj.get("severity")
                    matched = obj.get("matched-at") or u
                    summary.append({
                        "url": matched,
                        "status_code": None,
                        "title": name or "Nuclei finding",
                        "server": None,
                        "content_type": None,
                        "tls_version": None,
                        "ip": resolve_domain_to_ip(target),
                        "tool": "nuclei",
                        "severity": severity,
                        "details": obj,
                    })
                except json.JSONDecodeError:
                    # ignore malformed line
                    continue
        if not raw and all(not s for s in [summary]):
            # no findings; return success with empty summary
            return {"status": "success", "raw": raw, "summary": summary}
        return {"status": "success", "raw": raw, "summary": summary}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "nuclei timed out"}
    except FileNotFoundError:
        return {"status": "error", "message": f"nuclei binary not found: '{NUCLEI_BIN}'"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# --- AI Insights (heuristic) ---
def generate_ai_insights(target, summary, virustotal_data, projectdiscovery_data):
    # If configured, try LLM-based insights first
    if AI_PROVIDER == "ollama":
        try:
            # Compact inputs to keep prompt small
            vt_compact = {
                "positives": int(((virustotal_data or {}).get("last_analysis_stats", {}) or {}).get("malicious", 0) or 0),
                "suspicious": int(((virustotal_data or {}).get("last_analysis_stats", {}) or {}).get("suspicious", 0) or 0),
            }
            pd_summary = (projectdiscovery_data or {}).get("summary") or []
            pd_compact = []
            for item in pd_summary[:30]:
                pd_compact.append({
                    "tool": item.get("tool"),
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "status_code": item.get("status_code"),
                    "tls_version": item.get("tls_version"),
                    "url": item.get("url"),
                })
            instructions = (
                "You are a security assistant. Given a target and its scan summary, "
                "produce concise JSON with fields: concern_level(one of None, Low, Medium, High, Critical), "
                "explanation(one paragraph), key_findings(array of 3-8 short bullets), "
                "recommended_actions(array of 3-8 practical steps). Do not include extra fields."
            )
            payload = {
                "model": OLLAMA_MODEL,
                "prompt": instructions + "\n\nINPUT:\n" + json.dumps({
                    "target": target,
                    "summary": summary,
                    "virustotal": vt_compact,
                    "projectdiscovery": pd_compact,
                }),
                "stream": False,
            }
            url = OLLAMA_HOST.rstrip("/") + "/api/generate"
            resp = requests.post(url, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                text = (data or {}).get("response")
                if text:
                    try:
                        parsed = json.loads(text)
                        return {
                            "concern_level": parsed.get("concern_level") or (summary or {}).get("severity") or "Unknown",
                            "explanation": parsed.get("explanation") or "",
                            "key_findings": parsed.get("key_findings") or [],
                            "recommended_actions": parsed.get("recommended_actions") or [],
                        }
                    except Exception:
                        # Fallback: use raw text as explanation
                        return {
                            "concern_level": (summary or {}).get("severity") or (summary or {}).get("overall_status") or "Unknown",
                            "explanation": (text or "").strip(),
                            "key_findings": [],
                            "recommended_actions": [],
                        }
        except Exception:
            # If any LLM error, continue to heuristic
            pass
    if AI_PROVIDER == "openai" and OPENAI_API_KEY and OpenAI is not None:
        try:
            client = OpenAI(api_key=OPENAI_API_KEY)
            # Reduce payload size
            vt_compact = {
                "positives": int(((virustotal_data or {}).get("last_analysis_stats", {}) or {}).get("malicious", 0) or 0),
                "suspicious": int(((virustotal_data or {}).get("last_analysis_stats", {}) or {}).get("suspicious", 0) or 0),
            }
            pd_summary = (projectdiscovery_data or {}).get("summary") or []
            pd_compact = []
            for item in pd_summary[:30]:
                pd_compact.append({
                    "tool": item.get("tool"),
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "status_code": item.get("status_code"),
                    "tls_version": item.get("tls_version"),
                    "url": item.get("url"),
                })
            instructions = (
                "You are a security assistant. Given a target and its scan summary, "
                "produce concise JSON with fields: concern_level(one of None, Low, Medium, High, Critical), "
                "explanation(one paragraph), key_findings(array of 3-8 short bullets), "
                "recommended_actions(array of 3-8 practical steps). Do not include extra fields."
            )
            content_payload = {
                "target": target,
                "summary": summary,
                "virustotal": vt_compact,
                "projectdiscovery": pd_compact,
            }
            resp = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": instructions},
                    {"role": "user", "content": json.dumps(content_payload)},
                ],
                temperature=0.2,
            )
            text = resp.choices[0].message.content if resp and resp.choices else None
            if text:
                try:
                    parsed = json.loads(text)
                    # Ensure keys exist
                    return {
                        "concern_level": parsed.get("concern_level") or (summary or {}).get("severity") or "Unknown",
                        "explanation": parsed.get("explanation") or "",
                        "key_findings": parsed.get("key_findings") or [],
                        "recommended_actions": parsed.get("recommended_actions") or [],
                    }
                except Exception:
                    # Fallback: use raw text as explanation
                    return {
                        "concern_level": (summary or {}).get("severity") or (summary or {}).get("overall_status") or "Unknown",
                        "explanation": text.strip(),
                        "key_findings": [],
                        "recommended_actions": [],
                    }
        except Exception:
            # If any LLM error, continue to heuristic
            pass
    try:
        sev = (summary or {}).get("severity") or (summary or {}).get("overall_status") or "Unknown"
        stats = (virustotal_data or {}).get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        pd_items = (projectdiscovery_data or {}).get("summary") or []
        live_endpoints = [i for i in pd_items if i.get("status_code") in [200, 302, 403]]
        tls_issues = []
        nuclei_high = []
        for i in pd_items:
            tv = i.get("tls_version")
            if isinstance(tv, str):
                tv_low = tv.lower()
                if "tls 1.0" in tv_low or "tls 1.1" in tv_low or "ssl" in tv_low:
                    tls_issues.append(tv)
            if (i.get("tool") == "nuclei"):
                title = (i.get("title") or "")
                sev_i = (i.get("severity") or "").lower()
                if ("cve" in title.lower()) or (sev_i in ["high", "critical"]):
                    nuclei_high.append({"title": title or "nuclei finding", "severity": sev_i or None})

        key_findings = []
        if malicious > 0:
            key_findings.append(f"VirusTotal: {malicious} engines flagged as malicious")
        elif suspicious > 0:
            key_findings.append(f"VirusTotal: {suspicious} engines flagged as suspicious")
        if live_endpoints:
            key_findings.append(f"{len(live_endpoints)} live endpoints detected")
        if tls_issues:
            key_findings.append("Outdated TLS detected: " + ", ".join(sorted(set(tls_issues))))
        if nuclei_high:
            key_findings.append(f"{len(nuclei_high)} high/critical nuclei findings")

        # Concern level
        concern = "Low"
        if (sev == "High") or (malicious > 0) or nuclei_high:
            concern = "High"
        elif (sev == "Medium") or (suspicious > 0) or tls_issues or (len(live_endpoints) >= 10):
            concern = "Medium"

        explanation_parts = []
        if concern == "High":
            explanation_parts.append("There are indicators of active compromise or critical exposures.")
        elif concern == "Medium":
            explanation_parts.append("There are notable risks that warrant remediation and monitoring.")
        else:
            explanation_parts.append("Risk appears limited based on current findings.")

        if malicious > 0:
            explanation_parts.append("VirusTotal flagged malicious activity.")
        elif suspicious > 0:
            explanation_parts.append("VirusTotal flagged suspicious indicators.")
        if tls_issues:
            explanation_parts.append("Outdated TLS versions may weaken transport security.")
        if nuclei_high:
            explanation_parts.append("Nuclei reported high/critical templates; review immediately.")
        if live_endpoints:
            explanation_parts.append("Multiple live endpoints increase potential attack surface.")

        recommended_actions = []
        if malicious > 0 or nuclei_high:
            recommended_actions.append("Investigate flagged assets urgently; triage high/critical findings.")
        if suspicious > 0:
            recommended_actions.append("Increase monitoring; validate suspicious indicators with additional sources.")
        if tls_issues:
            recommended_actions.append("Upgrade TLS to 1.2/1.3; disable SSL/TLS 1.0/1.1.")
        if len(live_endpoints) >= 10:
            recommended_actions.append("Harden exposed endpoints; review rate-limiting and access controls.")
        if not recommended_actions:
            recommended_actions.append("Maintain standard security hygiene; schedule periodic re-scans.")

        return {
            "concern_level": concern,
            "explanation": " ".join(explanation_parts),
            "key_findings": key_findings,
            "recommended_actions": recommended_actions,
        }
    except Exception:
        return {
            "concern_level": (summary or {}).get("severity") or (summary or {}).get("overall_status") or "Unknown",
            "explanation": "Insights unavailable due to processing error.",
            "key_findings": [],
            "recommended_actions": ["Review raw findings manually."]
        }


@app.route("/", methods=["GET"])
def index():
    # Admin should only use the Admin Panel
    if session.get("admin_auth"):
        return redirect(url_for("admin_users"))
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    # Admin should not perform scans; redirect to Admin Panel
    if session.get("admin_auth"):
        return redirect(url_for("admin_users"))
    raw_target = request.form.get('target', '').strip()
    if not raw_target:
        return render_template('index.html', error="Please enter a target.")

    # Normalize input: accept full URLs or bare host/IP
    from urllib.parse import urlparse
    import ipaddress

    def normalize_target(s):
        try:
            p = urlparse(s)
            if p.scheme and p.netloc:
                host = p.netloc.split(':', 1)[0]
                return host
            return s
        except Exception:
            return s

    def is_ip_address(s):
        try:
            ipaddress.ip_address(s)
            return True
        except Exception:
            return False

    target = normalize_target(raw_target)
    if not target:
        return render_template('index.html', error="Please enter a valid target.")

    pd_scan_mode = (request.form.get('scan_mode') or os.getenv('PD_SCAN_MODE', 'fast')).lower()

    # VIRUSTOTAL
    virustotal_data = None
    vt_error = None
    if VT_API_KEY:
        try:
            import requests
            headers = {"x-apikey": VT_API_KEY}
            if is_ip_address(target):
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                vt_url = f"https://www.virustotal.com/api/v3/domains/{target}"
            resp = requests.get(vt_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                vt_json = resp.json()
                virustotal_data = extract_virustotal_data(vt_json)
                if not virustotal_data:
                    try:
                        vt_error = vt_json.get("error") or "No VirusTotal data found for target."
                    except Exception:
                        vt_error = "No VirusTotal data found for target."
            else:
                try:
                    err = resp.json().get("error")
                except Exception:
                    err = resp.text[:200]
                vt_error = f"VirusTotal error {resp.status_code}: {err}"
        except Exception as e:
            vt_error = f"VirusTotal request failed: {str(e)}"
            virustotal_data = None

    # PROJECTDISCOVERY (HTTPX + Subfinder + Nuclei with fallbacks)
    pd_result = run_httpx(target)
    projectdiscovery_data = {"summary": []}
    httpx_urls = []
    if pd_result.get("status") == "success" and pd_result.get("summary"):
        projectdiscovery_data["summary"].extend(pd_result["summary"])
        httpx_urls = [item.get("url") for item in pd_result["summary"] if item.get("url")]
    else:
        simple = probe_http_simple(target)
        if simple:
            projectdiscovery_data["summary"].append(simple)
            httpx_urls = [simple.get("url")]

    if not is_ip_address(target):
        sf = run_subfinder(target, scan_mode=pd_scan_mode)
        if sf.get("status") == "success" and sf.get("summary"):
            projectdiscovery_data["summary"].extend(sf["summary"])
        else:
            msg = sf.get("message") if isinstance(sf, dict) else "Subfinder produced no output"
            projectdiscovery_data["summary"].append({
                "url": target,
                "status_code": None,
                "title": f"Subfinder unavailable or no data: {msg}",
                "server": None,
                "content_type": None,
                "tls_version": None,
                "ip": resolve_domain_to_ip(target),
                "tool": "subfinder"
            })
    else:
        projectdiscovery_data["summary"].append({
            "url": target,
            "status_code": None,
            "title": "Subfinder skipped: requires domain (not IP)",
            "server": None,
            "content_type": None,
            "tls_version": None,
            "ip": target,
            "tool": "subfinder"
        })

    nu = run_nuclei(target, urls=httpx_urls or [f"https://{target}"], scan_mode=pd_scan_mode)
    if nu.get("status") == "success" and nu.get("summary"):
        projectdiscovery_data["summary"].extend(nu["summary"])
    else:
        msg = nu.get("message") if isinstance(nu, dict) else "No findings"
        projectdiscovery_data["summary"].append({
            "url": (httpx_urls[0] if httpx_urls else f"https://{target}"),
            "status_code": None,
            "title": f"Nuclei unavailable or no findings: {msg}",
            "server": None,
            "content_type": None,
            "tls_version": None,
            "ip": resolve_domain_to_ip(target),
            "tool": "nuclei"
        })

    # Compute summary
    summary = {"severity": "Low", "overall_status": "Low", "recommendations": []}
    reasons = []
    if virustotal_data:
        stats = virustotal_data.get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0:
            summary["severity"] = "High"; summary["overall_status"] = "High"
            reasons.append("VirusTotal reports malicious indicators")
        elif stats.get("suspicious", 0) > 0:
            summary["severity"] = "Medium"; summary["overall_status"] = "Medium"
            reasons.append("VirusTotal reports suspicious indicators")
    pd_items = projectdiscovery_data.get("summary") or []
    live_count = sum(1 for i in pd_items if i.get("status_code") in [200, 302, 403])
    if live_count > 0:
        reasons.append(f"ProjectDiscovery found {live_count} live endpoints")
        if (not virustotal_data) and live_count >= 10:
            summary["severity"] = "Medium"; summary["overall_status"] = "Medium"
            summary["recommendations"].append("Harden exposed endpoints; review access controls")
    summary["text"] = "; ".join(reasons) if reasons else "No significant findings"

    # AI insights (heuristic)
    ai_insights = generate_ai_insights(target, summary, virustotal_data, projectdiscovery_data)

    # Store minimal state in session (avoid large cookies)
    session["last_target"] = target
    session["last_summary_status"] = (summary.get("severity") or summary.get("overall_status") or "Unknown")

    # Persist scan to MongoDB if user is logged in
    scan_id = None
    persist_error = None
    try:
        db = get_db()
        if db is None:
            persist_error = "Database not configured."
            session["last_scan_id"] = None
        elif not session.get("user_id"):
            persist_error = "User not logged in."
            session["last_scan_id"] = None
        else:
            doc = {
                "user_id": ensure_object_id(session["user_id"]),
                "target": target,
                "created_at": datetime.utcnow(),
                "virustotal": virustotal_data,
                "projectdiscovery": projectdiscovery_data,
                "summary": summary,
                "ai_insights": ai_insights,
            }
            res = db.scans.insert_one(doc)
            scan_id = str(res.inserted_id)
            session["last_scan_id"] = scan_id
    except Exception as e:
        persist_error = f"Save failed: {str(e)}"
        session["last_scan_id"] = None

    return render_template(
        "results.html",
        target=target,
        virustotal=virustotal_data,
        projectdiscovery=projectdiscovery_data,
        summary=summary,
        ai_insights=ai_insights,
        ai_provider=AI_PROVIDER,
        scan_id=scan_id,
        vt_error=vt_error,
        persist_error=persist_error,
    )


@app.route("/projectdiscovery/scan", methods=["POST"])
def projectdiscovery_scan():
    # Parse form inputs
    target = request.form.get("target", "").strip()
    scan_options = request.form.getlist("scan_options")
    scan_depth = request.form.get("scan_depth", "standard")
    if not target:
        return json.dumps({"error": "No target specified"}), 400, {"Content-Type": "application/json"}
    # Delegate to helper
    payload = perform_projectdiscovery_scan(target, scan_options, scan_depth, include_vt=("virustotal" in scan_options))
    return json.dumps(payload), 200, {"Content-Type": "application/json"}

def perform_projectdiscovery_scan(target, scan_options, scan_depth, include_vt=False):
    virustotal_data = None
    vt_error = None
    if include_vt and VT_API_KEY:
        try:
            import requests, ipaddress
            headers = {"x-apikey": VT_API_KEY}
            def _is_ip(addr):
                try:
                    ipaddress.ip_address(addr); return True
                except Exception:
                    return False
            vt_url = (f"https://www.virustotal.com/api/v3/ip_addresses/{target}" if _is_ip(target)
                      else f"https://www.virustotal.com/api/v3/domains/{target}")
            resp = requests.get(vt_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                vt_json = resp.json()
                virustotal_data = extract_virustotal_data(vt_json)
                if not virustotal_data:
                    try:
                        vt_error = vt_json.get("error") or "No VirusTotal data found for target."
                    except Exception:
                        vt_error = "No VirusTotal data found for target."
            else:
                try:
                    err = resp.json().get("error")
                except Exception:
                    err = resp.text[:200]
                vt_error = f"VirusTotal error {resp.status_code}: {err}"
        except Exception as e:
            vt_error = f"VirusTotal request failed: {str(e)}"
            virustotal_data = None
    elif include_vt and not VT_API_KEY:
        vt_error = "VT_API_KEY not configured"

    results = []
    httpx_urls = []
    if "httpx" in scan_options:
        httpx_result = run_httpx(target)
        if httpx_result.get("summary"):
            results.extend(httpx_result["summary"])
            httpx_urls = [item.get("url") for item in httpx_result["summary"] if item.get("url")]
    if "nuclei" in scan_options:
        nu = run_nuclei(target, urls=(httpx_urls or [f"https://{target}"]), scan_mode=scan_depth)
        if nu.get("status") == "success" and nu.get("summary"):
            results.extend(nu["summary"])
        else:
            msg = nu.get("message") if isinstance(nu, dict) else "No findings"
            results.append({
                "title": f"Nuclei unavailable or no findings: {msg}",
                "tool": "nuclei",
                "url": (httpx_urls[0] if httpx_urls else f"https://{target}"),
                "ip": resolve_domain_to_ip(target)
            })
    if "subfinder" in scan_options and not all(ch.isdigit() or ch == '.' for ch in target):
        sf = run_subfinder(target, scan_mode=scan_depth)
        if sf.get("summary"):
            results.extend(sf["summary"])

    # Derive summary
    summary = {"severity": "Low", "overall_status": "Low", "recommendations": []}
    if virustotal_data and virustotal_data.get("last_analysis_stats", {}).get("malicious", 0) > 0:
        summary["severity"] = "High"; summary["overall_status"] = "High"
    elif virustotal_data and virustotal_data.get("last_analysis_stats", {}).get("suspicious", 0) > 0:
        summary["severity"] = "Medium"; summary["overall_status"] = "Medium"
    summary["text"] = "ProjectDiscovery scan completed"

    # Session context (minimal)
    session["last_target"] = target
    session["last_summary_status"] = (summary.get("severity") or summary.get("overall_status") or "Unknown")

    # Persist
    scan_id = None
    save_error = None
    try:
        db = get_db()
        if db is None:
            save_error = "Database not configured."
        elif not session.get("user_id"):
            save_error = "User not logged in."
        else:
            doc = {
                "user_id": ensure_object_id(session["user_id"]),
                "target": target,
                "created_at": datetime.utcnow(),
                "virustotal": virustotal_data,
                "projectdiscovery": {"summary": results},
                "summary": summary,
            }
            res = db.scans.insert_one(doc)
            scan_id = str(res.inserted_id)
    except Exception as e:
        save_error = f"Save failed: {str(e)}"

    return {"results": results, "scan_id": scan_id, "virustotal": virustotal_data, "vt_error": vt_error, "save_error": save_error, "summary": summary}

@app.route("/api/projectdiscovery/scan", methods=["POST"])
def projectdiscovery_scan_api():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or request.form.get("target") or "").strip()
    # scan_options may be list in JSON or come from form as list
    scan_options = data.get("scan_options")
    if not isinstance(scan_options, list) or not scan_options:
        scan_options = request.form.getlist("scan_options")
    scan_depth = (data.get("scan_depth") or request.form.get("scan_depth") or "standard").strip() or "standard"
    include_vt = bool(data.get("include_vt")) or ("virustotal" in (scan_options or []))
    if not target:
        return json.dumps({"error": "No target specified"}), 400, {"Content-Type": "application/json"}
    payload = perform_projectdiscovery_scan(target, scan_options or ["httpx","nuclei","subfinder"], scan_depth, include_vt)
    return json.dumps(payload), 200, {"Content-Type": "application/json"}


# ---------- Auth Routes ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    db = get_db()
    if db is None:
        return render_template("register.html", error="Database not configured.")
    full_name = request.form.get("full_name", "").strip()
    email = (request.form.get("email", "") or "").strip().lower()
    username = (request.form.get("username", "") or "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    if not username or not password or password != confirm:
        return render_template("register.html", error="Invalid input or passwords do not match.")
    # Prevent registering with an email that already exists (local or Google-linked)
    if email and db.users.find_one({"email": email}):
        return render_template("register.html", error="An account with this email already exists. If you used Google Sign-In previously, please log in with Google.")
    if db.users.find_one({"username": username}):
        return render_template("register.html", error="Username already exists.")
    hashed = generate_password_hash(password)
    res = db.users.insert_one({
        "full_name": full_name,
        "email": email,
        "username": username,
        "password": hashed,
        "created_at": datetime.utcnow(),
        # Default to email verification enabled
        "email_verification_enabled": True,
        # Mark origin provider for identification in admin UI
        "auth_provider": "local",
    })
    # Registration complete; proceed to login
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    db = get_db()
    if db is None:
        return render_template("login.html", error="Database not configured.")
    username = (request.form.get("username", "") or "").strip().lower()
    password = request.form.get("password", "")
    # Admin shortcut: allow admin to use the same login form
    if ADMIN_USERNAME:
        admin_un = ADMIN_USERNAME.strip().lower()
        if username == admin_un:
            ok = False
            if ADMIN_PASSWORD_HASH:
                ok = check_password_hash(ADMIN_PASSWORD_HASH, password)
            elif ADMIN_PASSWORD:
                ok = (password == ADMIN_PASSWORD)
            if not ok:
                return render_template("login.html", error="Invalid username or password.")
            session["admin_auth"] = True
            session["admin_username"] = ADMIN_USERNAME
            return redirect(url_for("admin_users"))
    user = db.users.find_one({"username": username})
    if not user or not check_password_hash(user.get("password", ""), password):
        return render_template("login.html", error="Invalid username or password.")
    # Email verification flow: if enabled, check trust window then send OTP; else finalize login
    if bool(user.get("email_verification_enabled", True)):
        # If user has a valid trust window, skip verification for now
        trust_until = user.get("email_trust_until")
        try:
            if trust_until and datetime.utcnow() < trust_until:
                session["user_id"] = str(user["_id"])
                session["username"] = user.get("username")
                return redirect(url_for("index"))
        except Exception:
            # If trust_until is malformed, fall back to normal verification
            pass
        code = generate_otp_code()
        expires = datetime.utcnow() + timedelta(minutes=10)
        try:
            db.users.update_one({"_id": user["_id"]}, {"$set": {"email_otp_code": code, "email_otp_expires": expires}})
        except Exception:
            return render_template("login.html", error="Unable to initiate verification. Please try again.")
        # Attempt to send email; even if sending fails, keep the flow so admin can fix mail later
        to_email = user.get("email") or ""
        send_email(to_email, "Your login verification code", f"Your verification code is {code}. It expires in 10 minutes.")
        session["pending_user_id"] = str(user["_id"])
        session["pending_username"] = user.get("username")
        session["pending_email"] = to_email
        return redirect(url_for("verify"))
    # Finalize login directly when email verification is disabled
    session["user_id"] = str(user["_id"])
    session["username"] = user.get("username")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# 2FA setup page to display QR for authenticator apps
@app.route("/2fa/setup")
def twofa_setup():
    db = get_db()
    if db is None:
        return render_template("login.html", error="Database not configured.")
    # Prefer explicit setup session, else fall back to pending/login user
    uid = session.get("setup_user_id") or session.get("pending_user_id") or session.get("user_id")
    if not uid:
        return redirect(url_for("login"))
    try:
        user_id = ObjectId(uid)
    except Exception:
        return redirect(url_for("login"))
    user = db.users.find_one({"_id": user_id})
    if not user:
        return redirect(url_for("login"))
    secret = user.get("totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        db.users.update_one({"_id": user_id}, {"$set": {"totp_secret": secret, "two_factor_enabled": True}})
    issuer = os.getenv("APP_NAME", "Surface Attack Monitoring")
    name = user.get("email") or user.get("username") or "user"
    totp = pyotp.TOTP(secret)
    otpauth_uri = totp.provisioning_uri(name=name, issuer_name=issuer)
    # Use online QR generator to avoid local dependencies
    from urllib.parse import quote
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={quote(otpauth_uri)}"
    return render_template("2fa_setup.html", secret=secret, otpauth_uri=otpauth_uri, qr_url=qr_url, username=user.get("username"))


# ---------- History ----------
@app.route("/history")
def history():
    # Only regular users can access history; admins are redirected to Admin Panel
    if session.get("admin_auth"):
        return redirect(url_for("admin_users"))
    if not session.get("user_id"):
        return redirect(url_for("login"))
    db = get_db()
    if db is None:
        return render_template("history.html", scans=[], error="Database not configured.")
    page = max(int(request.args.get("page", "1") or 1), 1)
    per_page = max(min(int(request.args.get("per_page", "10") or 10), 50), 1)
    try:
        uid = ObjectId(session["user_id"])
        filt = {"user_id": uid}
    except Exception:
        filt = {"user_id": session["user_id"]}
    # Optional filters
    start_date = (request.args.get("start_date") or "").strip()
    end_date = (request.args.get("end_date") or "").strip()
    domain_query = (request.args.get("domain") or "").strip()
    severity = (request.args.get("severity") or "").strip()
    # Date range (YYYY-MM-DD)
    date_cond = {}
    def _parse_date(val):
        try:
            return datetime.strptime(val, "%Y-%m-%d")
        except Exception:
            return None
    sd = _parse_date(start_date)
    ed = _parse_date(end_date)
    if sd:
        date_cond["$gte"] = sd
    if ed:
        # include entire end day
        date_cond["$lte"] = ed + timedelta(days=1) - timedelta(seconds=1)
    if date_cond:
        filt["created_at"] = date_cond
    if domain_query:
        filt["target"] = {"$regex": domain_query, "$options": "i"}
    if severity in {"Low", "Medium", "High"}:
        filt["summary.severity"] = severity
    
    total = db.scans.count_documents(filt)
    skips = (page - 1) * per_page
    cursor = db.scans.find(filt).sort("created_at", -1).skip(skips).limit(per_page)
    scans = list(cursor)
    for s in scans:
        s["_id"] = str(s["_id"])
    has_prev = page > 1
    has_next = page * per_page < total
    return render_template("history.html", scans=scans, page=page, per_page=per_page, total=total, has_prev=has_prev, has_next=has_next, start_date=start_date, end_date=end_date, domain_query=domain_query, severity=severity)


# ---------- Dashboard ----------
@app.route("/dashboard")
def dashboard():
    db = get_db()
    if db is None:
        return render_template("dashboard.html", error="Database not configured.")
    # Admin should use Admin Panel; redirect
    if session.get("admin_auth"):
        return redirect(url_for("admin_users"))
    
    user = current_user()
    if not user:
        return render_template("dashboard.html", guest=True)
    try:
        uid = ObjectId(session["user_id"])  # prefer ObjectId when possible
    except Exception:
        uid = session["user_id"]
    total = db.scans.count_documents({"user_id": uid})
    high = db.scans.count_documents({"user_id": uid, "summary.severity": "High"})
    medium = db.scans.count_documents({"user_id": uid, "summary.severity": "Medium"})
    low = db.scans.count_documents({"user_id": uid, "summary.severity": "Low"})
    # Optional filters applied to Recent Scans table
    start_date = (request.args.get("start_date") or "").strip()
    end_date = (request.args.get("end_date") or "").strip()
    domain_query = (request.args.get("domain") or "").strip()
    severity = (request.args.get("severity") or "").strip()
    dfilt = {"user_id": uid}
    date_cond = {}
    def _parse_date(val):
        try:
            return datetime.strptime(val, "%Y-%m-%d")
        except Exception:
            return None
    sd = _parse_date(start_date)
    ed = _parse_date(end_date)
    if sd:
        date_cond["$gte"] = sd
    if ed:
        date_cond["$lte"] = ed + timedelta(days=1) - timedelta(seconds=1)
    if date_cond:
        dfilt["created_at"] = date_cond
    if domain_query:
        dfilt["target"] = {"$regex": domain_query, "$options": "i"}
    if severity in {"Low", "Medium", "High"}:
        dfilt["summary.severity"] = severity
    recent = list(db.scans.find(dfilt).sort("created_at", -1).limit(5))
    for s in recent:
        s["_id"] = str(s["_id"])  # convenience for links
    last = recent[0] if recent else None
    return render_template("dashboard.html", user=user, total=total, high=high, medium=medium, low=low, recent=recent, last=last, start_date=start_date, end_date=end_date, domain_query=domain_query, severity=severity)

# ---------------- Admin Authentication & Panel ----------------
@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_auth", None)
    session.pop("admin_username", None)
    return redirect(url_for("login"))


@app.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    if not session.get("admin_auth"):
        return redirect(url_for("login"))
    db = get_db()
    if db is None:
        return render_template(
            "adminpanel.html",
            error="Database not configured.",
            users=[],
            logs=[],
            filters={"username": "", "target": "", "start": "", "end": "", "severity": ""},
            page=1,
            per_page=20,
            total=0,
            has_prev=False,
            has_next=False,
        )
    notice = None
    action = request.form.get("action")
    user_id = request.form.get("user_id")
    if request.method == "POST" and action and user_id:
        try:
            oid = ObjectId(user_id)
        except Exception:
            oid = None
            notice = "Invalid user id."
        if oid:
            if action == "delete":
                # Fetch user to notify before deletion
                u = db.users.find_one({"_id": oid})
                to_email = (u or {}).get("email") or ""
                try:
                    # Count scans before deletion so we can report how many were removed
                    try:
                        removed_scans_count = db.scans.count_documents({"user_id": oid})
                    except Exception:
                        removed_scans_count = None
                    # Delete the user
                    db.users.delete_one({"_id": oid})
                    # Cascade delete: remove all scans belonging to this user
                    try:
                        db.scans.delete_many({"user_id": oid})
                        if removed_scans_count is not None:
                            notice = f"User deleted. Removed {removed_scans_count} scan(s)."
                        else:
                            notice = "User deleted and all their scans removed."
                    except Exception:
                        # If scans deletion fails, still report user deletion
                        notice = "User deleted, but failed to remove their scans."
                except Exception:
                    notice = "Failed to delete user."
                # Send deletion notice email if possible (best-effort)
                if to_email:
                    try:
                        send_email(
                            to_email,
                            "Account deletion notice",
                            "Your Surface Attack Monitoring Tool (SAMT) account has been deleted by an administrator. If you need to login again, please register a new account."
                        )
                    except Exception:
                        # Ignore email errors to avoid blocking admin action
                        pass
            elif action == "toggle_admin":
                notice = "Admin role is exclusive to the system admin."
            elif action in {"toggle_email_verification", "toggle_2fa"}:
                # Support legacy action name 'toggle_2fa' by mapping it to email verification
                u = db.users.find_one({"_id": oid})
                # Disallow toggling for Google sign-in accounts
                if u and (u.get("auth_provider") == "google" or u.get("google_id")):
                    notice = "Cannot toggle email verification for Google sign-in accounts."
                else:
                    cur = bool(u.get("email_verification_enabled", True)) if u else True
                    db.users.update_one({"_id": oid}, {"$set": {"email_verification_enabled": not cur}})
                    notice = "Email verification setting updated."
    users = list(db.users.find({}, {"password": 0}))
    # attach scan counts and stringify ids for forms
    for u in users:
        try:
            uid_obj = u["_id"]
            u["scan_count"] = db.scans.count_documents({"user_id": uid_obj})
        except Exception:
            u["scan_count"] = 0
        u["_id"] = str(u["_id"]) 
    # --- System Logs (admin-wide scan history with filters) ---
    username_q = (request.args.get("username") or "").strip().lower()
    target_q = (request.args.get("target") or "").strip()
    start_q = (request.args.get("start") or "").strip()
    end_q = (request.args.get("end") or "").strip()
    severity_q = (request.args.get("severity") or "").strip()
    page = max(int(request.args.get("page", "1") or 1), 1)
    per_page = max(min(int(request.args.get("per_page", "20") or 20), 100), 1)
    filt = {}
    # Target filter supports substring, case-insensitive
    if target_q:
        filt["target"] = {"$regex": target_q, "$options": "i"}
    # Date range filters (YYYY-MM-DD)
    date_cond = {}
    from datetime import datetime
    def _parse_date(val):
        try:
            return datetime.strptime(val, "%Y-%m-%d")
        except Exception:
            return None
    sd = _parse_date(start_q)
    ed = _parse_date(end_q)
    if sd:
        date_cond["$gte"] = sd
    if ed:
        # include entire end day
        date_cond["$lte"] = ed + timedelta(days=1) - timedelta(seconds=1)
    if date_cond:
        filt["created_at"] = date_cond
    # Severity filter (exact match)
    if severity_q in {"Low", "Medium", "High"}:
        filt["$or"] = [{"summary.severity": severity_q}, {"summary.overall_status": severity_q}]
    # Username filter via user lookup
    if username_q:
        matching_users = list(db.users.find({"username": {"$regex": username_q, "$options": "i"}}, {"_id": 1}))
        ids = [u["_id"] for u in matching_users]
        # If no users match, ensure no scans return
        filt["user_id"] = {"$in": ids or [ObjectId("000000000000000000000000")]}  # dummy to return none when empty
    # Query scans
    try:
        total = db.scans.count_documents(filt)
        skips = (page - 1) * per_page
        cursor = db.scans.find(filt).sort("created_at", -1).skip(skips).limit(per_page)
        logs = list(cursor)
    except Exception:
        total = 0
        logs = []
    # Attach username/email to logs
    user_map = {}
    for s in logs:
        uid = s.get("user_id")
        if uid and uid not in user_map:
            try:
                udoc = db.users.find_one({"_id": uid}, {"username": 1, "email": 1})
            except Exception:
                udoc = None
            user_map[uid] = udoc or {}
        s["_id"] = str(s["_id"])  # for links
        s["user_meta"] = {
            "username": (user_map.get(uid) or {}).get("username") or "",
            "email": (user_map.get(uid) or {}).get("email") or "",
        }
    filters = {"username": username_q, "target": target_q, "start": start_q, "end": end_q, "severity": severity_q}
    has_prev = page > 1
    has_next = page * per_page < total
    return render_template("adminpanel.html", users=users, notice=notice, logs=logs, filters=filters, page=page, per_page=per_page, total=total, has_prev=has_prev, has_next=has_next)

# ---------- Report (by scan) & PDF ----------
from io import BytesIO
try:
    from xhtml2pdf import pisa
except Exception:
    pisa = None


def _report_context(doc):
    return {
        "target": doc.get("target"),
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "virustotal": doc.get("virustotal"),
        "projectdiscovery": doc.get("projectdiscovery"),
        "summary": doc.get("summary"),
        "ai_insights": doc.get("ai_insights"),
        "ai_provider": AI_PROVIDER,
    }


@app.route("/report/<scan_id>")
def report_scan(scan_id):
    db = get_db()
    if db is None:
        abort(500)
    try:
        doc = db.scans.find_one({"_id": ObjectId(scan_id)})
    except Exception:
        doc = None
    if not doc:
        abort(404)
    return render_template("report_pdf.html", **_report_context(doc))


def html_to_pdf(html):
    if not pisa:
        return None
    buf = BytesIO()
    pisa.CreatePDF(html, dest=buf)
    return buf.getvalue()


@app.route("/download/<scan_id>")
def download_pdf(scan_id):
    db = get_db()
    if db is None:
        abort(500)
    try:
        doc = db.scans.find_one({"_id": ObjectId(scan_id)})
    except Exception:
        doc = None
    if not doc:
        abort(404)
    html = render_template("report_pdf.html", **_report_context(doc))
    pdf = html_to_pdf(html)
    if not pdf:
        return Response(html, mimetype="text/html")
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"})


@app.route("/login/google")
def login_google():
    # Reload .env to pick up any newly added keys without restarting
    load_dotenv(override=True)
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        return render_template("login.html", error="Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.")
    # Re-register Google client with current credentials
    oauth.register(
        name="google",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    redirect_uri = url_for("login_google_callback", _external=True)
    # Use updated client
    google_client = oauth.create_client("google")
    return google_client.authorize_redirect(redirect_uri)


@app.route("/login/google/callback")
def login_google_callback():
    try:
        token = google.authorize_access_token()
        userinfo = token.get("userinfo")
        if not userinfo:
            resp = google.get("userinfo")
            userinfo = resp.json() if resp else None
        if not userinfo:
            return render_template("login.html", error="Failed to retrieve Google user info.")
        email = (userinfo.get("email") or "").lower()
        name = userinfo.get("name") or userinfo.get("given_name")
        sub = userinfo.get("sub")
        if not email:
            return render_template("login.html", error="Google did not provide an email. Please ensure 'email' scope is granted.")
        db = get_db()
        if db is None:
            return render_template("login.html", error="Database not configured.")
        user = db.users.find_one({"$or": [{"google_id": sub}, {"email": email}]})
        if user:
            # Link Google ID to existing account if not already linked; mark provider
            try:
                if not user.get("google_id"):
                    db.users.update_one({"_id": user["_id"]}, {"$set": {"google_id": sub, "auth_provider": "google"}})
                else:
                    # Ensure provider is set to google for Google-linked accounts
                    if user.get("auth_provider") != "google":
                        db.users.update_one({"_id": user["_id"]}, {"$set": {"auth_provider": "google"}})
            except Exception:
                pass
        else:
            # Create a new account for Google sign-in; ensure username uniqueness
            base_username = email.split("@")[0]
            username = base_username
            try:
                if db.users.find_one({"username": username}):
                    import random
                    username = f"{base_username}-{random.randint(1000,9999)}"
            except Exception:
                # On error, fall back to base username
                username = base_username
            doc = {
                "full_name": name,
                "email": email,
                "username": username,
                "password": None,
                "google_id": sub,
                "created_at": datetime.utcnow(),
                "auth_provider": "google",
            }
            res = db.users.insert_one(doc)
            user = db.users.find_one({"_id": res.inserted_id})
        session["user_id"] = str(user["_id"])
        session["username"] = user.get("username") or (email.split("@")[0])
        return redirect(url_for("index"))
    except Exception as e:
        return render_template("login.html", error=f"Google login failed: {str(e)}")

# ----- Email OTP helpers and verification routes (before app.run) -----
import random

def generate_otp_code(length=6):
    return ''.join(random.choice('0123456789') for _ in range(length))


def send_email(to_email, subject, text):
    try:
        # Prefer SendGrid if SENDGRID_API_KEY is set
        sg_key = os.getenv('SENDGRID_API_KEY')
        email_from = os.getenv('EMAIL_FROM', 'noreply@example.com')
        if sg_key:
            import requests
            url = 'https://api.sendgrid.com/v3/mail/send'
            headers = {
                'Authorization': f'Bearer {sg_key}',
                'Content-Type': 'application/json'
            }
            data = {
                'from': {'email': email_from},
                'personalizations': [{'to': [{'email': to_email}]}],
                'subject': subject,
                'content': [{'type': 'text/plain', 'value': text}]
            }
            resp = requests.post(url, headers=headers, json=data, timeout=10)
            return 200 <= resp.status_code < 300
        # Fallback to SMTP if configured
        smtp_host = os.getenv('SMTP_HOST')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_user = os.getenv('SMTP_USERNAME')
        smtp_pass = os.getenv('SMTP_PASSWORD')
        # Gmail app passwords are 16 chars with no spaces; clean up if provided spaced
        if smtp_host and 'gmail' in smtp_host.lower() and smtp_pass:
            smtp_pass = smtp_pass.replace(' ', '')
        if smtp_host and smtp_user and smtp_pass:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(text)
            msg['Subject'] = subject
            # Some providers (e.g., Gmail) require From to match the authenticated user
            msg['From'] = os.getenv('EMAIL_FROM', smtp_user) or smtp_user
            msg['To'] = to_email
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                try:
                    server.ehlo()
                except Exception:
                    pass
                server.starttls()
                try:
                    server.ehlo()
                except Exception:
                    pass
                server.login(smtp_user, smtp_pass)
                server.sendmail(msg['From'], [to_email], msg.as_string())
            return True
        return False
    except Exception as e:
        # Log the error to server console for easier debugging
        print(f"[mail] send_email error: {e}")
        return False


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    db = get_db()
    if db is None:
        return render_template('login.html', error='Database not configured.')
    pending_uid = session.get('pending_user_id')
    if request.method == 'GET':
        if not pending_uid:
            return render_template('login.html', error='No pending verification. Please log in.')
        return render_template('verify.html')
    # POST: check email-based OTP code
    code = (request.form.get('code', '') or '').strip()
    if not pending_uid or not code:
        return render_template('verify.html', error='Enter the 6-digit code.')
    try:
        user_id = ObjectId(pending_uid)
    except Exception:
        return render_template('login.html', error='Invalid session. Please log in again.')
    user = db.users.find_one({'_id': user_id})
    if not user:
        return render_template('login.html', error='User not found. Please log in again.')
    stored = (user.get('email_otp_code') or '').strip()
    expires = user.get('email_otp_expires')
    if not stored or not expires:
        return render_template('verify.html', error='Verification code not found. Please resend a new code.')
    # Check expiration
    if datetime.utcnow() > expires:
        return render_template('verify.html', error='Code expired. Please resend a new code.')
    if code != stored:
        return render_template('verify.html', error='Incorrect code. Try again or resend a new one.')
    # Finalize login
    session['user_id'] = str(user['_id'])
    session['username'] = user.get('username')
    # Admin session is reserved for the dedicated .env admin only
    next_endpoint = 'index'
    # Clear pending fields
    session.pop('pending_user_id', None)
    session.pop('pending_username', None)
    session.pop('pending_email', None)
    # Handle remember-me: trust this login for 1 hour if selected
    remember_raw = (request.form.get('remember_me', '') or '').strip().lower()
    remember_me = remember_raw in ('on', 'true', '1', 'yes')
    try:
        if remember_me:
            trust_until = datetime.utcnow() + timedelta(hours=1)
            db.users.update_one({'_id': user_id}, {
                '$set': {'email_trust_until': trust_until},
                '$unset': {'email_otp_code': "", 'email_otp_expires': ""}
            })
        else:
            db.users.update_one({'_id': user_id}, {'$unset': {'email_otp_code': "", 'email_otp_expires': ""}})
    except Exception:
        pass
    return redirect(url_for(next_endpoint))


@app.route('/verify/resend', methods=['POST'])
def verify_resend():
    db = get_db()
    if db is None:
        return render_template('login.html', error='Database not configured.')
    pending_uid = session.get('pending_user_id')
    if not pending_uid:
        return render_template('login.html', error='No pending verification. Please log in.')
    try:
        user_id = ObjectId(pending_uid)
    except Exception:
        return render_template('login.html', error='Invalid session. Please log in again.')
    user = db.users.find_one({'_id': user_id})
    if not user:
        return render_template('login.html', error='User not found. Please log in again.')
    code = generate_otp_code()
    expires = datetime.utcnow() + timedelta(minutes=10)
    try:
        db.users.update_one({'_id': user_id}, {'$set': {'email_otp_code': code, 'email_otp_expires': expires}})
    except Exception:
        return render_template('verify.html', error='Unable to generate a new code. Try again later.')
    to_email = user.get('email') or ''
    ok = send_email(to_email, 'Your new login verification code', f'Your verification code is {code}. It expires in 10 minutes.')
    if not ok:
        return render_template('verify.html', error='Unable to send email. Please try again later or contact support.', info=None)
    return render_template('verify.html', info='We sent a new code to your email. Please check your inbox.', error=None)


if __name__ == "__main__":
    PORT = int(os.getenv("PORT", "5000"))
    app.run(debug=True, port=PORT)
