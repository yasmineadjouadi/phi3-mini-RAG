import requests
import os
import socket
import time
from dotenv import load_dotenv
from datetime import datetime
from database.db import SessionLocal
from database.models import ScanHistory

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
TIMEOUT = 15


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    for prefix in ["https://", "http://"]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    if domain.startswith("www."):
        domain = domain[4:]
    domain = domain.split("/")[0]
    return domain


def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "N/A"


def calculate_risk(malicious, suspicious, reputation):
    reputation_penalty = abs(reputation) if reputation < 0 else 0
    score = (malicious * 5) + (suspicious * 3) + reputation_penalty
    if score == 0:    level = "Clean"
    elif score <= 20: level = "Low"
    elif score <= 50: level = "Medium"
    else:             level = "High"
    return level, score


def calculate_global_risk(vt_malicious, vt_suspicious, subdomain_count, vt_reputation=0):
    vt_component = (vt_malicious * 10) + (vt_suspicious * 4)
    sub_component = 0
    if vt_malicious > 0 and subdomain_count > 5:
        sub_component = min(subdomain_count * 0.5, 20)
    rep_penalty = abs(vt_reputation) if vt_reputation < 0 else 0
    global_score = round(vt_component + sub_component + rep_penalty)

    if global_score == 0:    level = "Clean"
    elif global_score <= 15: level = "Low"
    elif global_score <= 40: level = "Medium"
    else:                    level = "High"

    if vt_malicious > 5:
        confidence = "Strong"
    elif vt_malicious > 0 or vt_suspicious > 2:
        confidence = "Moderate"
    else:
        confidence = "Weak"

    return global_score, level, confidence


def hackertarget_subdomains(domain: str) -> dict:
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10
        )
        if resp.status_code != 200 or "error" in resp.text.lower():
            return {"subdomains": [], "count": 0}
        lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
        subdomains = [l.split(",")[0] for l in lines if "," in l]
        return {"subdomains": subdomains[:10], "count": len(subdomains)}
    except Exception:
        return {"subdomains": [], "count": 0}


def virustotal_domain(domain: str, retries: int = 3) -> dict | None:
    """
    Appelle VT avec retry sur 429 (rate limit).
    Retourne None si toutes les tentatives échouent.
    """
    if not VT_API_KEY:
        return None
    url     = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.json()["data"]["attributes"]
            elif resp.status_code == 429:
                wait = 20 * (attempt + 1)   # 20s, 40s, 60s
                print(f"[VT] Rate limit sur {domain} — attente {wait}s (tentative {attempt+1}/{retries})")
                time.sleep(wait)
            elif resp.status_code == 404:
                print(f"[VT] Domaine inconnu: {domain}")
                return {}   # domaine jamais scanné = données vides, pas une erreur
            else:
                print(f"[VT] Erreur {resp.status_code} pour {domain}")
                return None
        except Exception as e:
            print(f"[VT] Exception: {e}")
            return None

    print(f"[VT] Toutes les tentatives échouées pour {domain}")
    return None


def get_domain_report(domain: str) -> dict:
    domain     = normalize_domain(domain)
    ip_address = resolve_ip(domain)

    # ── VirusTotal avec retry ─────────────────────────────────
    vt_data = virustotal_domain(domain)

    if vt_data is None:
        # VT totalement inaccessible → fallback par règles heuristiques
        print(f"[WARN] VT inaccessible pour {domain} — fallback heuristique")
        vt_data     = {}
        vt_fallback = True
    else:
        vt_fallback = False

    stats      = vt_data.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    reputation = vt_data.get("reputation", 0)

    risk_level, risk_score = calculate_risk(malicious, suspicious, reputation)

    # ── HackerTarget ─────────────────────────────────────────
    ht_data = hackertarget_subdomains(domain)

    global_score, global_level, confidence = calculate_global_risk(
        malicious, suspicious, ht_data["count"], reputation
    )

    last_analysis_timestamp = vt_data.get("last_analysis_date")
    last_analysis_date = (
        datetime.utcfromtimestamp(last_analysis_timestamp).strftime("%Y-%m-%d")
        if last_analysis_timestamp else "N/A"
    )

    creation_timestamp = vt_data.get("creation_date")
    creation_date = (
        datetime.utcfromtimestamp(creation_timestamp).strftime("%Y-%m-%d")
        if creation_timestamp else "N/A"
    )

    # ── Sauvegarde DB ────────────────────────────────────────
    try:
        db = SessionLocal()
        db.add(ScanHistory(
            indicator=domain,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            source="VirusTotal+HackerTarget"
        ))
        db.commit()
        db.close()
    except Exception as e:
        print(f"[DB] Erreur sauvegarde: {e}")

    return {
        "domain"       : domain,
        "ip_address"   : ip_address,
        "registrar"    : vt_data.get("registrar", "N/A"),
        "creation_date": creation_date,
        "vt_fallback"  : vt_fallback,

        "virustotal": {
            "reputation_score"  : reputation,
            "detection"         : {
                "malicious" : malicious,
                "suspicious": suspicious,
                "undetected": undetected
            },
            "last_analysis_date": last_analysis_date,
            "risk_score"        : risk_score,
            "risk_level"        : risk_level
        },
        "hackertarget": {
            "subdomains"      : ht_data["subdomains"],
            "subdomains_count": ht_data["count"]
        },

        "global_risk_score": global_score,
        "global_risk_level": global_level,
        "confidence"       : confidence,
    }