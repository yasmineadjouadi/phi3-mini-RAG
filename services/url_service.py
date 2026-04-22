import requests
import os
import urllib.parse
import ipaddress
import socket
from dotenv import load_dotenv
from datetime import datetime
from database.db import SessionLocal
from database.models import ScanHistory

load_dotenv()
VT_API_KEY        = os.getenv("VT_API_KEY")
GOOGLE_SB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

TIMEOUT = 15

# -------------------- WHITELIST domaines légitimes --------------------
WHITELIST_DOMAINS = {
    "google.com", "googleapis.com", "googletagmanager.com", "googlevideo.com",
    "gstatic.com", "youtube.com", "facebook.com", "fbcdn.net",
    "instagram.com", "twitter.com", "linkedin.com", "microsoft.com",
    "microsoftonline.com", "apple.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "booking.com", "akamai.net", "akamaized.net",
    "netflix.com", "spotify.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "reddit.com", "twitch.tv", "discord.com",
    "zoom.us", "slack.com", "dropbox.com", "paypal.com",
    "pv-cdn.net", "gtld-servers.net", "dzen.ru", "mail.ru",
    "bing.com", "yahoo.com", "ebay.com", "aliexpress.com"
}

# -------------------- Plateformes légitimes abusées pour phishing --------------------
PHISHING_HOSTING_PLATFORMS = {
    "vercel.app", "webflow.io", "blogspot.com", "godaddysites.com",
    "netlify.app", "pages.dev", "glitch.me", "replit.app",
    "github.io", "gitlab.io", "wixsite.com", "weebly.com",
    "squarespace.com", "sites.google.com", "carrd.co",
    "notion.site", "bubbleapps.io", "bubble.io"
}

# -------------------- Keywords phishing dans les URLs --------------------
PHISHING_URL_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "billing", "password", "recover", "unlock",
    "suspended", "validate", "authenticate", "reset", "bank",
    "wallet", "crypto", "ledger", "metamask", "coinbase"
]

# -------------------- Marques imitées --------------------
IMPERSONATED_BRANDS = [
    "facebook", "instagram", "google", "amazon", "netflix",
    "apple", "paypal", "microsoft", "roblox", "coinbase",
    "metamask", "ledger", "binance", "chase", "wellsfargo"
]


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def analyze_url_phishing_signals(url: str, domain: str) -> dict:
    """
    Détecte les signaux de phishing dans l'URL indépendamment des APIs.
    Crucial pour les phishing hébergés sur plateformes légitimes (vercel, webflow...).
    """
    signals = []
    url_lower = url.lower()
    domain_lower = domain.lower()

    # 1. Plateforme de hosting connue pour phishing
    hosting_platform = None
    for platform in PHISHING_HOSTING_PLATFORMS:
        if domain_lower.endswith(platform) and domain_lower != platform:
            hosting_platform = platform
            break

    # 2. Keywords phishing dans l'URL
    found_keywords = [kw for kw in PHISHING_URL_KEYWORDS if kw in url_lower]

    # 3. Marque imitée dans le subdomain ou path
    found_brands = [brand for brand in IMPERSONATED_BRANDS if brand in url_lower]

    # 4. Pattern clone (ex: facebook-login-page-clone, netflix-clone)
    clone_pattern = "clone" in url_lower or "copy" in url_lower or "replica" in url_lower

    # 5. Subdomain suspect sur plateforme légitime (ex: facebook-login.vercel.app)
    if hosting_platform:
        subdomain = domain_lower.replace(f".{hosting_platform}", "")
        if subdomain and subdomain != domain_lower:
            if any(brand in subdomain for brand in IMPERSONATED_BRANDS):
                signals.append(f"Phishing: imite '{[b for b in IMPERSONATED_BRANDS if b in subdomain][0]}' sur {hosting_platform}")
            elif any(kw in subdomain for kw in PHISHING_URL_KEYWORDS):
                signals.append(f"Keywords phishing dans subdomain sur {hosting_platform}")
            elif clone_pattern:
                signals.append(f"Pattern clone détecté sur {hosting_platform}")
            else:
                signals.append(f"Hébergé sur plateforme à risque: {hosting_platform}")

    if found_brands and not hosting_platform:
        signals.append(f"Imite marque: {found_brands[0]}")

    if found_keywords and len(found_keywords) >= 2:
        signals.append(f"Keywords phishing: {', '.join(found_keywords[:3])}")

    # Score de phishing local (indépendant des APIs)
    phishing_score = 0
    if hosting_platform:
        phishing_score += 30
    if found_brands:
        phishing_score += 35
    if clone_pattern:
        phishing_score += 20
    if found_keywords:
        phishing_score += min(len(found_keywords) * 8, 25)

    phishing_score = min(100, phishing_score)

    return {
        "signals": signals,
        "score": phishing_score,
        "hosting_platform": hosting_platform,
        "found_brands": found_brands,
        "found_keywords": found_keywords,
        "is_suspicious": phishing_score >= 30
    }


# -------------------- VIRUSTOTAL --------------------
import base64
import time

def virustotal_url_scan(url: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not found"}

    headers = {"x-apikey": VT_API_KEY}

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=TIMEOUT
        )

        if resp.status_code == 404:
            time.sleep(15)
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data={"url": url},
                timeout=TIMEOUT
            )
            if submit.status_code == 429:
                return {"error": "VT rate limit — réessaie dans 1 minute"}
            if submit.status_code != 200:
                return {"error": f"VT submission failed: {submit.status_code}"}

            time.sleep(10)
            analysis_id = submit.json()["data"]["id"]
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=TIMEOUT
            )

        if resp.status_code == 429:
            return {"error": "VT rate limit — réessaie dans 1 minute"}

        if resp.status_code != 200:
            return {"error": f"VT error: {resp.status_code}"}

        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        verdict = "malicious"  if malicious > 3 else \
                  "suspicious" if malicious > 0 or suspicious > 0 else "clean"

        return {
            "verdict"   : verdict,
            "malicious" : malicious,
            "suspicious": suspicious,
            "undetected": stats.get("undetected", 0),
            "harmless"  : stats.get("harmless", 0)
        }

    except Exception as e:
        return {"error": str(e)}


# -------------------- GOOGLE SAFE BROWSING --------------------
def google_safe_browsing_scan(url: str) -> dict:
    if not GOOGLE_SB_API_KEY:
        return {"error": "Google Safe Browsing API key not found"}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_API_KEY}"
        payload = {
            "client": {"clientId": "TIP", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        resp = requests.post(endpoint, json=payload, timeout=TIMEOUT)
        if resp.status_code != 200:
            return {"error": f"GSB error: {resp.status_code}"}

        data = resp.json()
        matches = data.get("matches", [])

        if matches:
            threat_types = list({m["threatType"] for m in matches})
            return {
                "verdict":      "malicious",
                "threats":      threat_types,
                "match_count":  len(matches)
            }
        return {"verdict": "clean", "threats": [], "match_count": 0}

    except Exception as e:
        return {"error": str(e)}


# -------------------- PHISHTANK --------------------
def phishtank_scan(url: str) -> dict:
    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url":    urllib.parse.quote(url, safe=""),
                "format": "json",
                "app_key": os.getenv("PHISHTANK_API_KEY", "")
            },
            headers={"User-Agent": "phishtank/TIP"},
            timeout=TIMEOUT
        )
        if not resp.text.strip():
            return {"verdict": "unknown", "error": "empty response"}
        if resp.status_code != 200:
            return {"error": f"PhishTank error: {resp.status_code}"}

        data        = resp.json().get("results", {})
        in_database = data.get("in_database", False)
        verified    = data.get("verified", False)

        return {
            "verdict"    : "malicious"  if (in_database and verified) else
                           "suspicious" if in_database else "clean",
            "in_database": in_database,
            "verified"   : verified,
            "phish_id"   : data.get("phish_id")
        }
    except Exception as e:
        return {"verdict": "unknown", "error": str(e)}


# -------------------- RISK GLOBAL --------------------
def calculate_global_risk(vt: dict, gsb: dict, pt: dict, phishing_analysis: dict, is_whitelisted: bool) -> tuple:
    # Whitelisted → toujours clean
    if is_whitelisted:
        return 0, "clean", "Strong"

    score = 0

    # Signaux APIs
    vt_mal = vt.get("malicious", 0)
    vt_sus = vt.get("suspicious", 0)
    score += (vt_mal * 4) + (vt_sus * 2)

    if gsb.get("verdict") == "malicious":
        score += 40

    if pt.get("verdict") == "malicious":
        score += 35
    elif pt.get("verdict") == "suspicious":
        score += 15

    if gsb.get("verdict") == "malicious":
        score = max(score, 60)

    if pt.get("verdict") == "malicious" and pt.get("verified"):
        score = max(score, 70)

    # Signaux phishing locaux (indépendants des APIs)
    phishing_score = phishing_analysis.get("score", 0)
    if phishing_score >= 60:
        score = max(score, phishing_score)
    elif phishing_score >= 30:
        score = max(score, min(phishing_score, 45))

    score = min(100, score)

    level = ("critical" if score >= 80 else
             "high"     if score >= 60 else
             "medium"   if score >= 40 else
             "low"      if score >= 20 else "clean")

    sources_positive = sum([
        vt.get("verdict") == "malicious",
        gsb.get("verdict") == "malicious",
        pt.get("verdict") in ["malicious", "suspicious"],
        phishing_analysis.get("is_suspicious", False)
    ])
    confidence = "Strong"  if sources_positive >= 2 else \
                 "Moderate" if sources_positive == 1 else "Weak"

    return score, level, confidence


# -------------------- MAIN --------------------
def get_url_report(url: str) -> dict:
    domain = urllib.parse.urlparse(url).netloc or url
    # Nettoyer le www.
    clean_domain = domain.lower().lstrip("www.")

    # Vérification whitelist
    is_whitelisted = clean_domain in WHITELIST_DOMAINS or domain.lower() in WHITELIST_DOMAINS

    # Résolution IP
    try:
        ip_resolved = socket.gethostbyname(domain) \
                      if not is_ip_address(domain) else domain
    except Exception:
        ip_resolved = "Could not resolve"

    # Analyse phishing locale (avant les APIs)
    phishing_analysis = analyze_url_phishing_signals(url, domain)

    # Appels APIs
    vt_result  = virustotal_url_scan(url)
    gsb_result = google_safe_browsing_scan(url)
    pt_result  = phishtank_scan(url)

    score, level, confidence = calculate_global_risk(
        vt_result, gsb_result, pt_result, phishing_analysis, is_whitelisted
    )

    # Verdict final
    if is_whitelisted:
        final_verdict = "clean"
    elif gsb_result.get("verdict") == "malicious":
        final_verdict = "malicious"
    elif pt_result.get("verdict") == "malicious" and pt_result.get("verified"):
        final_verdict = "malicious"
    elif vt_result.get("verdict") == "malicious" and pt_result.get("verdict") == "malicious":
        final_verdict = "malicious"
    elif phishing_analysis.get("score", 0) >= 60:
        final_verdict = "suspicious"
    elif vt_result.get("verdict") == "malicious":
        final_verdict = "suspicious"
    elif vt_result.get("verdict") == "suspicious" or pt_result.get("verdict") == "suspicious":
        final_verdict = "suspicious"
    else:
        final_verdict = "clean"

    # Sauvegarde DB
    db = SessionLocal()
    db.add(ScanHistory(
        indicator=url,
        risk_level=level,
        risk_score=score,
        confidence=confidence,
        source="VirusTotal+GoogleSafeBrowsing+PhishTank"
    ))
    db.commit()
    db.close()

    return {
        "url"              : url,
        "domain"           : domain,
        "ip"               : ip_resolved,
        "type"             : "IP" if is_ip_address(domain) else "Domain",
        "scan_time"        : datetime.utcnow().isoformat(),
        "final_verdict"    : final_verdict,
        "global_risk_score": score,
        "global_risk_level": level,
        "confidence"       : confidence,
        "is_whitelisted"   : is_whitelisted,
        "phishing_analysis": phishing_analysis,   # nouveau champ pour le LLM
        "vendors": {
            "virustotal"          : vt_result,
            "google_safe_browsing": gsb_result,
            "phishtank"           : pt_result
        },
    }