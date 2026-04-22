import requests
import os
from dotenv import load_dotenv

load_dotenv()
MXTOOLBOX_API_KEY = os.getenv("MXTOOLBOX_API_KEY")
if not MXTOOLBOX_API_KEY:
    raise ValueError("API key MXToolbox manquante")
TIMEOUT = 10

def detect_provider(mx_list):
    if not mx_list:
        return "Inconnu"
    mx_string = " ".join([mx["serveur"] for mx in mx_list]).lower()
    if "google" in mx_string:
        return "Google Workspace"
    elif "outlook" in mx_string or "protection.outlook.com" in mx_string:
        return "Microsoft 365"
    elif "zoho" in mx_string:
        return "Zoho Mail"
    elif "yahoo" in mx_string:
        return "Yahoo Mail"
    else:
        return "Autre"

def detect_suspicious_tld(domain):
    suspicious_tlds = ['.vip', '.icu', '.cfd', '.xyz', '.club', '.top', '.gq', '.ml', '.bid', '.loan', '.date', '.tk', '.cf', '.ga', '.net']
    tld = '.' + domain.split('.')[-1].lower()
    # Ne pas pénaliser les domaines légitimes connus même avec .net
    legit_domains = ['cloudflare.net', 'apple-dns.net', 'trafficmanager.net', 'workers.dev']
    if domain in legit_domains:
        return False, None
    if tld in suspicious_tlds:
        return True, f"TLD suspect ({tld})"
    return False, None

def detect_typosquatting(domain):
    marques = ['apple', 'paypal', 'amazon', 'microsoft', 'google', 'facebook', 'netflix', 'dhl', 'fedex', 'ebay',
               'instagram', 'linkedin', 'dropbox', 'chase', 'irs', 'bankofamerica']
    domain_lower = domain.lower().replace('-', '').replace('.', '')
    for marque in marques:
        if marque in domain_lower:
            official_domains = [
                'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com',
                f'{marque}.com', f'{marque}.org', f'{marque}.net',
                'microsoftonline.com', 'microsoft.com', 'google.com',
                'googleapis.com', 'googletagmanager.com', 'googlevideo.com',
                'facebook.com', 'instagram.com', 'linkedin.com',
                'amazon.com', 'amazonaws.com', 'apple.com', 'icloud.com',
                'netflix.com', 'paypal.com', 'dropbox.com',
                'fbcdn.net', 'appsflyersdk.com'
            ]
            if domain not in official_domains:
                return True, f"Typosquatting: imite '{marque}'"
    return False, None

def detect_phishing_keywords(domain):
    """Détecte les keywords typiques de phishing dans le domaine"""
    phishing_keywords = [
        'secure', 'verify', 'alert', 'update', 'login',
        'confirm', 'billing', 'account', 'recover', 'locked',
        'suspended', 'refund', 'invoice', 'cancel', 'delivery',
        'security', 'validate', 'authenticate', 'reset', 'unlock'
    ]
    domain_lower = domain.lower()
    found = [kw for kw in phishing_keywords if kw in domain_lower]
    if found:
        return True, f"Keywords phishing: {', '.join(found[:3])}"
    return False, None

def detect_parking_provider(mx_list):
    parking_providers = ['above.com', 'parking', 'sedo', 'dan.com', 'bodis', 'domainpark', 'parkingcrew']
    mx_string = " ".join([mx["serveur"] for mx in mx_list]).lower()
    for provider in parking_providers:
        if provider in mx_string:
            return True, f"MX chez {provider} (parking)"
    return False, None

def analyze_mx_quality(mx_list):
    if not mx_list:
        return "Aucun serveur MX", -40
    issues = []
    penalty = 0
    if len(mx_list) == 1:
        pass
    elif len(mx_list) == 2:
        issues.append("Redondance limitée (2 MX)")
        penalty -= 10
    priorities = []
    for mx in mx_list:
        try:
            priorities.append(int(mx.get("priorite", 999)))
        except:
            priorities.append(999)
    if len(set(priorities)) == 1 and len(mx_list) > 1:
        issues.append("Tous les MX ont la même priorité")
        penalty -= 5
    mx_string = " ".join([mx["serveur"] for mx in mx_list]).lower()
    if any(x in mx_string for x in ['above.com', 'parking', 'sedo', 'dan.com']):
        issues.append("Hébergeur de parking détecté")
        penalty -= 20
    if issues:
        return ", ".join(issues[:2]), penalty
    return "MX OK", penalty

def analyze_spf_advanced(spf_record, domain):
    if not spf_record:
        return "SPF absent", -25
    spf_lower = spf_record.lower()
    penalty = 0
    issues = []
    include_count = spf_lower.count('include:')
    if include_count > 10:
        issues.append(f"Trop d'includes ({include_count})")
        penalty -= 15
    elif include_count > 5:
        issues.append(f"Beaucoup d'includes ({include_count})")
        penalty -= 5
    if "ip6:" in spf_lower and "/48" in spf_lower:
        issues.append("SPF suspect (IPv6 auto-généré)")
        penalty -= 15
    if "-all" in spf_lower:
        policy = "strict"
    elif "~all" in spf_lower:
        policy = "tolérant"
        penalty -= 2
    elif "?all" in spf_lower:
        policy = "neutre"
        penalty -= 10
    else:
        policy = "aucune"
        penalty -= 15
    if "_spf.google.com" in spf_lower or "_spf.microsoft.com" in spf_lower:
        if include_count <= 3:
            return f"SPF {policy} (provider majeur)", max(penalty, 0)
    if len(spf_record) > 450:
        issues.append("SPF très long (>450)")
        penalty -= 10
    elif len(spf_record) > 255:
        issues.append("SPF long (>255)")
        penalty -= 5
    if issues:
        status = f"SPF {policy} - " + ", ".join(issues[:2])
    else:
        status = f"SPF {policy}"
    return status, penalty

def analyze_dmarc(dmarc_record):
    if not dmarc_record:
        return "DMARC absent", -25
    dmarc_lower = dmarc_record.lower()
    penalty = 0
    issues = []
    if "p=reject" in dmarc_lower:
        policy = "strict"
    elif "p=quarantine" in dmarc_lower:
        policy = "modéré"
    elif "p=none" in dmarc_lower:
        policy = "surveillance"
        penalty -= 5
    else:
        policy = "invalide"
        penalty -= 15
    if "sp=none" in dmarc_lower:
        issues.append("sous-domaines non protégés")
        penalty -= 15
    elif "sp=quarantine" in dmarc_lower:
        issues.append("sous-domaines modérés")
        penalty -= 2
    if "pct=" in dmarc_lower:
        import re
        match = re.search(r'pct=(\d+)', dmarc_lower)
        if match and int(match.group(1)) < 100:
            issues.append(f"protection partielle ({match.group(1)}%)")
            penalty -= 5
    if "rua=" not in dmarc_lower:
        issues.append("pas de rapports")
        penalty -= 3
    if issues:
        return f"DMARC {policy} - " + ", ".join(issues[:2]), penalty
    return f"DMARC {policy}", penalty

DISPOSABLE_DOMAINS = {
    "yopmail.com", "mailinator.com", "guerrillamail.com",
    "tempmail.com", "throwam.com", "sharklasers.com",
    "trashmail.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "spamgourmet.com", "mytemp.email"
}

# Domaines officiels connus — jamais pénalisés
WHITELIST_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com",
    "github.com", "paypal.com", "netflix.com", "dropbox.com",
    "zoom.us", "slack.com", "adobe.com", "spotify.com",
    "mozilla.org", "stackoverflow.com", "cloudflare.com",
    "python.org", "action.eff.org"
}

def check_mail_reputation(email):
    if "@" not in email:
        return {"error": "Email invalide"}
    
    domain = email.split("@")[-1].lower()
    
    result = {
        "email": email,
        "domaine": domain,
        "mx": [],
        "spf": None,
        "dmarc": None,
        "fournisseur": None,
        "alertes": [],
        "score": 100,
        "phishing_signals": []  # nouveau champ pour le LLM
    }

    # -------------------- Whitelist --------------------
    is_whitelisted = domain in WHITELIST_DOMAINS
    if is_whitelisted:
        result["score"] = 100

    # -------------------- MX --------------------
    try:
        url = f"https://api.mxtoolbox.com/api/v1/Lookup/MX/?argument={domain}&authorization={MXTOOLBOX_API_KEY}"
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            seen = set()
            for item in data.get("Information", []):
                if isinstance(item, dict) and item.get("Hostname"):
                    host = item["Hostname"]
                    if host not in seen:
                        seen.add(host)
                        result["mx"].append({
                            "serveur": host,
                            "priorite": item.get("Pref", "N/A")
                        })
            if result["mx"]:
                mx_status, mx_penalty = analyze_mx_quality(result["mx"])
                if mx_penalty < 0 and not is_whitelisted:
                    result["alertes"].append(mx_status)
                    result["score"] += mx_penalty
            else:
                if not is_whitelisted:
                    result["alertes"].append("Aucun serveur MX")
                    result["score"] -= 40
        else:
            if not is_whitelisted:
                result["alertes"].append("Erreur MX")
                result["score"] -= 20
    except:
        if not is_whitelisted:
            result["alertes"].append("Timeout MX")
            result["score"] -= 20

    result["fournisseur"] = detect_provider(result["mx"])

    # -------------------- SPF --------------------
    try:
        url = f"https://api.mxtoolbox.com/api/v1/Lookup/SPF/?argument={domain}&authorization={MXTOOLBOX_API_KEY}"
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("Records"):
                spf_record = data["Records"][0]
                result["spf"] = spf_record
                status, penalty = analyze_spf_advanced(spf_record, domain)
                if penalty < 0 and not is_whitelisted:
                    result["alertes"].append(status)
                    result["score"] += penalty
            else:
                if not is_whitelisted:
                    result["alertes"].append("SPF absent")
                    result["score"] -= 25
        else:
            if not is_whitelisted:
                result["alertes"].append("Erreur SPF")
                result["score"] -= 15
    except:
        if not is_whitelisted:
            result["alertes"].append("Timeout SPF")
            result["score"] -= 15

    # -------------------- DMARC --------------------
    try:
        url = f"https://api.mxtoolbox.com/api/v1/Lookup/DMARC/?argument={domain}&authorization={MXTOOLBOX_API_KEY}"
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("Records"):
                dmarc_record = data["Records"][0]
                result["dmarc"] = dmarc_record
                status, penalty = analyze_dmarc(dmarc_record)
                if penalty < 0 and not is_whitelisted:
                    result["alertes"].append(status)
                    result["score"] += penalty
            else:
                if not is_whitelisted:
                    result["alertes"].append("DMARC absent")
                    result["score"] -= 25
        else:
            if not is_whitelisted:
                result["alertes"].append("Erreur DMARC")
                result["score"] -= 15
    except:
        if not is_whitelisted:
            result["alertes"].append("Timeout DMARC")
            result["score"] -= 15

    # -------------------- Détection phishing --------------------
    if not is_whitelisted:
        # TLD suspect
        is_suspicious, tld_alert = detect_suspicious_tld(domain)
        if is_suspicious:
            result["alertes"].append(tld_alert)
            result["phishing_signals"].append(tld_alert)
            result["score"] -= 20

        # Typosquatting
        is_typo, typo_alert = detect_typosquatting(domain)
        if is_typo:
            result["alertes"].append(typo_alert)
            result["phishing_signals"].append(typo_alert)
            result["score"] -= 30

        # Keywords phishing
        is_phishing_kw, phishing_alert = detect_phishing_keywords(domain)
        if is_phishing_kw:
            result["alertes"].append(phishing_alert)
            result["phishing_signals"].append(phishing_alert)
            # Pénalité double si typosquatting + keywords (combinaison très suspecte)
            if is_typo:
                result["score"] -= 25
            else:
                result["score"] -= 15

        # Domaine jetable
        if domain in DISPOSABLE_DOMAINS:
            result["alertes"].append("Domaine jetable")
            result["phishing_signals"].append("Domaine jetable")
            result["score"] -= 40

        # Parking
        if result["mx"]:
            is_parking, parking_alert = detect_parking_provider(result["mx"])
            if is_parking:
                result["alertes"].append(parking_alert)
                result["score"] -= 15

    # -------------------- Nettoyage et verdict --------------------
    result["alertes"] = list(dict.fromkeys(result["alertes"]))
    result["score"] = max(0, min(100, result["score"]))

    if result["score"] >= 80:
        result["verdict"] = "fiable"
    elif result["score"] >= 50:
        result["verdict"] = "douteux"
    else:
        result["verdict"] = "suspect"

    return result