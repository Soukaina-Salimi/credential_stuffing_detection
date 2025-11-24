# ================================================================
# SYSTÈME IP-ONLY : GÉNÉRATEUR + DÉTECTION + SCORING
# Version corrigée : bug sévérité 85-86 résolu + MEDIUM sanctions
# ================================================================

import re
import json
import os
import random
import datetime
import time
from datetime import datetime as dt, timedelta
from collections import defaultdict
import math

# ================================
# FICHIERS
# ================================
EVENTS_FILE = "events.json"
ALERT_FILE = "alerts.json"
SCORES_FILE = "threat_scores.json"
SANCTIONS_FILE = "sanctions.json"

# ================================
# CONFIGURATION GLOBALE
# ================================
SCORING_WEIGHTS = {
    "failed_attempts": 25,
    "attack_speed": 20,
    "tool_detection": 15,
    "geographic_risk": 10,
    "user_spread": 15,
    "persistence": 15,
}

DETECTION_CFG = {
    "BRUTE_FORCE_FAIL_THRESHOLD": 5,
    "USER_SPREAD_THRESHOLD": 4,
    "MIN_BOT_SPEED": 0.25,
    "PERSISTENCE_MINUTES": 15,
    "HIGH_VALUE_TARGETS": ["admin", "root", "security", "finance", "backup", "superuser", "dbadmin"],
}

SUSPICIOUS_USER_AGENTS = [
    "hydra", "sqlmap", "masscan", "nikto", "nmap",
    "burp", "metasploit", "python-requests", "curl", "wget"
]

HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "BR"]
MEDIUM_RISK_COUNTRIES = ["US", "MO"]

SEVERITY_LEVELS = {
    "CRITICAL": (86, 100),
    "HIGH": (61, 85),
    "MEDIUM": (31, 60),
    "LOW": (0, 30)
}

SANCTIONS = {
    "MEDIUM": {
        "action": "RATE_LIMIT",
        "duration_minutes": 60,
        "description": "Limitation du taux de requêtes (1/5s)",
        "block": False,
        "rate_limit": "1/5s"
    },
    "HIGH": {
        "action": "TEMPORARY_BLOCK",
        "duration_minutes": 180,
        "description": "Blocage temporaire (3 heures)",
        "block": True
    },
    "CRITICAL": {
        "action": "PERMANENT_BLOCK",
        "duration_minutes": None,
        "description": "Blocage permanent - Révision manuelle requise",
        "block": True,
        "requires_manual_review": True
    }
}

# ================================
# UTILITAIRES I/O JSON
# ================================
def load_json(path):
    if not os.path.exists(path):
        return {} if path in [SCORES_FILE, SANCTIONS_FILE] else []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Erreur chargement {path}: {e}")
        return {} if path in [SCORES_FILE, SANCTIONS_FILE] else []

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Erreur sauvegarde {path}: {e}")

def parse_datetime(date_str, time_str):
    s = f"{date_str} {time_str}"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.strptime(s, fmt)
        except:
            continue
    return dt.now()

# ================================
# SEVERITY - FONCTION CORRIGÉE
# ================================
def get_severity_level(score):
    """Détermine le niveau de sévérité selon le score.
    CORRECTION: Utilise >= pour gérer correctement les scores comme 85.97"""
    if score >= 86:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    else:
        return "LOW"

# ================================
# CALCUL SCORE PAR IP
# ================================
def calculate_threat_score_ip(events, ip):
    """Calcule le score de menace pour une IP spécifique"""
    score_components = {
        "failed_attempts": 0,
        "attack_speed": 0,
        "tool_detection": 0,
        "geographic_risk": 0,
        "user_spread": 0,
        "persistence": 0
    }
    reasons = []

    ip_events = [e for e in events if e.get("ip") == ip]
    if not ip_events:
        return 0, [], score_components, {}

    recent = ip_events[-200:]

    aggregated_stats = {
        "total_attempts": len(recent),
        "failed_attempts": 0,
        "success_attempts": 0,
        "unique_users": set(),
        "countries": set(),
        "user_agents": set(),
        "targeted_hvt": set(),
        "first_seen": None,
        "last_seen": None
    }

    times = []
    for e in recent:
        if e.get("status") == "FAIL":
            aggregated_stats["failed_attempts"] += 1
        elif e.get("status") == "SUCCESS":
            aggregated_stats["success_attempts"] += 1
        
        user = e.get("user")
        if user:
            aggregated_stats["unique_users"].add(user)
            if user in DETECTION_CFG["HIGH_VALUE_TARGETS"]:
                aggregated_stats["targeted_hvt"].add(user)
        
        country = e.get("country")
        if country:
            aggregated_stats["countries"].add(country)
        
        ua = e.get("ua")
        if ua:
            aggregated_stats["user_agents"].add(ua)
        
        try:
            t = parse_datetime(e.get("date", ""), e.get("time", ""))
            times.append(t)
        except:
            continue

    times = sorted(times)
    if times:
        aggregated_stats["first_seen"] = times[0].strftime("%Y-%m-%d %H:%M:%S")
        aggregated_stats["last_seen"] = times[-1].strftime("%Y-%m-%d %H:%M:%S")

    aggregated_stats["unique_users"] = list(aggregated_stats["unique_users"])
    aggregated_stats["countries"] = list(aggregated_stats["countries"])
    aggregated_stats["user_agents"] = list(aggregated_stats["user_agents"])
    aggregated_stats["targeted_hvt"] = list(aggregated_stats["targeted_hvt"])

    # Failed attempts
    num_fails = aggregated_stats["failed_attempts"]
    fail_thresh = DETECTION_CFG["BRUTE_FORCE_FAIL_THRESHOLD"]
    if num_fails >= fail_thresh:
        over = num_fails - (fail_thresh - 1)
        max_weight = SCORING_WEIGHTS["failed_attempts"]
        sc = min(max_weight, round(max_weight * (1 - math.exp(-over/3)), 2))
        score_components["failed_attempts"] = sc
        ratio = num_fails / len(recent) * 100
        reasons.append(f"{num_fails} tentatives échouées ({ratio:.1f}%)")

    # Attack speed
    if len(times) >= 3:
        diffs = [(times[i]-times[i-1]).total_seconds() for i in range(1, len(times))]
        diffs_sorted = sorted(diffs)
        cut = max(1, int(len(diffs_sorted)*0.1))
        trimmed = diffs_sorted[cut:len(diffs_sorted)-cut] if len(diffs_sorted) > 2*cut else diffs_sorted
        if trimmed:
            avg = sum(trimmed)/len(trimmed)
            w = SCORING_WEIGHTS["attack_speed"]
            if avg < 0.25:
                score_components["attack_speed"] = w
                reasons.append(f"Attaque très rapide ({avg:.2f}s/req)")
            elif avg < 0.6:
                score_components["attack_speed"] = round(w * 0.8, 2)
                reasons.append(f"Attaque rapide ({avg:.2f}s/req)")
            elif avg < 1.5:
                score_components["attack_speed"] = round(w * 0.5, 2)
                reasons.append(f"Attaque modérée ({avg:.2f}s/req)")

    # Tool detection
    for ua in aggregated_stats["user_agents"]:
        ua_l = ua.lower()
        if any(bot in ua_l for bot in SUSPICIOUS_USER_AGENTS):
            score_components["tool_detection"] = SCORING_WEIGHTS["tool_detection"]
            reasons.append(f"Outil automatisé: {ua[:40]}")
            break

    # Geographic risk
    geo_score = 0
    for c in aggregated_stats["countries"]:
        if c in HIGH_RISK_COUNTRIES:
            geo_score = max(geo_score, SCORING_WEIGHTS["geographic_risk"])
            reasons.append(f"Pays à haut risque: {c}")
            break
        elif c in MEDIUM_RISK_COUNTRIES:
            geo_score = max(geo_score, SCORING_WEIGHTS["geographic_risk"]//2)
            reasons.append(f"Pays risque moyen: {c}")
    score_components["geographic_risk"] = geo_score

    # User spread
    num_users = len(aggregated_stats["unique_users"])
    if num_users >= 15:
        score_components["user_spread"] = SCORING_WEIGHTS["user_spread"]
        reasons.append(f"Credential stuffing: {num_users} utilisateurs ciblés")
    elif num_users >= 8:
        score_components["user_spread"] = round(SCORING_WEIGHTS["user_spread"] * 0.8, 2)
        reasons.append(f"Multiple utilisateurs: {num_users}")
    elif num_users >= DETECTION_CFG["USER_SPREAD_THRESHOLD"]:
        score_components["user_spread"] = round(SCORING_WEIGHTS["user_spread"] * 0.5, 2)
        reasons.append(f"Plusieurs utilisateurs: {num_users}")

    # Persistence
    if len(times) >= 2:
        span_minutes = (times[-1] - times[0]).total_seconds() / 60.0
        pers_weight = SCORING_WEIGHTS["persistence"]
        if span_minutes >= DETECTION_CFG["PERSISTENCE_MINUTES"]:
            score_components["persistence"] = pers_weight
            reasons.append(f"Attaque persistante: {span_minutes:.0f} min")
        elif span_minutes >= (DETECTION_CFG["PERSISTENCE_MINUTES"] / 2):
            score_components["persistence"] = round(pers_weight * 0.6, 2)
            reasons.append(f"Attaque soutenue: {span_minutes:.0f} min")

    # High value targets bonus
    if aggregated_stats["targeted_hvt"]:
        hvt_bonus = 5
        reasons.append(f"Comptes sensibles ciblés: {', '.join(aggregated_stats['targeted_hvt'][:3])}")
        score_components["user_spread"] = min(100, score_components["user_spread"] + hvt_bonus)

    score = round(sum(score_components.values()), 2)
    return min(score, 100), reasons, score_components, aggregated_stats

# ================================
# APPLY SANCTION - VERSION CORRIGÉE
# ================================
def apply_sanction(entity_type, value, score, severity, reasons, components):
    """Applique une sanction basée sur le score et la sévérité
    CORRECTION: Vérifie d'abord si la sévérité existe dans SANCTIONS"""
    
    # Vérification de sévérité
    if severity not in SANCTIONS:
        print(f"⚠️ Aucune sanction définie pour sévérité: {severity} (score: {score})")
        return
    
    sanctions = load_json(SANCTIONS_FILE)
    if not isinstance(sanctions, dict):
        sanctions = {}
    
    sanction_config = SANCTIONS[severity]
    key = f"{entity_type}:{value}"
    now = dt.now()
    
    expires_at = None
    if sanction_config["duration_minutes"]:
        expires_at = (now + timedelta(minutes=sanction_config["duration_minutes"])).isoformat()
    
    sanction = {
        "entity_type": entity_type,
        "entity_value": value,
        "score": score,
        "severity": severity,
        "action": sanction_config["action"],
        "description": sanction_config["description"],
        "blocked": sanction_config["block"],
        "active": True,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        "reasons": reasons[:5],
        "components": components
    }
    
    if "rate_limit" in sanction_config:
        sanction["rate_limit"] = sanction_config["rate_limit"]
    
    if sanction_config.get("requires_manual_review"):
        sanction["requires_manual_review"] = True
    
    sanctions[key] = sanction
    save_json(SANCTIONS_FILE, sanctions)
    
    emoji = {"MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(severity, "⚪")
    print(f"{emoji} Sanction: {value} → {sanction_config['action']} | Score: {score} | {severity}")

# ================================
# DETECTION PAR IP - VERSION CORRIGÉE
# ================================
def detect_threats_by_ip(events):
    """Détecte les menaces en analysant chaque IP
    CORRECTION: Applique maintenant les sanctions MEDIUM correctement"""
    alerts = load_json(ALERT_FILE)
    scores = load_json(SCORES_FILE)

    if not isinstance(alerts, list):
        alerts = []
    if not isinstance(scores, dict):
        scores = {}

    latest = events[-1000:]
    
    ip_groups = defaultdict(list)
    for e in latest:
        ip = e.get("ip")
        if ip and ip not in LOCAL_IPS:
            ip_groups[ip].append(e)

    alerted_ips = {a.get("ip") for a in alerts if a.get("type") == "Threat Detection"}
    
    for ip, ip_events in ip_groups.items():
        if len(ip_events) < 3:
            continue
        
        score, reasons, components, stats = calculate_threat_score_ip(events, ip)
        severity = get_severity_level(score)
        
        # MODIFICATION: Traiter tous les scores >= 31 (MEDIUM, HIGH, CRITICAL)
        if score >= 31:
            scores[f"IP:{ip}"] = {
                "entity_type": "IP",
                "entity_value": ip,
                "score": score,
                "severity": severity,
                "reasons": reasons,
                "components": components,
                "stats": stats
            }
            
            # Appliquer sanction pour MEDIUM, HIGH et CRITICAL
            print(f"📊 Traitement IP {ip}: Score={score}, Sévérité={severity}")
            apply_sanction("IP", ip, score, severity, reasons, components)
            
            if ip not in alerted_ips:
                sample = ip_events[-1]
                alerts.append({
                    "type": "Threat Detection",
                    "ip": ip,
                    "score": score,
                    "severity": severity,
                    "reasons": reasons[:3],
                    "total_attempts": stats["total_attempts"],
                    "failed_attempts": stats["failed_attempts"],
                    "unique_users": len(stats["unique_users"]),
                    "countries": stats["countries"],
                    "date": sample.get("date", ""),
                    "time": sample.get("time", "")
                })
                alerted_ips.add(ip)

    save_json(ALERT_FILE, alerts)
    save_json(SCORES_FILE, scores)

# ================================
# GÉNÉRATEUR DE LOGS
# ================================
LEGIT_USERS = [
    "ahmed", "sara", "mehdi", "ilias", "youssef", "fatima",
    "karim", "noura", "hassan", "amina", "samir", "leila",
    "mohamed", "sanae", "oussama"
]
HIGH_VALUE_TARGETS = DETECTION_CFG["HIGH_VALUE_TARGETS"] + ["operator", "itmanager", "developer"]

USER_AGENTS_HUMANS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/102.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2) Safari/604.1"
]

USER_AGENTS_BOTS = [
    "python-requests/2.31.0",
    "curl/8.1.2",
    "hydra/9.4 brute-force",
    "sqlmap/1.7-dev",
    "masscan/1.3"
]

COUNTRIES = {
    "MO": ["41.248", "102.55", "105.158", "154.70"],
    "FR": ["5.39", "51.83", "151.80", "185.22"],
    "US": ["34.201", "54.23", "100.24"],
    "RU": ["45.12", "185.104", "91.215", "92.63"],
    "BR": ["170.79", "177.55", "186.212"],
    "CN": ["36.102", "116.10", "123.125"],
    "DE": ["5.56", "51.15", "78.47"],
    "NL": ["5.150", "185.53", "77.88"]
}

LOCAL_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.50", "10.0.0.7"]

def random_public_ip():
    """Génère une IP complète à 4 octets (A.B.C.D)"""
    country = random.choice(list(COUNTRIES.keys()))
    prefix = random.choice(COUNTRIES[country])
    
    parts = prefix.split('.')
    octets_needed = 4 - len(parts)
    
    for _ in range(octets_needed):
        parts.append(str(random.randint(1, 254)))
    
    return '.'.join(parts), country

def generate_credential_stuffing_burst(events, attempts=40):
    ip, country = random_public_ip()
    ua = random.choice(USER_AGENTS_BOTS)
    timestamp = dt.now()
    users_pool = LEGIT_USERS + HIGH_VALUE_TARGETS
    
    for i in range(attempts):
        user = random.choice(users_pool)
        delta = random.uniform(0.08, 0.8)
        timestamp += timedelta(seconds=delta)
        status = "FAIL" if random.random() < 0.88 else "SUCCESS"
        
        event = {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S.%f")[:-3],
            "ip": ip,
            "user": user,
            "status": status,
            "ua": ua,
            "country": country
        }
        events.append(event)
    
    return events

def generate_moderate_attack(events, attempts=15):
    ip, country = random_public_ip()
    user = random.choice(HIGH_VALUE_TARGETS + LEGIT_USERS)
    ua = random.choice(USER_AGENTS_BOTS if random.random() < 0.7 else USER_AGENTS_HUMANS)
    timestamp = dt.now()
    
    for i in range(attempts):
        delta = random.uniform(0.5, 2.0)
        timestamp += timedelta(seconds=delta)
        status = "FAIL" if random.random() < 0.85 else "SUCCESS"
        
        event = {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S.%f")[:-3],
            "ip": ip,
            "user": user,
            "status": status,
            "ua": ua,
            "country": country
        }
        events.append(event)
    
    return events

def generate_live_logs():
    print("=" * 70)
    print("🚀 Générateur de logs - Version IP uniquement")
    print("📊 Agrégation et scoring par IP")
    print("=" * 70)
    
    events = load_json(EVENTS_FILE)
    if not isinstance(events, list):
        events = []

    now = dt.now()
    iteration = 0

    try:
        while True:
            iteration += 1

            if random.random() < 0.08:
                events = generate_credential_stuffing_burst(events, attempts=random.randint(30, 70))
                if len(events) > 2000:
                    events = events[-2000:]
                save_json(EVENTS_FILE, events)
                detect_threats_by_ip(events)
                print("🔴 CRITICAL : credential stuffing massif")
                time.sleep(random.uniform(1.5, 3.0))
                continue

            if random.random() < 0.15:
                events = generate_moderate_attack(events, attempts=random.randint(10, 18))
                if len(events) > 2000:
                    events = events[-2000:]
                save_json(EVENTS_FILE, events)
                detect_threats_by_ip(events)
                print("🟡 MEDIUM : attaque modérée")
                time.sleep(random.uniform(1.0, 2.0))
                continue

            if random.random() < 0.35:
                ip, country = random_public_ip()
                user = random.choice(HIGH_VALUE_TARGETS + LEGIT_USERS)
                ua = random.choice(USER_AGENTS_BOTS if random.random() < 0.85 else USER_AGENTS_HUMANS)
                status = "FAIL" if random.random() < 0.9 else "SUCCESS"
                sleep = random.uniform(0.05, 0.6)
            else:
                if random.random() < 0.6:
                    ip, country = random_public_ip()
                else:
                    ip = random.choice(LOCAL_IPS)
                    country = "LAN"
                user = random.choice(LEGIT_USERS)
                ua = random.choice(USER_AGENTS_HUMANS)
                status = "SUCCESS" if random.random() > 0.15 else "FAIL"
                sleep = random.uniform(0.6, 5.0)

            now += timedelta(milliseconds=random.randint(50, 1200))
            event = {
                "date": now.strftime("%Y-%m-%d"),
                "time": now.strftime("%H:%M:%S.%f")[:-3],
                "ip": ip,
                "user": user,
                "status": status,
                "ua": ua,
                "country": country
            }

            events.append(event)
            if len(events) > 2000:
                events = events[-2000:]
            save_json(EVENTS_FILE, events)

            if iteration % 8 == 0:
                detect_threats_by_ip(events)

            status_icon = "✅" if status == "SUCCESS" else "❌"
            print(f"{status_icon} | {event['date']} {event['time']} | {ip:15s} | {user:12s} | {status:7s} | {country}")
            time.sleep(sleep)

    except KeyboardInterrupt:
        print("\n" + "=" * 30)
        print("🛑 Génération arrêtée")
        print("=" * 30)
        save_json(EVENTS_FILE, events)

if __name__ == "__main__":
    generate_live_logs()