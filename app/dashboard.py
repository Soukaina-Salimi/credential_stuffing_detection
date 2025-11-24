from flask import Flask, jsonify, render_template, request
import json
import os

app = Flask(__name__)

# ============================
# FONCTIONS UTILES INTERNES
# ============================

def load_json(path):
    """Charge un fichier JSON en toute sécurité"""
    if not os.path.exists(path):
        if path in ["events.json", "alerts.json"]:
            return []  
        return {}      

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if path in ["events.json", "alerts.json"]:
                return data if isinstance(data, list) else []
            return data if isinstance(data, dict) else {}
    except:
        if path in ["events.json", "alerts.json"]:
            return []
        return {}


def save_json(path, data):
    """Sauvegarde JSON proprement"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"❌ Erreur sauvegarde {path}: {e}")


def get_severity_level(score):
    """Détermine le niveau de sévérité selon le score."""
    if score >= 86:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    else:
        return "LOW"


# ======================================
# PATH DES FICHIERS
# ======================================
EVENTS_FILE = "events.json"
ALERTS_FILE = "alerts.json"
SCORES_FILE = "threat_scores.json"
SANCTIONS_FILE = "sanctions.json"


# ============================
# ROUTES FRONTEND
# ============================

@app.route("/")
def dashboard():
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/threats")
def threats_page():
    return render_template("threats.html", active_page="threats")


@app.route("/statistics")
def statistics_page():
    try:
        return render_template("statistics.html", active_page="statistics")
    except:
        return render_template("dashboard.html", active_page="dashboard")


# ============================
# API - EVENTS & ALERTS
# ============================

@app.route("/events")
def get_events():
    events = load_json(EVENTS_FILE)
    
    if isinstance(events, list):
        for ev in events:
            ev.setdefault("country", "Unknown")
            ev.setdefault("ua", "-")
            ev.setdefault("status", "UNKNOWN")
            ev.setdefault("date", "")
            ev.setdefault("time", "")
            ev.setdefault("ip", "0.0.0.0")
            ev.setdefault("user", "unknown")
    
    return jsonify(events)


@app.route("/alerts")
def get_alerts():
    alerts = load_json(ALERTS_FILE)
    return jsonify(alerts)


@app.route("/stats")
def get_stats():
    events = load_json(EVENTS_FILE)
    alerts = load_json(ALERTS_FILE)
    scores = load_json(SCORES_FILE)
    
    if not isinstance(events, list):
        events = []
    
    total_events = len(events)
    failed_logins = len([e for e in events if e.get("status") == "FAIL"])
    success_logins = len([e for e in events if e.get("status") == "SUCCESS"])
    
    # Compter les IPs uniques
    unique_ips = len(set(e.get("ip") for e in events if e.get("ip")))
    
    # Compter les menaces par sévérité
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    if isinstance(scores, dict):
        for score_data in scores.values():
            severity = score_data.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    stats = {
        "total_events": total_events,
        "total_alerts": len(alerts) if isinstance(alerts, list) else 0,
        "failed_logins": failed_logins,
        "success_logins": success_logins,
        "success_rate": round((success_logins / total_events * 100) if total_events else 0, 2),
        "unique_ips": unique_ips,
        "total_threats": len(scores) if isinstance(scores, dict) else 0,
        "severity_counts": severity_counts
    }
    
    return jsonify(stats)


# ============================
# API - SCORES (Version IP-only)
# ============================

@app.route("/api/scores")
def get_scores():
    """Retourne tous les scores de menaces (agrégés par IP)"""
    scores = load_json(SCORES_FILE)
    print(f"📊 API /api/scores appelée - {len(scores) if isinstance(scores, dict) else 0} menaces")
    return jsonify(scores)


@app.route("/api/sanctions")
def get_sanctions():
    """Retourne toutes les sanctions actives"""
    sanctions = load_json(SANCTIONS_FILE)
    scores = load_json(SCORES_FILE)
    
    # Nettoyer les sanctions obsolètes
    cleaned = {}
    changed = False
    
    if isinstance(sanctions, dict):
        for entity, sanction in sanctions.items():
            # Vérifier si l'entité existe dans les scores
            if entity not in scores:
                changed = True
                continue
            
            score = scores[entity].get("score", 0)
            
            # Supprimer si score < 31
            if score < 31:
                changed = True
                continue
            
            # Recalculer la sévérité pour corriger d'éventuelles incohérences
            correct_severity = get_severity_level(score)
            if sanction.get("severity") != correct_severity:
                sanction["severity"] = correct_severity
                changed = True
            
            # Vérifier l'expiration
            if sanction.get("expires_at"):
                try:
                    from datetime import datetime
                    expires = datetime.fromisoformat(sanction["expires_at"])
                    if datetime.now() > expires:
                        changed = True
                        continue
                except:
                    pass
            
            cleaned[entity] = sanction
    
    if changed:
        save_json(SANCTIONS_FILE, cleaned)
    
    print(f"📊 API /api/sanctions appelée - {len(cleaned)} sanctions actives")
    return jsonify(cleaned)


@app.route("/api/ip-details")
def get_ip_details():
    """Retourne les détails complets d'une IP spécifique"""
    ip = request.args.get("ip")
    
    if not ip:
        return jsonify({"error": "Missing IP parameter"}), 400
    
    scores = load_json(SCORES_FILE)
    key = f"IP:{ip}"
    
    if isinstance(scores, dict) and key in scores:
        return jsonify(scores[key])
    
    return jsonify({"error": "IP not found"}), 404


@app.route("/api/statistics")
def get_advanced_statistics():
    """Statistiques avancées pour la page statistics"""
    events = load_json(EVENTS_FILE)
    alerts = load_json(ALERTS_FILE)
    scores = load_json(SCORES_FILE)
    
    if not isinstance(events, list):
        events = []
    if not isinstance(alerts, list):
        alerts = []
    
    # Agrégation par pays
    countries = {}
    for e in events:
        c = e.get("country", "Unknown")
        countries[c] = countries.get(c, 0) + 1
    
    # Agrégation par IP
    ip_stats = {}
    for e in events:
        ip = e.get("ip")
        if not ip:
            continue
        
        if ip not in ip_stats:
            ip_stats[ip] = {
                "total": 0,
                "failed": 0,
                "success": 0,
                "users": set()
            }
        
        ip_stats[ip]["total"] += 1
        if e.get("status") == "FAIL":
            ip_stats[ip]["failed"] += 1
        elif e.get("status") == "SUCCESS":
            ip_stats[ip]["success"] += 1
        
        user = e.get("user")
        if user:
            ip_stats[ip]["users"].add(user)
    
    # Top IPs par nombre de tentatives
    top_ips_attempts = sorted(
        [(ip, data["total"]) for ip, data in ip_stats.items()],
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    # Top IPs par nombre d'échecs
    top_ips_failures = sorted(
        [(ip, data["failed"]) for ip, data in ip_stats.items()],
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    # Scores par sévérité
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    if isinstance(scores, dict):
        for score_data in scores.values():
            severity = score_data.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    return jsonify({
        "total_events": len(events),
        "total_alerts": len(alerts),
        "total_threats": len(scores) if isinstance(scores, dict) else 0,
        "unique_ips": len(ip_stats),
        "threats_by_severity": severity_counts,
        "top_countries": dict(sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_ips_attempts": dict(top_ips_attempts),
        "top_ips_failures": dict(top_ips_failures)
    })


@app.route("/api/remove-sanction", methods=["POST"])
def remove_sanction():
    """Lève une sanction manuellement"""
    data = request.get_json()
    
    s_type = data.get("type")
    value = data.get("value")
    
    if not s_type or not value:
        return jsonify({"success": False, "error": "Missing parameters"}), 400
    
    sanctions = load_json(SANCTIONS_FILE)
    key = f"{s_type}:{value}"
    
    if not isinstance(sanctions, dict) or key not in sanctions:
        return jsonify({"success": False, "error": "Sanction not found"}), 404
    
    # Marquer comme inactive au lieu de supprimer
    sanctions[key]["active"] = False
    save_json(SANCTIONS_FILE, sanctions)
    
    print(f"🔓 Sanction levée: {key}")
    
    return jsonify({
        "success": True,
        "message": f"Sanction levée pour {s_type}: {value}"
    })
def get_events_by_ip():
    """Retourne tous les événements pour une IP donnée"""
    ip = request.args.get("ip")
    
    if not ip:
        return jsonify({"error": "Missing IP parameter"}), 400
    
    events = load_json(EVENTS_FILE)
    
    if not isinstance(events, list):
        return jsonify([])
    
    ip_events = [e for e in events if e.get("ip") == ip]
    
    return jsonify(ip_events)


# ============================
# LAUNCH SERVER
# ============================

if __name__ == "__main__":
    print("=" * 70)
    print("🚀 Security Dashboard Server Starting (IP-only version)...")
    print("=" * 70)
    print("\n📊 Pages disponibles:")
    print("   • Dashboard Principal    : http://127.0.0.1:5000/")
    print("   • Menaces par IP         : http://127.0.0.1:5000/threats")
    print("   • Statistiques           : http://127.0.0.1:5000/statistics")
    print("=" * 70 + "\n")
    
    app.run(debug=True, host="0.0.0.0", port=5000)