from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from collections import OrderedDict, defaultdict
import hashlib
import time

app = Flask(__name__)
app.config["SECRET_KEY"] = "soc-secret"

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ============================
# STORAGE LAYERS
# ============================

alerts = OrderedDict()

cases = defaultdict(lambda: {
    "ip": None,
    "user": None,

    "alerts": [],
    "fingerprints": set(),

    "first_seen": None,
    "last_seen": None,

    "severity": "LOW",
    "attack_type": "NORMAL",

    "confidence": 0.0,
    "event_count": 0,

    # UEBA metrics
    "failed_auth_total": 0,
    "risk_score": 0.0
})


# ============================
# MITRE MAPPING (SIMPLE CORE SET)
# ============================

MITRE_MAP = {
    "BRUTE_FORCE": ["T1110.001"],
    "CREDENTIAL_STUFFING": ["T1110"],
    "PASSWORD_GUESSING": ["T1110.001"],
    "USER_ENUMERATION": ["T1589"],
    "NORMAL": []
}


# ============================
# HELPERS
# ============================

def now():
    return time.time()


def make_fingerprint(alert):
    raw = f"{alert.get('ip')}|{alert.get('user')}|{alert.get('attack_type')}|{alert.get('raw')}"
    return hashlib.sha256(raw.encode()).hexdigest()


def dedup_alert(alert_id, fingerprint, ttl=30):
    """
    Prevent alert flooding:
    - same ID OR same fingerprint within TTL ignored
    """
    if alert_id in alerts:
        return False

    for a in list(alerts.values())[-50:]:
        if a.get("fingerprint") == fingerprint and (now() - a.get("ts", 0)) < ttl:
            return False

    return True


def compute_case_risk(case):
    """
    UEBA-lite scoring
    """
    score = 0

    score += case["failed_auth_total"] * 2
    score += case["event_count"] * 1.5
    score += case["confidence"] * 50

    if case["attack_type"] == "BRUTE_FORCE":
        score += 30
    elif case["attack_type"] == "CREDENTIAL_STUFFING":
        score += 25

    return min(score / 100, 1.0)


def severity_from_risk(risk):
    if risk > 0.85:
        return "CRITICAL"
    if risk > 0.65:
        return "HIGH"
    if risk > 0.40:
        return "MEDIUM"
    return "LOW"


# ============================
# ROUTES
# ============================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/alerts")
def get_alerts():
    return jsonify(list(alerts.values()))


@app.route("/cases")
def get_cases():
    return jsonify(dict(cases))


# ============================
# SOCKET CONNECT
# ============================

@socketio.on("connect")
def on_connect():
    emit("init_alerts", list(alerts.values()))
    emit("init_cases", dict(cases))


# ============================
# ALERT INGESTION PIPELINE
# ============================

@socketio.on("new_alert")
def handle_new_alert(data):

    alert_id = data.get("id")
    if not alert_id:
        return

    fingerprint = make_fingerprint(data)

    # ----------------------------
    # DEDUP ENGINE
    # ----------------------------
    if not dedup_alert(alert_id, fingerprint):
        return

    data["fingerprint"] = fingerprint
    data["ts"] = now()

    # store alert
    alerts[alert_id] = data


    # ============================
    # CASE ENGINE (UEBA CORE)
    # ============================

    ip = data.get("ip", "unknown")
    user = data.get("user", "unknown")

    case = cases[f"{ip}:{user}"]  # stronger grouping than IP alone

    case["ip"] = ip
    case["user"] = user

    case["alerts"].append(alert_id)
    case["event_count"] += 1

    case["first_seen"] = case["first_seen"] or data.get("timestamp")
    case["last_seen"] = data.get("timestamp")

    # attack intelligence
    attack_type = data.get("attack_type", "UNKNOWN")
    case["attack_type"] = attack_type

    case["confidence"] = max(case["confidence"], data.get("confidence", 0.0))

    # UEBA aggregation
    case["failed_auth_total"] += data.get("failed_auth", 0)

    # risk scoring
    risk = compute_case_risk(case)
    case["risk_score"] = risk
    case["severity"] = severity_from_risk(risk)

    # attach MITRE mapping
    data["mitre"] = MITRE_MAP.get(attack_type, [])

    # ============================
    # BROADCAST
    # ============================

    emit("new_alert", data, broadcast=True)
    socketio.emit("case_update", case)

    print(f"📥 CASE UPDATED: {ip}:{user} | {attack_type} | {case['severity']}")


# ============================
# HEARTBEAT
# ============================

def heartbeat():
    while True:
        socketio.sleep(10)
        socketio.emit("status", {
            "msg": "alive",
            "alerts": len(alerts),
            "cases": len(cases)
        })


if __name__ == "__main__":
    socketio.start_background_task(heartbeat)

    print("🚨 Enterprise SOC running on http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)