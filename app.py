from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from collections import OrderedDict, defaultdict

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

# ----------------------------
# STORAGE LAYERS
# ----------------------------

alerts = OrderedDict()     # alert_id -> alert

cases = defaultdict(lambda: {
    "ip": None,
    "user": None,
    "alerts": [],
    "first_seen": None,
    "last_seen": None,
    "severity": "LOW",
    "attack_type": "NORMAL",
    "confidence": 0.0,
    "event_count": 0
})


# ----------------------------
# ROUTES
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/alerts")
def get_alerts():
    return jsonify(list(alerts.values()))


@app.route("/cases")
def get_cases():
    return jsonify(dict(cases))


# ----------------------------
# SOCKET CONNECTION
# ----------------------------
@socketio.on("connect")
def on_connect():
    print("Client connected")

    emit("init_alerts", list(alerts.values()))
    emit("init_cases", dict(cases))


# ----------------------------
# ALERT INGESTION (FROM realtime_ids.py)
# ----------------------------
@socketio.on("new_alert")
def handle_new_alert(data):
    alert_id = data.get("id")
    if not alert_id:
        return

    alerts[alert_id] = data

    ip = data.get("ip", "unknown")

    case = cases[ip]

    # ----------------------------
    # INIT CASE METADATA
    # ----------------------------
    case["ip"] = ip
    case["user"] = data.get("user", "unknown")

    case["alerts"].append(alert_id)
    case["event_count"] += 1

    case["first_seen"] = case["first_seen"] or data.get("timestamp")
    case["last_seen"] = data.get("timestamp")

    # ----------------------------
    # CASE EVOLUTION (INTELLIGENCE)
    # ----------------------------
    case["severity"] = data.get("severity", "LOW")
    case["attack_type"] = data.get("attack_type", "UNKNOWN")
    case["confidence"] = max(case["confidence"], data.get("confidence", 0.0))

    print(f"📥 Alert -> Case updated: {ip} ({alert_id})")

    # broadcast real-time updates
    socketio.emit("new_alert", data)
    socketio.emit("case_update", case)


# ----------------------------
# HEARTBEAT
# ----------------------------
def heartbeat():
    while True:
        socketio.sleep(10)
        socketio.emit("status", {"msg": "alive"})


if __name__ == "__main__":
    socketio.start_background_task(heartbeat)

    print("🚨 SOC Dashboard running on http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)