from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from collections import OrderedDict

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

# ----------------------------
# STORAGE (INCIDENT-AWARE)
# ----------------------------
alerts = OrderedDict()   # alert_id -> alert


# ----------------------------
# ROUTES
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/alerts")
def get_alerts():
    return jsonify(list(alerts.values()))


# ----------------------------
# SOCKET CONNECTION
# ----------------------------
@socketio.on("connect")
def on_connect():
    print("Client connected")

    # send full state on connect
    emit("init_alerts", list(alerts.values()))


# ----------------------------
# REAL ALERT HANDLER (FROM realtime_ids.py)
# ----------------------------
@socketio.on("new_alert")
def handle_new_alert(data):
    """
    Receives structured alerts from realtime_ids.py
    """
    alert_id = data.get("id")

    if not alert_id:
        return

    # store latest version of alert (overwrite = real-time update model)
    alerts[alert_id] = data

    print(f"📥 Alert received: {alert_id}")

    # broadcast to all dashboards
    socketio.emit("new_alert", data)


# ----------------------------
# OPTIONAL: SIMPLE BACKGROUND HEARTBEAT (debug only)
# ----------------------------
def heartbeat():
    while True:
        socketio.sleep(10)
        socketio.emit("status", {"msg": "alive"})


if __name__ == "__main__":
    socketio.start_background_task(heartbeat)

    print("🚨 SOC Dashboard running on http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)