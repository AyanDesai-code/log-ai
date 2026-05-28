import time
import subprocess
import hashlib
import re
from collections import deque, defaultdict
from datetime import datetime

from socketio import Client
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ----------------------------
# CONFIG
# ----------------------------
LOG_PATH = "/var/log/auth.log"
WINDOW_SIZE = 10
ALERT_COOLDOWN = 30  # seconds per IP

buffer = deque(maxlen=WINDOW_SIZE)

# ----------------------------
# SOCKET CLIENT
# ----------------------------
sio = Client(
    reconnection=True,
    logger=False,
    engineio_logger=False
)

# ----------------------------
# STATE (SIEM CORE)
# ----------------------------
last_alert_time = {}        # ip -> timestamp
incidents = defaultdict(lambda: {
    "failed_auth": 0,
    "sessions": 0,
    "logins": 0,
    "first_seen": None,
    "last_seen": None,
    "severity": "LOW"
})

# ----------------------------
# HELPERS
# ----------------------------
def make_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def extract_ip(line):
    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    return match.group(1) if match else "unknown"


def extract_user(line):
    match = re.search(r'for (invalid user )?(\w+)', line)
    return match.group(2) if match else "unknown"


def severity_from_score(failed):
    if failed >= 15:
        return "CRITICAL"
    if failed >= 10:
        return "HIGH"
    if failed >= 5:
        return "MEDIUM"
    return "LOW"


def should_alert(ip):
    now = time.time()
    if ip in last_alert_time:
        if now - last_alert_time[ip] < ALERT_COOLDOWN:
            return False
    last_alert_time[ip] = now
    return True


# ----------------------------
# SOCKET EVENTS
# ----------------------------
@sio.event
def connect():
    print("✅ Connected to SOC server")

@sio.event
def disconnect():
    print("❌ Disconnected from SOC server")


def send_alert(alert):
    try:
        if sio.connected:
            sio.emit("new_alert", alert)
            print("📡 Sent:", alert["id"])
    except Exception as e:
        print("Emit error:", e)


# ----------------------------
# FEATURE EXTRACTION
# ----------------------------
def extract_features(lines):
    failed_auth = 0
    sessions = 0
    logins = 0

    ip = "unknown"
    user = "unknown"

    for line in lines:
        l = line.lower()

        if ip == "unknown":
            ip = extract_ip(l)
        if user == "unknown":
            user = extract_user(l)

        if "failed password" in l or "authentication failure" in l:
            failed_auth += 1

        if "session opened" in l:
            sessions += 1

        if "gdm-password" in l:
            logins += 1

    return {
        "features": [failed_auth, sessions, logins],
        "ip": ip,
        "user": user
    }


# ----------------------------
# BASELINE MODEL
# ----------------------------
print("🔧 Building baseline...")

with open(LOG_PATH, "r") as f:
    raw = f.readlines()[-1000:]

baseline = []

for i in range(0, len(raw), WINDOW_SIZE):
    chunk = raw[i:i + WINDOW_SIZE]
    if len(chunk) == WINDOW_SIZE:
        baseline.append(extract_features(chunk)["features"])

if len(baseline) < 5:
    print("❌ Not enough baseline data")
    exit()

scaler = StandardScaler()
X_train = scaler.fit_transform(baseline)

model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X_train)

print("✅ Model ready")

# ----------------------------
# CONNECT SOCKET
# ----------------------------
sio.connect("http://localhost:5000")

# ----------------------------
# LIVE MONITORING
# ----------------------------
proc = subprocess.Popen(
    ["tail", "-F", LOG_PATH],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("👀 Monitoring logs...\n")

while True:
    line = proc.stdout.readline()
    if not line:
        continue

    line = line.strip()
    buffer.append(line)

    if len(buffer) < WINDOW_SIZE:
        continue

    result = extract_features(buffer)
    features = result["features"]
    ip = result["ip"]
    user = result["user"]

    X = scaler.transform([features])
    score = float(model.decision_function(X)[0])
    pred = int(model.predict(X)[0])

    # ----------------------------
    # UPDATE INCIDENT AGGREGATION
    # ----------------------------
    inc = incidents[ip]
    inc["failed_auth"] = features[0]
    inc["sessions"] = features[1]
    inc["logins"] = features[2]
    inc["last_seen"] = datetime.utcnow().isoformat()

    if not inc["first_seen"]:
        inc["first_seen"] = inc["last_seen"]

    inc["severity"] = severity_from_score(features[0])

    # ----------------------------
    # ESCALATION LOGIC
    # ----------------------------
    is_attack = pred == -1 or features[0] >= 5

    if is_attack and should_alert(ip):

        alert_id = make_id(f"{ip}-{user}-{line}-{score}")

        alert = {
            "id": alert_id,
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "user": user,
            "severity": inc["severity"],
            "failed_auth": features[0],
            "sessions": features[1],
            "logins": features[2],
            "score": score,
            "raw": line,
            "incident": dict(inc)   # grouped context
        }

        print("\n🚨 ALERT (GROUPED INCIDENT)")
        print(alert)

        send_alert(alert)

    time.sleep(0.1)