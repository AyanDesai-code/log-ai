import time
import subprocess
import hashlib
import re
from collections import deque, defaultdict
from datetime import datetime, timezone

from socketio import Client
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ----------------------------
# CONFIG
# ----------------------------
LOG_PATH = "/var/log/auth.log"
WINDOW_SIZE = 10
ALERT_COOLDOWN = 30

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
last_alert_time = {}

incidents = defaultdict(lambda: {
    "failed_auth": 0,
    "sessions": 0,
    "logins": 0,
    "first_seen": None,
    "last_seen": None,
    "severity": "LOW",
    "attack_type": "NORMAL",
    "confidence": 0.0,
    "event_count": 0
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
    if ip in last_alert_time and now - last_alert_time[ip] < ALERT_COOLDOWN:
        return False
    last_alert_time[ip] = now
    return True


# ----------------------------
# ATTACK CLASSIFICATION
# ----------------------------
from collections import Counter


def classify_attack(features, ip, user, buffer_lines):
    failed_auth, sessions, logins = features

    # ----------------------------
    # SAFETY: normalize buffer input
    # ----------------------------
    if not buffer_lines:
        buffer_lines = []

    normalized_lines = [str(l).lower() for l in buffer_lines]

    # ----------------------------
    # CONTEXT ANALYSIS
    # ----------------------------
    ip_counts = Counter()
    user_counts = Counter()

    for l in normalized_lines:
        ip_counts[extract_ip(l)] += 1
        user_counts[extract_user(l)] += 1

    repeated_user = user_counts.get(user, 0) >= 3
    repeated_ip = ip_counts.get(ip, 0) >= 3

    recent_failed = sum(
        1 for l in normalized_lines if "failed password" in l
    )

    # ----------------------------
    # SCORE MODEL
    # ----------------------------
    score = 0
    score += failed_auth * 10
    score += recent_failed * 5
    score += 5 if sessions == 0 else -5
    score += 3 if repeated_user else 0
    score += 3 if repeated_ip else 0

    # ----------------------------
    # CLASSIFICATION
    # ----------------------------
    if score >= 80:
        return "BRUTE_FORCE", 0.95

    if failed_auth >= 5 and repeated_user:
        return "CREDENTIAL_STUFFING", 0.85

    if failed_auth >= 3 and sessions == 0:
        return "USER_ENUMERATION", 0.80

    if 2 <= failed_auth < 5:
        return "PASSWORD_GUESSING", 0.60

    return "NORMAL", 0.50

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

    return [failed_auth, sessions, logins], ip, user


# ----------------------------
# BASELINE MODEL
# ----------------------------
print("🔧 Building baseline...")

with open(LOG_PATH, "r") as f:
    raw = f.readlines()[-1000:]

baseline = [
    extract_features(raw[i:i + WINDOW_SIZE])[0]
    for i in range(0, len(raw), WINDOW_SIZE)
    if len(raw[i:i + WINDOW_SIZE]) == WINDOW_SIZE
]

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

    features, ip, user = extract_features(buffer)

    X = scaler.transform([features])
    score = float(model.decision_function(X)[0])
    pred = int(model.predict(X)[0])

    inc = incidents[ip]

    # ----------------------------
    # INCIDENT AGGREGATION
    # ----------------------------
    inc["failed_auth"] += features[0]
    inc["sessions"] += features[1]
    inc["logins"] += features[2]
    inc["event_count"] += 1

    now = datetime.now(timezone.utc).isoformat()
    inc["last_seen"] = now
    if not inc["first_seen"]:
        inc["first_seen"] = now

    inc["severity"] = severity_from_score(inc["failed_auth"])

    attack_type, confidence = classify_attack(features, ip, user, buffer)
    inc["attack_type"] = attack_type
    inc["confidence"] = confidence

    # ----------------------------
    # ATTACK DETECTION
    # ----------------------------
    is_attack = pred == -1 or features[0] >= 5

    if is_attack and should_alert(ip):

        alert_id = make_id(f"{ip}-{user}-{line}-{score}")

        alert = {
            "id": alert_id,
            "timestamp": now,
            "ip": ip,
            "user": user,
            "severity": inc["severity"],
            "attack_type": attack_type,
            "confidence": confidence,
            "failed_auth": features[0],
            "sessions": features[1],
            "logins": features[2],
            "score": score,
            "raw": line,
            "incident": dict(inc)
        }

        print("\n🚨 ALERT (CLASSIFIED + GROUPED)")
        print(alert)

        send_alert(alert)

    time.sleep(0.1)