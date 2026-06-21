import time
import subprocess
import hashlib
import re
from collections import deque, defaultdict
from datetime import datetime, timezone

import socketio
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# =========================================================
# CONFIG
# =========================================================
LOG_PATH = "/var/log/auth.log"
WINDOW_SIZE = 12
ALERT_COOLDOWN = 20
CASE_WINDOW_TTL = 300  # 5 min behavioral window

buffer = deque(maxlen=WINDOW_SIZE)

# =========================================================
# SOCKET
# =========================================================
sio = socketio.Client(reconnection=True)

# =========================================================
# STATE
# =========================================================
last_alert_time = {}

cases = defaultdict(lambda: {
    "ip": None,
    "user": None,

    # ---- behavioral metrics (UEBA CORE)
    "failed_auth": 0,
    "failed_rate": 0.0,
    "unique_users_seen": set(),
    "unique_ips_seen": set(),

    # ---- activity
    "sessions": 0,
    "logins": 0,
    "event_count": 0,

    # ---- timeline
    "first_seen": None,
    "last_seen": None,

    # ---- intelligence
    "attack_type": "NORMAL",
    "confidence": 0.0,
    "severity": "LOW",

    # ---- MITRE ATT&CK mapping
    "mitre": [],
})


# =========================================================
# HELPERS
# =========================================================
def now():
    return datetime.now(timezone.utc).isoformat()


def make_id(text: str):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def extract_ip(line):
    m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    return m.group(1) if m else "unknown"


def extract_user(line):
    m = re.search(r'for (invalid user )?(\w+)', line)
    return m.group(2) if m else "unknown"


def severity_from_risk(risk):
    if risk >= 0.85:
        return "CRITICAL"
    if risk >= 0.70:
        return "HIGH"
    if risk >= 0.50:
        return "MEDIUM"
    return "LOW"


# =========================================================
# MITRE MAPPING (IMPORTANT FOR ENTERPRISE SOC)
# =========================================================
def mitre_map(label):
    return {
        "BRUTE_FORCE": ["T1110"],
        "CREDENTIAL_STUFFING": ["T1110.004"],
        "USER_ENUMERATION": ["T1589"],
        "PASSWORD_GUESSING": ["T1110.001"],
        "NORMAL": []
    }.get(label, [])


# =========================================================
# UEBA FEATURE EXTRACTION
# =========================================================
def extract_features(lines):
    failed = 0
    sessions = 0
    logins = 0

    ips = []
    users = []

    for l in lines:
        s = str(l).lower()

        ip = extract_ip(s)
        user = extract_user(s)

        if ip != "unknown":
            ips.append(ip)
        if user != "unknown":
            users.append(user)

        if "failed password" in s or "authentication failure" in s:
            failed += 1

        if "session opened" in s:
            sessions += 1

        if "gdm-password" in s:
            logins += 1

    ip = max(set(ips), key=ips.count) if ips else "unknown"
    user = max(set(users), key=users.count) if users else "unknown"

    return [failed, sessions, logins], ip, user


# =========================================================
# BASELINE ML MODEL (ANOMALY DETECTION)
# =========================================================
print("🔧 Training baseline model...")

with open(LOG_PATH, "r") as f:
    raw = f.readlines()[-1500:]

baseline = [
    extract_features(raw[i:i + WINDOW_SIZE])[0]
    for i in range(0, len(raw), WINDOW_SIZE)
    if len(raw[i:i + WINDOW_SIZE]) == WINDOW_SIZE
]

scaler = StandardScaler()
X_train = scaler.fit_transform(baseline)

model = IsolationForest(contamination=0.08, random_state=42)
model.fit(X_train)

print("✅ SIEM ML engine ready")


# =========================================================
# ALERT DEDUP ENGINE (CRITICAL ENTERPRISE FEATURE)
# =========================================================
def should_alert(ip, user, label):
    key = f"{ip}-{user}-{label}"
    now_t = time.time()

    if key in last_alert_time and now_t - last_alert_time[key] < ALERT_COOLDOWN:
        return False

    last_alert_time[key] = now_t
    return True


# =========================================================
# HYBRID CLASSIFIER (UEBA + RULE + ML FUSION)
# =========================================================
def hybrid_detect(features, ip, user, buffer_lines, ml_score):
    failed, sessions, logins = features
    lines = [str(l).lower() for l in buffer_lines]

    recent_failed = sum("failed password" in l for l in lines)
    session_absent = sessions == 0

    # -------------------------
    # BRUTE FORCE DOMINANT LOGIC (FIXED PRIORITY)
    # -------------------------
    brute_score = failed * 3 + recent_failed * 4

    enum_score = failed * 2 + (6 if session_absent else 0)
    stuffing_score = failed * 2 + (3 if user != "unknown" else 0)

    # -------------------------
    # RULES (ORDER FIXED)
    # -------------------------
    if brute_score >= 10:
        label = "BRUTE_FORCE"
        base = 0.97

    elif stuffing_score >= 6:
        label = "CREDENTIAL_STUFFING"
        base = 0.90

    elif enum_score >= 3:
        label = "USER_ENUMERATION"
        base = 0.82

    elif 3 <= failed < 6:
        label = "PASSWORD_GUESSING"
        base = 0.65

    else:
        label = "NORMAL"
        base = 0.50

    # -------------------------
    # ML FUSION
    # -------------------------
    anomaly = ml_score < -0.22

    risk = base
    if anomaly:
        risk += 0.12
    else:
        risk -= 0.05

    if anomaly and label != "NORMAL":
        risk += 0.10

    risk = max(0.0, min(1.0, risk))

    return label, risk
def sanitize(obj):
    """
    Recursively convert non-JSON-safe types.
    """
    if isinstance(obj, set):
        return list(obj)

    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [sanitize(v) for v in obj]

    return obj

# =========================================================
# SOCKET
# =========================================================
@sio.event
def connect():
    print("✅ Connected to SOC server")

@sio.event
def disconnect():
    print("❌ Disconnected")


def send_alert(alert):
    if sio.connected:
        sio.emit("new_alert", sanitize(alert))


# =========================================================
# CONNECT
# =========================================================
sio.connect("http://localhost:5000")


# =========================================================
# LIVE PIPELINE
# =========================================================
proc = subprocess.Popen(
    ["tail", "-F", LOG_PATH],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("👀 SIEM running...\n")

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
    ml_score = float(model.decision_function(X)[0])

    attack_type, risk = hybrid_detect(features, ip, user, buffer, ml_score)

    case = cases[ip]

    # -------------------------
    # UEBA CASE ENGINE
    # -------------------------
    case["ip"] = ip
    case["user"] = user

    case["event_count"] += 1
    case["failed_auth"] = max(case["failed_auth"], features[0])
    case["sessions"] = features[1]
    case["logins"] = features[2]

    case["unique_users_seen"].add(user)
    case["unique_ips_seen"].add(ip)

    case["failed_rate"] = case["failed_auth"] / max(1, case["event_count"])

    case["first_seen"] = case["first_seen"] or now()
    case["last_seen"] = now()

    case["attack_type"] = attack_type
    case["confidence"] = risk
    case["severity"] = severity_from_risk(risk)
    case["mitre"] = mitre_map(attack_type)

    # -------------------------
    # FINAL ATTACK DECISION
    # -------------------------
    is_attack = ml_score < -0.22 or features[0] >= 5

    if is_attack and should_alert(ip, user, attack_type):

        alert = {
            "id": make_id(f"{ip}-{user}-{line}-{ml_score}"),
            "timestamp": now(),

            "ip": ip,
            "user": user,

            "failed_auth": features[0],

            "severity": case["severity"],
            "attack_type": attack_type,

            "confidence": risk,
            "score": ml_score,

            "mitre": case["mitre"],

            "raw": line,

            "case": sanitize(dict(case))
}

        print("🚨 ALERT:", alert)
        send_alert(alert)

    time.sleep(0.05)