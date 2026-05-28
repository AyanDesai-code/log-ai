import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import requests
import datetime

log_path = "/var/log/auth.log"

rows = []

with open(log_path, "r") as f:
    for line in f:
        rows.append({
            "failed_auth": 1 if "Failed password" in line else 0,
            "password_changes": 1 if "password for" in line and "changed" in line else 0,
            "sessions": 1 if "session opened" in line else 0,
            "logins": 1 if "gdm-password" in line else 0
        })

df = pd.DataFrame(rows)

window_size = 30
df = df.groupby(df.index // window_size).sum()

scaler = StandardScaler()
X = scaler.fit_transform(df)

model = IsolationForest(contamination=0.2, random_state=42)
df["anomaly"] = model.fit_predict(X)

print(df)

for idx, row in df.iterrows():
    if row["anomaly"] == -1:

        alert = {
            "time": str(datetime.datetime.now()),
            "type": "ANOMALY DETECTED",
            "details": f"window={idx} failed={row['failed_auth']} sessions={row['sessions']} logins={row['logins']}"
        }

        try:
            requests.post("http://127.0.0.1:5000/push_alert", json=alert)
        except Exception as e:
            print("Failed to send alert:", e)