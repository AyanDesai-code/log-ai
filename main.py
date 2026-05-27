import re
from collections import defaultdict

log_file="/var/log/auth.log"

failed_logins = defaultdict(int)

pattern = re.compile(r"failed password.*from (\d+\. \d+\. \d+\ .\d+)")

with open(log_file, "r") as file:
    for line in file:
        match = pattern.search(line)
        if match:
            ip = match.group(1)
            failed_logins[ip]+=1
print("Suspcious IPs:")
for ip, count in failed_logins.items():
    if count > 5:
        print(ip, "->", count, "failed logins")