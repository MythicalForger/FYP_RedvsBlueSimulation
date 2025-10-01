import time
import os

LOG_FILE = "/app/logs/ai.log"

def check_line(line):
    suspicious_keywords = ["delete", "system32", "config", "password"]
    for kw in suspicious_keywords:
        if kw in line.lower():
            return True
    return False

print("[BLUE] Monitoring logs...")

# Ensure file exists
open(LOG_FILE, "a").close()

# Start monitoring
with open(LOG_FILE, "r") as f:
    f.seek(0, os.SEEK_END)  # go to end of file
    while True:
        line = f.readline()
        if line:
            print(f"[BLUE] Log: {line.strip()}")
            if check_line(line):
                print("🚨 [ALERT] Suspicious activity detected!")
        else:
            time.sleep(1)
