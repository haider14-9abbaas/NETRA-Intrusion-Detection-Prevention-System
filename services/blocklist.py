import json
import os
from typing import List

PATH = "data/blocked_ips.json"

def load_blocked_ips() -> List[str]:
    if not os.path.exists(PATH):
        return []
    with open(PATH, "r") as f:
        return json.load(f)

def save_blocked_ips(ips: List[str]):
    os.makedirs("data", exist_ok=True)
    with open(PATH, "w") as f:
        json.dump(sorted(set(ips)), f, indent=2)

def block_ip(ip: str):
    ips = load_blocked_ips()
    if ip not in ips:
        ips.append(ip)
    save_blocked_ips(ips)

def unblock_ip(ip: str):
    ips = load_blocked_ips()
    ips = [x for x in ips if x != ip]
    save_blocked_ips(ips)
