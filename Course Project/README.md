# ITIS 3200 - Secure Password Authentication System

## Project Overview

This project demonstrates the importance of proper password storage and authentication design by comparing a secure and insecure implementation side by side.

## Systems

- **insecure_app.py** - Uses SHA-256 without salts. Vulnerable to dictionary attacks and timing side-channels.
- **secure_app.py** - Uses bcrypt with unique salts and constant-time comparison. Resistant to both attacks.
- **attack_demo.py** - Demonstrates a dictionary attack and timing attack against both systems.

## How to Run

### Requirements
- Python 3.x
- Flask (`pip install flask`)
- bcrypt (`pip install bcrypt`)
- requests (`pip install requests`)

### Step 1: Start the insecure server
```bash
python insecure_app.py
```
Runs on http://localhost:5000

### Step 2: Start the secure server (new terminal)
```bash
python secure_app.py
```
Runs on http://localhost:5001

### Step 3: Run the attack demo (new terminal)
```bash
python attack_demo.py
```

## What the Demo Shows

1. **Dictionary Attack** - SHA-256 cracks all passwords in 0 seconds. bcrypt takes 13+ seconds for just 50 guesses per user.
2. **Timing Attack** - The insecure system leaks more timing information than the secure system, allowing username enumeration.

## Security Mechanisms

- **Salted bcrypt hashing** - Prevents rainbow table attacks and slows brute-force guessing
- **Constant-time comparison** - Prevents timing side-channel attacks that leak whether a username exists

## Detailed Report

### 1. System and Threat Description

#### System Description
The system studied in this project is a simple password authentication service built in Python using the Flask web framework. The system allows users to register accounts and log in with a username and password. When a user registers, the system processes their password through a hashing function and stores the result in a local SQLite database. When a user logs in, the system hashes the submitted password and compares it to the stored value to verify identity. No plaintext passwords are ever stored.

The users of this system are anyone creating an account on a web service. The assets that need protection are the stored password hashes, the existence of user accounts in the database, and the ability to authenticate as a legitimate user. Two versions of the system were built: an insecure version using SHA-256 without salts, and a secure version using bcrypt with unique salts and constant-time comparison.

#### Threat Model
This project focuses on two distinct threats. The first is offline password cracking. In this scenario, an attacker gains access to the stored authentication database through a server breach, database leak, or insider access. Once the attacker has the database, they can attempt to recover original passwords from the stored hashes offline without interacting with the live system. Because the attack is offline, the attacker can make millions of guesses per second using tools running on their own hardware.

The second threat is a timing side-channel attack. An attacker interacting with the login endpoint measures how long the server takes to respond to login attempts. If the server responds faster when a username does not exist than when it does, the attacker can enumerate valid usernames just by measuring response times. This leaks account existence information without requiring database access. The attacker is assumed to have network access to the login endpoint and the ability to send many automated requests.

### 2. Security Mechanism Design

#### Primary Mechanism: Salted bcrypt Hashing
The primary security mechanism is salted password hashing using bcrypt. When a user registers, the system calls bcrypt.gensalt() to generate a unique random salt for that user. The salt is combined with the password and passed to bcrypt.hashpw() before being stored. When a user logs in, the system calls bcrypt.checkpw() to compare the submitted password against the stored hash. The salt is embedded in the stored hash, so no separate salt storage is required.

The salt ensures that even if two users choose the same password, their stored hashes will be different. This prevents attackers from using precomputed rainbow tables to reverse hashes quickly. bcrypt is intentionally slow to compute, meaning each password guess requires significantly more time than a fast hash function like SHA-256. This makes brute-force and dictionary attacks much more expensive.

#### Supporting Mechanism: Constant-Time Comparison
The supporting mechanism is constant-time comparison to defend against the timing side-channel. In the secure implementation, when a user submits a login attempt for a username that does not exist, the system still computes a full bcrypt comparison against a dummy hash before returning a response. This ensures the server takes the same amount of time to respond regardless of whether the username exists. An attacker measuring response times cannot distinguish between valid and invalid usernames.

The dummy hash is computed once at server startup using DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt()). On every failed username lookup, the system calls bcrypt.checkpw(password, DUMMY_HASH) before returning the invalid response. This makes the response time consistent across all inputs.

### 3. Justification: Mechanism vs Threat

Salted bcrypt hashing directly addresses the offline password cracking threat. Without salts, identical passwords produce identical hashes. An attacker with a stolen database can hash common passwords once and compare them to every stored hash in the database at the same time. Salting forces the attacker to compute a separate hash for each user individually, multiplying the computational cost by the number of users.

bcrypt provides the security property of computational hardness. The cost factor built into bcrypt means each hash computation takes a measurable amount of time, around 100 to 300 milliseconds depending on hardware. SHA-256, by contrast, is designed for speed and can compute billions of hashes per second on modern hardware. This difference in computation time is the core property that makes bcrypt appropriate for password storage.

Constant-time comparison addresses the timing side-channel threat. Without this protection, the system provides different response times based on whether a username exists. This leaks the security property of account confidentiality. An attacker who can enumerate valid usernames has a smaller target set for credential stuffing or phishing attacks. By ensuring uniform response time, the system provides no timing oracle that reveals account existence.

### 4. Failure Case: What Breaks If You Get It Wrong

#### Failure Case 1: Unsalted SHA-256 Storage
The insecure implementation stores passwords as plain SHA-256 hashes with no salts. To demonstrate the attack, three test accounts were created with common passwords: alice with password123, bob with letmein, and carol with sunshine. A dictionary attack was run using a list of common passwords. The attack hashes each word in the list using SHA-256 and compares it to every stored hash.

The result was that all three passwords were cracked in 0.00 seconds. SHA-256 is fast enough that checking 10,000 password candidates against the entire database takes essentially no time. This demonstrates that any user choosing a common password has their credential immediately compromised if the database is stolen.

#### Failure Case 2: bcrypt Without Timing Protection
The same dictionary attack was run against the secure database using bcrypt. Checking just 50 password candidates per user took 13.38 seconds. At that rate, exhaustively checking a large wordlist would take hours or days per user, making the attack impractical for strong passwords. This confirms that bcrypt's computational cost is the key property protecting against offline cracking.

For the timing attack, the insecure system showed an average response time difference of 0.0164 seconds between valid and invalid usernames. The secure system reduced this difference to 0.0086 seconds, cutting the timing gap in half. The results confirm that the constant-time comparison is working. In a real network environment with lower baseline latency, the timing difference in the insecure system would be more pronounced and easier to exploit.

These two failure cases together show that secure authentication requires hardening both the storage layer and the behavioral layer. A system using bcrypt correctly but skipping constant-time comparison still leaks account existence. A system using constant-time comparison but storing passwords with SHA-256 is still vulnerable to offline cracking. Both mechanisms are necessary.

