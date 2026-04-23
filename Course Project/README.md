\# ITIS 3200 - Secure Password Authentication System



\## Project Overview

This project demonstrates the importance of proper password storage and authentication design by comparing a secure and insecure implementation side by side.



\## Systems

\- \*\*insecure\_app.py\*\* - Uses SHA-256 without salts. Vulnerable to dictionary attacks and timing side-channels.

\- \*\*secure\_app.py\*\* - Uses bcrypt with unique salts and constant-time comparison. Resistant to both attacks.

\- \*\*attack\_demo.py\*\* - Demonstrates a dictionary attack and timing attack against both systems.



\## How to Run



\### Requirements



\### Step 1: Start the insecure server



Runs on http://localhost:5000



\### Step 2: Start the secure server (new terminal)



Runs on http://localhost:5001



\### Step 3: Run the attack demo (new terminal)



\## What the Demo Shows

1\. \*\*Dictionary Attack\*\* - SHA-256 cracks all passwords in 0 seconds. bcrypt takes 13+ seconds for just 50 guesses per user.

2\. \*\*Timing Attack\*\* - The insecure system leaks more timing information than the secure system, allowing username enumeration.



\## Security Mechanisms

\- \*\*Salted bcrypt hashing\*\* - Prevents rainbow table attacks and slows brute-force guessing

\- \*\*Constant-time comparison\*\* - Prevents timing side-channel attacks that leak whether a username exists

