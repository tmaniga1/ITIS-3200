import hashlib
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("insecure_users.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)")
    return conn

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db()
    try:
        conn.execute("INSERT INTO users VALUES (?, ?)", (username, password_hash))
        conn.commit()
        return jsonify({"message": "registered"})
    except:
        return jsonify({"message": "username taken"}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]
    conn = get_db()
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        return jsonify({"message": "invalid"}), 401
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash == row[0]:
        return jsonify({"message": "login successful"})
    return jsonify({"message": "invalid"}), 401

if __name__ == "__main__":
    app.run(port=5000)