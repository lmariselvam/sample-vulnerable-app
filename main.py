# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # Added for safe evaluation

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # Fixed insecure deserialization of untrusted data (Issue 5)
    # Using ast.literal_eval for safe evaluation of literals
    try:
        return ast.literal_eval(blob.decode())
    except (ValueError, SyntaxError):
        raise ValueError("Invalid or unsafe input")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice"))  # Fixed SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"{'key': 'value'}")  # Example of safe literal
    except Exception as e:
        print("Deserialization error:", e)

# Fixed: Unsanitized input is no longer run as code in the deserialize_blob function.
# The ast.literal_eval() function is used instead of pickle.loads() to safely evaluate literals.
# This prevents arbitrary code execution while still allowing safe deserialization of basic data types.