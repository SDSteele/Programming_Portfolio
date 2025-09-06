# Method 1: One-liner with SSH and Python
# You can pipe the script directly into Python on the remote box:

ssh user@target "python3 -" << 'EOF'
import os, subprocess

def list_users():
    users = []
    with open("/etc/passwd") as f:
        for line in f:
            parts = line.split(":")
            username = parts[0]
            uid = int(parts[2])
            if uid >= 1000 and username != "nobody":
                users.append(username)
    return users

def lock_user(u):
    subprocess.run(["usermod","-L",u])
    subprocess.run(["usermod","-s","/usr/sbin/nologin",u])
    print(f"[+] Locked {u}")

for u in list_users():
    if u != "root":
        lock_user(u)
EOF

# Method 2: Use a Python “remote executor” on Kali
# If you want something more reusable, you can have a Python controller on Kali that connects with SSH, run cleanup code, and shows results

#!/usr/bin/env python3
"""
Remote Cleanup Executor
-----------------------
Runs user cleanup Python code on a remote system over SSH
without uploading files.
"""

import paramiko

REMOTE_CODE = r"""
import os, subprocess

def list_users():
    users = []
    with open("/etc/passwd") as f:
        for line in f:
            parts = line.split(":")
            username = parts[0]
            uid = int(parts[2])
            if uid >= 1000 and username != "nobody":
                users.append(username)
    return users

def lock_user(u):
    subprocess.run(["usermod","-L",u])
    subprocess.run(["usermod","-s","/usr/sbin/nologin",u])
    print(f"[+] Locked {u}")

for u in list_users():
    if u != "root":
        lock_user(u)
"""

def run_remote(host, user, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=password)

    stdin, stdout, stderr = ssh.exec_command(f"python3 -c \"{REMOTE_CODE}\"")

    print(stdout.read().decode())
    print(stderr.read().decode())

    ssh.close()

if __name__ == "__main__":
    target = input("Target host/IP: ")
    user = input("SSH username: ")
    password = input("SSH password: ")
    run_remote(target, user, password)


