#How to Use
# Save as cleanup.py, make executable:, chmod +x cleanup.py

# Run with root: sudo ./cleanup.py

# Choose an action: lock → locks all users
# - remove_sudo → strips admin rights
# - delete → deletes accounts and home dirs
# - skip → no action

#!/usr/bin/env python3
"""
Lab User Cleanup Script
-----------------------
Automates removal or restriction of unauthorized users in a lab environment.
Run as root: sudo python3 cleanup.py
"""

import os
import subprocess

def is_root():
    """Ensure script runs as root"""
    return os.geteuid() == 0

def list_users():
    """List non-system users"""
    users = []
    with open("/etc/passwd") as f:
        for line in f:
            parts = line.split(":")
            username = parts[0]
            uid = int(parts[2])
            if uid >= 1000 and username != "nobody":
                users.append(username)
    return users

def lock_user(user):
    subprocess.run(["usermod", "-L", user])
    subprocess.run(["usermod", "-s", "/usr/sbin/nologin", user])
    print(f"[+] Locked account: {user}")

def remove_sudo(user):
    subprocess.run(["gpasswd", "-d", user, "sudo"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[+] Removed {user} from sudo group")

def delete_user(user, remove_home=False):
    cmd = ["userdel"]
    if remove_home:
        cmd.append("-r")
    cmd.append(user)
    subprocess.run(cmd)
    print(f"[+] Deleted account: {user}")

def main():
    if not is_root():
        print("[-] Must run as root")
        return

    users = list_users()
    if not users:
        print("[*] No normal users found")
        return

    print("[*] Found user accounts:")
    for u in users:
        print(f" - {u}")

    action = input("\nChoose action for ALL users (lock/remove_sudo/delete/skip): ").strip().lower()
    for u in users:
        if u == "root":
            continue
        if action == "lock":
            lock_user(u)
        elif action == "remove_sudo":
            remove_sudo(u)
        elif action == "delete":
            delete_user(u, remove_home=True)
        elif action == "skip":
            print(f"[*] Skipped {u}")
        else:
            print("[-] Invalid choice")
            break

if __name__ == "__main__":
    main()
