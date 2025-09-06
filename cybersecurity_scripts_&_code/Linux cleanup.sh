#!/bin/bash
# Lab User Cleanup - Bash Edition
# Run with: sudo ./cleanup.sh

echo "[*] Starting user cleanup..."

# Get all non-system accounts (UID >= 1000)
for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
    if [[ "$user" != "root" ]]; then
        echo "[+] Locking account: $user"
        usermod -L "$user"
        usermod -s /usr/sbin/nologin "$user"

        echo "[+] Removing sudo rights (if any): $user"
        gpasswd -d "$user" sudo 2>/dev/null

        # Uncomment below to delete accounts + home dirs
        # echo "[!] Deleting account: $user"
        # userdel -r "$user"
    fi
done

echo "[*] Cleanup complete."
