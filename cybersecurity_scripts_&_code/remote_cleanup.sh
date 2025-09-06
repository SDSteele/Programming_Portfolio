# (run from Kali)
# How to Use
# Linux target:
# ./remote_cleanup.sh 192.168.1.50 linux root

# Windows target (with Evil-WinRM):
# ./remote_cleanup.sh 192.168.1.75 windows Administrator



#!/bin/bash
# Remote Cleanup Launcher
# Use: ./remote_cleanup.sh <target_ip> <os_type> <username>

TARGET_IP=$1
OS_TYPE=$2   # linux or windows
USER=$3

if [ -z "$TARGET_IP" ] || [ -z "$OS_TYPE" ] || [ -z "$USER" ]; then
    echo "Usage: $0 <target_ip> <os_type: linux|windows> <username>"
    exit 1
fi

echo "[*] Starting cleanup on $TARGET_IP ($OS_TYPE)..."

# -----------------------
# Linux Target Section
# -----------------------
if [ "$OS_TYPE" == "linux" ]; then
    ssh -tt ${USER}@${TARGET_IP} "bash -" <<'EOF'
        echo "[*] Running Linux user cleanup..."
        for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
            if [[ "$user" != "root" ]]; then
                echo "[+] Locking account: $user"
                usermod -L "$user"
                usermod -s /usr/sbin/nologin "$user"
                echo "[+] Removing sudo rights (if any): $user"
                gpasswd -d "$user" sudo 2>/dev/null
                # Uncomment below to delete instead of lock
                # userdel -r "$user"
            fi
        done
        echo "[*] Linux cleanup complete."
EOF
fi

# -----------------------
# Windows Target Section
# -----------------------
if [ "$OS_TYPE" == "windows" ]; then
    echo "[*] Running Windows user cleanup..."
    # If using evil-winrm
    evil-winrm -i $TARGET_IP -u $USER -p 'PASSWORD' -s /tmp <<'EOF'
        $users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }
        foreach ($u in $users) {
            Write-Host "[+] Disabling account: $($u.Name)"
            Disable-LocalUser -Name $u.Name
            # Uncomment to remove
            # Remove-LocalUser -Name $u.Name
        }
        Write-Host "[*] Windows cleanup complete."
EOF
fi

echo "[*] Cleanup done for $TARGET_IP."





