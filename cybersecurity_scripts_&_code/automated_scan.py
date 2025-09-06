import subprocess
import re
from datetime import datetime

# Mapping ports to follow-up actions
PORT_GUIDE = {
    21: "FTP - Try anonymous login, nmap --script ftp-*",
    22: "SSH - Check banner, ssh-audit, brute force (Hydra) if allowed",
    23: "Telnet - Insecure. Try basic login, grab banner",
    25: "SMTP - VRFY/EXPN users, nmap --script smtp-*",
    53: "DNS - Test zone transfers: dig axfr",
    80: "HTTP - Run Gobuster/Feroxbuster, check headers with curl, try Nikto",
    139: "NetBIOS - Use smbclient, enum4linux, nmap smb-*",
    443: "HTTPS - Same as HTTP, plus sslscan/testssl.sh",
    445: "SMB - enum4linux, smbmap, crackmapexec",
    3306: "MySQL - Try mysql login, nmap mysql-*",
    3389: "RDP - Test with xfreerdp, check for BlueKeep",
    8080: "Alt HTTP - Same as 80, look for admin panels"
}

SKULL_BANNER = r"""
      ______
   .-        -.
  /            \
 |,  .-.  .-.  ,|
 | )(_o/  \o_)( |
 |/     /\     \|
 (_     ^^     _)
  \__|IIIIII|__/
   | \IIIIII/ |
   \          /
    `--------`
     PortMortem
"""

def run_command(cmd):
    print(f"[+] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def run_rustscan(target):
    output = run_command(["rustscan", "-a", target, "--ulimit", "5000"])
    ports = re.findall(r"(\d+)/tcp", output)
    return list(set(map(int, ports)))

def run_nmap(target, ports):
    port_str = ",".join(map(str, ports))
    return run_command(["nmap", "-sV", "-Pn", "-p", port_str, target])

def parse_nmap(output):
    ports = []
    for line in output.splitlines():
        match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if match:
            ports.append((int(match.group(1)), match.group(2)))
    return ports

def run_gobuster(target):
    url = f"http://{target}"
    wordlist = "/usr/share/wordlists/dirb/common.txt"  # adjust if needed
    return run_command(["gobuster", "dir", "-u", url, "-w", wordlist])

def run_dirb(target):
    url = f"http://{target}"
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    return run_command(["dirb", url, wordlist])

def give_advice(ports):
    results = []
    for port, service in ports:
        advice = PORT_GUIDE.get(port, f"Unknown service ({service}), research manually.")
        results.append(f"**Port {port}/tcp ({service})**\n- Suggested next steps: {advice}\n")
    return results

def save_markdown(target, nmap_output, ports, gobuster_out=None, dirb_out=None):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"portmortem_{target}_{timestamp}.md"

    with open(filename, "w") as f:
        f.write(f"```\n{SKULL_BANNER}\n```\n\n")
        f.write(f"# PortMortem Report\n")
        f.write(f"**Target:** {target}\n\n")
        f.write(f"**Scan Time:** {timestamp}\n\n")

        f.write("## Nmap Output\n```\n")
        f.write(nmap_output)
        f.write("\n```\n\n")

        f.write("## Quick Advice\n")
        for entry in give_advice(ports):
            f.write(f"- {entry}\n")

        if gobuster_out:
            f.write("\n## Gobuster Results\n```\n")
            f.write(gobuster_out)
            f.write("\n```\n")

        if dirb_out:
            f.write("\n## Dirb Results\n```\n")
            f.write(dirb_out)
            f.write("\n```\n")

    print(f"[+] Report saved to {filename}")

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")

    # Step 1: RustScan
    open_ports = run_rustscan(target)
    print(f"[+] Open ports found by RustScan: {open_ports}")

    # Step 2: Nmap
    nmap_output = run_nmap(target, open_ports)
    print("\n--- Nmap Output ---\n")
    print(nmap_output)

    # Step 3: Parse ports & advice
    parsed_ports = parse_nmap(nmap_output)
    print("\n--- Quick Advice ---\n")
    for entry in give_advice(parsed_ports):
        print(entry)

    gobuster_out = None
    dirb_out = None

    # Step 4: If web ports open, run web fuzzers
    web_ports = [80, 8080, 443]
    if any(port for port, _ in parsed_ports if port in web_ports):
        print("\n--- Gobuster Results ---\n")
        gobuster_out = run_gobuster(target)
        print(gobuster_out)

        print("\n--- Dirb Results ---\n")
        dirb_out = run_dirb(target)
        print(dirb_out)

    # Step 5: Save markdown report
    save_markdown(target, nmap_output, parsed_ports, gobuster_out, dirb_out)
