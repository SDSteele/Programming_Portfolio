# Remote execution (from your machine to Windows target):
# If WinRM is enabled:
# Invoke-Command -ComputerName TARGET -ScriptBlock { <script above> }

# Lab User Cleanup - PowerShell Edition
# Run in admin PowerShell session

Write-Host "[*] Starting Windows user cleanup..."

# Get all local users except Administrator
$users = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" }

foreach ($u in $users) {
    Write-Host "[+] Disabling account: $($u.Name)"
    Disable-LocalUser -Name $u.Name

    # Uncomment below to delete the account instead
    # Write-Host "[!] Removing account: $($u.Name)"
    # Remove-LocalUser -Name $u.Name
}

Write-Host "[*] Cleanup complete."
