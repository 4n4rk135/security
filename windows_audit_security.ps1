# Windows Security Audit Script
# Comprehensive security audit for Windows systems
#
# Usage: powershell -ExecutionPolicy Bypass -File windows_audit_security.ps1
# Or:     .\windows_audit_security.ps1
#
# Requires    : Administrator privileges for full audit
# Created  by : aguskb

#Requires -Version 5.1

param(
    [switch]$ExportReport,
    [switch]$Silent,
    [string]$OutputPath = "$env:USERPROFILE\Desktop"
)

# ============================================
# Configuration
# ============================================
$Script:ReportData = @()
$Script:OverallScore = 0
$Script:TotalChecks = 0

# Colors for console output
$Colors = @{
    Red = "#FF4444"
    Green = "#44FF44"
    Yellow = "#FFFF44"
    Blue = "#4488FF"
}

# ============================================
# Helper Functions
# ============================================
function Write-AuditLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "Blue"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "[$timestamp] [$Level] $Message"
    
    if (-not $Silent) {
        switch ($Level) {
            "PASS" { $colorCode = "[32m" }  # Green
            "FAIL" { $colorCode = "[31m" }  # Red
            "WARN" { $colorCode = "[33m" }  # Yellow
            "INFO" { $colorCode = "[36m" }  # Cyan
            default { $colorCode = "[37m" } # White
        }
        Write-Host "$colorCode$formattedMessage[0m"
    }
}

function Add-CheckResult {
    param(
        [string]$Category,
        [string]$CheckName,
        [string]$Status,
        [string]$Details,
        [string]$Recommendation = ""
    )
    
    $Script:ReportData += [PSCustomObject]@{
        Category = $Category
        CheckName = $CheckName
        Status = $Status
        Details = $Details
        Recommendation = $Recommendation
    }
    
    $Script:TotalChecks++
    if ($Status -eq "PASS") {
        $Script:OverallScore++
    }
}

function Get-IsAdmin 
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================
# Banner
# ============================================
function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "          WINDOWS SECURITY AUDIT SCRIPT v1.0              " -ForegroundColor Cyan
    Write-Host "          Comprehensive Security Assessment               " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================
# 1. Windows Firewall Status
# ============================================
function Test-WindowsFirewall {
    Write-AuditLog "Checking Windows Firewall status..." "INFO"
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        
        $allEnabled = $true
        $profileStatus = @{}
        
        foreach ($profile in $profiles) {
            $profileStatus[$profile.Name] = $profile.Enabled
            if (-not $profile.Enabled) {
                $allEnabled = $false
            }
        }
        
        $status = if ($allEnabled) { "PASS" } else { "FAIL" }
        $details = "Domain: $($profileStatus['Domain']), Private: $($profileStatus['Private']), Public: $($profileStatus['Public'])"
        
        if ($allEnabled) {
            $recommendation = "Firewall is enabled on all profiles."
        } else {
            $recommendation = "Enable Windows Firewall on all profiles: Set-NetFirewallProfile -Profile All -Enabled True"
        }
        
        Add-CheckResult -Category "Firewall" -CheckName "Windows Firewall Status" -Status $status -Details $details -Recommendation $recommendation
        
        Write-AuditLog "Firewall check complete: $status" $status
        
        # Check firewall rules
        $inboundRules = Get-NetFirewallRule | Where-Object { $_.Direction -eq "Inbound" -and $_.Enabled -eq $true }
        $criticalRules = $inboundRules | Where-Object { $_.Action -eq "Allow" -and $_.Profile -eq "Any" }
        
        if ($criticalRules.Count -gt 10) {
            Add-CheckResult -Category "Firewall" -CheckName "Critical Inbound Rules" -Status "WARN" -Details "Found $($criticalRules.Count) critical allow rules" -Recommendation "Review and remove unnecessary inbound rules"
        } else {
            Add-CheckResult -Category "Firewall" -CheckName "Critical Inbound Rules" -Status "PASS" -Details "Found $($criticalRules.Count) critical allow rules"
        }
        
    } catch {
        Write-AuditLog "Error checking firewall: $_" "FAIL"
        Add-CheckResult -Category "Firewall" -CheckName "Windows Firewall Status" -Status "FAIL" -Details "Unable to retrieve firewall status: $_"
    }
}

# ============================================
# 2. Windows Update Status
# ============================================
function Test-WindowsUpdate {
    Write-AuditLog "Checking Windows Update status..." "INFO"
    
    try {
        # Check for pending updates
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        $pendingUpdates = $searchResult.Updates.Count
        
        if ($pendingUpdates -eq 0) {
            Add-CheckResult -Category "Updates" -CheckName "Pending Updates" -Status "PASS" -Details "No pending updates" -Recommendation "Continue regular update checks"
        } elseif ($pendingUpdates -lt 5) {
            Add-CheckResult -Category "Updates" -CheckName "Pending Updates" -Status "WARN" -Details "$pendingUpdates pending updates" -Recommendation "Install pending updates: Install-Module PSWindowsUpdate"
        } else {
            Add-CheckResult -Category "Updates" -CheckName "Pending Updates" -Status "FAIL" -Details "$pendingUpdates pending updates - CRITICAL" -Recommendation "Immediate update installation required"
        }
        
        # Check automatic update settings
        $autoUpdate = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue).AUOptions
        
        if ($autoUpdate -ge 4) {
            Add-CheckResult -Category "Updates" -CheckName "Automatic Updates" -Status "PASS" -Details "Automatic updates enabled (Level: $autoUpdate)"
        } else {
            Add-CheckResult -Category "Updates" -CheckName "Automatic Updates" -Status "FAIL" -Details "Automatic updates disabled or not configured" -Recommendation "Enable automatic updates via Group Policy or registry"
        }
        
        # Check last update date
        $lastUpdate = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install" -ErrorAction SilentlyContinue).LastSuccessTime
        
        if ($lastUpdate) {
            $daysSinceUpdate = ((Get-Date) - [DateTime]::Parse($lastUpdate)).Days
            if ($daysSinceUpdate -le 7) {
                Add-CheckResult -Category "Updates" -CheckName "Last Update Check" -Status "PASS" -Details "Last updated $daysSinceUpdate days ago"
            } elseif ($daysSinceUpdate -le 30) {
                Add-CheckResult -Category "Updates" -CheckName "Last Update Check" -Status "WARN" -Details "Last updated $daysSinceUpdate days ago" -Recommendation "Check for updates"
            } else {
                Add-CheckResult -Category "Updates" -CheckName "Last Update Check" -Status "FAIL" -Details "Last updated $daysSinceUpdate days ago - CRITICAL" -Recommendation "Immediate update required"
            }
        } else {
            Add-CheckResult -Category "Updates" -CheckName "Last Update Check" -Status "FAIL" -Details "No update history found"
        }
        
    } catch {
        Write-AuditLog "Error checking Windows Update: $_" "WARN"
        Add-CheckResult -Category "Updates" -CheckName "Windows Update Status" -Status "WARN" -Details "Unable to fully check update status: $_"
    }
}

# ============================================
# 3. Antivirus Status
# ============================================
function Test-AntivirusStatus {
    Write-AuditLog "Checking Antivirus status..." "INFO"
    
    try {
        $antivirus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        
        if ($antivirus) {
            $realTimeProtection = $antivirus.RealTimeProtectionEnabled
            $antivirusEnabled = $antivirus.AntivirusEnabled
            $antispywareEnabled = $antivirus.AntispywareEnabled
            $behaviorMonitor = $antivirus.BehaviorMonitorEnabled
            
            if ($antivirusEnabled -and $realTimeProtection) {
                Add-CheckResult -Category "Antivirus" -CheckName "Windows Defender Status" -Status "PASS" -Details "Antivirus enabled, Real-time protection active"
            } else {
                Add-CheckResult -Category "Antivirus" -CheckName "Windows Defender Status" -Status "FAIL" -Details "Antivirus: $antivirusEnabled, RTProtection: $realTimeProtection" -Recommendation "Enable Windows Defender and real-time protection"
            }
            
            # Check signature age
            $signatureAge = $antivirus.AntivirusSignatureAge
            if ($signatureAge -le 7) {
                Add-CheckResult -Category "Antivirus" -CheckName "Antivirus Signatures" -Status "PASS" -Details "Signatures updated $signatureAge days ago"
            } elseif ($signatureAge -le 14) {
                Add-CheckResult -Category "Antivirus" -CheckName "Antivirus Signatures" -Status "WARN" -Details "Signatures outdated: $signatureAge days" -Recommendation "Update antivirus definitions"
            } else {
                Add-CheckResult -Category "Antivirus" -CheckName "Antivirus Signatures" -Status "FAIL" -Details "Signatures severely outdated: $signatureAge days" -Recommendation "Immediate definition update required"
            }
            
            # Check behavior monitor
            if ($behaviorMonitor) {
                Add-CheckResult -Category "Antivirus" -CheckName "Behavior Monitoring" -Status "PASS" -Details "Behavior monitoring enabled"
            } else {
                Add-CheckResult -Category "Antivirus" -CheckName "Behavior Monitoring" -Status "FAIL" -Details "Behavior monitoring disabled" -Recommendation "Enable behavior monitoring"
            }
            
        } else {
            # Check for third-party antivirus
            $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
            
            if ($avProducts) {
                foreach ($av in $avProducts) {
                    Add-CheckResult -Category "Antivirus" -CheckName "Third-party Antivirus" -Status "PASS" -Details "Installed: $($av.displayName)"
                }
            } else {
                Add-CheckResult -Category "Antivirus" -CheckName "Antivirus Status" -Status "FAIL" -Details "No antivirus detected" -Recommendation "Install antivirus software immediately"
            }
        }
        
    } catch {
        Write-AuditLog "Error checking antivirus: $_" "WARN"
        Add-CheckResult -Category "Antivirus" -CheckName "Antivirus Status" -Status "WARN" -Details "Unable to check antivirus status"
    }
}

# ============================================
# 4. User Account Security
# ============================================
function Test-UserAccountSecurity {
    Write-AuditLog "Checking user account security..." "INFO"
    
    try {
        # Check for disabled guest account
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guestAccount -and $guestAccount.Enabled) {
            Add-CheckResult -Category "Accounts" -CheckName "Guest Account" -Status "FAIL" -Details "Guest account is enabled" -Recommendation "Disable guest account: Disable-LocalUser -Name Guest"
        } else {
            Add-CheckResult -Category "Accounts" -CheckName "Guest Account" -Status "PASS" -Details "Guest account is disabled"
        }
        
        # Check for empty passwords
        $usersWithEmptyPasswords = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false }
        if ($usersWithEmptyPasswords) {
            $userNames = ($usersWithEmptyPasswords | ForEach-Object { $_.Name }) -join ", "
            Add-CheckResult -Category "Accounts" -CheckName "Empty Passwords" -Status "FAIL" -Details "Users with empty passwords: $userNames" -Recommendation "Require passwords for all accounts"
        } else {
            Add-CheckResult -Category "Accounts" -CheckName "Empty Passwords" -Status "PASS" -Details "No accounts with empty passwords"
        }
        
        # Check password policy
        $passwordPolicy = net accounts 2>&1
        
        if ($passwordPolicy -match "Minimum password length.*?(\d+)") {
            $minLength = [int]$matches[1]
            if ($minLength -ge 8) {
                Add-CheckResult -Category "Accounts" -CheckName "Password Length Policy" -Status "PASS" -Details "Minimum password length: $minLength"
            } else {
                Add-CheckResult -Category "Accounts" -CheckName "Password Length Policy" -Status "FAIL" -Details "Minimum password length: $minLength (too short)" -Recommendation "Increase minimum password length to 8+ characters"
            }
        }
        
        # Check admin accounts
        $adminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($adminUsers) {
            $adminCount = $adminUsers.Count
            if ($adminCount -le 3) {
                Add-CheckResult -Category "Accounts" -CheckName "Administrator Accounts" -Status "PASS" -Details "Number of admin accounts: $adminCount"
            } else {
                Add-CheckResult -Category "Accounts" -CheckName "Administrator Accounts" -Status "WARN" -Details "Number of admin accounts: $adminCount" -Recommendation "Review and reduce admin accounts"
            }
        }
        
        # Check last logon for all users
        $allUsers = Get-LocalUser
        $inactiveUsers = $allUsers | Where-Object { $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) }
        
        if ($inactiveUsers) {
            $inactiveNames = ($inactiveUsers | ForEach-Object { $_.Name }) -join ", "
            Add-CheckResult -Category "Accounts" -CheckName "Inactive Accounts" -Status "WARN" -Details "Accounts inactive >90 days: $inactiveNames" -Recommendation "Disable or remove inactive accounts"
        } else {
            Add-CheckResult -Category "Accounts" -CheckName "Inactive Accounts" -Status "PASS" -Details "No inactive accounts found"
        }
        
    } catch {
        Write-AuditLog "Error checking user accounts: $_" "WARN"
    }
}

# ============================================
# 5. Open Ports Analysis
# ============================================
function Test-OpenPorts {
    Write-AuditLog "Checking open ports..." "INFO"
    
    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalPort
        
        $listeningPorts = $connections | Select-Object -ExpandProperty LocalPort -Unique
        
        # Check for dangerous ports
        $dangerousPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)
        $foundDangerous = @()
        
        foreach ($port in $listeningPorts) {
            if ($dangerousPorts -contains $port) {
                $foundDangerous += $port
            }
        }
        
        if ($foundDangerous) {
            Add-CheckResult -Category "Network" -CheckName "Dangerous Ports" -Status "WARN" -Details "Open dangerous ports: $($foundDangerous -join ', ')" -Recommendation "Review and close unnecessary ports"
        } else {
            Add-CheckResult -Category "Network" -CheckName "Dangerous Ports" -Status "PASS" -Details "No dangerous ports found open"
        }
        
        # Check for RDP
        if (3389 -in $listeningPorts) {
            Add-CheckResult -Category "Network" -CheckName "Remote Desktop (RDP)" -Status "WARN" -Details "RDP port 3389 is open" -Recommendation "Disable RDP if not required or use VPN"
        }
        
        # Check for SMB
        if (445 -in $listeningPorts) {
            Add-CheckResult -Category "Network" -CheckName "SMB/CIFS" -Status "WARN" -Details "SMB port 445 is open" -Recommendation "Disable SMB if not required or restrict to internal networks"
        }
        
        # Total open ports
        $portCount = $listeningPorts.Count
        if ($portCount -le 20) {
            Add-CheckResult -Category "Network" -CheckName "Total Open Ports" -Status "PASS" -Details "Open ports: $portCount"
        } else {
            Add-CheckResult -Category "Network" -CheckName "Total Open Ports" -Status "WARN" -Details "Open ports: $portCount (high)" -Recommendation "Review running services"
        }
        
    } catch {
        Write-AuditLog "Error checking open ports: $_" "WARN"
    }
}

# ============================================
# 6. Running Services
# ============================================
function Test-RunningServices {
    Write-AuditLog "Checking running services..." "INFO"
    
    try {
        $runningServices = Get-Service | Where-Object { $_.Status -eq "Running" }
        
        # Check for unnecessary services
        $dangerousServices = @(
            "TelnetService",
            "TlntSvr",
            "FTPService",
            "FTPSVC",
            "RemoteRegistry",
            "WinRM",
            "SNMPService",
            "SNMPTrap"
        )
        
        $runningDangerous = @()
        foreach ($svc in $dangerousServices) {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                $runningDangerous += $svc
            }
        }
        
        if ($runningDangerous) {
            Add-CheckResult -Category "Services" -CheckName "Dangerous Services" -Status "FAIL" -Details "Running dangerous services: $($runningDangerous -join ', ')" -Recommendation "Stop and disable unnecessary services"
        } else {
            Add-CheckResult -Category "Services" -CheckName "Dangerous Services" -Status "PASS" -Details "No dangerous services running"
        }
        
        # Check Remote Registry
        $remoteRegistry = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        if ($remoteRegistry -and $remoteRegistry.Status -eq "Running") {
            Add-CheckResult -Category "Services" -CheckName "Remote Registry" -Status "FAIL" -Details "Remote Registry is running" -Recommendation "Disable: Set-Service -Name RemoteRegistry -StartupType Disabled"
        } else {
            Add-CheckResult -Category "Services" -CheckName "Remote Registry" -Status "PASS" -Details "Remote Registry is disabled"
        }
        
        # Total services
        $serviceCount = $runningServices.Count
        if ($serviceCount -le 80) {
            Add-CheckResult -Category "Services" -CheckName "Total Running Services" -Status "PASS" -Details "Running services: $serviceCount"
        } else {
            Add-CheckResult -Category "Services" -CheckName "Total Running Services" -Status "WARN" -Details "Running services: $serviceCount (high)" -Recommendation "Review and disable unnecessary services"
        }
        
    } catch {
        Write-AuditLog "Error checking services: $_" "WARN"
    }
}

# ============================================
# 7. Security Event Log Settings
# ============================================
function Test-EventLogSecurity {
    Write-AuditLog "Checking event log settings..." "INFO"
    
    try {
        $logs = @("Security", "System", "Application")
        
        foreach ($logName in $logs) {
            $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
            
            if ($log) {
                $maxSizeGB = [math]::Round($log.FileSize / 1GB, 2)
                $retentionDays = switch ($log.LogMode) {
                    "Circular" { "Continuous" }
                    "Size" { "By size" }
                    "After" { "Days-based" }
                    default { "Unknown" }
                }
                
                # Check Security log size (should be at least 100MB)
                if ($logName -eq "Security" -and $maxSizeGB -lt 0.1) {
                    Add-CheckResult -Category "Logging" -CheckName "$logName Log Size" -Status "WARN" -Details "Size: $maxSizeGB GB - Consider increasing" -Recommendation "Increase Security log size to at least 100MB"
                } elseif ($maxSizeGB -gt 0) {
                    Add-CheckResult -Category "Logging" -CheckName "$logName Log Size" -Status "PASS" -Details "Size: $maxSizeGB GB"
                }
                
                # Check if log is enabled
                if ($log.IsEnabled) {
                    Add-CheckResult -Category "Logging" -CheckName "$logName Log Enabled" -Status "PASS" -Details "$logName logging enabled"
                } else {
                    Add-CheckResult -Category "Logging" -CheckName "$logName Log Enabled" -Status "FAIL" -Details "$logName logging disabled" -Recommendation "Enable $logName logging"
                }
            }
        }
        
        # Check for audit policy
        $auditPolicy = auditpol /get /category:* 2>&1
        
        if ($auditPolicy -match "Logon\s+Success and Failure") {
            Add-CheckResult -Category "Logging" -CheckName "Logon Audit Policy" -Status "PASS" -Details "Logon auditing enabled"
        } else {
            Add-CheckResult -Category "Logging" -CheckName "Logon Audit Policy" -Status "FAIL" -Details "Logon auditing not configured" -Recommendation "Enable logon auditing: auditpol /set /subcategory:Logon /success:enable /failure:enable"
        }
        
    } catch {
        Write-AuditLog "Error checking event logs: $_" "WARN"
    }
}

# ============================================
# 8. BitLocker Status
# ============================================
function Test-BitLockerStatus {
    Write-AuditLog "Checking BitLocker encryption..." "INFO"
    
    try {
        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        
        if ($volumes) {
            $unencryptedVolumes = $volumes | Where-Object { $_.ProtectionStatus -eq "Off" }
            
            if ($unencryptedVolumes) {
                $volNames = ($unencryptedVolumes | ForEach-Object { $_.MountPoint }) -join ", "
                Add-CheckResult -Category "Encryption" -CheckName "BitLocker Status" -Status "FAIL" -Details "Unencrypted volumes: $volNames" -Recommendation "Enable BitLocker on all volumes"
            } else {
                Add-CheckResult -Category "Encryption" -CheckName "BitLocker Status" -Status "PASS" -Details "All volumes encrypted"
            }
            
            # Check for TPM
            $tpmEnabled = $volumes | Where-Object { $_.TpmProtectorStatus -eq "Enabled" }
            if ($tpmEnabled) {
                Add-CheckResult -Category "Encryption" -CheckName "TPM Protection" -Status "PASS" -Details "TPM protection enabled"
            } else {
                Add-CheckResult -Category "Encryption" -CheckName "TPM Protection" -Status "WARN" -Details "TPM protection not enabled" -Recommendation "Enable TPM for enhanced security"
            }
            
        } else {
            Add-CheckResult -Category "Encryption" -CheckName "BitLocker Status" -Status "WARN" -Details "BitLocker not available or not configured"
        }
        
    } catch {
        Add-CheckResult -Category "Encryption" -CheckName "BitLocker Status" -Status "WARN" -Details "Unable to check BitLocker status"
    }
}

# ============================================
# 9. UAC Status
# ============================================
function Test-UACStatus {
    Write-AuditLog "Checking UAC settings..." "INFO"
    
    try {
        $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
        
        if ($uacEnabled -eq 1) {
            Add-CheckResult -Category "System" -CheckName "UAC Status" -Status "PASS" -Details "User Account Control is enabled"
        } else {
            Add-CheckResult -Category "System" -CheckName "UAC Status" -Status "FAIL" -Details "UAC is disabled" -Recommendation "Enable UAC: Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 1"
        }
        
        # Check admin approval mode
        $adminApproval = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").FilterAdministratorToken
        if ($adminApproval -eq 1) {
            Add-CheckResult -Category "System" -CheckName "Admin Approval Mode" -Status "PASS" -Details "Admin Approval Mode enabled"
        } else {
            Add-CheckResult -Category "System" -CheckName "Admin Approval Mode" -Status "WARN" -Details "Admin Approval Mode disabled"
        }
        
        # Check consent prompt behavior
        $consentPrompt = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").ConsentPromptBehaviorAdmin
        if ($consentPrompt -ge 1) {
            Add-CheckResult -Category "System" -CheckName "Admin Consent Prompt" -Status "PASS" -Details "Admin consent prompt configured (Level: $consentPrompt)"
        } else {
            Add-CheckResult -Category "System" -CheckName "Admin Consent Prompt" -Status "FAIL" -Details "No admin consent prompt" -Recommendation "Enable admin consent prompts"
        }
        
    } catch {
        Write-AuditLog "Error checking UAC: $_" "WARN"
    }
}

# ============================================
# 10. Remote Desktop Settings
# ============================================
function Test-RemoteDesktopSettings {
    Write-AuditLog "Checking Remote Desktop settings..." "INFO"
    
    try {
        $rdpEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
        
        if ($rdpEnabled -eq 1) {
            Add-CheckResult -Category "Remote" -CheckName "Remote Desktop" -Status "PASS" -Details "RDP is disabled"
        } else {
            Add-CheckResult -Category "Remote" -CheckName "Remote Desktop" -Status "WARN" -Details "RDP is enabled" -Recommendation "Disable RDP if not required"
            
            # Check NLA
            $nlaEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication
            if ($nlaEnabled -eq 1) {
                Add-CheckResult -Category "Remote" -CheckName "Network Level Authentication" -Status "PASS" -Details "NLA is required for RDP"
            } else {
                Add-CheckResult -Category "Remote" -CheckName "Network Level Authentication" -Status "FAIL" -Details "NLA is not required" -Recommendation "Enable NLA: Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
            }
        }
        
        # Check WinRM
        $winrmStatus = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($winrmStatus -and $winrmStatus.Status -eq "Running") {
            Add-CheckResult -Category "Remote" -CheckName "Windows Remote Management" -Status "WARN" -Details "WinRM is running" -Recommendation "Disable if not required"
        } else {
            Add-CheckResult -Category "Remote" -CheckName "Windows Remote Management" -Status "PASS" -Details "WinRM is not running"
        }
        
    } catch {
        Write-AuditLog "Error checking RDP settings: $_" "WARN"
    }
}

# ============================================
# 11. SMB Configuration
# ============================================
function Test-SMBConfiguration {
    Write-AuditLog "Checking SMB configuration..." "INFO"
    
    try {
        # Check SMBv1
        $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
        
        if ($smb1 -eq "Disabled") {
            Add-CheckResult -Category "Network" -CheckName "SMBv1 Protocol" -Status "PASS" -Details "SMBv1 is disabled"
        } else {
            Add-CheckResult -Category "Network" -CheckName "SMBv1 Protocol" -Status "FAIL" -Details "SMBv1 is enabled (vulnerable)" -Recommendation "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        }
        
        # Check SMBv2/3
        $smb2 = (Get-SmbServerConfiguration).EnableSMB2Protocol
        if ($smb2) {
            Add-CheckResult -Category "Network" -CheckName "SMBv2/v3 Protocol" -Status "PASS" -Details "SMBv2/v3 enabled"
        } else {
            Add-CheckResult -Category "Network" -CheckName "SMBv2/v3 Protocol" -Status "WARN" -Details "SMBv2/v3 disabled"
        }
        
        # Check SMB signing
        $smbSigning = (Get-SmbServerConfiguration).RequireSecuritySignature
        if ($smbSigning) {
            Add-CheckResult -Category "Network" -CheckName "SMB Signing" -Status "PASS" -Details "SMB signing required"
        } else {
            Add-CheckResult -Category "Network" -CheckName "SMB Signing" -Status "WARN" -Details "SMB signing not required" -Recommendation "Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature `$true"
        }
        
        # Check anonymous share access
        $nullSession = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").NullSessionPipes
        if ($nullSession) {
            Add-CheckResult -Category "Network" -CheckName "Null Session Pipes" -Status "FAIL" -Details "Null session pipes configured" -Recommendation "Disable null sessions"
        } else {
            Add-CheckResult -Category "Network" -CheckName "Null Session Pipes" -Status "PASS" -Details "Null session pipes disabled"
        }
        
    } catch {
        Write-AuditLog "Error checking SMB: $_" "WARN"
    }
}

# ============================================
# 12. Additional Security Checks
# ============================================
function Test-AdditionalSecurity {
    Write-AuditLog "Running additional security checks..." "INFO"
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Add-CheckResult -Category "System" -CheckName "PowerShell Version" -Status "PASS" -Details "PowerShell version: $($psVersion.ToString())"
    } else {
        Add-CheckResult -Category "System" -CheckName "PowerShell Version" -Status "FAIL" -Details "PowerShell version: $($psVersion.ToString()) - Upgrade recommended"
    }
    
    # Check Windows Defender SmartScreen
    $smartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
    if ($smartScreen.EnableSmartScreen -eq 1) {
        Add-CheckResult -Category "System" -CheckName "Windows SmartScreen" -Status "PASS" -Details "SmartScreen enabled"
    } else {
        Add-CheckResult -Category "System" -CheckName "Windows SmartScreen" -Status "WARN" -Details "SmartScreen not enabled"
    }
    
    # Check Windows Firewall notification
    $fwNotifications = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Defender Security Center\Notifications" -ErrorAction SilentlyContinue
    if ($fwNotifications.DisableNotifications -eq 1) {
        Add-CheckResult -Category "System" -CheckName "Security Notifications" -Status "FAIL" -Details "Security notifications disabled" -Recommendation "Enable security notifications"
    } else {
        Add-CheckResult -Category "System" -CheckName "Security Notifications" -Status "PASS" -Details "Security notifications enabled"
    }
    
    # Check last shutdown time
    $lastShutdown = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
    $uptime = ((Get-Date) - $lastShutdown).Days
    
    if ($uptime -le 30) {
        Add-CheckResult -Category "System" -CheckName "System Uptime" -Status "PASS" -Details "System uptime: $uptime days"
    } else {
        Add-CheckResult -Category "System" -CheckName "System Uptime" -Status "WARN" -Details "System uptime: $uptime days - Consider restart for updates"
    }
}

# ============================================
# Generate Report
# ============================================
function Show-Report {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "                    SECURITY AUDIT REPORT                " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Calculate score
    $scorePercent = [math]::Round(($Script:OverallScore / $Script:TotalChecks) * 100, 1)
    $passedChecks = $Script:TotalChecks - (($Script:ReportData | Where-Object { $_.Status -eq "FAIL" }).Count) - (($Script:ReportData | Where-Object { $_.Status -eq "WARN" }).Count)
    
    Write-Host "Security Score: $scorePercent% ($passedChecks/$Script:TotalChecks checks passed)" -ForegroundColor $(if ($scorePercent -ge 80) { "Green" } elseif ($scorePercent -ge 60) { "Yellow" } else { "Red" })
    Write-Host ""
    
    # Group by category
    $categories = $Script:ReportData | Group-Object Category
    
    foreach ($category in $categories) {
        Write-Host "---------------------------------------------------------------" -ForegroundColor Gray
        Write-Host "  $($category.Name)" -ForegroundColor Cyan
        Write-Host "---------------------------------------------------------------" -ForegroundColor Gray
        
        foreach ($check in $category.Group) {
            $statusColor = switch ($check.Status) {
                "PASS" { "Green" }
                "FAIL" { "Red" }
                "WARN" { "Yellow" }
                default { "White" }
            }
            
            $statusSymbol = switch ($check.Status) {
                "PASS" { "[+]" }
                "FAIL" { "[X]" }
                "WARN" { "[!]" }
                default { "[?]" }
            }
            
            Write-Host "  $statusSymbol $($check.CheckName): " -NoNewline -ForegroundColor $statusColor
            Write-Host $check.Status -ForegroundColor $statusColor
            Write-Host "    Details: $($check.Details)" -ForegroundColor Gray
            
            if ($check.Recommendation) {
                Write-Host "    -> $($check.Recommendation)" -ForegroundColor Yellow
            }
        }
        Write-Host ""
    }
    
    Write-Host "============================================================" -ForegroundColor Cyan
    
    # Summary
    $failCount = ($Script:ReportData | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($Script:ReportData | Where-Object { $_.Status -eq "WARN" }).Count
    
    if ($scorePercent -ge 80) {
        Write-Host "Status: SECURE" -ForegroundColor Green
    } elseif ($scorePercent -ge 60) {
        Write-Host "Status: NEEDS IMPROVEMENT" -ForegroundColor Yellow
    } else {
        Write-Host "Status: CRITICAL - IMMEDIATE ACTION REQUIRED" -ForegroundColor Red
    }
    
    Write-Host "Failures: $failCount | Warnings: $warnCount | Passed: $passedChecks"
    Write-Host ""
}

function Export-Report {
    param([string]$Path)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "SecurityAudit_$timestamp.html"
    $fullPath = Join-Path $Path $filename
    
    $scorePercent = [math]::Round(($Script:OverallScore / $Script:TotalChecks) * 100, 1)
    $failCount = ($Script:ReportData | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($Script:ReportData | Where-Object { $_.Status -eq "WARN" }).Count
    $passCount = $Script:TotalChecks - $failCount - $warnCount
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #1a237e, #0d47a1); color: white; padding: 20px; border-radius: 8px; }
        .score { font-size: 48px; font-weight: bold; }
        .pass { color: #2e7d32; }
        .fail { color: #c62828; }
        .warn { color: #f57c00; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }
        th { background: #1565c0; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #e0e0e0; }
        tr:hover { background: #f5f5f5; }
        .category { font-weight: bold; color: #1565c0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows Security Audit Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p class="score">Score: $scorePercent%</p>
    </div>
    <table>
        <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Status</th>
            <th>Details</th>
            <th>Recommendation</th>
        </tr>
"@
    
    foreach ($check in $Script:ReportData) {
        $statusClass = switch ($check.Status) {
            "PASS" { "pass" }
            "FAIL" { "fail" }
            "WARN" { "warn" }
        }
        
        $htmlContent += @"
        <tr>
            <td class="category">$($check.Category)</td>
            <td>$($check.CheckName)</td>
            <td class="$statusClass">$($check.Status)</td>
            <td>$($check.Details)</td>
            <td>$($check.Recommendation)</td>
        </tr>
"@
    }
    
    $htmlContent += @"
    </table>
    <p><strong>Summary:</strong> $failCount Failures, $warnCount Warnings, $passCount Passed</p>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $fullPath -Encoding UTF8
    Write-Host "Report exported to: $fullPath" -ForegroundColor Green
}

# ============================================
# Main Execution
# ============================================
function Main {
    Show-Banner
    
    # Check admin privileges
    if (-not (Get-IsAdmin)) {
        Write-AuditLog "This script requires administrator privileges for full functionality" "WARN"
        Write-AuditLog "Some checks may be limited without admin rights" "WARN"
    } else {
        Write-AuditLog "Running with administrator privileges" "INFO"
    }
    
    Write-Host ""
    Write-AuditLog "Starting security audit..." "INFO"
    Write-Host ""
    
    # Run all checks
    Test-WindowsFirewall
    Test-WindowsUpdate
    Test-AntivirusStatus
    Test-UserAccountSecurity
    Test-OpenPorts
    Test-RunningServices
    Test-EventLogSecurity
    Test-BitLockerStatus
    Test-UACStatus
    Test-RemoteDesktopSettings
    Test-SMBConfiguration
    Test-AdditionalSecurity
    
    # Show report
    Show-Report
    
    # Export if requested
    if ($ExportReport) {
        Export-Report -Path $OutputPath
    }
    
    $completedTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Audit completed at: $completedTime" -ForegroundColor Cyan
}

# Run main function
Main
