#
# PowerShell Attack Simulation
# MITRE ATT&CK: T1059.001 - PowerShell
# Tests Detection Rules: 200010, 200011, 200012, 200013, 200014
#
# ⚠️  WARNING: Only run in isolated lab environment!
#

# Colors for output
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"

function Write-Header {
    param($Text)
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor $BLUE
    Write-Host "║  $Text" -ForegroundColor $BLUE
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor $BLUE
}

function Write-Test {
    param($Number, $Description)
    Write-Host "`n[TEST $Number] $Description" -ForegroundColor $BLUE
    Write-Host "----------------------------------------"
}

function Log-Action {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    Add-Content -Path "simulation.log" -Value $logEntry
    Write-Host $logEntry
}

# Main header
Clear-Host
Write-Header "PowerShell Attack Simulation - MITRE ATT&CK: T1059.001"

# Safety check
Write-Host "`n⚠️  WARNING: This script simulates PowerShell-based attacks!" -ForegroundColor $RED
Write-Host "Only run in isolated lab environments.`n" -ForegroundColor $YELLOW

$confirm = Read-Host "Are you sure you want to continue? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Simulation cancelled." -ForegroundColor $YELLOW
    exit
}

Write-Host "`n[+] Starting PowerShell attack simulation...`n" -ForegroundColor $GREEN

# Test 1: Encoded PowerShell Command (Rule 200010)
Write-Test "1" "Encoded PowerShell Command Detection"
Write-Host "Expected Detection: Rule 200010 (Encoded PowerShell command)"

try {
    # Create a benign encoded command
    $command = "Write-Host 'This is a test of encoded command detection'"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    
    Write-Host "Executing encoded PowerShell command..." -ForegroundColor $YELLOW
    Log-Action "Executing encoded PowerShell: $command"
    
    # Execute the encoded command
    powershell.exe -EncodedCommand $encodedCommand
    
    Write-Host "✓ Encoded command executed (should trigger Rule 200010)" -ForegroundColor $GREEN
    Log-Action "Rule 200010 should have triggered - Encoded PowerShell"
}
catch {
    Write-Host "✗ Test failed: $_" -ForegroundColor $RED
}

Start-Sleep -Seconds 2

# Test 2: PowerShell Download Cradle (Rule 200011)
Write-Test "2" "PowerShell Download Cradle Detection"
Write-Host "Expected Detection: Rule 200011 (Download cradle)"

try {
    Write-Host "Simulating download cradle pattern..." -ForegroundColor $YELLOW
    
    # Simulate download cradle (without actually downloading)
    $downloadCradle = @"
# Simulated download cradle - NOT actually downloading
`$url = 'https://example.com/test.txt'
Write-Host "IEX (New-Object Net.WebClient).DownloadString('`$url')"
"@
    
    Log-Action "Simulating download cradle pattern"
    Invoke-Expression $downloadCradle
    
    Write-Host "✓ Download cradle pattern executed (should trigger Rule 200011)" -ForegroundColor $GREEN
    Log-Action "Rule 200011 should have triggered - Download cradle"
}
catch {
    Write-Host "✗ Test failed: $_" -ForegroundColor $RED
}

Start-Sleep -Seconds 2

# Test 3: Execution Policy Bypass (Rule 200012)
Write-Test "3" "Execution Policy Bypass Detection"
Write-Host "Expected Detection: Rule 200012 (Execution policy bypass)"

try {
    Write-Host "Executing with execution policy bypass..." -ForegroundColor $YELLOW
    
    # Create a temporary script
    $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    "Write-Host 'Test script with bypass'" | Out-File -FilePath $tempScript
    
    Log-Action "Executing PowerShell with -ExecutionPolicy Bypass"
    
    # Execute with bypass
    powershell.exe -ExecutionPolicy Bypass -File $tempScript
    
    # Cleanup
    Remove-Item $tempScript -Force
    
    Write-Host "✓ Execution policy bypass used (should trigger Rule 200012)" -ForegroundColor $GREEN
    Log-Action "Rule 200012 should have triggered - Execution policy bypass"
}
catch {
    Write-Host "✗ Test failed: $_" -ForegroundColor $RED
}

Start-Sleep -Seconds 2

# Test 4: Mimikatz Detection (Rule 200013)
Write-Test "4" "Mimikatz Keyword Detection"
Write-Host "Expected Detection: Rule 200013 (Mimikatz detection)"

try {
    Write-Host "Simulating Mimikatz keyword usage..." -ForegroundColor $YELLOW
    
    # Just use the keyword - NOT actually running Mimikatz
    $mimikatzSimulation = @"
# Simulated Mimikatz detection test - NOT running actual Mimikatz
Write-Host "Testing detection for keyword: mimikatz"
Write-Host "This should trigger the detection rule"
"@
    
    Log-Action "Simulating Mimikatz keyword for detection"
    Invoke-Expression $mimikatzSimulation
    
    Write-Host "✓ Mimikatz keyword detected (should trigger Rule 200013)" -ForegroundColor $GREEN
    Log-Action "Rule 200013 should have triggered - Mimikatz detection"
}
catch {
    Write-Host "✗ Test failed: $_" -ForegroundColor $RED
}

Start-Sleep -Seconds 2

# Test 5: Invoke-Expression Detection (Rule 200014)
Write-Test "5" "Invoke-Expression Pattern Detection"
Write-Host "Expected Detection: Rule 200014 (IEX usage)"

try {
    Write-Host "Using Invoke-Expression (IEX)..." -ForegroundColor $YELLOW
    
    # Use IEX with benign command
    $command = "Write-Host 'Testing IEX detection'"
    
    Log-Action "Executing command via Invoke-Expression"
    Invoke-Expression $command
    
    # Also test IEX alias
    IEX "Write-Host 'Testing IEX alias'"
    
    Write-Host "✓ Invoke-Expression used (should trigger Rule 200014)" -ForegroundColor $GREEN
    Log-Action "Rule 200014 should have triggered - Invoke-Expression"
}
catch {
    Write-Host "✗ Test failed: $_" -ForegroundColor $RED
}

Start-Sleep -Seconds 2

# Bonus Test: Multiple Techniques Combined
Write-Test "BONUS" "Combined PowerShell Techniques"
Write-Host "Expected Detection: Multiple rules (200010, 200014)"

try {
    Write-Host "Combining encoded command with IEX..." -ForegroundColor $YELLOW
    
    $command = "Write-Host 'Combined technique test'"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    
    Log-Action "Executing combined PowerShell techniques"
    
    # This should trigger multiple rules
    $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedCommand))
    Invoke-Expression $decoded
    
    Write-Host "✓ Combined techniques executed (should trigger multiple rules)" -ForegroundColor $GREEN
    Log-Action "Multiple rules should have triggered - Combined techniques"
}
catch {
    Write-Host "✗ Test failed: $_" -ForegroundColor $RED
}

# Summary
Write-Host "`n"
Write-Header "SIMULATION SUMMARY"

Write-Host "`nSimulation Type: PowerShell Attack Techniques"
Write-Host "MITRE ATT&CK: T1059.001 - PowerShell"
Write-Host "`nTests Executed:"
Write-Host "  1. Encoded Command (Rule 200010)"
Write-Host "  2. Download Cradle (Rule 200011)"
Write-Host "  3. Execution Policy Bypass (Rule 200012)"
Write-Host "  4. Mimikatz Detection (Rule 200013)"
Write-Host "  5. Invoke-Expression (Rule 200014)"
Write-Host "  BONUS. Combined Techniques"

Write-Host "`nExpected Wazuh Alerts:" -ForegroundColor $GREEN
Write-Host "  • Rule 200010: Encoded PowerShell command"
Write-Host "  • Rule 200011: PowerShell download cradle"
Write-Host "  • Rule 200012: Execution policy bypass"
Write-Host "  • Rule 200013: Mimikatz detection"
Write-Host "  • Rule 200014: Invoke-Expression usage"

Write-Host "`nVerification Steps:" -ForegroundColor $GREEN
Write-Host "1. Check Wazuh dashboard for alerts"
Write-Host "2. Or run on Wazuh server:"
Write-Host "   sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep '10001[0-4]'"

Write-Host "`nLog file: simulation.log"

# Check PowerShell event logs locally
Write-Host "`n[INFO] Checking local PowerShell event logs..." -ForegroundColor $YELLOW

try {
    $recentEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        ID = 4104
        StartTime = (Get-Date).AddMinutes(-5)
    } -MaxEvents 10 -ErrorAction SilentlyContinue
    
    if ($recentEvents) {
        Write-Host "✓ Found $($recentEvents.Count) PowerShell script block events in last 5 minutes" -ForegroundColor $GREEN
        Write-Host "These events should be forwarded to Wazuh for analysis"
    }
    else {
        Write-Host "⚠ No recent PowerShell events found" -ForegroundColor $YELLOW
        Write-Host "Ensure PowerShell Script Block Logging is enabled"
    }
}
catch {
    Write-Host "⚠ Could not access PowerShell event logs: $_" -ForegroundColor $YELLOW
}

Write-Host "`n[✓] PowerShell Attack Simulation Complete!`n" -ForegroundColor $GREEN

# Offer to check Wazuh server
$checkWazuh = Read-Host "`nWould you like to check Wazuh server for alerts? (yes/no)"
if ($checkWazuh -eq "yes") {
    $wazuhServer = Read-Host "Enter Wazuh server address (e.g., ubuntu@10.0.1.100)"
    if ($wazuhServer) {
        Write-Host "`nConnecting to Wazuh server..." -ForegroundColor $YELLOW
        ssh $wazuhServer "sudo tail -n 100 /var/ossec/logs/alerts/alerts.log | grep -A 5 'Rule: 20001'"
    }
}

Write-Host "`nSimulation complete. Review alerts in Wazuh dashboard.`n"
