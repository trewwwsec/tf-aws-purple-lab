<powershell>
# Variables from Terraform
$WazuhManagerIP = "${wazuh_server_ip}"

# Wait for Wazuh server to be ready
Write-Host "Waiting for Wazuh server to be ready..."
Start-Sleep -Seconds 120

# Download Wazuh agent
Write-Host "Downloading Wazuh agent..."
$DownloadURL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${wazuh_version}${wazuh_package_suffix}.msi"
$OutputPath = "C:\wazuh-agent.msi"

Invoke-WebRequest -Uri $DownloadURL -OutFile $OutputPath

# Install Wazuh agent
Write-Host "Installing Wazuh agent..."
Start-Process msiexec.exe -ArgumentList "/i $OutputPath /q WAZUH_MANAGER=$WazuhManagerIP WAZUH_REGISTRATION_SERVER=$WazuhManagerIP" -Wait

# Start service
Start-Service WazuhSvc

# Install Sysmon for enhanced logging
Write-Host "Installing Sysmon..."
$SysmonURL = "https://download.sysinternals.com/files/Sysmon.zip"
$SysmonZip = "C:\Sysmon.zip"
Invoke-WebRequest -Uri $SysmonURL -OutFile $SysmonZip
Expand-Archive -Path $SysmonZip -DestinationPath "C:\Sysmon" -Force

# Download Sysmon config (SwiftOnSecurity config is industry standard)
$ConfigURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$ConfigPath = "C:\Sysmon\sysmonconfig.xml"
Invoke-WebRequest -Uri $ConfigURL -OutFile $ConfigPath

# Install Sysmon with config
& "C:\Sysmon\Sysmon64.exe" -accepteula -i $ConfigPath

# Enable PowerShell script block logging
Write-Host "Enabling PowerShell logging..."
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}
Set-ItemProperty -Path $RegPath -Name "EnableScriptBlockLogging" -Value 1

# Enable module logging
$ModulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $ModulePath)) {
    New-Item -Path $ModulePath -Force | Out-Null
}
Set-ItemProperty -Path $ModulePath -Name "EnableModuleLogging" -Value 1

# Create installation marker
"Wazuh agent and Sysmon installed successfully" | Out-File -FilePath "C:\wazuh-install-complete.txt"

Write-Host "Wazuh agent installation complete!"
Write-Host "Connected to Wazuh manager at: $WazuhManagerIP"
</powershell>
