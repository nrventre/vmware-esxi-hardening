##################################################
#                                                #
#                                                #
# Script to verify and apply Esxi hardening      #
#                                                #
# For ESXi 6.5 and 6.7 versions                  #
#                                                #
# Autor Nicolas Ventre.                          #
#                                                #
# Versión 1.0                                    #
#                                                #
#                                                #
##################################################

#Connect to vcenter
$vcenter = Read-Host "vCenter name:"
$user = Read-Host "User:"
$password = Read-Host "Password:"

Write-Host -f green "Connecting to vCenter Server..."
Connect-VIServer -Server $vcenter -User $user -Password $password

#Create folder for logs output
$checkdir = Test-Path "$env:USERPROFILE\Documents\HardeningESXi-Logs" -PathType Container
if ($checkdir -eq "*True*"){}
else {New-Item $env:USERPROFILE\Documents\HardeningESXi-Logs -ItemType directory}

#Information to be used in the script
$ntp1 = Read-Host "Put primary NTP Server" #Put Primary NTP Server
$ntp2 = Read-Host "Put Secondary NTP Server"  #Put Secondary NTP Server
$domain = Read-Host "Put Domain, if your domain is hostname.test.local, you only need to put test.local" #Put Domain, if your domain is "hostname.test.local", you only need to put "test.local"

###############################################
#Verify NTP Servers and status                #
###############################################

Write-Host -f White "###############################################"
Write-Host -f White "#Checking NTP Servers...                      #"
Write-Host -f White "###############################################"

Get-VMHost |Sort Name|Select Name, @{N=“NTPServer“;E={$_ |Get-VMHostNtpServer}}, @{N=“ServiceRunning“;E={(Get-VmHostService -VMHost $_ |Where-Object {$_.key-eq “ntpd“}).Running}} | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\ntp.txt"

#Variables to verify if the first or Second NTP don't exist.
$ntp1check = gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\ntp.txt" | ft NTPServer | findstr /v " _$Null NTPServer ---- _$Null" | where-object {$_ -notlike "*ntp1*"} | foreach{$_.split(".")[0]}
$ntp2check = gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\ntp.txt" | ft NTPServer | findstr /v " _$Null NTPServer ---- _$Null" | where-object {$_ -notlike "*ntp2*"} | foreach{$_.split(".")[0]}

#Function to fix and leave the NTP Servers well loaded.
function cargarntp {
#If the output of $var1 is empty then everything is fine.
$var1 = foreach($line in Get-Content "$env:USERPROFILE\Documents\HardeningESXi-Logs\ntp.txt" | ft NTPServer | findstr /v " _$Null NTPServer ---- _$Null") { if($line -like '*ntp1*' -and $line -like '*ntp2*') { } else { $line } }
If ($var1 -eq $Null) {
Write-Host -f green "All NTP Servers are configured correctly"
}
else {
    #Check if the firs NTP Server is missing, if so, add the server.
    if ($ntp1check -ne $Null) {
    Write-Host -f green "Server $ntp1 is missing"
    $ntp1check | ForEach-Object {Get-VMHost "$_.$domain" | Remove-VMHostNtpServer -NtpServer $ntp2 -Confirm:$false}
    $ntp1check | ForEach-Object {Get-VMHost "$_.$domain" | Add-VMHostNtpServer -NtpServer $ntp1,$ntp2 -Confirm:$false}
    Write-Host -f green "Server $ntp1 was added successfully"
    }
    #Check if the Second NTP Server is missing, if so, add the server.
    elseif ($ntp2check -ne $Null) {
    Write-Host -f green "Server $ntp2 is missing"
    $ntp2check | ForEach-Object {Get-VMHost "_.$domain" | Add-VMHostNtpServer -NtpServer $ntp2}
    Write-Host -f green "Server $ntp2 was added successfully"
    }
    else {
        Write-Host -f green "There was a problem adding NTP Servers, please verify."
        }
}
}
#Execute the function
cargarntp


###############################################
#Verify NTP Service Status                    #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying NTP services...                    #"
Write-Host -f White "###############################################"

#Generate the file to store the result of the status of NTP services "$env:USERPROFILE\Documents\ntp-service.txt".
Get-VMHost |Sort Name|Select Name, @{N=“NTPServer“;E={$_ |Get-VMHostNtpServer}}, @{N=“ServiceRunning“;E={(Get-VmHostService -VMHost $_ |Where-Object {$_.key-eq “ntpd“}).Running}} | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\ntp-service.txt"

function serviciontp {
#Look in the File "$env:USERPROFILE\Documents\HardeningESXi-Logs\ntp-service.txt", the computers with the service stopped and send the information to "$env:USERPROFILE\Documents\ntp-service-error.txt".
$ntpservice = gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\ntp-service.txt" | ft ServiceRunning | findstr /v " _$Null ServiceRunning -------------- _$Null" | where-object {$_ -notlike "*True*"} | foreach{$_.split(".")[0]}
    #If the status of the services is True, mark everything correct, if it detects any like False, start the service.
    if($ntpservice -eq $Null) {
    Write-Host -f green "All NTP Services are started."
    }
    else {
    Write-Host -f red "Some NTP Services are Stopped."
    Write-Host -f red "Starting Service..."
    $ntpservice | ForEach-Object {Get-VMHost "$_.$domain" | Get-VMHostService |?{$_.key -eq ‘ntpd’} | Start-VMHostService -Confirm:$false}
    }

}
#Execute the function that validates the NTP services.
serviciontp

###########################################
#Verify LogDir Config                     #
###########################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying Logdir in Hosts...                 #"
Write-Host -f White "###############################################"

#Look in the advanced configurations which is the LogDir of the Host and send it to "$env:USERPROFILE\Documents\logdir.txt".
$checklogdir = Get-AdvancedSetting -Entity (Get-VMHost) -Name "Syslog.global.logDir" | Select Entity, Name, Value
$checklogdir | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\logdir.txt"

#It verifies if the LogDir is "scratch" (it can be modified by the desired one. If it does not contain the string scratch, it informs so that it is loaded manually as appropriate.
$var3 = foreach($line in gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\logdir.txt" | ft Value | findstr /v " _$Null Value ---- _$Null") { if($line -notcontains '*scratch*') { } else { $line } }
if ($var3 -notcontains "*scratch*") {
Write-Host -f green "The LogDir for all Hosts is /scratch/log"
}
else {
Write-Host -f red "You need to change the Host LogDir"
}

###############################################
#Verify SNMP service status                   #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying SNMP Service...                    #"
Write-Host -f White "###############################################"

#Searches the SNMP Service status for every hosts and generates the file "$env:USERPROFILE\Documents\HardeningESXi-Logs\snmp-service.txt" with the information.
Get-VMHost |Sort Name|Select Name, @{N=“SNMPServer“;E={$_ |Get-VMHostSnmp}}, @{N=“ServiceRunning“;E={(Get-VmHostService -VMHost $_ |Where-Object {$_.key-eq “snmpd“}).Running}} | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\snmp-service.txt"

#Function to validate the status of services and fix them. By default it is considered to be disabled.
function snmpservice {
#Look for the services if any are in state "True", if so, stoppthem.
$checksnmp = (gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\snmp-service.txt" | ft ServiceRunning | findstr /v " _$Null ServiceRunning -------------- _$Null")  | where-object {$_ -like "*True*"} | foreach{$_.split(".")[0]}
    if($checksnmp -eq $Null) {
    Write-Host -f green "All SNMP Services are correctly Stopped."
    }
    else {
    Write-Host -f red "Hosts with Started SNMP Service detected."
    Write-Host -f red "Stopping Services..."
    $esxhost = foreach($line in $checksnmp) {Get-VMHost -Name "$line.$domain" -Server $vcenter}
    $esxhost | Foreach {Start-VMHostService -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "snmpd"}) -Confirm:$false}
    }
}
#Load the function
snmpservice

###############################################
#Verify Managed Object Browser Config         #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying MOB Config ...                     #"
Write-Host -f White "###############################################"

#Find the status of the Managed Object Browser and send the information to "$env:USERPROFILE\Documents\HardeningESXi-Logs\mob-config.txt".
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob| Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\mob-config.txt"

#Function to validate the MOB status and propose to fix it.
function mobconfig {
#Check if config status is "False", if so, then is ok. If status is "True" then change it to False.
#Default state of the config must be False.

$checkmob = (gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\mob-config.txt" | ft Value | findstr /v " _$Null Value ----- _$Null") | where-object {$_ -like "*True*"} | foreach{$_.split(".")[0]}
    if($checkmob -eq $Null) {
    Write-Host -f green "Managed Object Browser are disabled in all hosts"
    }
    else {
    Write-Host -f red "Hosts with wrong Managed Object Browser config was detected"
    Write-Host -f red "Modifying variables..."
    $checkmob | ForEach {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false -Confirm:$false}
    }
}
#Execute the function
mobconfig


###############################################
#Verify TLS                                   #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying TLS Config ...                     #"
Write-Host -f White "###############################################"

#Validate TLS settings on every host. Should only have 1.2 enabled. Generates an output file with the information in "$env:USERPROFILE\Documents\HardeningESXi-Logs\tls-config.txt".
Get-vmhost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\tls-config.txt"

#Check if hosts only have TLS 1.2 enable, otherwise fix them.
function tlsconfig {
$checktls = (gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\tls-config.txt" | ft Value | findstr /v " _$Null Value ----- _$Null") | where-object {$_ -notmatch 'sslv3,tlsv1,tlsv1.1'} | foreach{$_.split(".")[0]}
    if ($checktls -eq $Null) {
    Write-host -f green "All the Hosts have only TSL 1.2 enable"
    }
    else{
    Write-Host -f red "Hosts with a bad TLS configuration was detected."
    Write-Host -f red "Modifying variables..."
    $checktls | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name "UserVars.ESXiVPsDisabledProtocols" | Set-AdvancedSetting -Value "sslv3,tlsv1,tlsv1.1" -Confirm:$false}
    }
}
#Execute the function.
tlsconfig


###############################################
#Verify Domain Status                         #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying Domain Config ...                  #"
Write-Host -f White "###############################################"

#Check domain status and log to file "$env:USERPROFILE\Documents\HardeningESXi-Logs\domain-config.txt". Domain Join needs to be disabled.
Get-VMHost | Get-VMHostAuthentication | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\domain-config.txt"

function chkdomain {
#Check if the domain column has information, if so, it proposes to remove host from domain.
$checkdomain = (gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\domain-config.txt" | ft Domain | findstr /v " _$Null Domain ------ _$Null")
    if($_ -eq $Null) {
    Write-Host -f green "All hosts are out of domain."
    } 
    else {
    write-host -f red "You must remove the host from the domain."
    write-host -f red "Removing domain config..."
    foreach($line in Get-VMHost) {$line | Get-VMHostAuthentication | Set-VMHostAuthentication -LeaveDomain -Force}
    }
}
chkdomain

###############################################
#Verify AccountUnlockTime                     #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying AccountUnlockTime  ...             #"
Write-Host -f White "###############################################"

#Check AccountUnlockTime, needs to be in 900
Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\aclt-config.txt"

#If AccountUnlockTime is not 900, fix AccountUnlockTime and set it to 900
function altconfig {
$checkalt = (gc $env:USERPROFILE\Documents\HardeningESXi-Logs\aclt-config.txt | ft Value | findstr /v " _$Null Value ----- _$Null") | where-object {$_ -notlike '*900*'} | foreach{$_.split(".")[0]}
if ($checkalt -eq $Null) {
Write-host -f green "All Hosts have Account Lock Time with 900"
}
else{
Write-Host -f red "Hosts with wrong AccountUnlockTime detected"
Write-Host -f red "Fixing hosts"
$checkalt | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:$false}
}
}
altconfig

###############################################
#Verify AccountLockFailures                   #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying AccountLockFailures  ...           #"
Write-Host -f White "###############################################"

#Check if AccountLockFailures is set to 5
Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\aclf-config.txt"

function alfconfig {
$checkaclf = Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures  | Select Entity, Name, Value | where-object {$_.value -notlike '*5*'} | Select-Object Entity | ft Entity | findstr /v " _$Null Entity ------ _$Null" | foreach{$_.split(".")[0]} | where {$_ -ne ""}
    if ($checkaclf -eq $Null) {
    Write-Host -f green "All Hosts have AccountLockFailures in 5"
    }
    else {
    Write-Host -f red "Hosts with wrong AccountLockFailures detected"
    Write-Host -f red "Fixing hosts"
    $checkaclf | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 5 -Confirm:$false}
    }

}
alfconfig

###############################################
#Verify ESXi Shell Interactive TimeOut     #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying ESXi Shell Interactive TimeOut...  #"
Write-Host -f White "###############################################"

#Check ESXi Shell Interactive TimeOut, needs to be in 900.
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\sito-config.txt"

# Verify and Fix host config to match 900
$checkesit = (gc $env:USERPROFILE\Documents\HardeningESXi-Logs\sito-config.txt | ft Value | findstr /v " _$Null Value ----- _$Null") | where-object {$_ -notlike '*900*'} | foreach{$_.split(".")[0]}

function sitoconfig {
    if ($checkesit -eq $Null) {
    Write-Host -f green "All Hosts have ESXi Shell Interactive TimeOut in 900"
    }
    else {
    Write-Host -f red "Hosts with wrong ESXi Shell Interactive TimeOut detected"
    Write-Host -f red "Fixing hosts"
    $checkesit | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900 -Confirm:$false}
    }
}
sitoconfig


###############################################
#Verify DCUI Access Time Out                  #
###############################################
Write-Host -f White "###############################################"
Write-Host -f White "#Verifying DCUI Access Time Out  ...          #"
Write-Host -f White "###############################################"

#Check DCUI Access Time Out, needs to be in 600
Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\dcuiato-config.txt"

#Verify DCUI Access Time Out configuration, and fix bad configurations.
$checkdcuiato = (gc $env:USERPROFILE\Documents\HardeningESXi-Logs\dcuiato-config.txt | ft Value | findstr /v " _$Null Value ----- _$Null") | where-object {$_ -notlike '*600*'} | foreach{$_.split(".")[0]}

function dcuiatoconfig {
    if ($checkdcuiato -eq $Null) {
    Write-Host -f green "All Hosts have DCUI Access Time Out in 600"
    }
    else {
    Write-Host -f red "Hosts with wrong DCUI Access Time Out detected"
    Write-Host -f red "Fixing hosts"
    $checkdcuiato | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false}
    }
}
dcuiatoconfig

###############################################
#Verify Security Password Quality Control     #
###############################################
Write-Host -f White "#####################################################"
Write-Host -f White "#Verifying Security Password Quality Control  ...   #"
Write-Host -f White "#####################################################"

#Check Security Password Quality Control, needs to be in "min=disabled,disabled,4,8,8"
Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\spqc-config.txt"

$checkspqc = Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl  | Select Entity, Name, Value | where-object {$_.value -notlike '*min=disabled,disabled,4,8,8*'} | Select-Object Entity | ft Entity | findstr /v " _$Null Entity ------ _$Null" | foreach{$_.split(".")[0]} | where {$_ -ne ""}

function spqcconfig {
    if ($checkspqc -eq $Null) {
    Write-Host -f green "All Hosts have Security Password Quality Control with min=disabled,disabled,4,8,8"
    }
    else {
    Write-Host -f red "Hosts with wrong Security Password Quality Control detected"
    Write-Host -f red "Fixing hosts"
    $checkspqc | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "min=disabled,disabled,4,8,8" -Confirm:$false}
    }
}
spqcconfig


###############################################
#Verify ESXi Shell TimeOut                    #
###############################################
Write-Host -f White "#############################################"
Write-Host -f White "#Verifying ESXi Shell TimeOut  ...          #"
Write-Host -f White "#############################################"

#Check if ESXi Shell TimeOut is set to 900
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\esto-config.txt"

#Verify host ESXi Shell TimeOut if not set to 900, then fix them.
$checkesto = (gc $env:USERPROFILE\Documents\HardeningESXi-Logs\esto-config.txt | ft Value | findstr /v " _$Null Value ----- _$Null") | where-object {$_ -notlike '*900*'} | foreach{$_.split(".")[0]}

function estoconfig {
    if ($checkesto -eq $Null) {
    Write-Host -f green "All Hosts have ESXi Shell TimeOut in 900"
    }
    else {
    Write-Host -f red "Hosts with wrong ESXi Shell TimeOut detected"
    Write-Host -f red "Fixing hosts"
    $checkesto | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 900 -Confirm:$false}
    }
}
estoconfig

###############################################
#Verify Transparent Page Sharing              #
###############################################
Write-Host -f White "#############################################"
Write-Host -f White "#Verifying Transparent Page Sharing  ...    #"
Write-Host -f White "#############################################"

#check if Transparent Page Sharing is set to 2.
Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\tps-config.txt"

#Verify if Transparent Page Sharing is set to 2, if not, then fix hosts
$checktps = Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Select Entity, Name, Value | where-object {$_.value -notlike '*2*'} | Select-Object Entity | ft Entity | findstr /v " _$Null Entity ------ _$Null" | foreach{$_.split(".")[0]} | where {$_ -ne ""}

function tpsconfig {
    if ($checktps -eq $Null) {
    Write-Host -f green "All Hosts have Transparent Page Sharing in 2"
    }
    else {
    Write-Host -f red "Hosts with wrong Transparent Page Sharing detected"
    Write-Host -f red "Fixing hosts"
    $checktps | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2 -Confirm:$false}
    }
}
tpsconfig


###############################################
#Verify DV Filter Bind Ip Address             #
###############################################
Write-Host -f White "#############################################"
Write-Host -f White "#Verifying DV Filter Bind Ip Address  ...   #"
Write-Host -f White "#############################################"

#Check if DV Filter Bind Ip Address is null.
Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress  | Select Entity, Name, Value | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\dvfbia-config.txt"

#Verify if DV Filter Bind Ip Address is Null, if not, fix hosts
$checkdvfbia = Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Select Entity, Name, Value | where-object {$_.value -ne ""}

function dvfbiaconfig {
    if ($checkdvfbia -eq $Null) {
    Write-Host -f green "All Hosts have DV Filter Bind Ip Address value empty"
    }
    else {
    Write-Host -f red "Hosts with wrong DV Filter Bind Ip Address detected"
    Write-Host -f red "Fixing hosts"
    $checkdvfbia | ForEach-Object {Get-VMHost "$_.$domain" | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value "" -Confirm:$false}
    }
}
dvfbiaconfig


###############################################
#Verify Allow Promiscuous Mode                #
###############################################
Write-Host -f White "#############################################"
Write-Host -f White "#Verifying Allow Promiscuous Mode  ...      #"
Write-Host -f White "#############################################"

#Check if Promiscuous Mode is enabled
Get-VirtualSwitch -Name "vSwitch*" | Get-SecurityPolicy | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\apm-config.txt"

#Verify if Promiscuous Mode is enabled, if so, then fix hosts
$checkapm = (gc $env:USERPROFILE\Documents\HardeningESXi-Logs\apm-config.txt | ft AllowPromiscuous | findstr /v " _$Null AllowPromiscuous ---------------- _$Null") | where-object {$_ -notlike '*False*'} | foreach{$_.split()[0]}

function apmconfig {
    if ($checkapm -eq $Null) {
    Write-Host -f green "All Hosts have Allow Promiscuous Mode value disabled"
    }
    else {
    Write-Host -f red "Hosts with wrong Allow Promiscuous Mode detected"
    Write-Host -f red "Fixing hosts"
    $checkapm | ForEach-Object {Get-VirtualSwitch $_ | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false -Confirm:$false}
    }
}
apmconfig


###############################################
#Verify Disable unsigned modules              #
###############################################
Write-Host -f White "#############################################"
Write-Host -f White "#Verifying Disable unsigned modules  ...    #"
Write-Host -f White "#This may take a few minutes                #"
Write-Host -f White "#############################################"
$esxcli = Get-ESXCLI -VMHost (Get-VMhost)
$generatefile = ForEach($line in $esxcli) {$line.software.vib.list() | Select AcceptanceLevel}
$generatefile | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\dum-config.txt"
$generateerrorfile = foreach($line in (gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\dum-config.txt" | ft AcceptanceLevel | findstr /v " _$Null AcceptanceLevel --------------- _$Null" | foreach{$_.split()[0]})) {if ($line -notlike "*CommunitySupported*") {} else {$line}}
if ($generateerrorfile -eq $Null) {
Write-host -f green "All Hosts have their modules signed from VMware or Partner"
}
else{
Write-Host -f red "Hosts with wrong firmed modules detected"
Write-Host -f red "You need to delete them manually"
}

###############################################
#Verify Software Acceptance                   #
###############################################
Write-Host -f White "#############################################"
Write-Host -f White "#Verifying Software Acceptance ...          #"
Write-Host -f White "#This may take a few minutes                #"
Write-Host -f White "#############################################"
$esxcli = Get-ESXCLI -VMHost (Get-VMhost)
$generatefile = ForEach($line in $esxcli) {$line.software.acceptance.get()}
$generatefile | Out-String | ForEach-Object { $_.Trim() } > "$env:USERPROFILE\Documents\HardeningESXi-Logs\sap-config.txt"
$generateerrorfile = foreach($line in (gc "$env:USERPROFILE\Documents\HardeningESXi-Logs\sap-config.txt")) {if ($line -like "*PartnerSupported*") {} else {$line}}
if ($generateerrorfile -eq $Null) {
Write-host -f green "All Hosts have PartnerSupported Software Acceptance"
}
else{
Write-Host -f red "Hosts with wrong Software Acceptance detected"
Write-Host -f red "You need to modify them manually"
}

Write-Host -f green "Check finalized"
Write-Host -f Green "Folfer '$env:USERPROFILE\Documents\HardeningESXi-Logs' Generated with all log files"
