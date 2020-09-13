# vmware-esxi-hardening
Powershell script to apply hardening recomendation in ESXi hosts  6.5 and 6.7

Script to verify and automatic apply hardening policies.

The script verify and fix the following points.
1.	Local NTP servers
2.	Syslog.global.logDir
3.	SNMP Service
4.	MOB Disable
5.	TLS Protocols (only allow 1.2)
6.	AD Auth
7.	Security.AccountUnlockTime
8.	Security.AccountLockFailures
9.	UserVars.DcuiTimeOut
10.	Security.PasswordQualityControl
11.	UserVars.ESXiShellInteractiveTimeOut
12.	UserVars.ESXiShellTimeOut
13.	Mem.ShareForceSalting -> set to 2
14.	Acceptance Level for VIBs
15.	Promiscuous Mode
16.	dvfilter API
17.	Unsigned Modules

Items: 2, 14 and 17, just check if it is ok or not. Because each infrastructure has its own policy.
