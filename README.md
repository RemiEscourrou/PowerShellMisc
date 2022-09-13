# PowerShellMisc

Some PowerShell scripts that I've written in the last few years to interact with Active Directory and Windows operating systems.

## Readme

### Get-DeleteLockedFile.ps1

A way to delete a running executable on the disk. This was originally found by Jonas Lykkegaard (@jonasLyk) and a [C# PoC](https://github.com/LloydLabs/delete-self-poc) was written by @LloydLabs. This can also be used to delete locked files on the disk that the calling process has permission to get DELETE access to. I just wrote the POC in PowerShell with [PSReflect](https://github.com/mattifestation/PSReflect).

`Get-DeleteLockedFile c:\users\test\desktop\executable.exe`

### Invoke-DefenderAutomaticExclusionsCheck.ps1

This check was inspired by a tweet from @splinter_code and @NathanMcNulty, mentioning the fact that Microsoft Defender Antivirus includes automatic exclusions for some windows role.

`Invoke-DefenderAutomaticExclusionsCheck`

### Get-WinComputerInfo.ps1

Use Netapi32 to retrieve information concerning the operating system, the last SMB start time and the current version from a remote server because we can't always trust data in Active Directory. Based on [PSReflect](https://github.com/mattifestation/PSReflect).

`Get-NetComputerToD sqlserver`

`Get-NetComputerVersion sqlserver`
```
HostName      StartTime
--------      ---------
sqlserver     18/07/2017 06:03:27
```

`Get-NetComputerVersion sqlserver`
```
wki100_platform_id  : 500
wki100_computername : sqlserver
wki100_langroup     : TESTLAB
wki100_ver_major    : 10
wki100_ver_minor    : 0
```
### Set-PasswordRemotely.ps1

Allow changing a password from a remote forest.

`Set-PasswordRemotely -DomainController DC.local -UserName superuser`

### Invoke-UserMimiTab.ps1

Provide a real-time table with the open sessions of the targeted users and track if the machine has been rebooted

`$DA = (Get-DomainGroupMember "Admins du domaine" -Recurse).MemberName`

`Invoke-UserMimiTab -UserTarget $DA -Verbose`

```
UserName      SawOn          HostName                Version     SawAt               LastReboot          CredsInMemory
--------      -----          --------                -------     -----               ----------          -------------
admin         192.168.1.24   dcserver.test.fr        6.3         07/21/2017 14:55:58 07/10/2017 10:00:19 Probably
admin         192.168.1.2    computer.test.fr        6.3         07/21/2017 14:55:58 07/17/2017 15:21:14 Probably
admin         192.168.1.12   sqlserver.test.fr       10.0        07/21/2017 14:55:58                     Lost Connection
```

### Query-Objects_light.ps1

A quick wrapper to perform LDAP query in PowerShell.

`Query-Objects_light -Domain mydomain.local -User Administrator -Password Admin123! -Filter "(&(objectCategory=User))" -Attributes Name`

### Get-GPPScript.ps1

Inspired from Groupers to analyze GPP Script in GPO and associated ACL

`Get-GPPScript mydomain.local`
```
IniFile                : \\mydomain.local\SYSVOL\mydomain.local\Policies\{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}\Machine\Scripts\scripts.ini
GPO                    : {XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}
Key                    : Shutdown
CmdLine                : \\mydomain.local\NETLOGON\SuperProduct\SuperProductUninstall.bat
Parameters             : /adminpassword toto
ScriptOwner            : BUILTIN\Administrators
Script_FullControl     : BUILTIN\Administrators
Script_TakeOwnership   : MYDOMAIN\InterestingGroup
Script_Modify          : 
Script_Write           :
Script_WriteData       :
Script_WriteAttributes :
```

### Invoke-CRADADA.ps1

Custom Active Directory dumper that extracts inside several csv:
- LDAP information (user, computer, OU, etc.) including ACL
- Local data from remote servers thanks to NetAPI
- GPO data and scripts

Nothing new here, I wrote it to have a better understanding of [Bloodhound](https://github.com/BloodHoundAD/BloodHound) / [ADCP](https://github.com/ANSSI-FR/AD-control-paths) at his beginning. The performance is awful thanks to PowerShell :p

Big up to my old friend @nicolas_dbresse with whom I started to play with the Active Directory <3

`Invoke-CRADADA -Domain mydomain.local -LDAPChecks All -NetAPIChecks All -ACL -Recurse`
```
> Results
	> GlobalLog.txt
	> mydomain.local
		> Logs.txt
		> Structure
			> Users.csv
			> Users_ACL.csv
			> Trusts.csv
			> Trusts_ACL.csv
			> printQueue.csv
			> printQueue_ACL.csv
			> OU.csv
			> OU_ACL.csv
			> Groups.csv
			> Groups_ACL.csv
			> GPO.csv
			> GPO_ACL.csv
			> Domain.csv
			> Domain_ACL.csv
			> Computers.csv
			> Computers_ACL.csv
			> AdminSDHolder.csv
			> AdminSDHolder_ACL.csv
		> GPO
			> GPPScript
			> All GPO xml files
			> GPPAutologon.csv
			> GPPPassword.csv
			> GPPScript.csv
		>NetApi
			> ComputerGroupMember.csv
			> ComputerSession.csv
			> ComputerShare.csv
			> ComputerStartTime.csv
			> ComputerVersion.csv
	> Subdomain or trusted domain if recursive mode is enabled
```

### Install-BloodHound.ps1

Original script [BloodHoundw64_LTI](https://github.com/SadProcessor/SomeStuff/blob/master/BloodHoundw64_LTI.ps1) from @SadProcessor, this version adds a quiet mode and the latest BloodHound versions.

`Install-BloodHound -quiet neo4j2022`

## License
 
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
 
## Acknowledgments
 
* Everyone referenced in the code, I hope I didn't miss any reference
* A special thanks to @harmj0y, @mattifestation & @itm4n for their amazing PowerShell works 
