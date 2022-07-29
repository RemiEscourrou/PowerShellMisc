function Invoke-MachineRoleCheck {
    <#
    .SYNOPSIS
    Gets the role of the machine (workstation, server, domain controller)
    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The role of the machine can be checked by reading the following registry key: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions. The "ProductType" value represents the role of the machine.
    
    .EXAMPLE
    PS C:\> Invoke-MachineRoleCheck
    Name  Role       
    ----  ----       
    WinNT WorkStation
    
    .NOTES
    WinNT = workstation
    LanmanNT = domain controller
    ServerNT = server
    #>
    
    [CmdletBinding()] Param()

    $Item = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    
    $FriendlyNames = @{
        "WinNT"     = "Workstation";
        "LanmanNT"  = "Domain Controller";
        "ServerNT"  = "Server";
    }

    if (-not $GetItemPropertyError) {
        try {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Item.ProductType
            $Result | Add-Member -MemberType "NoteProperty" -Name "Role" -Value $FriendlyNames[$Item.ProductType]
            $Result
        }
        catch {
            Write-Verbose "Hashtable error."
        }
    }
}

function Invoke-SystemInfoCheck {
    <#
    .SYNOPSIS
    Gets the name of the operating system and the full version string.
    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Reads the "Product Name" from the registry and gets the full version string based on the operating system.
    
    .EXAMPLE
    Invoke-SystemInfoCheck | fl
    Name    : Windows 10 Home
    Version : 10.0.18363 Version 1909 (18363.535)
    .LINK
    https://techthoughts.info/windows-version-numbers/
    #>
    
    [CmdletBinding()] Param()

    $OsVersion = Get-WindowsVersion

    
    if (-not $GetItemPropertyError) {

        if ($OsVersion.Major -ge 10) {
            $OsVersionStr = "$($OsVersion.Major).$($OsVersion.Minor).$($OsVersion.Build) Version $($Item.ReleaseId) ($($OsVersion.Build).$($Item.UBR))"
        }
        else {
            $OsVersionStr = "$($OsVersion.Major).$($OsVersion.Minor).$($OsVersion.Build) N/A Build $($OsVersion.Build)"
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Item.ProductName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $OsVersionStr
        $Result
    }
    else {
        Write-Verbose $GetItemPropertyError
    }
}

function Invoke-DefenderAutomaticExclusionsCheck {
    <#
    .SYNOPSIS
    CHeck if Microsoft Defender Automatic exclusions on Windows Server is enabled
    Author: @RemiEscourrou
    
    .DESCRIPTION
    This check was inspired by a tweet from @splinter_code and @NathanMcNulty, mentioning the fact that Microsoft Defender Antivirus includes automatic exclusions for some windows role
    These exclusions do not appear in the standard exclusion lists that are shown in the Windows Security app. Keep the following important points in mind:
	> Custom exclusions take precedence over automatic exclusions.
	> Automatic exclusions only apply to Real-time protection (RTP) scanning. Automatic exclusions are not honored during a full, quick, or on-demand scan.
	
	.NOTES
    @splinter_code: https://twitter.com/splinter_code/status/1481073265380581381
	@NathanMcNulty : https://twitter.com/NathanMcNulty/status/1481136160936132609
	Microsoft Docs: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-server-exclusions-microsoft-defender-antivirus?view=o365-worldwide

    #>

    [CmdletBinding()] Param()
	
	$MachineRole = Invoke-MachineRoleCheck
	
	if (-not $MachineRole.role -match "Workstation"){
		
		$RegCurrentVersion = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
		$ProductName = $RegCurrentVersion.ProductName.Split(" ")
		if ($ProductName[2] -ge "2016") {
			
			$RegExclusions = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
			$DisableAutoExclusions = $RegExclusions.DisableAutoExclusions
			if (($DisableAutoExclusions -eq "0") -or ($DisableAutoExclusions -eq $null)){
				Write-Host "Defender Automatic Exclusions is deployed"
			}
		}
		else (
			Write-Host "Defender Automatic Exclusions only applied on Windows Server 2016 or later"
		)
	}
	else (
		Write-Host "Defender Automatic Exclusions not deployed on workstation"
	)
}