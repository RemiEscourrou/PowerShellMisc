#requires -version 5

function Invoke-UserMimiTab 
{

<#
.SYNOPSIS

Author: Remi Escourrou (@remiesccourrou)
License: BSD 3-Clause
Required Dependencies: Get-NetDomainController (PowerView), Get-NetSession (PowerView), Get-NetComputerStartTime (WinGate), Get-NetComputerVersion (WinGate)

.DESCRIPTION


.PARAMETER UserTarget
User to TARGET
    
.PARAMETER During
Define the time during this spiers works
Default 600 minutes
    
.PARAMETER Frequency
Define the frequency of the scan
Default 6 minutes
    
.PARAMETER CleanScreen
Switch. Refresh Screen before show the result
    
.EXAMPLE
Invoke-UserMimiTab -UserTarget admin


.EXAMPLE
$DA = (Get-DomainGroupMember "Domain Admins" -Recurse).MemberName | 
Invoke-UserMimiTab -UserTarget $DA -CleanScreen

.OUTPUTS

UserName      SawOn          HostName                Version     SawAt               LastReboot          CredsInMemory
--------      -----          --------                -------     -----               ----------          -------------
admin         192.168.1.24   dcserver.test.fr        6.3         07/21/2017 14:55:58 07/10/2017 10:00:19 Probably
admin         192.168.1.2    computer.test.fr        6.3         07/21/2017 14:55:58 07/17/2017 15:21:14 Probably
admin         192.168.1.12   sqlserver.test.fr       10.0        07/21/2017 14:55:58                     Lost Connection

A PSCustomObject

#>
    Param(
        [String[]]
        $UserTarget,
         
        [Parameter(Mandatory=$False)]
         $During = "600",
        
        [Parameter(Mandatory=$False)]
         $Frequency = "6",
         
        [Switch]
        $CleanScreen,
        
        [Switch]
        $OnlyProbably
    )

    PROCESS {
        
        $UserMimiMaps = @()
        $finder = 1
        While($finder){
                   
                   
            $DomainController = Get-DomainController
            
            $NetSessions = Get-NetSession -HostName ($DomainController).IPAddress

            $ScanDate = Get-Date -Format "MM/dd/yyyy HH':'mm':'ss"

            Foreach ($User in $UserTarget) {
				
                $NetSessions | Where-Object { $_.UserName -eq $User} | ForEach-Object {
                
                    #Write-Verbose $User
                    
                    if($_.CName.Substring(2) -eq "[::1]"){
                        $ComputerIP = $_.ComputerName
                    }
                    else {
                        $ComputerIP = $_.CName.Substring(2)
                    }
                    
                    # If the the entry is already created, move one
                    if ( $UserMimiMaps | ? {($_.UserName -eq $User) -and ($_.SawOn -eq $ComputerIP)}){
                        Write-Verbose "UserMimiMap already created"
                    }
                    
                    # If the entry is not present, create it
                    else {
                        $UserMimiMap = New-Object PSObject
                        $UserMimiMap | Add-Member Noteproperty 'UserName' $_.UserName
                        
                        $UserMimiMap | Add-Member Noteproperty 'SawOn' $ComputerIP
                        
                        Try {
                            $ComputerDNS = Resolve-DnsName $ComputerIP -ErrorAction Stop
                        }
                        Catch {
                            $ComputerDNS = $Null
                        }
                        $UserMimiMap | Add-Member Noteproperty 'HostName' $ComputerDNS.NameHost
                        
                        $ComputerVersion = Get-NetComputerVersion -ComputerName $ComputerIP
                        if($ComputerVersion) {
                            $UserMimiMap | Add-Member Noteproperty 'Version' "$(($ComputerVersion).wki100_ver_major).$(($ComputerVersion).wki100_ver_minor)"
                        }
                        else {
                            $UserMimiMap | Add-Member Noteproperty 'Version' "error"
                        }                       
                        
                        $UserMimiMap | Add-Member Noteproperty 'SawAt' $ScanDate    
                        
                        $LastReboot = Get-NetComputerStartTime -ComputerName $ComputerIP
                        
                        if($LastReboot) {
                            $dateLastReboot = ($LastReboot.StartTime).toString("MM/dd/yyyy HH':'mm':'ss")                
                            $UserMimiMap | Add-Member Noteproperty 'LastReboot' $dateLastReboot
                            $UserMimiMap | Add-Member Noteproperty 'CredsInMemory' "Very likely"
                        }
                        else {
                            $UserMimiMap | Add-Member Noteproperty 'LastReboot' ""
                            $UserMimiMap | Add-Member Noteproperty 'CredsInMemory' "Host Disconnected"
                        }
                       
                        Write-Verbose "Add newone UserMimiMap"
                       
                        $UserMimiMaps += $UserMimiMap
                    }
                }
            }

            # Maj the value of 
            if ($UserMimiMaps) {
                $UserMimiMaps | Where-Object {$_.CredsInMemory -ne "No"} | ForEach-Object {
                
                    $MAJLastReboot = (Get-NetComputerStartTime -ComputerName $_.SawOn)
                    
                    if($MAJLastReboot){                        
                        if ($MAJLastReboot.StartTime -gt $_.SawAt) {
                            $_.LastReboot = $MAJLastReboot.StartTime
                            $_.CredsInMemory = "No"
                        }
                        else {
                            Write-Host "Creds still in Memory"
                        }
                    }
                    else {
                        $_.CredsInMemory = "Host Disconnected"
                    }
                }
                
                if ($CleanScreen) {
                    Clear-Host
                }
                
                if ($OnlyProbably) {
                    $UserMimiMaps | Where-Object {$_.CredsInMemory -eq "Probably"} | Select * | Format-Table -Autosize
                }
                else {
                    #Write-Host $UserMimiMaps
                    $UserMimiMaps | Select * | Format-Table -Autosize
                }
            
            }
        }
    }
}
    
    
    